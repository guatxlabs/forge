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
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use base64::Engine;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;

use std::time::Duration;
use tokio::sync::{broadcast, Mutex as AsyncMutex};

// FINDINGS LIBRARY (modèles de findings réutilisables — livrable client type Ghostwriter). Feature
// console à part entière : ses handlers/logique vivent dans son PROPRE module (règle : pas de gros bloc
// de handlers dans ce main.rs déjà volumineux). Ce main.rs n'y contribue que la ligne `mod` + le
// `merge` des routes (build_router). Le module réutilise App + les helpers d'auth/ledger de ce fichier
// (visibles depuis un module descendant de la racine de crate).
mod finding_templates;
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
// SAUVEGARDE / RESTAURATION CHIFFRÉE (+ politique/scheduler offsite, /api/backup*, /api/restore) et
// MIGRATION / CHIFFREMENT AU REPOS — deux sous-systèmes cohésifs déplacés hors de main.rs (PURE MOVE,
// Wave 2). Re-exportés `pub(crate)` à la racine de crate pour que le module de tests (`super::*`) ET les
// appelants inter-modules (`crate::backup_write_atomic`, `crate::backup_encrypt`, `crate::sha256_hex_bytes`,
// … depuis compliance) continuent de les résoudre inchangés. `dbmigrate::copy_ledger_and_key` référence
// `crate::backup::backup_write_atomic` (dépendance croisée volontaire — même trio base+ledger+clé).
mod backup;
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

// Version produit — SOURCE DE VÉRITÉ UNIQUE : le fichier `VERSION` à la racine du repo, lu à la
// COMPILATION (`include_str!`). Le même fichier alimente le moteur Python (forge/__init__.py) et
// est vérifié en dérive par la CI (`make check-version`). `CARGO_MANIFEST_DIR` = `console/`, donc
// `../VERSION` = la racine. Un `\n` de fin est possible -> trim au point d'usage (forge_version()).
const FORGE_VERSION_RAW: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../VERSION"));

/// Version nettoyée (sans espaces/newline de fin), réutilisable partout (CLI `--version`,
/// JSON `/health`, pied de page de l'UI web). Reste `&'static` (sous-tranche de la const).
fn forge_version() -> &'static str {
    FORGE_VERSION_RAW.trim()
}

// SCHEMA de base (idempotent — execute_batch). Les ajouts de colonnes sur les tables existantes
// passent par `migrate()` (ALTER error-ignored) pour ne pas casser une base déjà peuplée.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS campaign(id INTEGER PRIMARY KEY, name TEXT, started TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS finding(
  id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, title TEXT, severity TEXT,
  category TEXT, mitre TEXT, status TEXT, evidence TEXT, tool TEXT, poc TEXT,
  UNIQUE(campaign, target, title) ON CONFLICT IGNORE);
CREATE TABLE IF NOT EXISTS runrecord(
  id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, kind TEXT, mitre TEXT,
  fired INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS panel(
  id INTEGER PRIMARY KEY, name TEXT, query TEXT, viz TEXT DEFAULT 'table', position INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS dashboard(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, descr TEXT DEFAULT '', position INTEGER DEFAULT 0,
  created TEXT DEFAULT '', updated TEXT DEFAULT '');
-- MODULE (connecteurs) : `available` = disponibilité SONDÉE au boot (host). `enabled` et
-- `available_override` = INTENTION OPÉRATEUR gouvernée depuis l'admin console (jamais écrasée par un
-- re-probe, cf. populate_modules) : `enabled=0` désinstalle opérationnellement le connecteur ;
-- `available_override` (NULL=suivre la sonde, 0/1=forcer) surcharge la disponibilité host. Disponibilité
-- EFFECTIVE = enabled AND (available_override ?? available). Un module désactivé (enabled=0 ou override=0)
-- est SKIP au tir même si son binaire est présent (scope.json disabled_modules -> engine.execute).
CREATE TABLE IF NOT EXISTS module(
  kind TEXT PRIMARY KEY, exploit INTEGER DEFAULT 0, destructive INTEGER DEFAULT 0,
  available INTEGER DEFAULT 1, mitre TEXT DEFAULT '', descr TEXT DEFAULT '',
  web_allowed INTEGER DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
  available_override INTEGER DEFAULT NULL);
CREATE TABLE IF NOT EXISTS roe_decision(
  id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, run_id TEXT, action_id TEXT, target TEXT,
  kind TEXT, verdict TEXT, exploit INTEGER DEFAULT 0, destructive INTEGER DEFAULT 0, reasons TEXT);
CREATE TABLE IF NOT EXISTS run_job(
  id INTEGER PRIMARY KEY, run_id TEXT UNIQUE, campaign TEXT, ts TEXT, status TEXT,
  mode TEXT, fired INTEGER DEFAULT 0, dry_run INTEGER DEFAULT 0, vetoed INTEGER DEFAULT 0,
  errors INTEGER DEFAULT 0, skipped_budget TEXT DEFAULT '[]', coverage_gaps TEXT DEFAULT '{}', detail TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS ledger_entry(
  seq INTEGER PRIMARY KEY, ts TEXT, kind TEXT, detail TEXT, prev TEXT, hash TEXT, alg TEXT, sig TEXT);
CREATE TABLE IF NOT EXISTS run_log(
  id INTEGER PRIMARY KEY, run_id TEXT, ts TEXT, stream TEXT, line TEXT);
CREATE INDEX IF NOT EXISTS idx_run_log_run ON run_log(run_id, id);
-- COMPTES UTILISATEURS (#6) : identités individuelles + attribution. `role` ∈ {viewer|operator|admin}
-- (contrainte applicative, pas SQL — voir validate_role). `pass_hash` = argon2id (jamais en clair).
-- `disabled` = 1 désactive le compte (login refusé, fail-closed). UNIQUE(login) anti-doublon.
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, login TEXT UNIQUE NOT NULL, role TEXT NOT NULL,
  pass_hash TEXT NOT NULL, disabled INTEGER DEFAULT 0, created TEXT DEFAULT '');
-- SESSIONS COURTES : on stocke le SHA-256 du token (jamais le token en clair — fuite DB inoffensive),
-- l'user_id propriétaire, l'horodatage de création et d'expiration (epoch s). Index pour le purge/lookup.
CREATE TABLE IF NOT EXISTS session(
  token_sha TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id);
-- SETTINGS (KV) : configuration MUTABLE d'administration (politique opérateur, source de détection,
-- params par défaut, état du wizard de 1er déploiement…). `updated` = horodatage de dernière écriture.
-- Les mutations sont réservées à check_admin (attribution individuelle stricte) et ledgerisées par
-- l'appelant. Substrat neutre : une clé absente = comportement par défaut (aucune valeur inventée).
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated TEXT NOT NULL);
-- ENGAGEMENT (objet de 1re classe — à la workspace Metasploit) : un espace de travail ISOLÉ. Chaque
-- engagement porte SON scope (scope_json = in/out scope autoritatif), SON mode (white|grey|black),
-- SON ledger (ledger_path : chaîne SHA-256 tamper-evident DÉDIÉE) et sa gouvernance (classification/
-- retention_policy). ISOLATION FAIL-CLOSED : un run applique le scope-guard de SON engagement — il ne
-- touche JAMAIS le scope, les findings ni le ledger d'un AUTRE engagement. La colonne `campaign`
-- (finding/run_job) reste un sous-label LIBRE AU SEIN d'un engagement. finding/runrecord/roe_decision/
-- run_job portent `engagement_id` (DEFAULT 1 = engagement #1, créé au boot depuis le scope serveur
-- courant via ensure_default_engagement : migration rétro-compat ZÉRO-PERTE). `status` ∈ {active|
-- archived}, `mode` ∈ {white|grey|black} (contraintes applicatives, pas SQL). `tenant_id` (ENTERPRISE,
-- ajouté par migrate ; DEFAULT 1 = tenant #1) rattache l'engagement à un TENANT : le filtre fail-closed
-- tenancy.rs (flag-gated) restreint chaque lecture/écriture aux engagements des tenants accordés au
-- caller — NO-OP en community (single implicit tenant #1, byte-identique).
CREATE TABLE IF NOT EXISTS engagement(
  id INTEGER PRIMARY KEY, name TEXT, status TEXT DEFAULT 'active', mode TEXT DEFAULT 'grey',
  scope_json TEXT NOT NULL DEFAULT '{}', ledger_path TEXT NOT NULL DEFAULT '',
  classification TEXT, retention_policy TEXT, created TEXT DEFAULT '', updated TEXT DEFAULT '');
-- FINDINGS LIBRARY (bibliothèque de modèles réutilisables — objet livrable client, cf. Ghostwriter).
-- Un `finding_template` est GLOBAL (réutilisable ACROSS engagements — jamais rattaché à un engagement) :
-- il porte des gabarits PARAMÉTRÉS (`{target}`/`{param}` remplis À L'APPLICATION). APPLIQUER un modèle
-- CRÉE un finding dans l'engagement ACTIF UNIQUEMENT (isolation : le template est global, le finding
-- produit appartient à SON engagement, comme tout finding). `refs` = références libres (SQL-safe : on
-- évite le mot réservé `references`, exposé `references` dans l'API JSON). `severity` ∈ SEVERITIES
-- (INFO|LOW|MEDIUM|HIGH|CRITICAL, contrainte applicative). CRUD gouverné (create/edit=operator,
-- delete=admin) + ledgerisé `console.finding_template.*` — voir console/src/finding_templates.rs.
CREATE TABLE IF NOT EXISTS finding_template(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, vuln_class TEXT DEFAULT '', cwe TEXT DEFAULT '',
  severity TEXT DEFAULT 'INFO', title_tmpl TEXT DEFAULT '', description_tmpl TEXT DEFAULT '',
  remediation_tmpl TEXT DEFAULT '', refs TEXT DEFAULT '', created TEXT DEFAULT '', updated TEXT DEFAULT '');
-- TENANT (ENTERPRISE — row-level multi-tenancy, separable/flag-gated). Top of the hierarchy:
-- TENANT ──< ENGAGEMENT ──< findings/runs (data inherits tenant via engagement_id). Community (default)
-- runs as a SINGLE IMPLICIT TENANT #1 with byte-identical behaviour — the tenant filter (tenancy.rs) is a
-- no-op unless the enterprise flag is engaged. `status` ∈ {active|archived} (applicative constraint).
CREATE TABLE IF NOT EXISTS tenant(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT DEFAULT 'active',
  created TEXT DEFAULT '', updated TEXT DEFAULT '');
-- TENANT_GRANT (ENTERPRISE) : maps which USERS may access which TENANTS. FAIL-CLOSED enforcement
-- (tenancy.rs) — a user only sees/acts on engagements whose tenant_id is in their granted set; no grant
-- => zero rows / 403. `role` ∈ {tenant_admin|tenant_operator|tenant_viewer} (applicative). UNIQUE(user,tenant)
-- => at most one grant per (user,tenant). In community mode grants are unused (single implicit tenant).
CREATE TABLE IF NOT EXISTS tenant_grant(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, tenant_id INTEGER NOT NULL,
  role TEXT NOT NULL DEFAULT 'tenant_viewer', created TEXT DEFAULT '',
  UNIQUE(user_id, tenant_id) ON CONFLICT IGNORE);
CREATE INDEX IF NOT EXISTS idx_tenant_grant_user ON tenant_grant(user_id);
";

/// Migrations additives (ALTER) — chaque ALTER est error-ignored : si la colonne existe déjà
/// (base ancienne ou re-boot) SQLite renvoie une erreur qu'on absorbe. Idempotent.
fn migrate(db: &Connection) {
    let alters = [
        // run_id corrèle finding/runrecord avec le run_job qui les a produits (boucle purple).
        "ALTER TABLE finding ADD COLUMN run_id TEXT DEFAULT ''",
        "ALTER TABLE finding ADD COLUMN fix TEXT DEFAULT ''",
        // taxonomie client séparée (LOT REPORTING) : CWE dédié + CVSS de base (vecteur + score),
        // distincts de `category` (fourre-tout historique) et `mitre` (ATT&CK). Le moteur Python
        // (schema.Finding.to_dict) émet déjà ces champs ; l'ingest les capte si présents, sinon le
        // rapport dérive le CWE depuis `category` (rétro-compat). Additifs/error-ignored.
        "ALTER TABLE finding ADD COLUMN cwe TEXT DEFAULT ''",
        "ALTER TABLE finding ADD COLUMN cvss_vector TEXT DEFAULT ''",
        "ALTER TABLE finding ADD COLUMN cvss_score REAL DEFAULT 0",
        "ALTER TABLE runrecord ADD COLUMN run_id TEXT DEFAULT ''",
        // panel étendu : description, largeur de colonne, horodatage de mise à jour.
        "ALTER TABLE panel ADD COLUMN descr TEXT DEFAULT ''",
        "ALTER TABLE panel ADD COLUMN col_span INTEGER DEFAULT 1",
        "ALTER TABLE panel ADD COLUMN updated TEXT DEFAULT ''",
        // dashboard_id : un panel appartient à un dashboard (vue). DEFAULT 1 = dashboard par défaut
        // (créé/garanti au boot par ensure_default_dashboard) -> rétro-compat : les panels existants
        // d'une base ancienne héritent du dashboard #1 sans intervention.
        "ALTER TABLE panel ADD COLUMN dashboard_id INTEGER DEFAULT 1",
        // run_job étendu (C2-light) : provenance opérateur + traçage du process spawné.
        // `pid` = PID du groupe de process (setsid) pour cancel/watchdog ; -1 si terminé.
        "ALTER TABLE run_job ADD COLUMN pid INTEGER DEFAULT -1",
        "ALTER TABLE run_job ADD COLUMN started_by TEXT DEFAULT ''",
        "ALTER TABLE run_job ADD COLUMN reason TEXT DEFAULT ''",
        "ALTER TABLE run_job ADD COLUMN targets TEXT DEFAULT '[]'",
        "ALTER TABLE run_job ADD COLUMN modules TEXT DEFAULT '[]'",
        "ALTER TABLE run_job ADD COLUMN started TEXT DEFAULT ''",
        "ALTER TABLE run_job ADD COLUMN finished TEXT DEFAULT ''",
        "ALTER TABLE run_job ADD COLUMN exit_code INTEGER DEFAULT NULL",
        // GOUVERNANCE CONNECTEUR (#4) : intention opérateur persistée sur la table `module`, distincte
        // de la disponibilité SONDÉE (`available`). `enabled` NOT NULL DEFAULT 1 (autorisé par SQLite car
        // la colonne a un DEFAULT) ; `available_override` NULL = suivre la sonde. Ces deux colonnes ne
        // sont JAMAIS réécrites par populate_modules (re-probe) — seul l'admin les mute (POST /api/modules/:kind).
        "ALTER TABLE module ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE module ADD COLUMN available_override INTEGER DEFAULT NULL",
        // ENGAGEMENT (objet de 1re classe) : chaque ligne de données appartient à un engagement.
        // DEFAULT 1 (engagement #1) => rétro-compat ZÉRO-PERTE : une base ANTÉRIEURE voit TOUTES ses
        // lignes existantes rattachées à l'engagement par défaut (créé au boot depuis le scope serveur
        // courant, ensure_default_engagement). NOT NULL autorisé par SQLite ici car la colonne a un
        // DEFAULT constant (aucune ligne existante ne devient NULL). L'isolation applicative (un run
        // n'écrit que dans SON engagement) est portée par run_create/ingest.
        "ALTER TABLE finding ADD COLUMN engagement_id INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE runrecord ADD COLUMN engagement_id INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE roe_decision ADD COLUMN engagement_id INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE run_job ADD COLUMN engagement_id INTEGER NOT NULL DEFAULT 1",
        // TENANT (ENTERPRISE) : chaque engagement appartient à un tenant. DEFAULT 1 (tenant #1) =>
        // rétro-compat ZÉRO-PERTE : une base ANTÉRIEURE voit TOUS ses engagements rattachés au tenant
        // par défaut (créé au boot par ensure_default_tenant). NOT NULL autorisé (DEFAULT constant).
        // L'isolation applicative (filtre fail-closed) est portée par tenancy.rs — no-op en community.
        "ALTER TABLE engagement ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1",
    ];
    for a in alters {
        let _ = db.execute(a, []); // error-ignored (colonne déjà présente)
    }
    // ENGAGEMENT (objet de 1re classe) : re-créée ici (idempotent, CREATE IF NOT EXISTS) en plus du
    // SCHEMA, pour qu'une base ANTÉRIEURE à son introduction l'obtienne au 1er boot suivant la mise à
    // jour (même discipline que `settings`). error-ignored.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS engagement(
           id INTEGER PRIMARY KEY, name TEXT, status TEXT DEFAULT 'active', mode TEXT DEFAULT 'grey',
           scope_json TEXT NOT NULL DEFAULT '{}', ledger_path TEXT NOT NULL DEFAULT '',
           classification TEXT, retention_policy TEXT, created TEXT DEFAULT '', updated TEXT DEFAULT '')",
        [],
    );
    // SETTINGS (KV) : re-créée ici (idempotent, CREATE IF NOT EXISTS) en plus du SCHEMA, pour qu'une
    // base ANTÉRIEURE à son introduction l'obtienne au 1er boot suivant la mise à jour. error-ignored.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated TEXT NOT NULL)",
        [],
    );
    // FINDINGS LIBRARY : re-créée ici (idempotent) en plus du SCHEMA, pour qu'une base ANTÉRIEURE à son
    // introduction obtienne la table `finding_template` au 1er boot suivant la mise à jour (même
    // discipline que `engagement`/`settings`). GLOBALE (aucun engagement_id) — voir finding_templates.rs.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS finding_template(
           id INTEGER PRIMARY KEY, name TEXT NOT NULL, vuln_class TEXT DEFAULT '', cwe TEXT DEFAULT '',
           severity TEXT DEFAULT 'INFO', title_tmpl TEXT DEFAULT '', description_tmpl TEXT DEFAULT '',
           remediation_tmpl TEXT DEFAULT '', refs TEXT DEFAULT '', created TEXT DEFAULT '', updated TEXT DEFAULT '')",
        [],
    );
    // TENANT / TENANT_GRANT (ENTERPRISE) : re-créées ici (idempotent) en plus du SCHEMA, pour qu'une base
    // ANTÉRIEURE à leur introduction les obtienne au 1er boot suivant la mise à jour (même discipline que
    // `engagement`/`settings`). Le seeding du tenant #1 + backfill est fait par ensure_default_tenant.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS tenant(
           id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT DEFAULT 'active',
           created TEXT DEFAULT '', updated TEXT DEFAULT '')",
        [],
    );
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS tenant_grant(
           id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, tenant_id INTEGER NOT NULL,
           role TEXT NOT NULL DEFAULT 'tenant_viewer', created TEXT DEFAULT '',
           UNIQUE(user_id, tenant_id) ON CONFLICT IGNORE)",
        [],
    );
    let _ = db.execute("CREATE INDEX IF NOT EXISTS idx_tenant_grant_user ON tenant_grant(user_id)", []);
}

/// Garantit l'existence du dashboard par défaut (id=1) — rétro-compat : la colonne `panel.dashboard_id`
/// a DEFAULT 1, donc tout panel pré-existant pointe déjà ici. Idempotent (INSERT OR IGNORE sur id=1).
/// Recale aussi les panels orphelins (dashboard_id NULL/0/inexistant) vers le dashboard #1.
fn ensure_default_dashboard(db: &Connection) {
    let _ = db.execute(
        "INSERT OR IGNORE INTO dashboard(id,name,descr,position,created,updated)
         VALUES(1,'Défaut','Dashboard par défaut (rétro-compat)',0,datetime('now'),datetime('now'))",
        [],
    );
    // panels sans dashboard valide -> rattachés au défaut (ne casse jamais un panel existant).
    let _ = db.execute(
        "UPDATE panel SET dashboard_id=1
         WHERE dashboard_id IS NULL OR dashboard_id NOT IN (SELECT id FROM dashboard)",
        [],
    );
}

/// ENGAGEMENT résolu (vue en mémoire d'une ligne `engagement`) : le scope in/out DÉCODÉ depuis
/// `scope_json`, le `mode` effectif et le `ledger_path` DÉDIÉ. C'est CET objet (jamais les App globals)
/// que le run flow consomme : scope-guard = `scope_in`/`scope_out` de l'engagement (fail-closed),
/// journalisation dans `ledger_path` de l'engagement. Isolation : un run pour l'engagement A ne voit
/// que le scope de A.
#[derive(Clone, Debug)]
struct Engagement {
    id: i64,
    mode: String,
    scope_in: Vec<String>,
    scope_out: Vec<String>,
    ledger_path: String,
}

/// Extrait la liste de chaînes d'un champ tableau d'un scope_json (in_scope/out_scope). Absent/mal
/// formé => vide (fail-closed pour in_scope : un engagement sans in_scope ne lance rien).
fn scope_json_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// Charge un engagement par id : décode `scope_json` (in/out scope) et le `mode` (le `mode` du
/// scope_json prime sur la colonne `mode` s'il est présent — le scope reste la source autoritaire du
/// périmètre). None si l'id n'existe pas. Pure lecture (aucune écriture).
fn load_engagement(db: &Connection, id: i64) -> Option<Engagement> {
    let (mode_col, scope_json, ledger_path): (String, String, String) = db
        .query_row(
            "SELECT mode, scope_json, ledger_path FROM engagement WHERE id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok()?;
    let v: Value = serde_json::from_str(&scope_json).unwrap_or_else(|_| json!({}));
    let mode = v
        .get("mode")
        .and_then(|m| m.as_str())
        .map(String::from)
        .unwrap_or(mode_col);
    Some(Engagement {
        id,
        mode,
        scope_in: scope_json_list(&v, "in_scope"),
        scope_out: scope_json_list(&v, "out_scope"),
        ledger_path,
    })
}

/// MIGRATION ZÉRO-PERTE — garantit l'ENGAGEMENT #1 : si la table `engagement` est VIDE, crée
/// l'engagement #1 depuis le scope serveur COURANT (in_scope + mode via load_server_scope) et le
/// ledger COURANT (App.ledger_path). Les lignes finding/runrecord/roe_decision/run_job existantes
/// gardent engagement_id=1 (DEFAULT de la colonne ajoutée par migrate) => rétro-compat totale. Le
/// `campaign` free-text existant reste un sous-label AU SEIN de l'engagement #1. Idempotent : ne fait
/// RIEN si un engagement existe déjà (n'écrase jamais un scope/ledger déjà provisionné).
fn ensure_default_engagement(db: &Connection, scope_in: &[String], scope_mode: &str, ledger_path: &str) {
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM engagement", [], |r| r.get(0))
        .unwrap_or(0);
    if count > 0 {
        return; // déjà provisionné — ne jamais écraser
    }
    let scope_json = json!({
        "_comment": "scope de l'engagement #1 — dérivé du scope serveur courant au 1er boot (migration zéro-perte)",
        "mode": scope_mode,
        "in_scope": scope_in,
        "out_scope": []
    })
    .to_string();
    let _ = db.execute(
        "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
         VALUES(1,?,?,?,?,?,datetime('now'),datetime('now'))",
        rusqlite::params!["Engagement par défaut", "active", scope_mode, scope_json, ledger_path],
    );
}

/// MIGRATION ZÉRO-PERTE (ENTERPRISE / rétro-compat) — garantit le TENANT #1 (défaut). Si la table
/// `tenant` est VIDE : crée le tenant #1, backfille tout engagement au tenant #1 (la colonne
/// `engagement.tenant_id` a DEFAULT 1, ceci est un filet défensif), et SÈME un grant vers le tenant #1
/// pour CHAQUE utilisateur existant (rôle dérivé du rôle RBAC : admin->tenant_admin, operator->
/// tenant_operator, sinon tenant_viewer). But : quand l'admin ENGAGE plus tard le flag enterprise, les
/// comptes déjà provisionnés conservent l'accès à l'espace historique (« existing users implicitly have
/// full access to tenant #1 »). En COMMUNITY le filtre est de toute façon un no-op ; ces grants restent
/// inertes. Idempotent : ne fait RIEN si un tenant existe déjà (n'écrase jamais un provisioning).
fn ensure_default_tenant(db: &Connection) {
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM tenant", [], |r| r.get(0))
        .unwrap_or(0);
    if count > 0 {
        return; // déjà provisionné — ne jamais écraser
    }
    let _ = db.execute(
        "INSERT INTO tenant(id,name,status,created,updated)
         VALUES(1,'Tenant par défaut','active',datetime('now'),datetime('now'))",
        [],
    );
    // filet défensif : tout engagement sans tenant valide -> tenant #1 (la colonne a déjà DEFAULT 1).
    let _ = db.execute(
        "UPDATE engagement SET tenant_id=1 WHERE tenant_id IS NULL OR tenant_id NOT IN (SELECT id FROM tenant)",
        [],
    );
    // rétro-compat : chaque utilisateur existant reçoit un grant vers le tenant #1 (rôle dérivé du RBAC).
    let _ = db.execute(
        "INSERT OR IGNORE INTO tenant_grant(user_id,tenant_id,role,created)
         SELECT id, 1,
                CASE role WHEN 'admin' THEN 'tenant_admin' WHEN 'operator' THEN 'tenant_operator' ELSE 'tenant_viewer' END,
                datetime('now')
           FROM users",
        [],
    );
}

/// `web_allowed` : un module est lançable depuis l'UI web seulement s'il n'exploite pas, n'est pas
/// destructif, et n'est pas l'interception IDOR (qui tamper une requête en vol — réservé CLI/opérateur).
fn module_web_allowed(kind: &str, exploit: bool, destructive: bool) -> bool {
    !exploit && !destructive && kind != "evasion.idor_intercept"
}

/// INTENTION OPÉRATEUR de désactiver un connecteur (gouvernance, indépendante de la sonde host) :
/// vrai si `enabled=0` OU `available_override=Some(false)` (override explicite « indisponible »). Un
/// simple binaire absent (probed=0, sans override) N'EST PAS une désactivation opérateur — le moteur
/// le SKIP déjà via sa propre sonde. C'est CE set qu'on refuse dans validate_modules et qu'on injecte
/// dans scope.json `disabled_modules` (pour que le moteur SKIP même un outil PRÉSENT que l'opérateur a
/// désactivé). Fonction PURE (testable, aucun I/O).
fn module_operator_disabled(enabled: bool, available_override: Option<bool>) -> bool {
    !enabled || available_override == Some(false)
}

/// Disponibilité EFFECTIVE d'un connecteur = `enabled AND (available_override ?? probed_available)`.
/// Exposée au front (badge « effectif ») et cohérente avec module_operator_disabled : effective=false
/// dès que l'opérateur désactive (enabled=0 / override=0) OU que la sonde host est négative sans override.
/// Fonction PURE (testable, aucun I/O).
fn module_effectively_available(enabled: bool, available_override: Option<bool>, probed_available: bool) -> bool {
    enabled && available_override.unwrap_or(probed_available)
}

/// Résout le répertoire des assets web statiques (style.css/app.js/fonts/…) de façon robuste,
/// indépendamment du cwd — sans ça, le défaut relatif `"web"` est servi en 0 octet quand la console
/// est lancée hors `console/` (seul index.html survit via include_str!). Ordre de priorité :
///   1) $FORGE_CONSOLE_WEB s'il est posé (override explicite de l'opérateur) ;
///   2) <dir-du-binaire>/web et <dir-du-binaire>/../web (cas `./target/{debug,release}/forge-console`
///      lancé de n'importe où : les assets sont copiés/symlinkés à côté, ou restent dans console/web) ;
///   3) $FORGE_PKG_DIR/console/web puis ./console/web puis ./web (cas lancé depuis console/ ou la racine) ;
///   4) repli `"web"` (comportement historique, lancé depuis console/).
fn resolve_web_dir() -> String {
    if let Ok(w) = std::env::var("FORGE_CONSOLE_WEB") {
        if !w.is_empty() {
            return w;
        }
    }
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // assets copiés/symlinkés à côté du binaire (déploiement)
            candidates.push(dir.join("web"));
            // ./console/target/{debug,release}/forge-console -> remonter au crate console/, puis web/
            // (target/release -> target -> console -> console/web)
            candidates.push(dir.join("..").join("..").join("web"));
            // tolérance si le binaire est une marche plus haut (target/forge-console)
            candidates.push(dir.join("..").join("web"));
        }
    }
    if let Ok(pkg) = std::env::var("FORGE_PKG_DIR") {
        candidates.push(std::path::PathBuf::from(&pkg).join("console").join("web"));
    }
    candidates.push(std::path::PathBuf::from("console").join("web"));
    candidates.push(std::path::PathBuf::from("web"));
    for c in &candidates {
        if c.join("style.css").is_file() {
            return c.to_string_lossy().into_owned();
        }
    }
    // aucun asset trouvé : repli historique (au moins index.html via include_str! reste servi).
    "web".to_string()
}

/// Charge le scope serveur autorisé (in_scope + mode) pour pré-filtrer les cibles lançables via le
/// web. Source : $FORGE_CONSOLE_SCOPE s'il pointe un scope.json ; sinon <pkg_dir>/scope.json. Si rien
/// n'est trouvé/parsable -> in_scope VIDE (fail-closed : aucune cible lançable depuis le web).
fn load_server_scope(pkg_dir: &str) -> (Vec<String>, String) {
    let path = std::env::var("FORGE_CONSOLE_SCOPE")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| std::path::Path::new(pkg_dir).join("scope.json").to_string_lossy().into_owned());
    match std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
        Some(v) => {
            let in_scope = v.get("in_scope").and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let mode = v.get("mode").and_then(|m| m.as_str()).unwrap_or("grey").to_string();
            (in_scope, mode)
        }
        None => {
            eprintln!("[forge-console] scope serveur introuvable ({path}) — C2 fail-closed (aucune cible lançable)");
            (vec![], "grey".to_string())
        }
    }
}

/// Peuple la table `module` au boot depuis le registre Python (`python3 -m forge.cli modules`).
/// Tente d'abord `--json` (si la CLI le supporte un jour), sinon parse la sortie texte :
///   "  <kind>   exploit=<bool> destructive=<bool>". Best-effort : si python/forge absent, on
///   laisse la table en l'état (les lectures /api/modules renverront ce qu'il y a). `forge` est
///   importé depuis le parent du cwd console ; on lance depuis FORGE_PKG_DIR si défini, sinon `..`.
fn populate_modules(db: &Connection) {
    let pkg_dir = std::env::var("FORGE_PKG_DIR").unwrap_or_else(|_| "..".to_string());
    let py = std::env::var("FORGE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    // 1) essai JSON
    let parsed = std::process::Command::new(&py)
        .args(["-m", "forge.cli", "modules", "--json"])
        .current_dir(&pkg_dir)
        .output()
        .ok()
        .and_then(|o| if o.status.success() { parse_modules_json(&String::from_utf8_lossy(&o.stdout)) } else { None })
        // 2) repli texte
        .or_else(|| {
            std::process::Command::new(&py)
                .args(["-m", "forge.cli", "modules"])
                .current_dir(&pkg_dir)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| parse_modules_text(&String::from_utf8_lossy(&o.stdout)))
        });
    let mods = match parsed {
        Some(m) if !m.is_empty() => m,
        _ => {
            eprintln!("[forge-console] modules: registre Python indisponible (table `module` inchangée)");
            return;
        }
    };
    let mut n = 0;
    for m in &mods {
        let kind = m.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if kind.is_empty() { continue; }
        let exploit = m.get("exploit").and_then(|v| v.as_bool()).unwrap_or(false);
        let destructive = m.get("destructive").and_then(|v| v.as_bool()).unwrap_or(false);
        let available = m.get("available").and_then(|v| v.as_bool()).unwrap_or(true);
        let mitre = m.get("mitre").and_then(|v| v.as_str()).unwrap_or("");
        let descr = m.get("descr").or_else(|| m.get("desc")).and_then(|v| v.as_str()).unwrap_or("");
        upsert_probed_module(db, kind, exploit, destructive, available, mitre, descr);
        n += 1;
    }
    println!("[forge-console] modules: {n} enregistrés dans la table `module`");
}

/// UPSERT d'un module SONDÉ, avec NO-CLOBBER de l'intention opérateur. Sur conflit (module déjà connu),
/// ne met à jour QUE les champs SONDÉS (exploit/destructive/available/mitre/descr) ; `web_allowed`
/// (posé au 1er INSERT via module_web_allowed), `enabled` et `available_override` sont ABSENTS de la
/// clause SET -> une ligne existante conserve son intention de gouvernance, tandis qu'un NOUVEAU module
/// hérite de web_allowed dérivé et des DEFAULT `enabled=1` / `available_override=NULL`. Extrait de
/// populate_modules pour être testé sans spawn Python (régression : un disable manuel survit au re-probe).
/// Le plancher exploit reste garanti indépendamment de web_allowed (validate_modules teste
/// exploit/destructive en propre, en amont).
fn upsert_probed_module(db: &Connection, kind: &str, exploit: bool, destructive: bool,
                        available: bool, mitre: &str, descr: &str) {
    let web_allowed = module_web_allowed(kind, exploit, destructive);
    let _ = db.execute(
        "INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed)
         VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(kind) DO UPDATE SET exploit=excluded.exploit, destructive=excluded.destructive,
           available=excluded.available, mitre=excluded.mitre, descr=excluded.descr",
        rusqlite::params![kind, exploit as i64, destructive as i64, available as i64, mitre, descr, web_allowed as i64],
    );
}

fn parse_modules_json(s: &str) -> Option<Vec<Value>> {
    let v: Value = serde_json::from_str(s.trim()).ok()?;
    match v {
        Value::Array(a) => Some(a),
        Value::Object(ref o) => o.get("modules").and_then(|m| m.as_array()).cloned(),
        _ => None,
    }
}

/// Parse la sortie texte de `forge modules` :
///   "Modules enregistrés :"
///   "  access_control.idor      exploit=True destructive=False"
fn parse_modules_text(s: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in s.lines() {
        let t = line.trim();
        if t.is_empty() || !t.contains("exploit=") { continue; }
        let kind = match t.split_whitespace().next() { Some(k) => k, None => continue };
        let exploit = t.contains("exploit=True");
        let destructive = t.contains("destructive=True");
        out.push(json!({ "kind": kind, "exploit": exploit, "destructive": destructive }));
    }
    out
}

/// Évènement SSE diffusé pendant un run (lignes stdout/stderr du moteur + transitions de statut).
#[derive(Clone)]
struct RunEvent {
    run_id: String,
    kind: String, // "log" | "status"
    payload: Value,
}

/// État partagé des runs vivants (C2-light gouverné) — ISOLATION PAR ENGAGEMENT.
/// `current` mappe `engagement_id -> RunHandle` du run VIVANT de CET engagement. Conséquences :
///   - CONCURRENCE INTER-ENGAGEMENT : plusieurs engagements peuvent avoir un run vivant EN MÊME TEMPS
///     (clés distinctes) — démarrer un run pour B pendant qu'un run de A est vivant ne renvoie JAMAIS
///     409 (aucun 409 croisé) ;
///   - FIFO PAR ENGAGEMENT : au plus UN run vivant par engagement — un 2e /api/run sur le MÊME
///     engagement est refusé 409 (refus immédiat, pas de file), jamais sur un autre.
///
/// Le verrou async dans /api/run sérialise la réservation (check `contains_key` -> insert) : la clé
/// étant l'engagement_id, un run n'inspecte ni ne retire JAMAIS le slot d'un autre engagement
/// (isolation par construction). Le `broadcast::Sender` SSE vit hors de ce verrou (clone lock-free dans
/// App.events) pour que les pompes stdout puissent diffuser sans le prendre.
struct RunState {
    current: HashMap<i64, RunHandle>, // engagement_id -> run vivant DE CET engagement (au plus 1)
}

/// Slot d'un run vivant, rangé sous la clé `engagement_id` de `RunState.current`. `run_id` est
/// GLOBAL-unique (traçable, sert de garde anti-course à la libération) ; `pgid` = groupe de process
/// (setsid) pour cancel/watchdog (killpg de tout le sous-arbre).
struct RunHandle {
    run_id: String,
    pgid: i32, // group de process (setsid) -> kill group pour cancel/watchdog
}

#[derive(Clone)]
struct App {
    db: Arc<Mutex<Connection>>,
    db_path: Arc<String>,
    token_sha: Arc<String>,
    token_raw: Arc<String>,          // token bearer EN CLAIR — passé au moteur spawné pour /api/ingest
    user: Arc<String>,
    pass_hash: Arc<String>,          // argon2id ; vide = auth OFF (dev localhost)
    // GATE D'AUTH ENGAGÉE ? — cache recalculé au boot ET à chaque mutation de comptes (create/disable/
    // role-change/delete) pour éviter une requête DB par requête HTTP. `true` dès qu'un hash env est
    // posé (FORGE_CONSOLE_PASS_HASH) OU qu'au moins un compte activé existe en base : la gate s'engage
    // sur l'ÉTAT DB, pas seulement sur l'env (ferme le trou dev-open « comptes en base, env vide »).
    // FAIL-CLOSED : tant qu'un compte activé ou un hash existe, la gate reste engagée.
    auth_required: Arc<AtomicBool>,
    operator_hash: Arc<String>,      // argon2id du rôle OPÉRATEUR (C2) ; vide => FAIL-CLOSED (403 sur tout C2)
    allowed_hosts: Arc<Vec<String>>, // anti-DNS-rebinding
    ledger_path: Arc<String>,        // JSONL du ledger d'engagement (FORGE_CONSOLE_LEDGER)
    pkg_dir: Arc<String>,            // racine du paquet Forge (cwd du spawn `python -m forge.cli`)
    python: Arc<String>,            // interpréteur python (FORGE_PYTHON, défaut python3)
    scope_in: Arc<Vec<String>>,      // in_scope autorisé (recopié dans le scope du run, fail-closed)
    scope_mode: Arc<String>,         // mode du scope (white|grey|black) recopié tel quel
    // DÉTECTION (défensif, purple) : SOURCE de détection CONFIGURABLE (plugin), plus rien de codé en
    // dur. Objet JSON `{kind, endpoint?, auth?:{type,secret}, query?, mapping?}` chargé au boot depuis
    // `settings.detection_source`, avec REPLI rétro-compat sur l'env legacy PLUME_URL/PLUME_TOKEN
    // (traité comme `{kind:plume, endpoint:PLUME_URL, auth:{type:basic,secret:PLUME_TOKEN}}`). `kind`
    // absent/none => couverture en FAIL-OPEN LISIBLE (source_reachable:false, aucune métrique inventée).
    // Le SECRET (auth.secret) n'est JAMAIS renvoyé par un GET, ni journalisé, ni ledgerisé (rédigé).
    // Verrou RW : rechargé (reload_detection_source) après toute mutation de `settings.detection_source`.
    detection_source: Arc<std::sync::RwLock<Arc<Value>>>,
    run_timeout_secs: u64,           // watchdog (FORGE_RUN_TIMEOUT, défaut 1800s)
    run_state: Arc<AsyncMutex<RunState>>,
    events: broadcast::Sender<RunEvent>, // bus SSE lock-free (clone du Sender)
    // Sérialise lecture-head -> calcul -> écriture du ledger JSONL (anti-race : deux appends
    // concurrents liraient le MÊME prev/seq et casseraient la chaîne SHA-256). Cache aussi le head
    // (prev,seq) pour éviter de relire tout le fichier à chaque append (O(n²) -> O(1) amorti).
    ledger_lock: Arc<Mutex<LedgerHead>>,
}

/// Head courant du ledger console (dernier hash + dernière seq), maintenu sous `ledger_lock`.
/// `loaded=false` => pas encore initialisé depuis le disque (lecture paresseuse au 1er append).
#[derive(Default)]
struct LedgerHead {
    prev: String,
    seq: i64,
    loaded: bool,
}

impl App {
    /// Verrouille la connexion SQLite en RÉCUPÉRANT un mutex empoisonné (un panic en section
    /// critique empoisonnait le Mutex et tout `.lock().unwrap()` ultérieur paniquait à son tour ->
    /// DoS API permanent). `into_inner()` reprend la garde : la connexion rusqlite reste utilisable
    /// (une requête échouée renvoie une Err, pas un état mémoire corrompu). Fail-open contrôlé.
    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Vrai s'il existe AU MOINS un compte ACTIVÉ (`disabled=0`) dans la table `users`. Requête légère
    /// (`LIMIT 1`). Ne verrouille QUE le mutex DB : ne JAMAIS l'appeler en tenant déjà `self.db()`
    /// (deadlock). Un échec de lecture -> false (l'engagement de la gate retombe alors sur `pass_hash`).
    fn any_enabled_user(&self) -> bool {
        let db = self.db();
        db.query_row("SELECT 1 FROM users WHERE disabled=0 LIMIT 1", [], |_| Ok(())).is_ok()
    }

    /// Recalcule et met en cache `auth_required` : la gate d'auth s'engage si un hash d'env est posé
    /// (`FORGE_CONSOLE_PASS_HASH` non vide) OU si au moins un compte activé existe en base. À appeler
    /// au BOOT et après CHAQUE mutation de comptes pour que l'état DB pilote la gate sans requête par
    /// requête. FAIL-CLOSED : on n'ouvre jamais la gate tant qu'un compte activé ou un hash existe.
    /// Ne pas appeler en tenant `self.db()` (any_enabled_user reverrouille le mutex).
    fn recompute_auth_required(&self) {
        let required = !self.pass_hash.is_empty() || self.any_enabled_user();
        self.auth_required.store(required, Ordering::SeqCst);
    }

    /// Lecture O(1) du cache : la gate d'auth est-elle engagée ? (voir recompute_auth_required).
    fn auth_required(&self) -> bool {
        self.auth_required.load(Ordering::SeqCst)
    }

    /// Vrai s'il existe AU MOINS un compte ADMIN activé (`role='admin' AND disabled=0`). Distinct de
    /// any_enabled_user (qui compte TOUT rôle) : le wizard de 1er déploiement considère la console
    /// « provisionnée » dès qu'un ADMIN peut administrer (pas un simple viewer). Requête légère
    /// (`LIMIT 1`). Ne verrouille QUE le mutex DB (ne pas appeler en tenant déjà `self.db()`).
    fn any_enabled_admin(&self) -> bool {
        let db = self.db();
        db.query_row("SELECT 1 FROM users WHERE role='admin' AND disabled=0 LIMIT 1", [], |_| Ok(())).is_ok()
    }

    /// La console est-elle déjà PROVISIONNÉE ? Vrai si un admin activé existe en base OU si un hash
    /// d'amorçage env est posé (`FORGE_CONSOLE_PASS_HASH`). Pilote l'auto-désactivation du wizard de
    /// 1er déploiement : `POST /api/setup` se ferme (409) dès que `provisioned()` est vrai. Ne pas
    /// appeler en tenant déjà `self.db()` (any_enabled_admin reverrouille le mutex).
    fn provisioned(&self) -> bool {
        !self.pass_hash.is_empty() || self.any_enabled_admin()
    }

    /// Configuration COURANTE de la source de détection (clone bon-marché de l'`Arc<Value>` en cache).
    /// Récupère un verrou empoisonné (into_inner) : un panic passé ne doit pas geler la lecture purple.
    fn detection_config(&self) -> Arc<Value> {
        self.detection_source.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Recalcule le cache `detection_source` depuis `settings.detection_source` (repli env legacy
    /// PLUME_URL/PLUME_TOKEN si la clé est absente). À appeler au BOOT et après CHAQUE mutation de
    /// `settings.detection_source` (wizard/config admin) pour que la source pilote la couverture sans
    /// relire la table à chaque requête. Ne pas appeler en tenant déjà `self.db()` (relock du mutex DB).
    fn reload_detection_source(&self) {
        let cfg = {
            let db = self.db();
            resolve_detection_source(&db)
        };
        let mut w = self.detection_source.write().unwrap_or_else(|e| e.into_inner());
        *w = Arc::new(cfg);
    }

    /// Invalide le cache du head ledger (prev/seq) -> le PROCHAIN `append_console_ledger` relira le
    /// head depuis le disque. À appeler après une mutation du fichier ledger effectuée HORS de
    /// `append_console_ledger` (ex. un restore qui remplace intégralement le ledger par celui de
    /// l'archive) : sans cela, le cache (prev/seq) resterait périmé et le prochain append casserait la
    /// chaîne SHA-256. Récupère un verrou empoisonné (into_inner) : un panic passé ne gèle pas l'audit.
    fn invalidate_ledger_head(&self) {
        let mut head = self.ledger_lock.lock().unwrap_or_else(|e| e.into_inner());
        head.loaded = false;
    }
}

fn gs(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

// --- auth opérateur (argon2) + RBAC, repris du modèle auth_guard/host_guard de Plume ---

fn check_basic(app: &App, b64: &str) -> bool {
    let raw = match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let s = match String::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut it = s.splitn(2, ':');
    let u = it.next().unwrap_or("");
    let p = it.next().unwrap_or("");
    u == app.user.as_str() && verify_pw(p, &app.pass_hash)
}

// --- rôle OPÉRATEUR (C2-light) — FAIL-CLOSED, indépendant du viewer ---
//
// Le lancement de campagnes (POST /api/run, cancel) est une capacité PRIVILÉGIÉE, distincte de la
// simple lecture du dashboard (viewer Basic/Bearer). Elle exige une preuve d'opérateur dédiée via
// l'en-tête `X-Forge-Operator: <mot de passe>` vérifiée contre `operator_hash` (argon2id).
//
// FAIL-CLOSED : si `operator_hash` est vide (non configuré), AUCUN endpoint C2 n'est ouvert — 403,
// même quand le viewer tourne en mode dev-open (pass_hash vide). check_operator NE consulte JAMAIS
// pass_hash/token : l'authz C2 est totalement découplée de l'auth viewer. Sous-commande pour le
// hash : `forge-console hashpw-operator <mot de passe>`.

/// Preuve opérateur par HASH ENV (rétro-compat) : vrai seulement si `operator_hash` est configuré ET
/// que l'en-tête `X-Forge-Operator` correspond. Vide => toujours faux (fail-closed). Aucune
/// dépendance au viewer (pass_hash/token). C'est le repli 'bootstrap' quand aucun compte individuel
/// n'est en session.
fn check_operator_env(app: &App, headers: &HeaderMap) -> bool {
    if app.operator_hash.is_empty() {
        return false; // FAIL-CLOSED : rôle opérateur non provisionné via env -> repli C2 refusé
    }
    let supplied = headers
        .get("x-forge-operator")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if supplied.is_empty() {
        return false;
    }
    verify_pw(supplied, &app.operator_hash)
}

/// Test d'APPARTENANCE d'une IP à un CIDR (ou à une IP exacte quand il n'y a pas de `/`). std-only
/// (u32/u128 + masque de préfixe, aucune dépendance). Familles hétérogènes (v4 vs v6) -> false.
/// Réseau/préfixe malformé ou hors borne -> false (fail-closed pour CETTE entrée). Fonction PURE.
fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    let cidr = cidr.trim();
    let (net, prefix): (&str, Option<u32>) = match cidr.split_once('/') {
        Some((n, p)) => match p.trim().parse::<u32>() {
            Ok(v) => (n.trim(), Some(v)),
            Err(_) => return false, // préfixe non numérique -> entrée rejetée (fail-closed)
        },
        None => (cidr, None), // pas de '/' -> comparaison d'IP exacte
    };
    let net_ip: IpAddr = match net.parse() {
        Ok(i) => i,
        Err(_) => return false,
    };
    match (ip, net_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let bits = prefix.unwrap_or(32);
            if bits > 32 {
                return false;
            }
            let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(*a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let bits = prefix.unwrap_or(128);
            if bits > 128 {
                return false;
            }
            let mask: u128 = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(*a) & mask) == (u128::from(b) & mask)
        }
        _ => false, // v4 vs v6 : jamais dans le même réseau
    }
}

/// IP client EFFECTIVE pour la politique opérateur source-CIDR. Par défaut = IP du pair TCP
/// (ConnectInfo). On n'honore le DERNIER hop de `X-Forwarded-For` QUE si le pair TCP réel `peer` est
/// LUI-MÊME un proxy de confiance, c.-à-d. tombe dans l'un des `trusted_proxy_cidrs`. Sinon (client
/// direct qui court-circuite le vrai proxy, pair hors CIDR, ou pair inconnu) le XFF est INTÉGRALEMENT
/// IGNORÉ et on retombe FAIL-CLOSED sur `peer` — sans quoi un client se connectant directement à
/// l'origine pourrait forger `X-Forwarded-For: <IP-dans-l'allowlist>` et usurper la politique source.
/// La liste `trusted_proxy_cidrs` vide => aucun proxy de confiance => XFF toujours ignoré.
/// Fonction PURE (testable sans connexion réelle).
fn effective_client_ip(peer: Option<IpAddr>, headers: &HeaderMap, trusted_proxy_cidrs: &[String]) -> Option<IpAddr> {
    if let Some(p) = peer {
        // Le pair TCP DOIT être un proxy de confiance pour qu'on accorde foi au XFF qu'il a posé.
        if !trusted_proxy_cidrs.is_empty() && trusted_proxy_cidrs.iter().any(|c| ip_in_cidr(&p, c)) {
            if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                if let Some(last) = xff.split(',').map(|s| s.trim()).rfind(|s| !s.is_empty()) {
                    if let Ok(ip) = last.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
            // pair = proxy de confiance mais aucun XFF exploitable -> repli sur le pair (le proxy).
        }
    }
    // pair non-proxy (client direct), hors CIDR, ou inconnu -> XFF IGNORÉ, fail-closed sur le pair.
    peer
}

/// Test de VALIDITÉ d'une entrée CIDR (ou IP exacte sans `/`) selon les mêmes critères que
/// `ip_in_cidr` : IP v4/v6 parsable + préfixe numérique dans les bornes de la famille. Sert à
/// distinguer un `trusted_proxy` réellement configuré (au moins un CIDR valide) d'une valeur héritée
/// « truthy » non-CIDR (ex. "1", "true") qui NE doit PAS valoir « tout faire confiance ». Fonction PURE.
fn cidr_is_valid(cidr: &str) -> bool {
    let cidr = cidr.trim();
    match cidr.split_once('/') {
        Some((n, p)) => match p.trim().parse::<u32>() {
            Ok(bits) => match n.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => bits <= 32,
                Ok(IpAddr::V6(_)) => bits <= 128,
                Err(_) => false,
            },
            Err(_) => false,
        },
        None => cidr.parse::<IpAddr>().is_ok(),
    }
}

/// Parse le réglage `settings.trusted_proxy` en une LISTE de CIDRs de proxies de confiance. Accepte
/// (dans l'ordre) : (1) un tableau JSON de chaînes CIDR `["10.0.0.0/24","..."]` ; (2) une liste
/// séparée par des virgules `10.0.0.0/24, 172.16.0.0/12` ; (3) un CIDR unique. Chaque entrée est
/// VALIDÉE (`cidr_is_valid`) ; les entrées invalides sont écartées. RÉTRO-COMPAT / MIGRATION : une
/// valeur héritée « truthy » non-CIDR (ex. "1", "true", "yes") ne produit AUCUN CIDR valide -> liste
/// VIDE -> AUCUN proxy de confiance (repli fail-closed sur le pair). On ne conserve JAMAIS
/// silencieusement l'ancien comportement « boolean = fais confiance à tout XFF ». Fonction PURE.
fn parse_trusted_proxy_cidrs(raw: &str) -> Vec<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let candidates: Vec<String> = match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(arr)) => arr.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).collect(),
        // pas un tableau JSON (chaîne "1", bool true, CSV, CIDR nu…) -> split CSV / valeur unique.
        _ => raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
    };
    candidates.into_iter().filter(|c| cidr_is_valid(c)).collect()
}

/// POLITIQUE OPÉRATEUR source-CIDR — OPT-IN, fail-closed UNIQUEMENT quand configurée. Lit
/// `settings.operator_policy.source_cidrs` : si absent/vide -> AUCUNE restriction (true, défaut = none,
/// zéro valeur codée en dur). Sinon l'IP client effective (cf. effective_client_ip) DOIT tomber dans
/// l'un des CIDRs, faute de quoi l'action opérateur est refusée. Politique active + IP indéterminée
/// (aucun pair, aucun XFF) -> refus (fail-closed). Ne restreint QUE le C2 opérateur (appelée depuis
/// check_operator) — jamais l'admin ni le viewer.
fn operator_source_allowed(app: &App, headers: &HeaderMap, peer: Option<IpAddr>) -> bool {
    let (cidrs, trusted_proxy_cidrs) = {
        let db = app.db();
        let cidrs: Vec<String> = settings_get(&db, "operator_policy")
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.get("source_cidrs").and_then(|c| c.as_array()).cloned())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        // `trusted_proxy` = CIDR(s) des proxies de confiance (cf. parse_trusted_proxy_cidrs). Un XFF
        // n'est honoré que si le pair TCP tombe dans l'un d'eux ; sinon repli fail-closed sur le pair.
        let trusted_proxy_cidrs = settings_get(&db, "trusted_proxy")
            .map(|s| parse_trusted_proxy_cidrs(&s))
            .unwrap_or_default();
        (cidrs, trusted_proxy_cidrs)
    };
    if cidrs.is_empty() {
        return true; // aucune contrainte source configurée -> défaut = aucune restriction
    }
    match effective_client_ip(peer, headers, &trusted_proxy_cidrs) {
        Some(ip) => cidrs.iter().any(|c| ip_in_cidr(&ip, c)),
        None => false, // politique active mais IP client indéterminée -> fail-closed
    }
}

/// Authz C2 (run/cancel) — FAIL-CLOSED. Vrai si :
///   1) une SESSION valide porte un rôle operator|admin (compte individuel) OU la preuve par hash env
///      (X-Forge-Operator) matche (compte 'bootstrap'/admin) — un viewer en session ne passe JAMAIS ;
///   2) ET la politique source-CIDR (opt-in) l'autorise : si `settings.operator_policy.source_cidrs`
///      est configuré, l'IP client (`peer`, ou dernier hop XFF UNIQUEMENT si le pair TCP est lui-même
///      dans un CIDR de `settings.trusted_proxy`) doit être dans l'allowlist ; non configuré ->
///      aucune restriction (défaut = none).
///
/// `peer` = IP du pair TCP (ConnectInfo) fournie par le handler ; None dans les tests/harness où elle
/// est simulée. La contrainte source ne s'applique QU'AU C2 opérateur — jamais admin/viewer.
fn check_operator(app: &App, headers: &HeaderMap, peer: Option<IpAddr>) -> bool {
    // 1) AUTHN opérateur : l'identité réelle en session prime (viewer -> refus, pas de repli env),
    //    sinon repli rétro-compat par hash env.
    let authed = match resolve_session_identity(app, headers) {
        Some(id) => id.is_operator,
        None => check_operator_env(app, headers),
    };
    if !authed {
        return false;
    }
    // 2) contrainte source-CIDR (opt-in, fail-closed quand configurée).
    operator_source_allowed(app, headers, peer)
}

/// Réponse standard d'un refus C2 (403). Distingue « non provisionné » (501-like message) de
/// « mauvaise preuve » sans fuir lequel — message stable, code 403 dans les deux cas (fail-closed).
fn operator_denied(app: &App) -> (StatusCode, Json<Value>) {
    // Message stable et non-fuiteur. On ne distingue plus que le cas « aucune voie operator possible »
    // (ni hash env, ni — par construction — session valide ici) du cas « preuve invalide/insuffisante ».
    let why = if app.operator_hash.is_empty() {
        "rôle opérateur non provisionné (aucune session operator|admin valide, FORGE_CONSOLE_OPERATOR_HASH absent) — C2 fermé"
    } else {
        "preuve opérateur invalide ou absente (session operator|admin via POST /api/login, ou en-tête X-Forge-Operator)"
    };
    (StatusCode::FORBIDDEN, Json(json!({"error": "operator_required", "why": why})))
}

// --- rôle ADMIN (administration : setup, comptes, settings, gouvernance des connecteurs) ---
//
// Distinct de l'opérateur : administrer la console (créer/désactiver des comptes, muter la table
// `settings`, gouverner les connecteurs) est une capacité de plus haut privilège que lancer un run.
//
// FAIL-CLOSED + ATTRIBUTION INDIVIDUELLE STRICTE : check_admin exige une SESSION valide portant le
// rôle `admin` (resolve_session_identity). Contrairement à check_operator, il N'Y A PAS de repli par
// hash env — une mutation d'administration DOIT être imputable à un compte individuel nommé (pas à un
// secret partagé « bootstrap »). Sans session admin -> refus. Un viewer/operator ne passe JAMAIS.

/// Authz ADMINISTRATION — FAIL-CLOSED. Vrai UNIQUEMENT si une session valide porte le rôle `admin`.
/// Aucun repli env-hash (attribution individuelle obligatoire). Miroir de check_operator, plus strict.
fn check_admin(app: &App, headers: &HeaderMap) -> bool {
    match resolve_session_identity(app, headers) {
        Some(id) => id.role == "admin",
        None => false, // aucune session individuelle -> refus (pas de repli hash env pour l'admin)
    }
}

/// Réponse standard d'un refus admin (403). Message stable et non-fuiteur (fail-closed).
fn admin_denied() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "admin_required",
            "why": "administration réservée à une session au rôle admin (POST /api/login) — pas de repli par secret partagé"
        })),
    )
}

// --- settings KV : configuration mutable d'administration (get/set avec horodatage) ---

/// Lit une clé de configuration dans la table `settings`. None si absente ou erreur DB (fail-soft en
/// LECTURE : une clé non provisionnée => valeur par défaut côté appelant, jamais de valeur inventée).
#[allow(dead_code)] // substrat consommé par les routes settings/setup/detection à venir
fn settings_get(db: &Connection, key: &str) -> Option<String> {
    db.query_row("SELECT value FROM settings WHERE key=?", [key], |r| r.get::<_, String>(0)).ok()
}

/// Écrit (upsert) une clé de configuration avec l'horodatage `updated` courant. PRIMARY KEY sur `key`
/// => une seule ligne par clé (pas de doublon). Renvoie une erreur si l'écriture DB échoue (l'appelant
/// admin doit pouvoir la propager avant de ledgeriser). Mutations réservées à check_admin.
#[allow(dead_code)] // substrat consommé par les routes settings/setup/detection à venir
fn settings_set(db: &Connection, key: &str, value: &str) -> Result<(), String> {
    db.execute(
        "INSERT INTO settings(key,value,updated) VALUES(?,?,datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
        rusqlite::params![key, value],
    )
    .map(|_| ())
    .map_err(|e| format!("écriture settings échouée: {e}"))
}

// =====================================================================================
// COMPTES UTILISATEURS (#6) — identités individuelles + attribution.
//
// Avant : les 3 rôles (viewer/operator/admin) étaient des MOTS DE PASSE PARTAGÉS (hash via env) —
// impossible de savoir QUI a armé un exploit. On ajoute des comptes individuels (table `users`) +
// des sessions courtes (table `session`), tout en PRÉSERVANT la rétro-compat : si aucune session
// n'est présente, on retombe sur les hash via env (FORGE_CONSOLE_PASS_HASH/OPERATOR_HASH) en tant
// que compte 'bootstrap' (la console live tourne déjà comme ça — elle ne doit pas casser).
//
// FAIL-CLOSED : `operator` reste fail-closed (un viewer n'arme rien). L'attribution propage l'identité
// (login) au lieu du littéral 'operator' dans run_job.started_by, run_cancel et le ledger ('actor').

/// Durée de vie d'une session (secondes) — sessions COURTES. Override par FORGE_CONSOLE_SESSION_TTL.
fn session_ttl_secs() -> i64 {
    std::env::var("FORGE_CONSOLE_SESSION_TTL")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(3600) // 1 h par défaut
}

/// Epoch s courant (UTC). Sans dépendance chrono — SystemTime depuis l'UNIX_EPOCH.
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Identité résolue d'un appelant : login affiché en attribution + rôle effectif. `is_operator`
/// = peut armer le C2 (operator|admin OU bootstrap env-hash). `via_session` distingue un compte
/// individuel (true) du repli bootstrap par hash env (false).
#[derive(Clone, Debug)]
struct Identity {
    login: String,
    role: String,
    is_operator: bool,
    via_session: bool,
}

/// Extrait le token de session du porteur : en-tête `Authorization: Bearer <t>` (priorité) OU cookie
/// `forge_session=<t>`. Renvoie le token EN CLAIR (à hasher avant lookup), vide si absent.
fn session_token_from_headers(headers: &HeaderMap) -> String {
    if let Some(authz) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(tok) = authz.strip_prefix("Bearer ") {
            let t = tok.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    // cookie forge_session=...
    if let Some(cookie) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            let p = part.trim();
            if let Some(val) = p.strip_prefix("forge_session=") {
                if !val.is_empty() {
                    return val.to_string();
                }
            }
        }
    }
    String::new()
}

/// Résout l'identité depuis une session VALIDE (non expirée, compte non désactivé). None si pas de
/// session présentée, session inconnue/expirée, ou compte désactivé (fail-closed). Purge en passant
/// la session expirée (best-effort). Lecture du compte au moment du lookup => un rôle changé/désactivé
/// prend effet immédiatement même sur une session déjà émise.
fn resolve_session_identity(app: &App, headers: &HeaderMap) -> Option<Identity> {
    let tok = session_token_from_headers(headers);
    if tok.is_empty() {
        return None;
    }
    let token_sha = sha_hex(&tok);
    let db = app.db();
    let row = db.query_row(
        "SELECT s.expires, u.login, u.role, u.disabled
           FROM session s JOIN users u ON u.id = s.user_id
          WHERE s.token_sha = ?",
        [&token_sha],
        |r| Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
        )),
    );
    match row {
        Ok((expires, login, role, disabled)) => {
            if disabled != 0 {
                return None; // compte désactivé -> fail-closed
            }
            if now_epoch() >= expires {
                // session expirée -> purge best-effort et refus
                let _ = db.execute("DELETE FROM session WHERE token_sha=?", [&token_sha]);
                return None;
            }
            let is_operator = role == "operator" || role == "admin";
            Some(Identity { login, role, is_operator, via_session: true })
        }
        Err(_) => None,
    }
}

/// Identité effective d'un appelant pour l'ATTRIBUTION et l'AUTHZ C2 :
///   1) session valide (compte individuel) -> identité réelle (login/role) ;
///   2) SINON repli RÉTRO-COMPAT : preuve opérateur par hash env (X-Forge-Operator) -> compte
///      'bootstrap' (role=admin, is_operator=true) ; preuve viewer Basic -> 'bootstrap' viewer.
///
/// None => aucune identité (anonyme dev-open ou pas de preuve). via_session=false sur les replis env.
fn resolve_identity(app: &App, headers: &HeaderMap) -> Option<Identity> {
    if let Some(id) = resolve_session_identity(app, headers) {
        return Some(id);
    }
    // Repli bootstrap (rétro-compat) : l'en-tête opérateur env-hash agit comme un compte admin.
    if !app.operator_hash.is_empty() && check_operator_env(app, headers) {
        return Some(Identity {
            login: "bootstrap".into(),
            role: "admin".into(),
            is_operator: true,
            via_session: false,
        });
    }
    None
}

/// Login d'attribution : identité résolue si présente, sinon le littéral historique 'operator'
/// (ce qui préserve EXACTEMENT le comportement existant quand seul le hash env est en jeu mais qu'on
/// n'a pas matché ci-dessus — cas dev-open). N'altère aucun garde-fou.
fn attribution_login(app: &App, headers: &HeaderMap) -> String {
    resolve_identity(app, headers).map(|i| i.login).unwrap_or_else(|| "operator".into())
}

/// GET /api/whoami — identité effective de l'appelant (pour l'UI : afficher l'utilisateur connecté,
/// activer/masquer les actions C2 selon le rôle). Résout la session (compte individuel) ou le repli
/// bootstrap env-hash. `authenticated:false` si aucune identité (dev-open anonyme).
async fn whoami(State(app): State<App>, headers: HeaderMap) -> impl IntoResponse {
    // ENTERPRISE flags for the SPA (additive; all false in the community default => byte-identical UI).
    // Drives whether the enterprise views/nav render at all (server stays the authority via each module's
    // own flag + admin gate). Exposing "engaged or not" is not a secret (the login page already reveals
    // SSO availability). NEVER carries a client_secret / SCIM token.
    let enterprise = json!({
        "tenancy": tenancy::enabled(&app),
        "sso": sso::enabled(&app),
        "scim": scim::enabled(&app),
        "rbac": rbac::enabled(&app),
        "compliance": compliance::enabled(&app),
    });
    match resolve_identity(&app, &headers) {
        Some(id) => Json(json!({
            "authenticated": true,
            "login": id.login,
            "role": id.role,
            "is_operator": id.is_operator,
            "via_session": id.via_session, // false => repli bootstrap (hash env), true => compte individuel
            "enterprise": enterprise,
        })),
        None => Json(json!({"authenticated": false, "login": Value::Null, "role": Value::Null, "is_operator": false, "via_session": false, "enterprise": enterprise})),
    }
}

/// Génère un token de session opaque (256 bits hex via CSPRNG OS). Le Result de getrandom est propagé
/// (panic) : un échec d'entropie produirait un token PRÉVISIBLE -> usurpation de session.
fn gen_session_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("CSPRNG (getrandom) indisponible — refus de générer une session faible");
    hex(&b)
}

/// Crée une session pour `user_id` (token EN CLAIR renvoyé à l'appelant, SHA-256 persisté). Retourne
/// (token_clair, expires_epoch). Purge en passant les sessions expirées de l'utilisateur (best-effort).
fn create_session(app: &App, user_id: i64) -> (String, i64) {
    let token = gen_session_token();
    let token_sha = sha_hex(&token);
    let now = now_epoch();
    let expires = now + session_ttl_secs();
    let db = app.db();
    let _ = db.execute("DELETE FROM session WHERE user_id=? AND expires<=?", rusqlite::params![user_id, now]);
    let _ = db.execute(
        "INSERT OR REPLACE INTO session(token_sha,user_id,created,expires) VALUES(?,?,?,?)",
        rusqlite::params![token_sha, user_id, now, expires],
    );
    (token, expires)
}

/// Provisionne un compte dans la table `users` (argon2id). Idempotent vis-à-vis du login : si le login
/// existe déjà, MET À JOUR rôle + hash + réactive (disabled=0). Renvoie le rôle validé ou une erreur.
/// Utilisé par la sous-commande CLI `useradd`. Validation login/role stricte (fail-closed).
fn upsert_user(db: &Connection, login: &str, role: &str, pass_hash: &str) -> Result<String, String> {
    let login = validate_login(login)?;
    let role = validate_role(role)?;
    if pass_hash.is_empty() {
        return Err("hash de mot de passe vide".into());
    }
    db.execute(
        "INSERT INTO users(login,role,pass_hash,disabled,created)
         VALUES(?,?,?,0,datetime('now'))
         ON CONFLICT(login) DO UPDATE SET role=excluded.role, pass_hash=excluded.pass_hash, disabled=0",
        rusqlite::params![login, role, pass_hash],
    )
    .map_err(|e| format!("écriture users échouée: {e}"))?;
    Ok(role)
}

// =====================================================================================
// ADMINISTRATION WEB DES COMPTES (#4) — CRUD réservé check_admin (session admin, fail-closed),
// chaque mutation ATTRIBUÉE à l'admin acteur et LEDGERISÉE (append_console_ledger). Aucune route ne
// renvoie jamais `pass_hash`. Après chaque mutation, `auth_required` est recalculé (la gate d'auth
// s'engage/se désengage sur l'ÉTAT DB — cf. recompute_auth_required). Les mots de passe/hash n'entrent
// JAMAIS dans le ledger (login/rôle/booléens seuls). Roles conservés tels quels : viewer|operator|admin.
// =====================================================================================

/// Rang de privilège d'un rôle (viewer < operator < admin). Sert à détecter une RÉTROGRADATION (rang
/// décroissant) qui doit purger les sessions du compte pour un effet immédiat. Rôle inconnu -> 0.
fn role_rank(r: &str) -> i32 {
    match r {
        "admin" => 3,
        "operator" => 2,
        "viewer" => 1,
        _ => 0,
    }
}

/// Nombre d'admins ACTIVÉS (`role='admin' AND disabled=0`). Substrat du garde-fou « dernier admin » :
/// on n'autorise JAMAIS une opération qui laisserait 0 admin activé (verrouillage total de l'admin).
/// À appeler EN TENANT DÉJÀ le guard `db` (pas de re-lock) pour que le check+mutation soient ATOMIQUES
/// sous le même mutex (anti-TOCTOU). Échec de lecture -> 0 => l'opération est refusée (fail-closed).
fn enabled_admin_count(db: &Connection) -> i64 {
    db.query_row("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0", [], |r| r.get(0)).unwrap_or(0)
}

/// Liste les comptes pour l'admin — `{login, role, disabled, created}`. Ne SÉLECTIONNE même pas
/// `pass_hash` (fuite structurellement impossible). Ordre alphabétique. Lecture pure (aucun ledger).
fn admin_list_users(app: &App) -> Vec<Value> {
    let db = app.db();
    let mut stmt = match db.prepare("SELECT login, role, disabled, created FROM users ORDER BY login") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map([], |r| {
        Ok(json!({
            "login": r.get::<_, String>(0)?,
            "role": r.get::<_, String>(1)?,
            "disabled": r.get::<_, i64>(2)? != 0,
            "created": r.get::<_, Option<String>>(3)?.unwrap_or_default(),
        }))
    })
    .map(|it| it.filter_map(|x| x.ok()).collect())
    .unwrap_or_default()
}

/// Crée un compte individuel. Valide login/rôle (fail-closed), hash argon2id HORS mutex, refuse un login
/// déjà pris (409 — l'édition sert à muter). Recalcule `auth_required` (1er compte activé -> gate) et
/// ledgerise avec l'admin acteur (login/rôle seuls, JAMAIS le mot de passe). Retourne la vue publique.
fn admin_create_user(app: &App, actor: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    let login = validate_login(&gs(body, "login")).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let role = validate_role(&gs(body, "role")).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let password = gs(body, "password");
    if password.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "mot de passe vide refusé".into()));
    }
    // argon2id est coûteux -> on hash AVANT de prendre le mutex DB (ne pas geler l'API pendant le KDF).
    let hash = hash_pw(&password);
    {
        let db = app.db();
        // création STRICTE : un login déjà présent -> 409 (passer par l'édition pour modifier).
        if db.query_row("SELECT 1 FROM users WHERE login=?", [&login], |_| Ok(())).is_ok() {
            return Err((StatusCode::CONFLICT, format!("le compte '{login}' existe déjà (utilisez l'édition)")));
        }
        upsert_user(&db, &login, &role, &hash).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    app.recompute_auth_required();
    append_console_ledger(app, "console.admin.user.create", json!({"actor": actor, "login": login, "role": role}));
    Ok(json!({"login": login, "role": role, "disabled": false}))
}

/// Modifie un compte : changement de rôle, réinitialisation de mot de passe, (dé)activation (champs tous
/// optionnels). GARDE-FOU dernier admin (fail-closed, 409) : refuse toute opération qui retirerait le
/// DERNIER admin activé (désactivation ou rétrogradation du seul admin). PURGE les sessions du compte
/// quand l'effet doit être immédiat : désactivation, rétrogradation (rang décroissant) OU reset de mot
/// de passe (une session volée ne survit pas au reset). Check dernier-admin + mutations + purge sous UN
/// SEUL guard DB (atomique, anti-TOCTOU). Recalcule `auth_required`, ledgerise (jamais le mot de passe).
fn admin_update_user(app: &App, actor: &str, target_login: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    let target_login = validate_login(target_login).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let new_role: Option<String> = if body.get("role").is_some() {
        Some(validate_role(&gs(body, "role")).map_err(|e| (StatusCode::BAD_REQUEST, e))?)
    } else {
        None
    };
    let password = gs(body, "password");
    let reset_pw = !password.is_empty();
    let new_disabled: Option<bool> = body.get("disabled").and_then(|v| v.as_bool());
    if new_role.is_none() && !reset_pw && new_disabled.is_none() {
        return Err((StatusCode::BAD_REQUEST, "aucun changement fourni (role|password|disabled)".into()));
    }
    // hash HORS section critique (argon2id coûteux).
    let new_hash: Option<String> = if reset_pw { Some(hash_pw(&password)) } else { None };

    // ENTERPRISE (fail-closed marker) : un super-admin DÉSIGNÉ (provisioning) est NON-DÉSACTIVABLE — on
    // refuse toute désactivation / rétrogradation sous `admin`. No-op pour un login non super-admin.
    // Appelé HORS du guard DB (guard_superadmin_user_mutation reverrouille son propre lock).
    tenancy::guard_superadmin_user_mutation(app, &target_login, new_disabled == Some(true), new_role.as_deref(), false)
        .map_err(|e| (StatusCode::CONFLICT, e))?;

    let (purge, eff_role, eff_disabled) = {
        let db = app.db();
        let (old_role, old_disabled_i): (String, i64) = db
            .query_row("SELECT role, disabled FROM users WHERE login=?", [&target_login], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|_| (StatusCode::NOT_FOUND, format!("compte '{target_login}' introuvable")))?;
        let old_disabled = old_disabled_i != 0;
        let eff_role = new_role.clone().unwrap_or_else(|| old_role.clone());
        let eff_disabled = new_disabled.unwrap_or(old_disabled);
        // GARDE-FOU dernier admin : si le compte ÉTAIT un admin activé et ne l'est PLUS après l'op,
        // refuser tant qu'il ne reste qu'un seul admin activé (fail-closed : jamais 0 admin -> lockout).
        let was_enabled_admin = old_role == "admin" && !old_disabled;
        let still_enabled_admin = eff_role == "admin" && !eff_disabled;
        if was_enabled_admin && !still_enabled_admin && enabled_admin_count(&db) <= 1 {
            return Err((
                StatusCode::CONFLICT,
                "impossible : dernier admin activé (désactivation/rétrogradation refusée, fail-closed)".into(),
            ));
        }
        if let Some(r) = &new_role {
            db.execute("UPDATE users SET role=? WHERE login=?", rusqlite::params![r, target_login])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj rôle échouée: {e}")))?;
        }
        if let Some(h) = &new_hash {
            db.execute("UPDATE users SET pass_hash=? WHERE login=?", rusqlite::params![h, target_login])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj mot de passe échouée: {e}")))?;
        }
        if let Some(d) = new_disabled {
            db.execute("UPDATE users SET disabled=? WHERE login=?", rusqlite::params![d as i64, target_login])
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj état échouée: {e}")))?;
        }
        let downgrade = new_role.as_ref().map(|r| role_rank(r) < role_rank(&old_role)).unwrap_or(false);
        let disabling = new_disabled == Some(true);
        let purge = disabling || downgrade || reset_pw;
        if purge {
            // effet IMMÉDIAT : révoque toutes les sessions actives du compte (même mutex que l'update).
            let _ = db.execute(
                "DELETE FROM session WHERE user_id=(SELECT id FROM users WHERE login=?)",
                [&target_login],
            );
        }
        (purge, eff_role, eff_disabled)
    };
    app.recompute_auth_required();
    append_console_ledger(app, "console.admin.user.update", json!({
        "actor": actor,
        "login": target_login,
        "role": new_role,
        "disabled": new_disabled,
        "password_reset": reset_pw,
        "sessions_purged": purge,
    }));
    Ok(json!({
        "login": target_login,
        "role": eff_role,
        "disabled": eff_disabled,
        "sessions_purged": purge,
        "password_reset": reset_pw,
    }))
}

/// Supprime un compte. GARDE-FOU (fail-closed, 409) : refuse de supprimer le DERNIER admin activé
/// (verrouillage total de l'administration). Purge d'abord ses sessions, puis la ligne `users`, sous
/// UN SEUL guard DB (atomique). Recalcule `auth_required` et ledgerise l'action avec l'admin acteur.
fn admin_delete_user(app: &App, actor: &str, target_login: &str) -> Result<Value, (StatusCode, String)> {
    let target_login = validate_login(target_login).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // ENTERPRISE (fail-closed marker) : un super-admin DÉSIGNÉ est NON-SUPPRIMABLE. No-op pour un login
    // ordinaire. Appelé HORS du guard DB (reverrouille son propre lock).
    tenancy::guard_superadmin_user_mutation(app, &target_login, false, None, true)
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    {
        let db = app.db();
        let (role, disabled): (String, i64) = db
            .query_row("SELECT role, disabled FROM users WHERE login=?", [&target_login], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|_| (StatusCode::NOT_FOUND, format!("compte '{target_login}' introuvable")))?;
        if role == "admin" && disabled == 0 && enabled_admin_count(&db) <= 1 {
            return Err((StatusCode::CONFLICT, "impossible de supprimer le dernier admin activé (fail-closed)".into()));
        }
        // révoque les sessions AVANT la suppression de la ligne (effet immédiat + pas d'orphelin).
        let _ = db.execute(
            "DELETE FROM session WHERE user_id=(SELECT id FROM users WHERE login=?)",
            [&target_login],
        );
        db.execute("DELETE FROM users WHERE login=?", [&target_login])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("suppression échouée: {e}")))?;
    }
    app.recompute_auth_required();
    append_console_ledger(app, "console.admin.user.delete", json!({"actor": actor, "login": target_login}));
    Ok(json!({"deleted": target_login}))
}

/// GOUVERNANCE CONNECTEUR (#4) — mute l'intention opérateur sur un module : `enabled` (install/uninstall
/// opérationnel), `available_override` (NULL=suivre la sonde host, true/false=forcer), `web_allowed`.
/// Chaque champ est OPTIONNEL (présence = mutation, absence = inchangé) ; `available_override` accepte
/// aussi `null` (EFFACER l'override). Le connecteur doit exister dans le registre (404 sinon — l'admin ne
/// crée pas de module fantôme). Mutation attribuée + ledgerisée (jamais de secret). Renvoie la vue à-jour
/// (avec `effective_available`). L'enforcement au tir vit ailleurs (scope.json disabled_modules + filtre
/// --modules + refus validate_modules) : ici on ne fait QUE persister l'intention.
fn admin_set_module(app: &App, actor: &str, kind: &str, body: &Value) -> Result<Value, (StatusCode, String)> {
    // kind = clé de module bien formée (même grammaire que validate_campaign) — anti entrée hostile.
    let kind = validate_campaign(kind).map_err(|e| (StatusCode::BAD_REQUEST, format!("kind invalide: {e}")))?;

    // Trois champs optionnels, typés stricts. available_override distingue 3 états (inchangé/effacé/forcé).
    #[derive(Clone, Copy)]
    enum Ov { Unchanged, Clear, Set(bool) }
    let enabled: Option<bool> = match body.get("enabled") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err((StatusCode::BAD_REQUEST, "enabled doit être un booléen".into())),
    };
    let web_allowed: Option<bool> = match body.get("web_allowed") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err((StatusCode::BAD_REQUEST, "web_allowed doit être un booléen".into())),
    };
    let ov: Ov = match body.get("available_override") {
        None => Ov::Unchanged,
        Some(Value::Null) => Ov::Clear,
        Some(Value::Bool(b)) => Ov::Set(*b),
        Some(_) => return Err((StatusCode::BAD_REQUEST, "available_override doit être un booléen ou null".into())),
    };
    if enabled.is_none() && web_allowed.is_none() && matches!(ov, Ov::Unchanged) {
        return Err((StatusCode::BAD_REQUEST, "aucun changement fourni (enabled|available_override|web_allowed)".into()));
    }

    let view = {
        let db = app.db();
        // le connecteur doit exister (catalogue = source de vérité des kinds, peuplé au boot).
        if db.query_row("SELECT 1 FROM module WHERE kind=?", [&kind], |_| Ok(())).is_err() {
            return Err((StatusCode::NOT_FOUND, format!("connecteur '{kind}' inconnu du registre")));
        }
        if let Some(e) = enabled {
            db.execute("UPDATE module SET enabled=? WHERE kind=?", rusqlite::params![e as i64, kind])
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj enabled échouée: {err}")))?;
        }
        if let Some(w) = web_allowed {
            db.execute("UPDATE module SET web_allowed=? WHERE kind=?", rusqlite::params![w as i64, kind])
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj web_allowed échouée: {err}")))?;
        }
        match ov {
            Ov::Unchanged => {}
            Ov::Clear => {
                db.execute("UPDATE module SET available_override=NULL WHERE kind=?", [&kind])
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj available_override échouée: {err}")))?;
            }
            Ov::Set(b) => {
                db.execute("UPDATE module SET available_override=? WHERE kind=?", rusqlite::params![b as i64, kind])
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("maj available_override échouée: {err}")))?;
            }
        }
        // vue à-jour (un seul row) pour la réponse ET le ledger (effective_available inclus).
        modules_catalog(&db)
            .into_iter()
            .find(|m| m.get("kind").and_then(|v| v.as_str()) == Some(kind.as_str()))
            .unwrap_or_else(|| json!({"kind": kind}))
    };
    // LEDGER : mutation d'administration attribuée à l'acteur (qui/quoi/quand). Aucun secret n'entre ici.
    append_console_ledger(app, "console.admin.module.set", json!({
        "actor": actor,
        "kind": kind,
        "enabled": enabled,
        "available_override": match ov { Ov::Unchanged => Value::Null, Ov::Clear => Value::String("cleared".into()), Ov::Set(b) => Value::Bool(b) },
        "web_allowed": web_allowed,
        "effective_available": view.get("effective_available").cloned().unwrap_or(Value::Null),
    }));
    Ok(view)
}

/// GET /api/users — liste des comptes (admin, fail-closed 403 sinon). Jamais `pass_hash`.
async fn users_list(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    (StatusCode::OK, Json(json!({"users": admin_list_users(&app)}))).into_response()
}

/// POST /api/users {login,role,password} — crée un compte (admin). Mutation attribuée + ledgerisée.
async fn users_create(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_create_user(&app, &actor, &body) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "user_create_failed", "why": why}))).into_response(),
    }
}

/// POST /api/users/:login {role?,password?,disabled?} — modifie un compte (admin). Purge les sessions
/// sur désactivation/rétrogradation/reset ; bloque le retrait du dernier admin activé (409).
async fn users_update(State(app): State<App>, headers: HeaderMap, Path(login): Path<String>, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_update_user(&app, &actor, &login, &body) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "user_update_failed", "why": why}))).into_response(),
    }
}

/// DELETE /api/users/:login — supprime un compte (admin). Bloque la suppression du dernier admin (409).
async fn users_delete(State(app): State<App>, headers: HeaderMap, Path(login): Path<String>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_delete_user(&app, &actor, &login) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "user_delete_failed", "why": why}))).into_response(),
    }
}

/// POST /api/modules/:kind {enabled?, available_override?, web_allowed?} — GOUVERNE un connecteur
/// (install/uninstall opérationnel). Réservé admin (check_admin, fail-closed 403 sinon). Mutation
/// attribuée à l'admin acteur + ledgerisée. Désactiver un connecteur l'empêche RÉELLEMENT de tirer
/// (scope.json disabled_modules + filtre --modules + refus validate_modules), y compris pour les modules
/// choisis par le planner. Cette route est la contrepartie « écriture » de GET /api/modules (lecture).
async fn module_governance(State(app): State<App>, headers: HeaderMap, Path(kind): Path<String>, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    match admin_set_module(&app, &actor, &kind, &body) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err((s, why)) => (s, Json(json!({"error": "module_set_failed", "why": why}))).into_response(),
    }
}

/// Anti-DNS-rebinding : l'en-tête Host doit être NON VIDE et présent dans l'allowlist.
/// FAIL-CLOSED : un Host absent/vide est REFUSÉ (avant, il passait — fail-open exploitable par un
/// client qui omet/efface Host pour contourner le filtre anti-rebinding). 421 dans tous les cas non
/// autorisés (Host vide OU hors allowlist).
async fn host_guard(State(app): State<App>, req: Request, next: Next) -> Response {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    if host_allowed(host, &app.allowed_hosts) {
        next.run(req).await
    } else {
        (StatusCode::MISDIRECTED_REQUEST, "host non autorisé (anti-rebinding)").into_response()
    }
}

/// Décision pure du host_guard (testable) : le Host (port retiré) doit être NON VIDE et présent dans
/// l'allowlist. FAIL-CLOSED sur Host vide/absent.
fn host_allowed(host_header: &str, allowed: &[String]) -> bool {
    let h = host_header.split(':').next().unwrap_or("");
    !h.is_empty() && allowed.iter().any(|a| a == h)
}

/// Décision PURE du auth_guard (testable sans middleware/HTTP) : la requête est-elle AUTORISÉE à
/// passer ? `true` => on laisse passer ; `false` => le middleware répond 401 (login portal côté SPA).
///
/// La gate s'engage sur `auth_required` (cache : hash env posé OU compte activé en base — voir
/// recompute_auth_required), et NON plus sur `pass_hash` seul : un fresh install avec des comptes en
/// base mais sans hash env est désormais GATÉ (ferme le trou dev-open historique). Quand la gate est
/// désengagée (dev-open : ni hash env, ni compte activé), tout passe (les ÉCRITURES restent gatées par
/// leur propre check_token/check_operator). Quand elle est engagée, on accepte : (1) une session
/// individuelle valide (cookie/Bearer <session>, tout rôle) ; (2) Basic viewer (pass_hash env) ;
/// (3) Bearer = token d'ingest. Sinon refus (401). FAIL-CLOSED.
fn auth_guard_allows(app: &App, headers: &HeaderMap) -> bool {
    if !app.auth_required() {
        return true; // dev-open : ni hash env ni compte activé -> gate désengagée
    }
    // Session individuelle (cookie forge_session ou Bearer <session>) -> accès lecture (tout rôle).
    // Vérifié AVANT le Bearer ingest-token : un token de session valide identifie un compte réel.
    if resolve_session_identity(app, headers).is_some() {
        return true;
    }
    let authz = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(b64) = authz.strip_prefix("Basic ") {
        if check_basic(app, b64.trim()) {
            return true;
        }
    }
    if let Some(tok) = authz.strip_prefix("Bearer ") {
        if ct_eq_str(&sha_hex(tok.trim()), &app.token_sha) {
            return true;
        }
    }
    false
}

/// RBAC (middleware) : la gate s'engage dès qu'un hash env est posé OU qu'un compte activé existe en
/// base (auth_required). Engagée + sans preuve valide -> 401 (le SPA affiche alors le portail de
/// login). Désengagée (dev-open) -> passe. Toute la décision vit dans auth_guard_allows (testable).
async fn auth_guard(State(app): State<App>, req: Request, next: Next) -> Response {
    if auth_guard_allows(&app, req.headers()) {
        return next.run(req).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Basic realm=\"forge\"")],
        "auth requise",
    )
        .into_response()
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

/// Vérifie le bearer token (sha256). Gate des écritures (ingest, panels).
fn check_token(app: &App, headers: &HeaderMap) -> bool {
    let tok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    ct_eq_str(&sha_hex(tok), &app.token_sha)
}

// ===========================================================================================
// PURPLE-TEAM (DÉFENSIF) — mesure de la couverture de DÉTECTION du SOC.
//
// Objectif blue-team : pour chaque technique ATT&CK TIRÉE en red-team autorisée par Forge
// (runrecord.fired=1), vérifier si la colonne BLEUE Plume l'a DÉTECTÉE (une alerte taguée du
// même `mitre`). On expose les TROUS de détection (missed) + le délai moyen de détection (MTTD).
//
// Source RED  : table `runrecord` (fired=1) de CETTE console — la technique + l'horodatage du tir.
// Source BLUE : GET {PLUME_URL}/api/coverage/detections -> [{mitre, count, first_ts}] (epoch s).
// Jointure    : sur le champ `mitre` commun (ex T1190/T1046/T1110).
//   detected = techniques tirées présentes côté Plume ; missed = tirées ABSENTES de Plume.
//   MTTD/tech = first_ts(détection) - ts(tir red) en secondes (>=0 ; négatif tronqué à 0 — une
//   détection antérieure au tir vient d'un run précédent, on ne « gagne » pas de temps négatif).
//
// FAIL-OPEN LISIBLE (NON négociable) : si Plume est injoignable / PLUME_URL absent / réponse
// illisible, on renvoie `plume_reachable:false` et on NE FABRIQUE JAMAIS de detected/missed/MTTD
// (listes vides, agrégats nuls). Un SOC muet ne doit pas se traduire en « tout détecté » NI en
// « tout raté » — l'opérateur voit explicitement que la mesure n'a pas pu être faite.
// LECTURE pure : aucun spawn, aucune écriture ; gardée par auth_guard comme le reste de l'API.
// ===========================================================================================

/// Parse un horodatage de tir red-team en epoch secondes (i64). Forge émet de l'ISO-8601 UTC
/// (`2026-06-26T12:00:00+00:00` / `...Z`) ; on tolère aussi un epoch déjà nu (défensif). Renvoie
/// `None` si illisible -> le MTTD de cette technique est marqué indisponible (jamais inventé).
fn parse_fire_ts(ts: &str) -> Option<i64> {
    let s = ts.trim();
    if s.is_empty() {
        return None;
    }
    // 1) epoch nu déjà fourni (ex "1719403200") — tolérance, pas le cas nominal.
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    // 2) ISO-8601 : YYYY-MM-DDTHH:MM:SS[.frac][Z|±HH:MM]. On lit la partie civile UTC et applique
    //    l'offset éventuel. Pas de chrono : conversion calendaire jours-depuis-epoch à la main
    //    (algorithme « days_from_civil », valable pour le calendrier grégorien proleptique).
    let (date_part, rest) = s.split_once('T').or_else(|| s.split_once(' '))?;
    let mut d = date_part.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // sépare l'heure de l'offset/zone (Z, +hh:mm, -hh:mm). On coupe au 1er marqueur d'offset.
    let mut offset_secs: i64 = 0;
    let time_str: &str = {
        let r = rest.trim_end();
        if let Some(stripped) = r.strip_suffix('Z').or_else(|| r.strip_suffix('z')) {
            stripped
        } else {
            // l'offset commence au 1er '+'/'-' rencontré dans `rest` (HH:MM:SS n'en contient pas) ;
            // le 'T' a déjà été retiré en amont, donc tout signe ici borne le décalage de fuseau.
            if let Some(pos) = r.find(['+', '-']) {
                let (t, off) = r.split_at(pos);
                let sign = if off.starts_with('-') { -1 } else { 1 };
                let off = &off[1..];
                let mut op = off.split(':');
                let oh: i64 = op.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                let om: i64 = op.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                offset_secs = sign * (oh * 3600 + om * 60);
                t
            } else {
                r
            }
        }
    };
    // heure civile (on coupe une éventuelle fraction de seconde).
    let time_core = time_str.split('.').next().unwrap_or(time_str);
    let mut t = time_core.split(':');
    let hh: i64 = t.next()?.parse().ok()?;
    let mm: i64 = t.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let ss: i64 = t.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    if !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=60).contains(&ss) {
        return None;
    }
    // days_from_civil (Howard Hinnant) : jours depuis 1970-01-01 pour une date grégorienne.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0,365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468;
    let epoch_utc = days * 86400 + hh * 3600 + mm * 60 + ss;
    // l'horodatage civil était exprimé dans le fuseau `offset_secs` -> on revient à l'UTC.
    Some(epoch_utc - offset_secs)
}

// ===========================================================================================
// SOURCE DE DÉTECTION CONFIGURABLE (plugin infra-agnostique) — substrat de la boucle purple.
//
// La console ne code plus « Plume » en dur. La SOURCE de détection (SIEM/IDS/pare-feu) est décrite
// par un objet JSON `{kind, endpoint?, auth?:{type,secret}, query?, mapping?}` rangé dans
// `settings.detection_source`. `kind` ∈ {plume, generic_http, crowdsec, fortigate_syslog, pfsense,
// opnsense, file_jsonl, elastic, exec, none} ; `auth.type` ∈ {none, basic, bearer, api_key_header,
// mtls}. Les kinds `plume`/`generic_http` (http) sont interrogés EN RUST (fetcher intégré ci-dessous) ;
// les kinds « messy » (et generic_http en https, pour TLS) sont DÉLÉGUÉS au collecteur Python
// (`forge.cli detections`). Dans TOUS les cas la sortie est normalisée en `[(mitre,count,first_ts)]`
// puis passée à `compute_purple_coverage` (jointure MITRE INCHANGÉE). Échec/mauvaise config =>
// FAIL-OPEN LISIBLE (source_reachable:false), jamais de detected/missed/MTTD inventés.
// ===========================================================================================

/// Résout la config de source de détection : `settings.detection_source` (VERBATIM si objet JSON
/// valide) sinon REPLI rétro-compat sur l'env legacy PLUME_URL/PLUME_TOKEN (implicitement
/// `{kind:plume, endpoint:PLUME_URL, auth:{type:basic,secret:PLUME_TOKEN}}`), sinon `{kind:none}`.
/// Le repli n'a lieu QUE si la clé settings est ABSENTE (une config explicite `{kind:none}` NE
/// retombe PAS sur l'env). Fonction pure vis-à-vis de la DB (lecture seule).
fn resolve_detection_source(db: &Connection) -> Value {
    if let Some(s) = settings_get(db, "detection_source") {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if v.is_object() {
                return v;
            }
        }
    }
    // repli env legacy : uniquement si settings n'a PAS de detection_source lisible.
    let url = std::env::var("PLUME_URL").unwrap_or_default().trim_end_matches('/').to_string();
    let token = std::env::var("PLUME_TOKEN").unwrap_or_default();
    if !url.is_empty() {
        return json!({"kind": "plume", "endpoint": url, "auth": {"type": "basic", "secret": token}});
    }
    json!({"kind": "none"})
}

/// `kind` de la source (défaut "none", trim).
fn ds_kind(cfg: &Value) -> String {
    cfg.get("kind").and_then(|v| v.as_str()).unwrap_or("none").trim().to_string()
}

/// `endpoint` de la source (URL http(s):// ou chemin fichier selon le kind ; défaut vide, trim).
fn ds_endpoint(cfg: &Value) -> String {
    cfg.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
}

/// Type d'auth déclaré (`auth.type`, avec tolérance à la forme plate `auth_type` écrite par le
/// wizard). Défaut "none". NE renvoie JAMAIS le secret — juste le NOM du schéma (pour le ledger/log).
fn ds_auth_type(cfg: &Value) -> String {
    cfg.get("auth").and_then(|a| a.get("type")).and_then(|v| v.as_str())
        .or_else(|| cfg.get("auth_type").and_then(|v| v.as_str()))
        .unwrap_or("none").trim().to_string()
}

/// Secret d'auth (`auth.secret`) — MANIÉ COMME UN SECRET DE SESSION : lu UNIQUEMENT pour construire
/// l'en-tête d'auth du fetch et pour la rédaction ; jamais renvoyé/journalisé/ledgerisé.
fn ds_secret(cfg: &Value) -> String {
    cfg.get("auth").and_then(|a| a.get("secret")).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// Remplace toute occurrence du secret par `[secret rédigé]` dans un message destiné à une réponse/au
/// log/au ledger. Garde-fou défense-en-profondeur (les messages d'erreur n'échoient normalement pas le
/// secret) ; no-op si le secret est vide ou trop court pour être remplacé sans risque de sur-rédaction.
fn redact_secret(msg: &str, secret: &str) -> String {
    if secret.len() < 4 {
        return msg.to_string();
    }
    msg.replace(secret, "[secret rédigé]")
}

/// Liste FERMÉE des `kind` de source de détection acceptés (parité avec le registre du collecteur Python
/// `forge.collectors` + les kinds interrogés en Rust). `none` désactive la mesure (fail-open lisible).
/// Sert de garde-fou d'entrée sur POST /api/detection/source (fail-closed : un kind inconnu est refusé,
/// jamais persisté) et alimente le sélecteur de l'UI admin/wizard.
const DETECTION_KINDS: &[&str] = &[
    "none", "plume", "generic_http", "crowdsec", "elastic", "opensearch",
    "fortigate_syslog", "pfsense", "opnsense", "file_jsonl", "exec",
];

fn is_known_detection_kind(kind: &str) -> bool {
    DETECTION_KINDS.contains(&kind)
}

/// Copie RÉDIGÉE d'une config de source : retire le secret d'auth (`auth.secret`) et tout `secret` posé
/// à plat. Utilisée par GET /api/detection/source et la réponse de POST — le SECRET n'est JAMAIS renvoyé
/// (manié comme un secret de session). Tout le reste (kind/endpoint/auth.type/query/mapping) est conservé
/// pour permettre l'édition côté admin sans jamais re-rendre le secret.
fn redact_detection_config(cfg: &Value) -> Value {
    let mut out = cfg.clone();
    if let Some(m) = out.as_object_mut() {
        m.remove("secret");
        if let Some(auth) = m.get_mut("auth").and_then(|a| a.as_object_mut()) {
            auth.remove("secret");
        }
    }
    out
}

/// Sémantique WRITE-ONLY du secret : si `keep_secret` et que la config entrante ne porte PAS de secret
/// non vide, réinjecte le secret STOCKÉ (config de détection effective courante) dans `auth.secret`.
/// Permet à l'admin d'éditer endpoint/mapping — ou de TESTER la source — SANS re-saisir le secret (jamais
/// rendu côté UI : affiché ••• une fois posé). No-op si aucun secret n'est déjà stocké, ou si l'appelant
/// fournit un nouveau secret non vide (celui-ci prime alors).
fn apply_kept_secret(app: &App, cfg: &Value, keep_secret: bool) -> Value {
    let mut out = cfg.clone();
    if keep_secret && ds_secret(cfg).is_empty() {
        let stored = ds_secret(&app.detection_config());
        if !stored.is_empty() {
            let atype = ds_auth_type(cfg);
            if let Some(m) = out.as_object_mut() {
                let auth = m.entry("auth").or_insert_with(|| json!({}));
                if !auth.is_object() {
                    *auth = json!({});
                }
                if let Some(am) = auth.as_object_mut() {
                    am.entry("type").or_insert_with(|| json!(atype));
                    am.insert("secret".into(), json!(stored));
                }
            }
        }
    }
    out
}

/// Schéma d'authentification HTTP du fetcher intégré. `mtls` n'est PAS ici (le client TCP brut ne fait
/// pas de TLS — un endpoint mTLS passe par un kind délégué au collecteur Python).
enum HttpAuth {
    None,
    Basic(String),                         // base64 de user:pass -> `Authorization: Basic ...`
    Bearer(String),                        // token -> `Authorization: Bearer ...`
    ApiKeyHeader { name: String, value: String }, // en-tête d'API arbitraire (ex: X-API-Key: ...)
}

/// Construit l'`HttpAuth` du fetcher intégré depuis la config source. `basic`/`bearer` prennent
/// `auth.secret` ; `api_key_header` prend `auth.header` (défaut `X-API-Key`) + `auth.secret`. `none`,
/// `mtls` ou un type inconnu => aucun en-tête (le TLS/mTLS relève d'un kind délégué au Python).
fn parse_http_auth(cfg: &Value) -> HttpAuth {
    let auth = cfg.get("auth");
    let atype = ds_auth_type(cfg);
    let secret = ds_secret(cfg);
    match atype.as_str() {
        "basic" => HttpAuth::Basic(secret),
        "bearer" => HttpAuth::Bearer(secret),
        "api_key_header" => {
            let name = auth.and_then(|a| a.get("header")).and_then(|v| v.as_str())
                .unwrap_or("X-API-Key").to_string();
            HttpAuth::ApiKeyHeader { name, value: secret }
        }
        _ => HttpAuth::None,
    }
}

/// GET HTTP/1.1 minimal et BLOQUANT (lancé via spawn_blocking) — pas de dépendance HTTP lourde.
/// Ne gère QUE `http://host[:port]/path` (le service bind en HTTP clair, derrière Traefik/forward-auth
/// en prod ; pour TLS, viser un endpoint interne http:// OU un kind délégué au collecteur Python).
/// `auth` porte le schéma d'authentification (none/basic/bearer/api_key_header). `allow_https` : si
/// faux (kind=plume, rétro-compat EXACTE) une URL https:// est refusée avec le message historique ;
/// si vrai (generic_http) une URL https:// est refusée avec un message d'aiguillage (TLS non géré
/// nativement) — le chemin generic_http+https est de toute façon délégué au Python en amont. Renvoie
/// le corps (string) en cas de 200, sinon Err. Timeout dur (connect + lecture).
fn http_get_blocking(url: &str, auth: &HttpAuth, timeout: Duration, allow_https: bool) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let rest = if let Some(r) = url.strip_prefix("http://") {
        r
    } else if url.strip_prefix("https://").is_some() {
        return Err(if allow_https {
            "HTTPS non géré nativement par le fetcher intégré — viser un endpoint http:// interne, \
             ou un kind délégué au collecteur Python (elastic/exec) pour le TLS".to_string()
        } else {
            "PLUME_URL doit commencer par http:// (TLS non géré côté console — utiliser un endpoint interne)".to_string()
        });
    } else {
        return Err("l'endpoint doit commencer par http:// (ou https:// pour un kind délégué)".to_string());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = authority.split(':').next().unwrap_or(authority);
    let port: u16 = authority.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(80);
    // résolution + connexion avec timeout (évite un blocage si la source est down).
    use std::net::ToSocketAddrs;
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("résolution {host}:{port} échouée: {e}"))?
        .next()
        .ok_or_else(|| format!("aucune adresse pour {host}:{port}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connexion {addr} échouée: {e}"))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: forge-console-detection\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    // En-tête d'auth selon le schéma. Un secret/valeur vide => aucun en-tête (cas anonyme, ex.
    // SOC_PUBLIC_DEMO). Anti-injection d'en-tête : on refuse toute valeur portant CR/LF.
    let no_crlf = |s: &str| !s.contains('\r') && !s.contains('\n');
    match auth {
        HttpAuth::None => {}
        HttpAuth::Basic(b) if !b.is_empty() && no_crlf(b) => req.push_str(&format!("Authorization: Basic {b}\r\n")),
        HttpAuth::Bearer(t) if !t.is_empty() && no_crlf(t) => req.push_str(&format!("Authorization: Bearer {t}\r\n")),
        HttpAuth::ApiKeyHeader { name, value }
            if !name.is_empty() && !value.is_empty() && no_crlf(name) && no_crlf(value) =>
        {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        _ => {}
    }
    stream.write_all(req.as_bytes()).map_err(|e| format!("écriture requête échouée: {e}"))?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| format!("lecture réponse échouée: {e}"))?;
    let text = String::from_utf8_lossy(&raw);
    // sépare l'en-tête du corps (CRLFCRLF). Vérifie un statut 200.
    let split = text.find("\r\n\r\n").ok_or_else(|| "réponse HTTP malformée (pas d'en-tête/corps)".to_string())?;
    let head = &text[..split];
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200") {
        return Err(format!("statut HTTP inattendu: {status_line}"));
    }
    let body = &text[split + 4..];
    // gère un éventuel Transfer-Encoding: chunked (Plume/axum peut chunker) — décode best-effort.
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        // IDIO-1 : dé-chunk sur les OCTETS BRUTS du corps (l'en-tête HTTP est ASCII, donc l'offset
        // `split + 4` calculé sur la vue lossy est le même offset d'octet dans `raw`).
        Ok(dechunk(&raw[split + 4..]))
    } else {
        Ok(body.to_string())
    }
}

/// Décode un corps HTTP `chunked` (best-effort) : tailles hex par ligne, terminé par un chunk 0.
///
/// IDIO-1 : le dé-chunking opère sur les OCTETS BRUTS (`&[u8]`). Les tailles de chunk sont des comptes
/// d'octets ; indexer une chaîne issue de `from_utf8_lossy` avec ces offsets pouvait tomber au milieu
/// d'un caractère (les octets invalides deviennent U+FFFD, 3 octets) -> panique de tranche `&str` ou
/// sortie décalée. On assemble d'abord les octets utiles, puis on convertit UNE fois en fin. Pour une
/// entrée ASCII valide, la sortie est identique à l'ancienne implémentation.
fn dechunk(body: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::new();
    let mut rest: &[u8] = body;
    while let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") {
        let size_line = &rest[..nl];
        // la taille peut porter des extensions après ';' — on ne garde que l'hex.
        let hex_seg = size_line.split(|&b| b == b';').next().unwrap_or(&[]);
        let size = match std::str::from_utf8(hex_seg)
            .ok()
            .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
        {
            Some(s) => s,
            None => break,
        };
        if size == 0 {
            break;
        }
        let start = nl + 2;
        let end = start + size;
        if end > rest.len() {
            out.extend_from_slice(&rest[start..]);
            break;
        }
        out.extend_from_slice(&rest[start..end]);
        // saute le CRLF de fin de chunk.
        rest = if end + 2 <= rest.len() { &rest[end + 2..] } else { &[] };
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Corrélation PURE (testable, sans I/O) red-team(tiré) × blue-team(détecté).
///
/// - `fired` : techniques tirées par Forge -> (mitre, ts_epoch_du_tir Option). Une technique peut
///   apparaître plusieurs fois (plusieurs tirs) ; on prend le tir le PLUS RÉCENT pour le MTTD (le SOC
///   doit détecter le tir courant), et on compte les tirs.
/// - `detections` : map mitre -> (count_alertes, first_ts_epoch) renvoyée par Plume.
///
/// Renvoie l'objet JSON exposé par /api/purple/coverage (hors champ plume_reachable, ajouté par
/// le handler). detected/missed sont des intersections/différences STRICTES sur `mitre`.
fn compute_purple_coverage(
    fired: &[(String, Option<i64>)],
    detections: &std::collections::HashMap<String, (i64, i64)>,
) -> Value {
    // agrège les tirs par technique : nb de tirs + horodatage du tir le plus récent (pour MTTD).
    let mut fired_by: std::collections::BTreeMap<String, (i64, Option<i64>)> = std::collections::BTreeMap::new();
    for (mitre, ts) in fired {
        if mitre.is_empty() {
            continue;
        }
        let e = fired_by.entry(mitre.clone()).or_insert((0, None));
        e.0 += 1;
        if let Some(t) = ts {
            // on garde le tir le PLUS RÉCENT (max) -> MTTD calculé contre le dernier tir.
            e.1 = Some(e.1.map_or(*t, |cur: i64| cur.max(*t)));
        }
    }

    let mut detected: Vec<Value> = Vec::new();
    let mut missed: Vec<Value> = Vec::new();
    let mut mttd_samples: Vec<i64> = Vec::new();

    for (mitre, (fires, last_fire_ts)) in &fired_by {
        match detections.get(mitre) {
            Some((count, first_ts)) => {
                // MTTD = première détection - dernier tir. Indisponible si le ts du tir est illisible.
                // Tronqué à 0 si négatif (détection antérieure = run précédent ; pas de gain négatif).
                let mttd = last_fire_ts.map(|ft| (*first_ts - ft).max(0));
                if let Some(m) = mttd {
                    mttd_samples.push(m);
                }
                detected.push(json!({
                    "mitre": mitre,
                    "fires": fires,
                    "alert_count": count,
                    "first_detection_ts": first_ts,
                    "fire_ts": last_fire_ts,
                    "mttd_secs": mttd,
                }));
            }
            None => {
                missed.push(json!({
                    "mitre": mitre,
                    "fires": fires,
                    "fire_ts": last_fire_ts,
                }));
            }
        }
    }

    let n_fired = fired_by.len() as i64;
    let n_detected = detected.len() as i64;
    let n_missed = missed.len() as i64;
    let detection_rate = if n_fired > 0 { n_detected as f64 / n_fired as f64 } else { 0.0 };
    let mttd_avg = if !mttd_samples.is_empty() {
        Some(mttd_samples.iter().sum::<i64>() as f64 / mttd_samples.len() as f64)
    } else {
        None
    };
    let mttd_max = mttd_samples.iter().copied().max();

    json!({
        "techniques_fired": n_fired,
        "techniques_detected": n_detected,
        "techniques_missed": n_missed,
        "detection_rate": detection_rate,   // [0,1] — part des techniques tirées détectées par le SOC
        "mttd_avg_secs": mttd_avg,           // null si aucun échantillon mesurable
        "mttd_max_secs": mttd_max,           // null si aucun échantillon mesurable
        "detected": detected,                // techniques tirées ET détectées (avec MTTD)
        "missed": missed,                    // TROUS de détection : tirées mais jamais alertées
    })
}

/// Construit l'objet de FAIL-OPEN LISIBLE (source_reachable/plume_reachable:false) : compte les
/// techniques tirées (pour information) mais NE FABRIQUE PAS de detected/missed/MTTD. Réutilisé par
/// tous les chemins où la mesure n'a pas pu se faire (source absente/injoignable/illisible, lecture DB
/// échouée). `plume_reachable`/`plume_url` sont conservés (rétro-compat du SPA et du rapport qui les
/// lisent) et MIROITÉS en `source_reachable`/`source_url` (nommage neutre infra-agnostique). `url` ne
/// contient JAMAIS le secret (endpoint seul). `reason` a déjà été rédigé par l'appelant.
fn purple_fail_open(url: &str, fired: &[(String, Option<i64>)], reason: &str) -> Value {
    let n_fired = fired
        .iter()
        .filter(|(m, _)| !m.is_empty())
        .map(|(m, _)| m.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as i64;
    json!({
        "plume_reachable": false,
        "source_reachable": false,
        "plume_url": url,
        "source_url": url,
        "error": reason,
        "techniques_fired": n_fired,
        "techniques_detected": 0,
        "techniques_missed": 0,
        "detection_rate": 0.0,
        "mttd_avg_secs": Value::Null,
        "mttd_max_secs": Value::Null,
        "detected": [],
        "missed": [],
    })
}

/// Lit les techniques tirées (runrecord.fired=1, mitre non vide) + horodatage du tir, filtrées par
/// une clause WHERE additionnelle (campaign ou run_id) déjà validée par l'appelant (param lié).
fn read_fired_techniques(app: &App, eid: Option<i64>, extra_cond: Option<(&str, &str)>) -> Vec<(String, Option<i64>)> {
    let db = app.db();
    // ENGAGEMENT : `eid=Some(id)` restreint aux tirs de CET engagement (vue /purple/coverage). `None`
    // = pas de filtre engagement (run_report : le `run_id` isole déjà les records d'un seul engagement).
    // engagement_id est un entier RÉSOLU -> inliné sans risque d'injection.
    let eng_clause = eid.map(|e| format!(" AND engagement_id={e}")).unwrap_or_default();
    let (sql, args): (String, Vec<String>) = match extra_cond {
        Some((col, val)) => (
            format!("SELECT mitre, ts FROM runrecord WHERE fired=1 AND mitre<>''{eng_clause} AND {col}=?"),
            vec![val.to_string()],
        ),
        None => (
            format!("SELECT mitre, ts FROM runrecord WHERE fired=1 AND mitre<>''{eng_clause}"),
            vec![],
        ),
    };
    let mut stmt = match db.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
        let mitre: String = r.get::<_, Option<String>>(0)?.unwrap_or_default();
        let ts_raw: String = r.get::<_, Option<String>>(1)?.unwrap_or_default();
        Ok((mitre, parse_fire_ts(&ts_raw)))
    })
    .map(|it| it.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Accès à une valeur JSON par CHEMIN POINTÉ ("a.b.c") ; None si un segment manque. Un chemin vide
/// renvoie la valeur racine. Sert au `mapping` des sources generic_http (champ natif -> mitre/ts/count).
fn json_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        if seg.is_empty() {
            continue;
        }
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Valeur au chemin pointé rendue en String (string telle quelle, sinon repr scalaire, sinon vide).
fn json_path_str(v: &Value, path: &str) -> String {
    match json_path(v, path) {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.as_str().map(str::to_string).unwrap_or_default(),
        None => String::new(),
    }
}

/// Valeur au chemin pointé rendue en i64 (int, sinon f64 tronqué, sinon parse d'une string ; None si
/// absent/illisible).
fn json_path_i64(v: &Value, path: &str) -> Option<i64> {
    let n = json_path(v, path)?;
    n.as_i64()
        .or_else(|| n.as_f64().map(|f| f as i64))
        .or_else(|| n.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
}

/// Mapping IDENTITÉ de la réponse Plume `{detections:[{mitre,count,first_ts}]}` -> `[(mitre,count,ts)]`.
/// Réutilisé aussi pour la sortie NORMALISÉE du collecteur Python (même contrat de sortie).
fn parse_plume_detections(parsed: &Value) -> Vec<(String, i64, i64)> {
    let mut out = Vec::new();
    if let Some(arr) = parsed.get("detections").and_then(|v| v.as_array()) {
        for d in arr {
            let mitre = d.get("mitre").and_then(|v| v.as_str()).unwrap_or("");
            if mitre.is_empty() {
                continue;
            }
            let count = d.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            let first_ts = d.get("first_ts").and_then(|v| v.as_i64()).unwrap_or(0);
            out.push((mitre.to_string(), count, first_ts));
        }
    }
    out
}

/// Applique le `mapping` d'une source generic_http à une réponse arbitraire -> `[(mitre,count,ts)]`.
/// `mapping` : `{records?: "chemin.vers.tableau", mitre?: "champ", ts?: "champ", count?: "champ"}`.
/// - `records` localise le tableau d'enregistrements (défaut : tableau racine, sinon champ `detections`
///   / `results`) ;
/// - chaque enregistrement fournit `mitre` (défaut champ "mitre"), `ts` (défaut "first_ts"), et un
///   `count` OPTIONNEL (si absent chaque enregistrement compte 1) ;
/// - agrégation par mitre : count sommé, first_ts = min. Aucune fabrication : un tableau introuvable
///   ou vide -> Err / vec vide (l'appelant bascule alors en fail-open).
fn map_detections(parsed: &Value, mapping: Option<&Value>) -> Result<Vec<(String, i64, i64)>, String> {
    let default_map = json!({});
    let m = mapping.unwrap_or(&default_map);
    let records_path = m.get("records").and_then(|v| v.as_str()).unwrap_or("");
    let mitre_field = m.get("mitre").and_then(|v| v.as_str()).unwrap_or("mitre");
    let ts_field = m.get("ts").and_then(|v| v.as_str()).unwrap_or("first_ts");
    let count_field = m.get("count").and_then(|v| v.as_str());

    let arr: Vec<Value> = if !records_path.is_empty() {
        json_path(parsed, records_path)
            .and_then(|v| v.as_array().cloned())
            .ok_or_else(|| format!("aucun tableau de détections au chemin '{records_path}'"))?
    } else {
        parsed
            .as_array()
            .cloned()
            .or_else(|| parsed.get("detections").and_then(|v| v.as_array()).cloned())
            .or_else(|| parsed.get("results").and_then(|v| v.as_array()).cloned())
            .ok_or_else(|| "aucun tableau de détections (records/detections/results absents)".to_string())?
    };

    // agrégation par mitre : (count sommé, first_ts min).
    let mut agg: std::collections::BTreeMap<String, (i64, i64)> = std::collections::BTreeMap::new();
    for rec in &arr {
        let mitre = json_path_str(rec, mitre_field);
        if mitre.is_empty() {
            continue;
        }
        let ts = json_path_i64(rec, ts_field).unwrap_or(0);
        let c = match count_field {
            Some(cf) => json_path_i64(rec, cf).unwrap_or(1),
            None => 1,
        };
        let e = agg.entry(mitre).or_insert((0, ts));
        e.0 += c;
        if ts < e.1 {
            e.1 = ts;
        }
    }
    Ok(agg.into_iter().map(|(k, (c, t))| (k, c, t)).collect())
}

/// Construit l'URL d'une source generic_http : endpoint + `query` optionnelle (string, `{since}`
/// substitué), jointe par '?' si l'endpoint n'a pas de query-string, sinon '&'.
fn generic_http_url(endpoint: &str, query: Option<&Value>, since: i64) -> String {
    match query.and_then(|v| v.as_str()).filter(|q| !q.is_empty()) {
        Some(q) => {
            let q = q.replace("{since}", &since.to_string());
            let q = q.trim_start_matches(['?', '&']);
            let sep = if endpoint.contains('?') { '&' } else { '?' };
            format!("{endpoint}{sep}{q}")
        }
        None => endpoint.to_string(),
    }
}

/// Fetch + normalisation EN RUST d'une source http (`plume` ou `generic_http` en clair). `is_plume` :
/// URL = `{endpoint}/api/coverage/detections?since=N` + mapping IDENTITÉ + http-only (rétro-compat
/// EXACTE) ; sinon URL = endpoint + `query`, mapping configuré, https autorisé (aiguillé au Python en
/// amont). BLOQUANT (à lancer via spawn_blocking).
fn rust_http_collect(cfg: &Value, since: i64, is_plume: bool) -> Result<Vec<(String, i64, i64)>, String> {
    let endpoint = ds_endpoint(cfg);
    if endpoint.is_empty() {
        return Err("endpoint de la source de détection non configuré".to_string());
    }
    let auth = parse_http_auth(cfg);
    let timeout = Duration::from_secs(8);
    let url = if is_plume {
        format!("{}/api/coverage/detections?since={}", endpoint.trim_end_matches('/'), since)
    } else {
        generic_http_url(&endpoint, cfg.get("query"), since)
    };
    let body = http_get_blocking(&url, &auth, timeout, !is_plume)?;
    let parsed: Value = serde_json::from_str(body.trim())
        .map_err(|e| format!("réponse illisible (JSON invalide): {e}"))?;
    if is_plume {
        Ok(parse_plume_detections(&parsed))
    } else {
        map_detections(&parsed, cfg.get("mapping"))
    }
}

/// Délègue la collecte au COLLECTEUR PYTHON pour les kinds « messy » (crowdsec/fortigate_syslog/
/// pfsense/opnsense/file_jsonl/elastic/exec, et generic_http en https pour le TLS). Même patron de
/// spawn no-shell que populate_modules (`python3 -m forge.cli detections --since N --source ...`).
/// La config (AVEC secret) est passée par ENV `FORGE_DETECTION_SOURCE` (jamais en argv -> pas de fuite
/// via `ps`/cmdline, cf. le token console de run_create) ; l'argv ne porte que `--source env:...`. Le
/// collecteur émet `{detections:[{mitre,count,first_ts}]}` sur stdout. Toute erreur -> Err (fail-open),
/// le stderr éventuel étant RÉDIGÉ du secret avant de remonter.
async fn collect_via_python(app: &App, cfg: &Value, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    let py = app.python.as_str().to_string();
    let pkg_dir = app.pkg_dir.as_str().to_string();
    let source_json = cfg.to_string();
    let secret = ds_secret(cfg);
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new(&py)
            .args([
                "-m", "forge.cli", "detections",
                "--since", &since.to_string(),
                "--source", "env:FORGE_DETECTION_SOURCE",
            ])
            .current_dir(&pkg_dir)
            .env("FORGE_DETECTION_SOURCE", &source_json)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("collecteur Python injoignable: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = redact_secret(err.trim(), &secret);
            let err: String = err.chars().take(240).collect();
            return Err(format!("collecteur Python a échoué (code {:?}): {err}", out.status.code()));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let parsed: Value = serde_json::from_str(stdout.trim())
            .map_err(|e| format!("sortie du collecteur illisible (JSON invalide): {e}"))?;
        Ok(parse_plume_detections(&parsed))
    })
    .await
    .unwrap_or_else(|e| Err(format!("tâche collecteur interrompue: {e}")))
}

/// AIGUILLAGE central : collecte les détections de la source CONFIGURÉE (cache App) -> `[(mitre,count,
/// first_ts)]`. Voir `collect_detections_with` pour la logique de dispatch sur `kind`.
async fn collect_detections(app: &App, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    let cfg = app.detection_config();
    collect_detections_with(app, &cfg, since).await
}

/// Dispatch sur `kind` d'une config source DONNÉE (utilisé aussi par POST /api/detection/test pour
/// tester une config fournie sans la persister). `plume`/`generic_http`(http) -> fetch Rust ;
/// generic_http(https) + kinds messy -> collecteur Python. Résultat -> jointure MITRE INCHANGÉE.
async fn collect_detections_with(app: &App, cfg: &Value, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    match ds_kind(cfg).as_str() {
        "none" | "" => {
            Err("source de détection non configurée (kind=none) — couverture indisponible".to_string())
        }
        kind @ ("plume" | "generic_http") => {
            let is_plume = kind == "plume";
            // generic_http en https -> délégué au Python (TLS non géré par le fetcher intégré).
            if !is_plume && ds_endpoint(cfg).starts_with("https://") {
                return collect_via_python(app, cfg, since).await;
            }
            let cfg_owned = cfg.clone();
            tokio::task::spawn_blocking(move || rust_http_collect(&cfg_owned, since, is_plume))
                .await
                .unwrap_or_else(|e| Err(format!("tâche HTTP interrompue: {e}")))
        }
        "crowdsec" | "fortigate_syslog" | "pfsense" | "opnsense" | "file_jsonl" | "elastic" | "exec" => {
            collect_via_python(app, cfg, since).await
        }
        other => Err(format!("kind de source de détection inconnu: {other}")),
    }
}

/// Interroge la SOURCE DE DÉTECTION configurée et corrèle avec les techniques `fired` -> objet de
/// couverture complet. FAIL-OPEN LISIBLE à chaque étape qui peut échouer (source absente/injoignable/
/// illisible) : `source_reachable`/`plume_reachable:false` + raison RÉDIGÉE, JAMAIS de detected/missed/
/// MTTD inventés. La jointure MITRE (compute_purple_coverage) est INCHANGÉE quel que soit le `kind`.
/// Réutilisé par l'endpoint /api/purple/coverage (alias /api/detection/coverage) ET la section purple
/// du rapport de run. `endpoint`/`source_url` exposés pour la traçabilité NE contiennent jamais le secret.
async fn fetch_purple_coverage(app: &App, fired: Vec<(String, Option<i64>)>) -> Value {
    let cfg = app.detection_config();
    let disp = ds_endpoint(&cfg); // endpoint seul (jamais le secret) pour la traçabilité
    let kind = ds_kind(&cfg);
    // AUTONOME (standalone) vs source configurée : une source EST configurée si `kind` n'est ni none/vide
    // ni un kind http (plume/generic_http) sans endpoint (parité EXACTE avec le log de boot). Ce booléen
    // permet au SPA de distinguer « aucune source configurée — Forge en autonome » (état NORMAL, attendu)
    // de « source configurée mais INJOIGNABLE » (anomalie à signaler). Aucun des deux n'invente de métrique.
    let http_kind = kind == "plume" || kind == "generic_http";
    let source_configured = !(kind == "none" || kind.is_empty() || (http_kind && disp.is_empty()));
    // `since` = plus ancien tir red (borne la fenêtre côté source) ; 0 si aucun tir horodaté lisible.
    let since = fired.iter().filter_map(|(_, t)| *t).min().unwrap_or(0);
    match collect_detections(app, since).await {
        Ok(dets) => {
            let mut detections: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
            for (mitre, count, first_ts) in dets {
                if mitre.is_empty() {
                    continue;
                }
                // dernière occurrence prime (agrégée en amont) ; contrat identique à l'ancien parse.
                detections.insert(mitre, (count, first_ts));
            }
            // corrélation pure -> réponse. reachable:true (la mesure a bien eu lieu).
            let mut cov = compute_purple_coverage(&fired, &detections);
            if let Value::Object(ref mut m) = cov {
                m.insert("plume_reachable".into(), json!(true));
                m.insert("source_reachable".into(), json!(true));
                m.insert("plume_url".into(), json!(disp));
                m.insert("source_url".into(), json!(disp));
                m.insert("source_kind".into(), json!(kind));
                m.insert("source_configured".into(), json!(true));
            }
            cov
        }
        // fail-open lisible ; la raison est rédigée du secret (défense en profondeur). On y JOINT le
        // `kind` et `source_configured` pour que le SPA/rapport rende l'état AUTONOME (source absente,
        // normal) distinctement d'une source configurée mais injoignable (anomalie).
        Err(e) => {
            let mut fo = purple_fail_open(&disp, &fired, &redact_secret(&e, &ds_secret(&cfg)));
            if let Value::Object(ref mut m) = fo {
                m.insert("source_kind".into(), json!(kind));
                m.insert("source_configured".into(), json!(source_configured));
            }
            fo
        }
    }
}

/// GET /api/detection/coverage[?campaign=X] (alias rétro-compat /api/purple/coverage) — couverture de
/// DÉTECTION (purple-team défensif). Joint runrecord[fired=1] (techniques tirées en red-team Forge)
/// avec les détections de la SOURCE configurée (kind=plume/generic_http/crowdsec/…). Réponse :
///   {
///     "source_reachable": bool,        // (miroir rétro-compat: plume_reachable) false => FAIL-OPEN lisible
///     "source_configured": bool,       // false => AUCUNE source configurée (Forge AUTONOME/standalone) ;
///                                       //   true + source_reachable:false => source posée mais injoignable
///     "source_url": "...",             // (miroir: plume_url) endpoint pour traçabilité — JAMAIS le secret
///     "source_kind": "...",            // kind de la source (none en autonome)
///     "techniques_fired|detected|missed": i64,
///     "detection_rate": f64,           // [0,1]
///     "mttd_avg_secs"|"mttd_max_secs": f64|i64|null,
///     "detected": [ {mitre, fires, alert_count, first_detection_ts, fire_ts, mttd_secs} ],
///     "missed":   [ {mitre, fires, fire_ts} ],
///     ("error": "...")                 // présent UNIQUEMENT si source_reachable=false (raison lisible)
///   }
/// Si source_reachable=false : detected/missed=[], compteurs/MTTD nuls — jamais de faux détecté/raté.
async fn purple_coverage(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : la couverture de détection est calculée sur les tirs de l'engagement actif UNIQUEMENT.
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // côté RED : techniques tirées (fired=1) + horodatage du tir, filtrées par campaign optionnelle.
    let fired = read_fired_techniques(&app, Some(eid), q.get("campaign").map(|c| ("campaign", c.as_str())));
    (StatusCode::OK, Json(fetch_purple_coverage(&app, fired).await))
}

/// POST /api/detection/test — ADMIN (check_admin, fail-closed 403). Exécute collect_detections UNE
/// fois contre une config FOURNIE (`{detection_source:{...}}` ou l'objet config à plat dans le corps)
/// ou, à défaut, la config STOCKÉE. Renvoie `{reachable, count, sample_mitres, error?}` — le SECRET
/// n'est JAMAIS renvoyé. Ledgerise `console.detection.test` (actor + kind + endpoint + auth_type +
/// reachable + count ; JAMAIS le secret). LECTURE seule côté source (ne persiste pas la config testée).
async fn detection_test(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    // WRITE-ONLY : `keep_secret` permet de tester une config éditée SANS re-saisir le secret déjà posé
    // (le secret write-only n'est jamais rendu par GET). apply_kept_secret réinjecte alors le secret stocké.
    let keep = body.get("keep_secret").and_then(|v| v.as_bool()).unwrap_or(false);
    // config à tester : {detection_source:{...}} > objet-config à plat ({kind:...}) > config stockée.
    let cfg: Arc<Value> = if let Some(v) = body.get("detection_source").filter(|v| v.is_object()) {
        Arc::new(apply_kept_secret(&app, v, keep))
    } else if body.is_object() && body.get("kind").is_some() {
        Arc::new(apply_kept_secret(&app, &body, keep))
    } else {
        app.detection_config()
    };
    let secret = ds_secret(&cfg);
    let kind = ds_kind(&cfg);
    // since=0 : test « prends tout » (le but est de vérifier la joignabilité, pas une fenêtre précise).
    let result = collect_detections_with(&app, &cfg, 0).await;
    let (reachable, count, samples, error) = match result {
        Ok(dets) => {
            let count = dets.len() as i64;
            // échantillon de mitres DISTINCTS (max 8) — aide au diagnostic sans divulguer de secret.
            let mut seen = std::collections::BTreeSet::new();
            let mut samples: Vec<String> = Vec::new();
            for (m, _, _) in &dets {
                if seen.insert(m.clone()) {
                    samples.push(m.clone());
                }
                if samples.len() >= 8 {
                    break;
                }
            }
            (true, count, samples, None)
        }
        Err(e) => (false, 0i64, Vec::new(), Some(redact_secret(&e, &secret))),
    };
    // AUDIT : trace du test. JAMAIS le secret (endpoint + type d'auth seuls).
    append_console_ledger(&app, "console.detection.test", json!({
        "actor": actor,
        "kind": kind,
        "endpoint": ds_endpoint(&cfg),
        "auth_type": ds_auth_type(&cfg),
        "reachable": reachable,
        "count": count,
    }));
    let mut out = json!({
        "reachable": reachable,
        "count": count,
        "sample_mitres": samples,
    });
    if let (Value::Object(ref mut m), Some(e)) = (&mut out, error) {
        m.insert("error".into(), json!(e));
    }
    (StatusCode::OK, Json(out)).into_response()
}

/// GET /api/detection/source — ADMIN (check_admin, fail-closed 403). Renvoie la config de source de
/// détection EFFECTIVE (settings.detection_source sinon repli env legacy PLUME_URL/PLUME_TOKEN), le
/// SECRET RETIRÉ (jamais renvoyé — manié comme un secret de session), plus `secret_set` (un secret
/// est-il posé ?) et la liste FERMÉE des kinds. L'UI admin/wizard édite cette config ; le secret
/// write-only s'affiche ••• (secret_set) et n'est jamais re-rendu au client.
async fn detection_source_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let cfg = app.detection_config();
    let secret_set = !ds_secret(&cfg).is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "source": redact_detection_config(&cfg),
            "secret_set": secret_set,
            "kinds": DETECTION_KINDS,
        })),
    )
        .into_response()
}

/// POST /api/detection/source — ADMIN (check_admin, fail-closed 403). Persiste `settings.detection_source`
/// (config VERBATIM) puis recharge le cache (la couverture utilise immédiatement la nouvelle source).
/// Corps : `{detection_source:{...}}` OU l'objet-config à plat (`{kind,...}`), + `keep_secret?:bool`
/// (write-only : conserver le secret déjà posé sans le re-saisir). `kind` est validé contre la liste
/// FERMÉE (fail-closed, jamais persisté sinon). Ledgerise `console.detection.source.set` (actor + kind +
/// endpoint + auth_type — JAMAIS le secret). Réponse = config RÉDIGÉE + secret_set (le secret n'y est jamais).
async fn detection_source_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    // config entrante : {detection_source:{...}} > objet-config à plat ({kind:...}). Les clés de contrôle
    // (keep_secret) sont retirées de la config à plat pour ne pas polluer ce qui est persisté.
    let incoming: Value = if let Some(v) = body.get("detection_source").filter(|v| v.is_object()) {
        v.clone()
    } else if body.is_object() && body.get("kind").is_some() {
        let mut c = body.clone();
        if let Some(m) = c.as_object_mut() {
            m.remove("keep_secret");
        }
        c
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "bad_request", "why": "corps attendu : {detection_source:{kind,...}} ou {kind,...}"})),
        )
            .into_response();
    };
    let kind = ds_kind(&incoming);
    if !is_known_detection_kind(&kind) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "bad_kind", "why": format!("kind de source inconnu : {kind}")})),
        )
            .into_response();
    }
    // WRITE-ONLY : si keep_secret et aucun nouveau secret fourni, réinjecte le secret déjà posé.
    let keep = body.get("keep_secret").and_then(|v| v.as_bool()).unwrap_or(false);
    let cfg = apply_kept_secret(&app, &incoming, keep);
    {
        let db = app.db();
        if let Err(e) = settings_set(&db, "detection_source", &cfg.to_string()) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "settings_write_failed", "why": e})),
            )
                .into_response();
        }
    }
    // recharge le cache -> /api/detection/coverage bascule immédiatement sur la nouvelle source.
    app.reload_detection_source();
    // AUDIT : mutation d'administration attribuée + ledgerisée. JAMAIS le secret (endpoint + type seuls).
    append_console_ledger(&app, "console.detection.source.set", json!({
        "actor": actor,
        "kind": kind,
        "endpoint": ds_endpoint(&cfg),
        "auth_type": ds_auth_type(&cfg),
    }));
    let secret_set = !ds_secret(&cfg).is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "source": redact_detection_config(&cfg),
            "secret_set": secret_set,
            "saved": true,
        })),
    )
        .into_response()
}

// ===========================================================================================
// Endpoints de PARITÉ LECTURE / GOUVERNANCE (viewer, aucun spawn armé).
//
// Ces routes exposent la décision de scope, un plan « à blanc » (dry-plan, rien ne tire), le
// rafraîchissement du registre de modules, et le rendu markdown d'un rapport de run. Toutes
// réutilisent les garde-fous existants (host_in_server_scope, validate_*, scope FORCÉ allow_*=false).
// ===========================================================================================

/// GET /api/runs/:id/report — rend en markdown un rapport d'engagement pour CE run, à partir des
/// données stockées côté console (run_job + findings + roe_decision pour le run_id). Miroir Rust de
/// `forge.report.build_report` (synthèse, findings, transparence ROE). LECTURE (viewer).
/// 404 si le run_id est inconnu de run_job.
async fn run_report(State(app): State<App>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    // format : md (DÉFAUT — rétro-compat), html (livrable client brandé), pdf (si outil dispo).
    let format = q.get("format").map(|s| s.as_str()).unwrap_or("md");
    // le run doit exister (sinon 404, comme run_detail). Le verrou DB est confiné dans ce bloc :
    // AUCUN MutexGuard rusqlite (!Send) ne doit survivre à l'await réseau plus bas.
    let (job, fired) = {
        let db = app.db();
        let job = match db.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), [&id], run_job_json) {
            Ok(v) => v,
            Err(_) => return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"}))).into_response(),
        };
        // PURPLE : techniques TIRÉES par CE run (red) — lues avant de relâcher le verrou. Le `run_id`
        // isole déjà les records d'un seul engagement -> pas de filtre engagement additionnel (None).
        drop(db);
        let fired = read_fired_techniques(&app, None, Some(("run_id", &id)));
        (job, fired)
    };
    // I/O réseau Plume HORS verrou DB. Fail-open lisible si Plume injoignable.
    let purple = fetch_purple_coverage(&app, fired).await;
    // annexe chaîne-de-custody : intégrité du ledger + attribution (started_by résolu du run).
    let started_by = job.get("started_by").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let custody = build_ledger_custody(&app, &started_by);

    match format {
        "html" => {
            let html = {
                let db = app.db();
                render_run_report_html(&db, &id, &job, Some(&purple), &custody)
            };
            ([("content-type", "text/html; charset=utf-8")], Html(html)).into_response()
        }
        "pdf" => {
            // PDF : depuis le HTML brandé, via un outil système SI présent (pas de dep lourde ajoutée).
            let html = {
                let db = app.db();
                render_run_report_html(&db, &id, &job, Some(&purple), &custody)
            };
            match render_pdf_from_html(&html).await {
                Some(bytes) => (
                    StatusCode::OK,
                    [
                        ("content-type", "application/pdf".to_string()),
                        ("content-disposition", format!("inline; filename=\"forge-report-{id}.pdf\"")),
                    ],
                    bytes,
                ).into_response(),
                None => (
                    StatusCode::NOT_IMPLEMENTED,
                    Json(json!({
                        "error": "pdf_unavailable",
                        "why": "aucun moteur PDF (wkhtmltopdf/weasyprint) détecté sur l'hôte",
                        "hint": "ouvrez ?format=html puis « Imprimer » → « Enregistrer au format PDF » (CSS @media print fourni), ou installez wkhtmltopdf/weasyprint pour activer ?format=pdf"
                    })),
                ).into_response(),
            }
        }
        _ => {
            // md (défaut) — rétro-compat stricte : même contenu qu'avant + annexe custody.
            let md = {
                let db = app.db();
                render_run_report_md(&db, &id, &job, Some(&purple), Some(&custody))
            };
            (StatusCode::OK, [("content-type", "text/markdown; charset=utf-8")], md).into_response()
        }
    }
}




/// Résout le `ledger_path` de l'engagement PROPRIÉTAIRE d'un run (via run_job.engagement_id ->
/// engagement.ledger_path). Défaut : App.ledger_path (engagement #1 / rétro-compat). ISOLATION : tout
/// acte console lié à un run (cancel, fin de run) est journalisé dans le ledger de SON engagement,
/// jamais celui d'un autre.
fn engagement_ledger_for_run(app: &App, run_id: &str) -> String {
    let db = app.db();
    db.query_row(
        "SELECT e.ledger_path FROM run_job j JOIN engagement e ON e.id=j.engagement_id WHERE j.run_id=?",
        [run_id],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| app.ledger_path.as_str().to_string())
}

/// Journalise un acte de run dans le ledger de SON engagement. Si l'engagement partage le ledger de la
/// console (App.ledger_path = engagement #1), on passe par append_console_ledger (cache de head O(1),
/// chaîne préservée). Sinon on écrit dans le ledger DÉDIÉ de l'engagement via ledger_append_standalone
/// (relecture de head à la volée). Dans les DEUX cas la chaîne SHA-256 reste vérifiable
/// (/api/ledger/verify) et un engagement ne touche JAMAIS le ledger d'un autre.
fn append_run_ledger_path(app: &App, ledger_path: &str, kind: &str, detail: Value) {
    if ledger_path == app.ledger_path.as_str() {
        append_console_ledger(app, kind, detail);
    } else {
        let _ = ledger_append_standalone(ledger_path, kind, &detail);
    }
}

/// Horodatage compact UTC pour les run_id, sans dépendance chrono : YYYYmmddHHMMSS dérivé du temps
/// unix (suffisant pour l'unicité combiné au token aléatoire).
fn chrono_now_compact() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}


/// Construit le routeur axum complet : routes PUBLIQUES (hors auth_guard : /health, /api/login, wizard
/// de 1er déploiement /api/setup*) + routes PROTÉGÉES (derrière auth_guard) + fallback ServeDir, le
/// tout sous host_guard (anti-rebinding). Extrait de main() pour être exercé TEL QUEL par les tests
/// d'intégration (parité stricte du câblage : ce qui est gaté en prod l'est en test). `app` est déplacé
/// dans le routeur (with_state) ; le ConnectInfo est branché au moment du `serve`, pas ici.
fn build_router(app: App, web_dir: &str) -> Router {
    // routes protégées par auth_guard ; ServeDir sert les assets statiques (style.css/app.js/quetzal.svg/
    // favicon.svg/fonts/…) en fallback pour toute route non-API non matchée — l'index `/` reste rendu
    // par include_str!.
    let protected = Router::new()
        .route("/", get(index))
        .route("/api/whoami", get(whoami))
        .route("/api/ingest", post(ingest))
        .route("/api/findings", get(findings))
        .route("/api/findings/:id", get(finding_detail))
        .route("/api/runrecords", get(runrecords))
        .route("/api/coverage", get(coverage))
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
        // /health : sonde ouverte (hors auth_guard). JSON {status, version} — `version` provient
        // du fichier VERSION (source unique). `forge doctor --purple` ne teste que le code HTTP 200.
        .route("/health", get(|| async { Json(json!({"status": "ok", "version": forge_version()})) }))
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
        .layer(middleware::from_fn_with_state(app.clone(), host_guard))
        .with_state(app)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // sous-commandes de provisioning de hash argon2id :
    //   forge-console hashpw <password>           -> hash du viewer (FORGE_CONSOLE_PASS_HASH)
    //   forge-console hashpw-operator <password>  -> hash du rôle OPÉRATEUR C2 (FORGE_CONSOLE_OPERATOR_HASH)
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        // --version / -V : imprime la version unique (fichier VERSION, include_str! à la compile).
        Some("--version") | Some("-V") => {
            println!("forge-console {}", forge_version());
            return;
        }
        Some("hashpw") | Some("hashpw-operator") => {
            match args.get(2) {
                Some(pw) if !pw.is_empty() => {
                    println!("{}", hash_pw(pw));
                    return;
                }
                _ => {
                    eprintln!("usage: forge-console {} <password>", args[1]);
                    std::process::exit(2);
                }
            }
        }
        // Parité LECTURE locale (CLI) : lit la MÊME base SQLite que l'API, en READ-ONLY, et
        // imprime en table (défaut) ou JSON (--json). Aucune écriture, aucun spawn — pure lecture.
        Some(cmd @ ("findings" | "roe" | "coverage" | "query")) => {
            std::process::exit(run_read_cli(cmd, &args[2..]));
        }
        // Provisioning d'un COMPTE INDIVIDUEL : forge-console useradd <login> <role> [--pass <pw>]
        //   role ∈ {viewer|operator|admin}. Le mot de passe est lu sur STDIN par défaut (jamais en
        //   argv -> pas de fuite via ps/cmdline) ; `--pass <pw>` est toléré pour le scripting. Le hash
        //   argon2id est calculé ici et stocké dans `users` (idempotent par login : upsert + réactive).
        Some("useradd") => {
            std::process::exit(run_useradd_cli(&args[2..]));
        }
        // AMORÇAGE DÉMO : forge-console seed-demo [--dir <path>] [--campaign <name>]
        //   Charge l'engagement de référence synthétique (examples/reference-engagement/) DIRECTEMENT
        //   dans la base SQLite (hors-ligne, sans réseau, sans /api/ingest) pour qu'une console fraîche
        //   affiche immédiatement Findings/Coverage/Purple/Runs. Idempotent (purge la campagne démo).
        Some("seed-demo") => {
            std::process::exit(run_seed_demo_cli(&args[2..]));
        }
        // MIGRATION DE DONNÉES : forge-console migrate --from <dir|db> --to <db> [--ledger <path>]
        //   [--verify] [--encrypt --key-env <ENVVAR>]. Importe un install Forge existant (non-Docker)
        //   vers une base cible (Docker/autre) : copie DB (VACUUM INTO / SQLCipher), ledger + clé
        //   .ed25519 (0600), puis SCHEMA + migrate() sur la cible. UX primaire = conteneur one-shot.
        Some("migrate") => {
            std::process::exit(run_migrate_cli(&args[2..]));
        }
        // SAUVEGARDE CHIFFRÉE : forge-console backup --out <archive> --passphrase-env <ENVVAR>
        //   [--db <path>] [--ledger <path>]. Archive TOUJOURS chiffrée (argon2id + XChaCha20-Poly1305)
        //   regroupant snapshot DB (VACUUM INTO) + ledger + clé .ed25519 + manifest.json. Passphrase
        //   lue UNIQUEMENT depuis l'ENV (jamais argv). Chaîne ledger vérifiée avant, backup tracé.
        Some("backup") => {
            std::process::exit(run_backup_cli(&args[2..]));
        }
        // RESTAURATION CHIFFRÉE : forge-console restore --in <archive> --passphrase-env <ENVVAR>
        //   [--to <db>] [--ledger <path>] [--force]. Déchiffre (mauvaise passphrase/altération => rien
        //   écrit), vérifie les sha256 du manifest + la chaîne ledger, refuse d'écraser un install non
        //   vide sans --force, place db/ledger/clé (.ed25519 = 0600). Restore tracé au ledger.
        Some("restore") => {
            std::process::exit(run_restore_cli(&args[2..]));
        }
        // VÉRIF LEDGER (lecture seule, NON INTERACTIVE, RAPIDE) : forge-console ledger verify
        //   [--ledger <path>] [--json]. Recompute la chaîne SHA-256 du ledger JSONL et exit immédiat
        //   (0 intègre / 1 rompu-absent / 2 usage). NE démarre PAS le serveur, n'ouvre PAS la base,
        //   ne lit PAS STDIN. La vérif de signature reste côté `forge ledger verify --pubkey` (Python).
        Some("ledger") => {
            std::process::exit(run_ledger_cli(&args[2..]));
        }
        _ => {}
    }

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
    conn.execute_batch(SCHEMA).expect("schema");
    migrate(&conn); // ALTER additifs error-ignored (run_id, fix, panel étendu, run_job C2, dashboard_id)
    ensure_default_dashboard(&conn); // dashboard #1 (rétro-compat) + rattache les panels orphelins
    populate_modules(&conn); // table `module` peuplée depuis `forge.cli modules`
    reconcile_runs(&conn); // run_job 'running' orphelins (reboot console) -> 'failed'

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
    // ENGAGEMENT #1 (migration ZÉRO-PERTE) : si la table `engagement` est vide, on la crée depuis le
    // scope serveur COURANT (scope_in/scope_mode) + le ledger COURANT. Les lignes existantes gardent
    // engagement_id=1 (DEFAULT posé par migrate). Idempotent : ne réécrit jamais un engagement existant.
    ensure_default_engagement(&conn, &scope_in, &scope_mode, &ledger_path);
    // TENANT #1 (ENTERPRISE / migration ZÉRO-PERTE) : si la table `tenant` est vide, crée le tenant par
    // défaut, backfille les engagements (tenant_id=1) et sème les grants rétro-compat des comptes existants.
    // NO-OP fonctionnel en community (le filtre tenancy.rs ne s'engage que sous le flag enterprise).
    ensure_default_tenant(&conn);
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
        // token auto-généré : l'opérateur DOIT pouvoir le récupérer une fois. On l'imprime alors en
        // clair (sinon /api/ingest serait inutilisable), mais on signale qu'il est éphémère.
        println!("[forge-console] ingest token (auto-généré, éphémère — pose FORGE_CONSOLE_TOKEN pour le fixer): {token}  fp=sha8:{token_fp}");
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
        events,
        ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
    };
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

// =====================================================================================
// Tests de régression des correctifs de sûreté/sécurité (durcissement audit).
// =====================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Verrou global sérialisant les tests qui LISENT/ÉCRIVENT des variables d'ENV partagées
    /// (FORGE_ALLOW_API_MIGRATE / FORGE_CONSOLE_IMPORT_DIR) — l'ENV du process est global, donc ces
    /// tests ne doivent pas courir en parallèle. Empoisonnement ignoré (into_inner) : un panic
    /// antérieur ne doit pas bloquer les suivants.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// App minimale pour tester append_console_ledger (ledger sur disque, reste inerte).
    fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(SCHEMA).expect("schema");
        let (events, _) = broadcast::channel::<RunEvent>(64);
        App {
            db: Arc::new(Mutex::new(conn)),
            db_path: Arc::new(":memory:".into()),
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
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        }
    }

    fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        let uniq = format!("{}-{}-{}", name, std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        p.push(uniq);
        p.to_string_lossy().into_owned()
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

    /// Construit un HeaderMap avec un Authorization: Bearer <tok> (utilisé pour simuler une session).
    fn bearer_headers(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {tok}").parse().unwrap());
        h
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

    /// Récupère l'id d'un compte par login (helper de test).
    fn uid_of(app: &App, login: &str) -> i64 {
        let db = app.db();
        db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
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

        let app = include_str!("../web/app.js");
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

    /// Crée un dossier temporaire unique.
    fn tmp_dir(name: &str) -> String {
        let d = tmp_path(name);
        std::fs::create_dir_all(&d).expect("mkdir tmp");
        d
    }

    /// Sème une base SOURCE au schéma ANCIEN : `finding` SANS les colonnes additives (cwe/run_id/…),
    /// et PAS de table settings/users. La migration doit l'upgrader EN PLACE (SCHEMA + migrate()).
    fn seed_old_source_db(path: &str) {
        let c = Connection::open(path).expect("open src db");
        c.execute_batch(
            "CREATE TABLE finding(id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, title TEXT,
                severity TEXT, category TEXT, mitre TEXT, status TEXT, evidence TEXT, tool TEXT, poc TEXT);",
        )
        .expect("old schema");
        c.execute(
            "INSERT INTO finding(id,title,target,campaign) VALUES(1,'old-finding','h.example','c1')",
            [],
        )
        .expect("insert old row");
    }

    /// [MIGRATION plaintext] copie COHÉRENTE (VACUUM INTO) + upgrade EN PLACE : la cible reçoit les
    /// colonnes additives (cwe) et les tables neuves (settings) via SCHEMA+migrate(), la donnée
    /// source survit, le ledger + la clé voyagent, et le ledger cible reste VÉRIFIABLE (chaîne
    /// SHA-256 continue avec l'entrée `console.migrate`).
    #[test]
    fn migrate_plaintext_copies_and_upgrades_schema() {
        let src_dir = tmp_dir("forge-mig-src");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        // ledger source (2 entrées chaînées) + clé de signature .ed25519.
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        ledger_append_standalone(&src_ledger, "engagement.start", &json!({"a": 1})).unwrap();
        ledger_append_standalone(&src_ledger, "action.recon", &json!({"a": 2})).unwrap();
        std::fs::write(format!("{src_ledger}.ed25519"), b"fake-ed25519-key-32-bytes-xxxxxx").unwrap();

        let to = tmp_path("forge-mig-to.db");
        let target_ledger = tmp_path("forge-mig-to.jsonl");
        let opts = MigrateOpts {
            from: src_dir.clone(),
            to: to.clone(),
            ledger: Some(target_ledger.clone()),
            verify: true,
            encrypt: false,
            key_env: None,
            actor: "test".to_string(),
        };
        let report = run_migration(&opts).expect("migration doit réussir");
        assert_eq!(report["ok"], true);
        assert_eq!(report["encrypted"], false, "build par défaut -> copie en clair");
        assert_eq!(report["verify"]["ok"], true, "ledger source intact -> verify ok");

        // 1) schéma UPGRADÉ en place : colonne additive `cwe` présente, donnée source préservée.
        let dst = Connection::open(&to).expect("open target");
        let cwe: String = dst
            .query_row("SELECT cwe FROM finding WHERE id=1", [], |r| r.get(0))
            .expect("colonne cwe ajoutée par migrate()");
        assert_eq!(cwe, "", "cwe = DEFAULT '' sur une ligne migrée");
        let title: String = dst.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding", "la donnée source survit à la copie");
        // 2) table neuve `settings` créée par SCHEMA sur la cible (absente de la source ancienne).
        let n: i64 = dst.query_row("SELECT count(*) FROM settings", [], |r| r.get(0)).expect("table settings créée");
        assert_eq!(n, 0);

        // 3) ledger + clé copiés ; ledger cible VÉRIFIABLE (2 source + 1 console.migrate = 3, intègre).
        assert_eq!(report["ledger_copied"], true);
        assert_eq!(report["key_copied"], true);
        assert!(std::path::Path::new(&format!("{target_ledger}.ed25519")).exists(), "clé .ed25519 copiée");
        let v = verify_ledger_chain(&target_ledger);
        assert!(v.ok, "ledger cible doit rester intègre après l'append console.migrate");
        assert_eq!(v.entries, 3, "2 entrées source + 1 entrée de migration");
        let last = read_ledger_lines(&target_ledger).pop().unwrap();
        assert_eq!(last["kind"], "console.migrate", "la migration est tracée au ledger cible");
        assert_eq!(last["detail"]["encrypted"], false);

        drop(dst);
        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::remove_file(&target_ledger);
        let _ = std::fs::remove_file(format!("{target_ledger}.ed25519"));
    }

    /// [MIGRATION --verify] passe sur un ledger INTACT et ABORTE (aucune écriture cible) sur un ledger
    /// ALTÉRÉ (une entrée tamperée casse le recompute de hash).
    #[test]
    fn migrate_verify_passes_intact_aborts_on_tamper() {
        // --- cas INTACT : verify ok, migration réussit. ---
        let src_dir = tmp_dir("forge-mig-verify-ok");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        for i in 0..4 {
            ledger_append_standalone(&src_ledger, "console.test", &json!({"i": i, "msg": "événement"})).unwrap();
        }
        let to_ok = tmp_path("forge-mig-verify-ok-to.db");
        let led_ok = tmp_path("forge-mig-verify-ok-to.jsonl");
        let ok_opts = MigrateOpts {
            from: src_dir.clone(), to: to_ok.clone(), ledger: Some(led_ok.clone()),
            verify: true, encrypt: false, key_env: None, actor: "test".to_string(),
        };
        let r = run_migration(&ok_opts).expect("ledger intact -> migration réussit");
        assert_eq!(r["verify"]["ok"], true);
        assert!(std::path::Path::new(&to_ok).exists(), "cible écrite quand le ledger est intact");

        // --- cas ALTÉRÉ : on tampere une entrée -> verify échoue -> ABORT avant toute écriture. ---
        let src_dir2 = tmp_dir("forge-mig-verify-tamper");
        let src_db2 = format!("{src_dir2}/forge-console.db");
        seed_old_source_db(&src_db2);
        let src_ledger2 = format!("{src_dir2}/engagement.jsonl");
        for i in 0..4 {
            ledger_append_standalone(&src_ledger2, "console.test", &json!({"i": i, "msg": "événement"})).unwrap();
        }
        // altère le CONTENU d'une entrée sans recalculer son hash -> "hash recalculé != stocké".
        let tampered = std::fs::read_to_string(&src_ledger2).unwrap().replacen("événement", "ALTÉRÉ", 1);
        std::fs::write(&src_ledger2, tampered).unwrap();
        // pré-condition : la vérif détecte bien la rupture.
        let vchk = verify_ledger_chain(&src_ledger2);
        assert!(!vchk.ok && vchk.exists, "le ledger tamperé doit être détecté comme rompu");

        let to_bad = tmp_path("forge-mig-verify-tamper-to.db");
        let bad_opts = MigrateOpts {
            from: src_dir2.clone(), to: to_bad.clone(), ledger: Some(tmp_path("forge-mig-tamper-to.jsonl")),
            verify: true, encrypt: false, key_env: None, actor: "test".to_string(),
        };
        let err = run_migration(&bad_opts).expect_err("ledger rompu -> migration AVORTÉE");
        assert!(err.contains("AVORTÉE"), "message d'abort explicite: {err}");
        assert!(!std::path::Path::new(&to_bad).exists(), "AUCUNE écriture cible sur abort (verify avant copie)");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&src_dir2);
        let _ = std::fs::remove_file(&to_ok);
        let _ = std::fs::remove_file(&led_ok);
        let _ = std::fs::remove_file(format!("{led_ok}.ed25519"));
    }

    /// [MIGRATION clé] la clé de signature `.ed25519` voyage AVEC le ledger, en mode 0600 FORCÉ
    /// (même si la source est plus permissive) — sinon la chaîne signée devient invérifiable.
    #[cfg(unix)]
    #[test]
    fn migrate_copies_ed25519_key_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let src_dir = tmp_dir("forge-mig-key");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let src_ledger = format!("{src_dir}/engagement.jsonl");
        ledger_append_standalone(&src_ledger, "engagement.start", &json!({"a": 1})).unwrap();
        // clé source DÉLIBÉRÉMENT en 0644 -> prouve que la copie FORCE 0600 (pas un simple héritage).
        let src_key = format!("{src_ledger}.ed25519");
        std::fs::write(&src_key, b"raw-ed25519-private-key-32-bytes").unwrap();
        std::fs::set_permissions(&src_key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let to = tmp_path("forge-mig-key-to.db");
        let target_ledger = tmp_path("forge-mig-key-to.jsonl");
        let opts = MigrateOpts {
            from: src_dir.clone(), to: to.clone(), ledger: Some(target_ledger.clone()),
            verify: false, encrypt: false, key_env: None, actor: "test".to_string(),
        };
        run_migration(&opts).expect("migration ok");

        let dst_key = format!("{target_ledger}.ed25519");
        assert!(std::path::Path::new(&dst_key).exists(), "clé .ed25519 copiée dans le dossier ledger cible");
        let mode = std::fs::metadata(&dst_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "la clé doit être 0600 (secret de signature)");
        // contenu identique (la clé est le même secret).
        assert_eq!(std::fs::read(&dst_key).unwrap(), b"raw-ed25519-private-key-32-bytes");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&to);
        let _ = std::fs::remove_file(&target_ledger);
        let _ = std::fs::remove_file(&dst_key);
    }

    /// [MIGRATION chiffrement — build par défaut] `--encrypt` sans la feature `encryption` renvoie une
    /// ERREUR CLAIRE (jamais un faux succès en clair). Ce test n'existe QUE dans le build par défaut.
    #[cfg(not(feature = "encryption"))]
    #[test]
    fn migrate_encrypt_without_feature_errors_clearly() {
        let src_dir = tmp_dir("forge-mig-noenc");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let opts = MigrateOpts {
            from: src_dir.clone(), to: tmp_path("forge-mig-noenc-to.db"), ledger: None,
            verify: false, encrypt: true, key_env: Some("FORGE_TEST_KEY".to_string()), actor: "test".to_string(),
        };
        let err = run_migration(&opts).expect_err("encrypt sans feature -> erreur");
        assert!(err.contains("NON compilé") || err.contains("features encryption"),
            "message doit dire que le chiffrement n'est pas compilé: {err}");
        let _ = std::fs::remove_dir_all(&src_dir);
    }

    /// [MIGRATION chiffrement — build chiffré] plaintext -> SQLCipher -> relecture avec la clé. GARDÉ
    /// derrière `#[cfg(feature="encryption")]` : SKIP (non compilé) dans la suite par défaut, pour ne
    /// PAS faire dépendre celle-ci de SQLCipher/openssl. Exécuté seulement via `--features encryption`.
    #[cfg(feature = "encryption")]
    #[test]
    fn migrate_encrypted_roundtrip_reads_back_with_key() {
        let src_dir = tmp_dir("forge-mig-enc");
        let src_db = format!("{src_dir}/forge-console.db");
        seed_old_source_db(&src_db);
        let to = tmp_path("forge-mig-enc-to.db");
        std::env::set_var("FORGE_TEST_ENC_KEY", "correct horse battery staple");
        let opts = MigrateOpts {
            from: src_dir.clone(), to: to.clone(), ledger: Some(tmp_path("forge-mig-enc-to.jsonl")),
            verify: false, encrypt: true, key_env: Some("FORGE_TEST_ENC_KEY".to_string()), actor: "test".to_string(),
        };
        let report = run_migration(&opts).expect("migration chiffrée doit réussir");
        assert_eq!(report["encrypted"], true);

        // relecture AVEC la bonne clé -> lisible ; la donnée source a survécu.
        let dst = Connection::open(&to).unwrap();
        dst.pragma_update(None, "key", "correct horse battery staple").unwrap();
        let title: String = dst.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding");

        // relecture SANS clé -> illisible (preuve que la base est bien chiffrée au repos).
        let bad = Connection::open(&to).unwrap();
        assert!(bad.query_row("SELECT count(*) FROM finding", [], |r| r.get::<_, i64>(0)).is_err(),
            "sans PRAGMA key, une base chiffrée est illisible");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&to);
    }

    // ---------------------------------------------------------------------------------------
    // SAUVEGARDE / RESTAURATION CHIFFRÉE (backup / restore)
    // ---------------------------------------------------------------------------------------

    /// Sème une source d'engagement complète : base (schéma ancien, 1 finding), ledger chaîné à
    /// `entries` entrées, et une clé de signature `.ed25519`. Renvoie (db, ledger, key).
    fn seed_backup_source(dir: &str, entries: usize) -> (String, String, String) {
        let db = format!("{dir}/forge-console.db");
        seed_old_source_db(&db);
        let ledger = format!("{dir}/engagement.jsonl");
        for i in 0..entries {
            ledger_append_standalone(&ledger, "engagement.step", &json!({"i": i, "msg": "événement"})).unwrap();
        }
        let key = format!("{ledger}.ed25519");
        std::fs::write(&key, b"raw-ed25519-signing-key-32-bytes").unwrap();
        (db, ledger, key)
    }

    /// [BACKUP crypto] round-trip byte-for-byte : la base (snapshot), le ledger et la clé sortent de
    /// l'archive IDENTIQUES à ce qui y est entré. Le restore place la DB et la clé VERBATIM, et
    /// reproduit le ledger d'origine à l'octet près (puis y ajoute une entrée `console.restore` de
    /// traçabilité). La donnée SQLite survit (contenu relisible).
    #[test]
    fn backup_restore_roundtrips_db_ledger_key_byte_for_byte() {
        let src_dir = tmp_dir("forge-bk-rt-src");
        let (src_db, src_ledger, src_key) = seed_backup_source(&src_dir, 2);
        // capture l'état AVANT le backup (le backup appendra `console.backup` à la SOURCE après coup).
        let orig_ledger = std::fs::read(&src_ledger).unwrap();
        let orig_key = std::fs::read(&src_key).unwrap();

        let out = tmp_path("forge-bk-rt.age");
        let pass = "correct horse battery staple";
        let bopts = BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db.clone(),
            ledger: Some(src_ledger.clone()), ts: Some("@1234".to_string()), actor: "test".to_string(),
        };
        let brep = run_backup(&bopts).expect("backup doit réussir");
        assert_eq!(brep["encrypted"], true, "l'archive est TOUJOURS chiffrée");
        assert_eq!(brep["included_ledger"], true);
        assert_eq!(brep["included_key"], true);
        assert!(std::path::Path::new(&out).exists(), "archive écrite");

        // l'archive ne commence PAS par les octets d'un tar en clair (magic FORGE + chiffré).
        let raw = std::fs::read(&out).unwrap();
        assert_eq!(&raw[0..8], BACKUP_MAGIC, "en-tête FORGEBK1");
        // fidélité au niveau ARCHIVE : déchiffre + extrait -> db/ledger/clé égaux aux sources (octet-près).
        let pt = backup_decrypt(&raw, pass).expect("déchiffrement ok");
        let entries = backup_extract_tar(&pt).unwrap();
        let ar_get = |n: &str| entries.iter().find(|(x, _)| x == n).map(|(_, b)| b.clone()).unwrap();
        let ar_db = ar_get(BACKUP_ENTRY_DB);
        let ar_ledger = ar_get(BACKUP_ENTRY_LEDGER);
        let ar_key = ar_get(BACKUP_ENTRY_KEY);
        assert_eq!(ar_ledger, orig_ledger, "ledger archivé == ledger source (byte-for-byte)");
        assert_eq!(ar_key, orig_key, "clé archivée == clé source (byte-for-byte)");
        // manifest présent, sha256 par fichier cohérents.
        let manifest: Value = serde_json::from_slice(&ar_get(BACKUP_ENTRY_MANIFEST)).unwrap();
        assert_eq!(manifest["schema"], BACKUP_SCHEMA_VERSION);
        assert_eq!(manifest["created_at"], "@1234", "timestamp passé-en-argument conservé");
        assert_eq!(manifest["files"]["db.sqlite"]["sha256"], sha256_hex_bytes(&ar_db));

        // restore dans un dossier NEUF (aucun écrasement).
        let to_dir = tmp_dir("forge-bk-rt-to");
        let to_db = format!("{to_dir}/forge-console.db");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        let ropts = RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: false, actor: "test".to_string(),
        };
        let rrep = run_restore(&ropts).expect("restore doit réussir");
        assert_eq!(rrep["restored_key"], true);

        // DB placée VERBATIM == db archivée (byte-for-byte) + contenu SQLite relisible.
        assert_eq!(std::fs::read(&to_db).unwrap(), ar_db, "DB restaurée == snapshot archivé (byte-for-byte)");
        let dst = Connection::open(&to_db).unwrap();
        let title: String = dst.query_row("SELECT title FROM finding WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(title, "old-finding", "la donnée SQLite survit au round-trip");
        drop(dst);

        // clé restaurée == clé source (byte-for-byte). La clé voyage AVEC le ledger.
        let to_key = format!("{to_ledger}.ed25519");
        assert!(std::path::Path::new(&to_key).exists(), "clé .ed25519 restaurée à côté du ledger");
        assert_eq!(std::fs::read(&to_key).unwrap(), orig_key, "clé restaurée == source (byte-for-byte)");

        // ledger : les 2 entrées d'origine sont reproduites À L'OCTET PRÈS en préfixe ; une entrée
        // `console.restore` de traçabilité est ajoutée ; la chaîne reste intègre.
        let restored_ledger = std::fs::read(&to_ledger).unwrap();
        assert!(restored_ledger.starts_with(&orig_ledger), "préfixe ledger == source (byte-for-byte)");
        let lines = read_ledger_lines(&to_ledger);
        assert_eq!(lines.len(), 3, "2 entrées source + 1 console.restore");
        assert_eq!(lines[2]["kind"], "console.restore", "restore tracé au ledger (métadonnées)");
        let vfin = verify_ledger_chain(&to_ledger);
        assert!(vfin.ok, "chaîne du ledger restauré + trace reste vérifiable");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP crypto] une MAUVAISE passphrase échoue proprement (tag AEAD) et n'écrit RIEN sur disque.
    #[test]
    fn backup_wrong_passphrase_fails_and_writes_nothing() {
        let src_dir = tmp_dir("forge-bk-wp-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-wp.age");
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: "the-right-one".to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");

        // déchiffrement direct avec la mauvaise passphrase -> Err (jamais de plaintext).
        let raw = std::fs::read(&out).unwrap();
        assert!(backup_decrypt(&raw, "the-WRONG-one").is_err(), "mauvaise passphrase -> tag AEAD invalide");
        assert!(backup_decrypt(&raw, "the-right-one").is_ok(), "bonne passphrase -> ok (sanity)");

        // restore complet avec mauvaise passphrase : Err ET aucune écriture cible.
        let to_dir = tmp_dir("forge-bk-wp-to");
        let to_db = format!("{to_dir}/db.sqlite");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        let err = run_restore(&RestoreOpts {
            input: out.clone(), passphrase: "the-WRONG-one".to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: true, actor: "test".to_string(),
        }).expect_err("mauvaise passphrase -> restore échoue");
        assert!(err.contains("AEAD") || err.contains("passphrase"), "erreur claire: {err}");
        assert!(!std::path::Path::new(&to_db).exists(), "RIEN écrit (db) sur mauvaise passphrase");
        assert!(!std::path::Path::new(&to_ledger).exists(), "RIEN écrit (ledger) sur mauvaise passphrase");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP crypto] un octet retourné dans l'archive (corps OU en-tête lié en AAD) casse le tag
    /// Poly1305 -> déchiffrement refusé, restore échoue et n'écrit rien.
    #[test]
    fn backup_flipped_byte_fails_aead_tag() {
        let src_dir = tmp_dir("forge-bk-flip-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-flip.age");
        let pass = "passphrase-forte-123";
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");
        let raw = std::fs::read(&out).unwrap();
        let hdr = backup_parse_header(&raw).unwrap();

        // 1) octet retourné dans le CIPHERTEXT.
        let mut t1 = raw.clone();
        let idx = hdr.header_len + 4; // dans le corps chiffré
        t1[idx] ^= 0xFF;
        assert!(backup_decrypt(&t1, pass).is_err(), "corps altéré -> tag AEAD invalide");

        // 2) octet retourné dans le SEL (en-tête, lié en AAD) : la clé dérivée diffère ET l'AAD change
        //    -> le tag AEAD échoue. Le sel occupe les octets 22..38 (après magic|ver|m|t|p|salt_len).
        let mut t2 = raw.clone();
        t2[25] ^= 0xFF; // à l'intérieur de la zone sel
        assert!(backup_decrypt(&t2, pass).is_err(), "sel altéré -> clé/AAD différents -> tag AEAD invalide");

        // 2b) octet retourné dans les PARAMS argon2 (en-tête, malléable AVANT authentification) : rejet
        //     PROPRE (Err, jamais de panic/DoS) grâce à la validation des bornes de la KDF.
        let mut t2b = raw.clone();
        t2b[12] ^= 0xFF; // octet de poids fort de m_cost -> valeur absurde
        assert!(backup_decrypt(&t2b, pass).is_err(), "params argon2 corrompus -> Err propre (pas de panic)");

        // 3) restore sur archive altérée : Err + aucune écriture.
        let tampered = tmp_path("forge-bk-flip-tampered.age");
        std::fs::write(&tampered, &t1).unwrap();
        let to_dir = tmp_dir("forge-bk-flip-to");
        let to_db = format!("{to_dir}/db.sqlite");
        let err = run_restore(&RestoreOpts {
            input: tampered.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(format!("{to_dir}/engagement.jsonl")), force: true, actor: "test".to_string(),
        }).expect_err("archive altérée -> restore échoue");
        assert!(err.contains("AEAD") || err.contains("altérée"), "erreur claire: {err}");
        assert!(!std::path::Path::new(&to_db).exists(), "RIEN écrit sur archive altérée");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
        let _ = std::fs::remove_file(&tampered);
    }

    /// [BACKUP intégrité] le manifest re-vérifie le sha256 de chaque fichier : un sha falsifié (même
    /// dans un plaintext par ailleurs bien chiffré) fait ÉCHOUER le restore sans rien placer.
    #[test]
    fn restore_rejects_manifest_sha_mismatch() {
        let db = b"fausse-base-sqlite-pour-le-test".to_vec();
        // manifest annonçant un sha256 VOLONTAIREMENT faux pour db.sqlite.
        let bad_manifest = json!({
            "kind": "forge-console-backup", "schema": BACKUP_SCHEMA_VERSION,
            "files": {"db.sqlite": {"sha256": "0".repeat(64), "size": db.len()}}
        });
        let mb = serde_json::to_vec_pretty(&bad_manifest).unwrap();
        let tar = backup_build_tar(&[(BACKUP_ENTRY_MANIFEST, &mb), (BACKUP_ENTRY_DB, &db)]).unwrap();
        let sealed = backup_encrypt(&tar, "pw").unwrap(); // bien chiffré : l'AEAD passera.
        let arch = tmp_path("forge-bk-shamism.age");
        std::fs::write(&arch, &sealed).unwrap();

        let to_dir = tmp_dir("forge-bk-shamism-to");
        let to_db = format!("{to_dir}/db.sqlite");
        let err = run_restore(&RestoreOpts {
            input: arch.clone(), passphrase: "pw".to_string(), to: Some(to_db.clone()),
            ledger: Some(format!("{to_dir}/engagement.jsonl")), force: true, actor: "test".to_string(),
        }).expect_err("sha256 falsifié -> restore refusé");
        assert!(err.contains("sha256 mismatch"), "erreur d'intégrité manifest: {err}");
        assert!(!std::path::Path::new(&to_db).exists(), "aucun placement quand le manifest est incohérent");

        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&arch);
    }

    /// [BACKUP garde] le restore REFUSE d'écraser un install existant NON VIDE sans `--force`, puis
    /// l'écrase quand `--force` est fourni.
    #[test]
    fn restore_without_force_refuses_to_clobber() {
        let src_dir = tmp_dir("forge-bk-clob-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 2);
        let out = tmp_path("forge-bk-clob.age");
        let pass = "pw-clobber";
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");

        // install cible PRÉ-EXISTANT et NON VIDE.
        let to_dir = tmp_dir("forge-bk-clob-to");
        let to_db = format!("{to_dir}/forge-console.db");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        let sentinel = b"NE-PAS-ECRASER-existant".to_vec();
        std::fs::write(&to_db, &sentinel).unwrap();

        // sans --force -> REFUS, et la donnée existante est INTACTE.
        let err = run_restore(&RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: false, actor: "test".to_string(),
        }).expect_err("clobber refusé sans --force");
        assert!(err.contains("force") || err.contains("REFUSÉ"), "message anti-clobber: {err}");
        assert_eq!(std::fs::read(&to_db).unwrap(), sentinel, "install existant NON écrasé");

        // avec --force -> écrase.
        run_restore(&RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db.clone()),
            ledger: Some(to_ledger.clone()), force: true, actor: "test".to_string(),
        }).expect("--force autorise l'écrasement");
        assert_ne!(std::fs::read(&to_db).unwrap(), sentinel, "install écrasé avec --force");
        let dst = Connection::open(&to_db).unwrap();
        let n: i64 = dst.query_row("SELECT count(*) FROM finding", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "la base restaurée contient le finding source");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP perms] la clé `.ed25519` restaurée est en 0600 — MÊME si la clé source est plus
    /// permissive (0644). La clé de signature reste un secret non-lisible par autrui.
    #[cfg(unix)]
    #[test]
    fn restored_ed25519_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let src_dir = tmp_dir("forge-bk-perm-src");
        let (src_db, src_ledger, src_key) = seed_backup_source(&src_dir, 2);
        // clé source DÉLIBÉRÉMENT 0644 -> prouve que le restore FORCE 0600.
        std::fs::set_permissions(&src_key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let out = tmp_path("forge-bk-perm.age");
        let pass = "pw-perm";
        run_backup(&BackupOpts {
            out: out.clone(), passphrase: pass.to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect("backup ok");

        let to_dir = tmp_dir("forge-bk-perm-to");
        let to_db = format!("{to_dir}/forge-console.db");
        let to_ledger = format!("{to_dir}/engagement.jsonl");
        run_restore(&RestoreOpts {
            input: out.clone(), passphrase: pass.to_string(), to: Some(to_db),
            ledger: Some(to_ledger.clone()), force: false, actor: "test".to_string(),
        }).expect("restore ok");
        let to_key = format!("{to_ledger}.ed25519");
        let mode = std::fs::metadata(&to_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "clé de signature restaurée en 0600");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&to_dir);
        let _ = std::fs::remove_file(&out);
    }

    /// [BACKUP intégrité] un ledger source à la chaîne ROMPUE fait AVORTER le backup AVANT toute
    /// écriture d'archive.
    #[test]
    fn backup_aborts_on_tampered_ledger_chain() {
        let src_dir = tmp_dir("forge-bk-tamper-src");
        let (src_db, src_ledger, _key) = seed_backup_source(&src_dir, 4);
        // altère le CONTENU d'une entrée sans recalculer son hash -> "hash recalculé != stocké".
        let tampered = std::fs::read_to_string(&src_ledger).unwrap().replacen("événement", "ALTÉRÉ", 1);
        std::fs::write(&src_ledger, tampered).unwrap();
        assert!(!verify_ledger_chain(&src_ledger).ok, "pré-condition : ledger détecté rompu");

        let out = tmp_path("forge-bk-tamper.age");
        let err = run_backup(&BackupOpts {
            out: out.clone(), passphrase: "pw".to_string(), db: src_db,
            ledger: Some(src_ledger), ts: None, actor: "test".to_string(),
        }).expect_err("ledger rompu -> backup AVORTÉ");
        assert!(err.contains("AVORTÉ"), "message d'abort explicite: {err}");
        assert!(!std::path::Path::new(&out).exists(), "AUCUNE archive écrite sur abort");

        let _ = std::fs::remove_dir_all(&src_dir);
    }

    /// [BACKUP crypto] la KDF argon2id est déterministe (mêmes passphrase+sel+params -> même clé) mais
    /// sensible à la passphrase, et deux archives du MÊME plaintext diffèrent (sel+nonce aléatoires).
    #[test]
    fn backup_kdf_deterministic_and_archives_use_fresh_salt_nonce() {
        let salt = [7u8; BACKUP_SALT_LEN];
        let dp = Params::default();
        let k1 = backup_derive_key("pw", &salt, dp.m_cost(), dp.t_cost(), dp.p_cost()).unwrap();
        let k2 = backup_derive_key("pw", &salt, dp.m_cost(), dp.t_cost(), dp.p_cost()).unwrap();
        let k3 = backup_derive_key("other", &salt, dp.m_cost(), dp.t_cost(), dp.p_cost()).unwrap();
        assert_eq!(k1, k2, "KDF déterministe (re-dérivable au restore)");
        assert_ne!(k1, k3, "passphrase différente -> clé différente");
        assert_ne!(k1, [0u8; BACKUP_KEY_LEN], "clé non tous-zeros");

        let pt = b"payload identique".to_vec();
        let a = backup_encrypt(&pt, "pw").unwrap();
        let b = backup_encrypt(&pt, "pw").unwrap();
        assert_ne!(a, b, "sel+nonce aléatoires -> chiffrés distincts pour un même plaintext");
        assert_eq!(backup_decrypt(&a, "pw").unwrap(), pt, "round-trip AEAD (a)");
        assert_eq!(backup_decrypt(&b, "pw").unwrap(), pt, "round-trip AEAD (b)");
        assert!(backup_encrypt(&pt, "").is_err(), "passphrase vide REFUSÉE (fail-closed)");
        assert!(backup_decrypt(&a, "").is_err(), "passphrase vide REFUSÉE au déchiffrement");
    }

    // ---------------------------------------------------------------------------------------------
    // API SAUVEGARDE / RESTAURATION / POLITIQUE (admin-gated) + runner programmé
    // ---------------------------------------------------------------------------------------------

    /// Consomme une Response axum et parse son corps JSON (helper de test).
    async fn resp_json(r: Response) -> Value {
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&b).unwrap_or(Value::Null)
    }

    /// App de test dont `db_path`/`ledger_path` pointent sur des fichiers RÉELS (le moteur backup ouvre
    /// la base sur disque en read-only + VACUUM INTO). Sème un admin, une base au SCHEMA courant, un
    /// ledger chaîné (1 entrée) et une clé .ed25519. Renvoie (app, db_path, ledger_path, admin_token).
    fn test_app_disk(dir: &str) -> (App, String, String, String) {
        let db_path = format!("{dir}/forge-console.db");
        let ledger = format!("{dir}/engagement.jsonl");
        let conn = Connection::open(&db_path).expect("open disk db");
        conn.execute_batch(SCHEMA).expect("schema");
        migrate(&conn);
        upsert_user(&conn, "adm", "admin", &hash_pw("pw")).unwrap();
        upsert_user(&conn, "viw", "viewer", &hash_pw("pw")).unwrap();
        upsert_user(&conn, "opr", "operator", &hash_pw("pw")).unwrap();
        ledger_append_standalone(&ledger, "engagement.start", &json!({"a": 1})).unwrap();
        std::fs::write(format!("{ledger}.ed25519"), b"raw-ed25519-signing-key-32-bytes!").unwrap();
        let (events, _) = broadcast::channel::<RunEvent>(64);
        let app = App {
            db: Arc::new(Mutex::new(conn)),
            db_path: Arc::new(db_path.clone()),
            token_sha: Arc::new(sha_hex("t")),
            token_raw: Arc::new("t".into()),
            user: Arc::new("forge".into()),
            pass_hash: Arc::new(String::new()),
            auth_required: Arc::new(AtomicBool::new(true)),
            operator_hash: Arc::new(String::new()),
            allowed_hosts: Arc::new(vec!["localhost".into()]),
            ledger_path: Arc::new(ledger.clone()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(RunState { current: HashMap::new() })),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        };
        let (atok, _) = create_session(&app, uid_of(&app, "adm"));
        (app, db_path, ledger, atok)
    }

    /// [BACKUP API gate] /api/backup, /api/restore, /api/backup/policy sont ADMIN-ONLY : viewer,
    /// operator et l'anonyme reçoivent 403 ; l'admin passe. Vérifie les handlers HTTP réels (check_admin).
    #[tokio::test]
    async fn backup_restore_policy_routes_are_admin_only_403() {
        let dir = tmp_dir("forge-bkapi-403");
        let (app, _db, _led, atok) = test_app_disk(&dir);
        let (vtok, _) = create_session(&app, uid_of(&app, "viw"));
        let (otok, _) = create_session(&app, uid_of(&app, "opr"));
        let pbody = || Json(json!({"passphrase": "correct horse battery staple"}));

        // POST /api/backup : viewer/operator/anonyme -> 403.
        assert_eq!(api_backup(State(app.clone()), bearer_headers(&vtok), pbody()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup(State(app.clone()), bearer_headers(&otok), pbody()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup(State(app.clone()), HeaderMap::new(), pbody()).await.status(), StatusCode::FORBIDDEN);
        // admin -> 200 (téléchargement de l'archive chiffrée).
        assert_eq!(api_backup(State(app.clone()), bearer_headers(&atok), pbody()).await.status(), StatusCode::OK);

        // POST /api/restore : viewer/operator -> 403.
        let rbody = || Json(json!({"archive_b64": "AA==", "passphrase": "x"}));
        assert_eq!(api_restore(State(app.clone()), bearer_headers(&vtok), rbody()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_restore(State(app.clone()), bearer_headers(&otok), rbody()).await.status(), StatusCode::FORBIDDEN);

        // GET/POST /api/backup/policy : viewer/operator -> 403 ; admin -> 200.
        assert_eq!(api_backup_policy_get(State(app.clone()), bearer_headers(&vtok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup_policy_get(State(app.clone()), bearer_headers(&otok)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_backup_policy_get(State(app.clone()), bearer_headers(&atok)).await.status(), StatusCode::OK);
        assert_eq!(
            api_backup_policy_set(State(app.clone()), bearer_headers(&vtok), Json(json!({"enabled": false}))).await.status(),
            StatusCode::FORBIDDEN
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [BACKUP API] POST /api/backup : passphrase manquante -> 400 (fail-closed) ; avec passphrase ->
    /// 200 + corps = archive CHIFFRÉE (magic FORGEBK1, déchiffrable) ; l'entrée ledger `console.backup`
    /// est écrite MAIS la passphrase n'apparaît JAMAIS dans le fichier ledger.
    #[tokio::test]
    async fn api_backup_downloads_encrypted_archive_and_never_ledgers_passphrase() {
        let dir = tmp_dir("forge-bkapi-dl");
        let (app, _db, ledger, atok) = test_app_disk(&dir);
        let secret_pass = "s3cr3t-passphrase-do-not-log-42";

        // passphrase absente -> 400.
        let r = api_backup(State(app.clone()), bearer_headers(&atok), Json(json!({}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "passphrase absente -> 400 fail-closed");

        // avec passphrase -> 200 + archive chiffrée téléchargeable.
        let r = api_backup(State(app.clone()), bearer_headers(&atok), Json(json!({"passphrase": secret_pass}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let disp = r.headers().get("content-disposition").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(disp.contains("attachment") && disp.contains("forge-backup-"), "Content-Disposition de téléchargement: {disp}");
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[0..8], BACKUP_MAGIC, "corps = archive chiffrée (magic FORGEBK1)");
        assert!(backup_decrypt(&body, secret_pass).is_ok(), "archive déchiffrable avec la bonne passphrase");
        assert!(backup_decrypt(&body, "mauvaise").is_err(), "mauvaise passphrase -> tag AEAD invalide");

        // le ledger contient `console.backup` MAIS jamais la passphrase.
        let ledger_txt = std::fs::read_to_string(&ledger).unwrap();
        assert!(ledger_txt.contains("console.backup"), "l'action backup est ledgerisée");
        assert!(!ledger_txt.contains(secret_pass), "la passphrase n'apparaît JAMAIS dans le ledger");
        assert!(verify_ledger_chain(&ledger).ok, "chaîne du ledger intacte après backup via API");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [RESTORE API] chemins de sûreté : (a) validation par défaut (apply absent) NE réécrit RIEN et
    /// répond applied:false ; (b) apply=true SANS confirm -> 400 (confirmation requise), rien écrit ;
    /// (c) mauvaise passphrase -> 422 propre + ledger `console.restore.validate` ok:false SANS la
    /// passphrase ; (d) apply=true+confirm=true -> swap effectué, restart_required:true.
    #[tokio::test]
    async fn api_restore_validate_default_confirm_required_and_apply() {
        let src_dir = tmp_dir("forge-rsapi-src");
        let (app, db_path, ledger, atok) = test_app_disk(&src_dir);
        let secret_pass = "restore-pass-never-logged-99";

        // fabrique une VRAIE archive chiffrée à partir de la source disque.
        let arch = tmp_path("forge-rsapi.forge");
        run_backup(&BackupOpts {
            out: arch.clone(), passphrase: secret_pass.to_string(), db: db_path.clone(),
            ledger: Some(ledger.clone()), ts: Some("@1000".into()), actor: "test".into(),
        }).expect("backup source");
        let archive_b64 = base64::engine::general_purpose::STANDARD.encode(std::fs::read(&arch).unwrap());

        // (a) validation par défaut : 200 applied:false, aucune écriture destructive.
        let db_before = std::fs::read(&db_path).unwrap();
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": secret_pass}))).await;
        assert_eq!(r.status(), StatusCode::OK, "validation par défaut -> 200");
        let j = resp_json(r).await;
        assert_eq!(j["applied"], false, "validation par défaut n'applique RIEN");
        assert_eq!(j["validated"]["ok"], true, "archive validée");
        assert_eq!(std::fs::read(&db_path).unwrap(), db_before, "base LIVE inchangée par la validation");

        // (b) apply sans confirm -> 400.
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": secret_pass, "apply": true}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "apply sans confirm -> 400");
        assert_eq!(std::fs::read(&db_path).unwrap(), db_before, "base LIVE inchangée sans confirm");

        // (c) mauvaise passphrase -> 422 + trace validate ok:false, jamais la passphrase.
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": "WRONG"}))).await;
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY, "mauvaise passphrase -> 422");
        let ledger_txt = std::fs::read_to_string(&ledger).unwrap();
        assert!(ledger_txt.contains("console.restore.validate"), "tentative de restore ledgerisée");
        assert!(!ledger_txt.contains(secret_pass), "la passphrase n'apparaît JAMAIS dans le ledger");
        assert!(!ledger_txt.contains("WRONG"), "la passphrase (même erronée) n'est jamais ledgerisée");

        // (d) apply=true+confirm=true -> swap effectué, redémarrage requis annoncé.
        let r = api_restore(State(app.clone()), bearer_headers(&atok),
            Json(json!({"archive_b64": archive_b64, "passphrase": secret_pass, "apply": true, "confirm": true}))).await;
        assert_eq!(r.status(), StatusCode::OK, "apply+confirm -> 200");
        let j = resp_json(r).await;
        assert_eq!(j["applied"], true, "swap appliqué");
        assert_eq!(j["restart_required"], true, "redémarrage requis annoncé (base live tenue par la connexion)");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_file(&arch);
    }

    /// [POLICY API] round-trip d'une politique (schedule/rétention/offsite) + RÉDACTION : un GET ne
    /// renvoie JAMAIS un secret (champ secretish rédigé), mais conserve `passphrase_env` (un NOM d'ENV).
    #[tokio::test]
    async fn backup_policy_round_trips_and_get_redacts_secrets() {
        let dir = tmp_dir("forge-pol-rt");
        let (app, _db, _led, atok) = test_app_disk(&dir);

        // POST : politique complète, avec un secret inline dans offsite exec (doit être rédigé au GET).
        let policy = json!({
            "enabled": true,
            "interval_secs": 3600,
            "retention": 7,
            "passphrase_env": "FORGE_BACKUP_PASSPHRASE",
            "staging_dir": format!("{dir}/staging"),
            "offsite": {"kind": "exec", "program": "/usr/bin/rclone",
                        "args": ["copy", "{archive}", "remote:forge/"], "token": "SUPER-SECRET-TOKEN"}
        });
        let r = api_backup_policy_set(State(app.clone()), bearer_headers(&atok), Json(policy)).await;
        assert_eq!(r.status(), StatusCode::OK, "politique valide enregistrée");

        // GET : round-trip des champs non-secrets + rédaction du secret.
        let r = api_backup_policy_get(State(app.clone()), bearer_headers(&atok)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let j = resp_json(r).await;
        let p = &j["policy"];
        assert_eq!(p["enabled"], true);
        assert_eq!(p["interval_secs"], 3600);
        assert_eq!(p["retention"], 7);
        assert_eq!(p["passphrase_env"], "FORGE_BACKUP_PASSPHRASE", "le NOM d'ENV n'est PAS un secret -> conservé");
        assert_eq!(p["offsite"]["kind"], "exec");
        assert_eq!(p["offsite"]["program"], "/usr/bin/rclone");
        assert_eq!(p["offsite"]["token"], "***REDACTED***", "tout champ secretish est RÉDIGÉ au GET");
        assert_eq!(j["configured"], true);

        // la valeur PERSISTÉE ne contient jamais de `passphrase` en clair (seul passphrase_env).
        let stored = { let db = app.db(); settings_get(&db, "backup_policy").unwrap() };
        assert!(!stored.contains("\"passphrase\""), "aucun `passphrase` en clair persisté");
        assert!(stored.contains("FORGE_BACKUP_PASSPHRASE"), "passphrase_env persisté");

        // politique invalide : enabled sans interval -> 400, rien n'est écrasé.
        let r = api_backup_policy_set(State(app.clone()), bearer_headers(&atok),
            Json(json!({"enabled": true, "passphrase_env": "X"}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "enabled sans interval -> 400");
        // offsite kind inconnu -> 400.
        let r = api_backup_policy_set(State(app.clone()), bearer_headers(&atok),
            Json(json!({"enabled": false, "offsite": {"kind": "ftp"}}))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "offsite kind hors none/local_dir/exec -> 400");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [POLICY] validate_backup_policy : fail-closed (interval/passphrase_env requis si enabled ;
    /// exec program absolu). redact_backup_policy : rédige un secret, conserve `*_env`.
    #[test]
    fn backup_policy_validation_and_redaction_units() {
        // enabled sans interval -> Err.
        assert!(validate_backup_policy(&json!({"enabled": true, "passphrase_env": "P"})).is_err());
        // enabled sans passphrase_env -> Err.
        assert!(validate_backup_policy(&json!({"enabled": true, "interval_secs": 60})).is_err());
        // exec program relatif -> Err (pas de résolution PATH).
        assert!(validate_backup_policy(&json!({"enabled": false, "offsite": {"kind": "exec", "program": "rclone"}})).is_err());
        // valide : disabled + offsite none.
        assert!(validate_backup_policy(&json!({"enabled": false, "offsite": {"kind": "none"}})).is_ok());
        // le `passphrase` en clair est RETIRÉ à la persistance.
        let clean = validate_backup_policy(&json!({"enabled": false, "passphrase": "LEAK"})).unwrap();
        assert!(clean.get("passphrase").is_none(), "passphrase en clair jamais persistée");
        // rédaction.
        let red = redact_backup_policy(&json!({"passphrase_env": "P", "secret": "S", "offsite": {"token": "T", "kind": "exec"}}));
        assert_eq!(red["passphrase_env"], "P", "NOM d'ENV conservé");
        assert_eq!(red["secret"], "***REDACTED***");
        assert_eq!(red["offsite"]["token"], "***REDACTED***", "rédaction récursive");
        assert_eq!(red["offsite"]["kind"], "exec", "champ non-secret conservé");
    }

    /// [SCHEDULER] run_scheduled_backup : avec une politique activée + une passphrase via ENV + un offsite
    /// local_dir, crée une archive CHIFFRÉE dans le staging, la copie offsite, ledgerise (scheduled +
    /// offsite) et NE FUITE JAMAIS la passphrase. Passphrase ENV absente -> Err (fail-closed, pas de
    /// crash). Politique désactivée -> skip.
    #[test]
    fn scheduled_backup_encrypts_ships_local_dir_and_never_leaks_passphrase() {
        let _g = env_lock(); // ENV process-global
        let dir = tmp_dir("forge-sched");
        let (app, _db, ledger, _atok) = test_app_disk(&dir);
        let staging = format!("{dir}/staging");
        let offsite_dir = format!("{dir}/offsite");
        let pass_env = "FORGE_TEST_SCHED_PASS";
        let secret_pass = "scheduled-pass-shh-77";

        {
            let db = app.db();
            settings_set(&db, "backup_policy", &json!({
                "enabled": true, "interval_secs": 1, "retention": 2,
                "passphrase_env": pass_env, "staging_dir": staging,
                "offsite": {"kind": "local_dir", "dir": offsite_dir}
            }).to_string()).unwrap();
        }

        // (a) passphrase ENV absente -> Err (fail-closed), aucune archive, pas de crash.
        std::env::remove_var(pass_env);
        assert!(run_scheduled_backup(&app).is_err(), "passphrase ENV absente -> fail-closed");

        // (b) passphrase ENV posée -> backup + offsite.
        std::env::set_var(pass_env, secret_pass);
        let rep = run_scheduled_backup(&app).expect("backup programmé réussit");
        std::env::remove_var(pass_env);
        assert_eq!(rep["ok"], true);

        // une archive chiffrée dans le staging (magic + déchiffrable).
        let staged: Vec<_> = std::fs::read_dir(&staging).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".forge")).collect();
        assert_eq!(staged.len(), 1, "une archive dans le staging");
        let raw = std::fs::read(staged[0].path()).unwrap();
        assert_eq!(&raw[0..8], BACKUP_MAGIC, "archive chiffrée");
        assert!(backup_decrypt(&raw, secret_pass).is_ok(), "déchiffrable avec la passphrase ENV");

        // l'archive a été copiée offsite (local_dir).
        let shipped: Vec<_> = std::fs::read_dir(&offsite_dir).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".forge")).collect();
        assert_eq!(shipped.len(), 1, "archive expédiée dans l'offsite local_dir");

        // ledger : entrées scheduled + offsite, jamais la passphrase.
        let ltxt = std::fs::read_to_string(&ledger).unwrap();
        assert!(ltxt.contains("console.backup.scheduled"), "backup programmé ledgerisé");
        assert!(ltxt.contains("console.backup.offsite"), "expédition offsite ledgerisée");
        assert!(!ltxt.contains(secret_pass), "la passphrase n'apparaît JAMAIS dans le ledger");
        assert!(verify_ledger_chain(&ledger).ok, "chaîne du ledger intacte");

        // (c) politique désactivée -> skip (aucune erreur).
        { let db = app.db(); settings_set(&db, "backup_policy", &json!({"enabled": false}).to_string()).unwrap(); }
        let rep = run_scheduled_backup(&app).expect("désactivée -> Ok");
        assert_eq!(rep["skipped"], true, "politique désactivée -> skip");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [SCHEDULER] scheduled_backup_due : dû si activé + interval écoulé depuis backup_last_run ;
    /// jamais dû si désactivé ou interval=0. Rétention : conserve les N plus récentes.
    #[test]
    fn scheduled_due_gate_and_retention() {
        let dir = tmp_dir("forge-sched-due");
        let (app, _db, _led, _atok) = test_app_disk(&dir);
        {
            let db = app.db();
            assert!(!scheduled_backup_due(&db), "aucune politique -> pas dû");
            settings_set(&db, "backup_policy", &json!({"enabled": true, "interval_secs": 3600, "passphrase_env": "P"}).to_string()).unwrap();
            settings_set(&db, "backup_last_run", &chrono_now_compact()).unwrap();
            assert!(!scheduled_backup_due(&db), "dernière exécution à l'instant -> pas encore dû");
            settings_set(&db, "backup_last_run", "0").unwrap();
            assert!(scheduled_backup_due(&db), "last_run très ancien -> dû");
            settings_set(&db, "backup_policy", &json!({"enabled": false}).to_string()).unwrap();
            assert!(!scheduled_backup_due(&db), "désactivé -> jamais dû");
        }
        // rétention : 4 archives, keep=2 -> 2 restent.
        let ret = format!("{dir}/ret");
        std::fs::create_dir_all(&ret).unwrap();
        for i in 0..4 {
            std::fs::write(format!("{ret}/forge-backup-{i}.forge"), format!("a{i}")).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(15)); // mtimes distinctes
        }
        apply_backup_retention(&ret, 2);
        let left = std::fs::read_dir(&ret).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".forge")).count();
        assert_eq!(left, 2, "rétention conserve exactement les 2 plus récentes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [OFFSITE exec] ship_offsite exec : argv fixe (aucun shell), token `{archive}` substitué ; un
    /// programme qui sort en échec -> Err ; un timeout tue le process (Err). Le succès renvoie shipped:true.
    #[test]
    fn offsite_exec_no_shell_success_failure_and_timeout() {
        let dir = tmp_dir("forge-offx");
        let arch = format!("{dir}/a.forge");
        std::fs::write(&arch, b"payload").unwrap();
        // succès : /bin/cp {archive} -> {dir}/copied.forge (argv fixe, aucun shell).
        let dst = format!("{dir}/copied.forge");
        let r = ship_offsite(&json!({"kind": "exec", "program": "/bin/cp", "args": ["{archive}", dst]}), &arch);
        assert!(r.is_ok(), "cp argv fixe -> succès: {r:?}");
        assert!(std::path::Path::new(&dst).exists(), "token archive substitué -> fichier copié");
        // échec : /bin/false -> code != 0 -> Err.
        assert!(ship_offsite(&json!({"kind": "exec", "program": "/bin/false", "args": []}), &arch).is_err(),
            "exit code != 0 -> Err");
        // timeout : /bin/sleep 5 avec timeout_secs=1 -> Err (process tué).
        let r = ship_offsite(&json!({"kind": "exec", "program": "/bin/sleep", "args": ["5"], "timeout_secs": 1}), &arch);
        assert!(r.is_err() && r.unwrap_err().contains("timeout"), "dépassement -> tué + Err");
        // none -> no-op.
        assert_eq!(ship_offsite(&json!({"kind": "none"}), &arch).unwrap()["shipped"], false);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        let db = app.db();
        let scope_json = json!({"mode": mode, "in_scope": scope_in, "out_scope": []}).to_string();
        db.execute(
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
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(SCHEMA).expect("schema"); // `finding` n'a PAS encore engagement_id
        // ligne « ancienne » insérée AVANT l'ajout de la colonne (simule une base antérieure).
        conn.execute(
            "INSERT INTO finding(id,title,target,campaign) VALUES(1,'old-finding','h.example','c1')",
            [],
        )
        .unwrap();
        migrate(&conn); // ALTER ... ADD COLUMN engagement_id NOT NULL DEFAULT 1 -> backfill à 1
        let eid: i64 = conn
            .query_row("SELECT engagement_id FROM finding WHERE id=1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(eid, 1, "ligne existante rétro-rattachée à l'engagement #1 (DEFAULT)");

        // table engagement vide -> ensure_default_engagement crée #1 depuis le scope/ledger COURANTS.
        let n0: i64 = conn.query_row("SELECT COUNT(*) FROM engagement", [], |r| r.get(0)).unwrap();
        assert_eq!(n0, 0, "aucun engagement avant l'amorçage");
        ensure_default_engagement(
            &conn,
            &["a.example.com".to_string(), "*.b.example.com".to_string()],
            "grey",
            "/tmp/eng1.jsonl",
        );
        let eng = load_engagement(&conn, 1).expect("engagement #1 créé");
        assert_eq!(eng.id, 1);
        assert_eq!(eng.mode, "grey");
        assert_eq!(eng.scope_in, vec!["a.example.com".to_string(), "*.b.example.com".to_string()],
            "scope de l'engagement #1 = scope serveur courant");
        assert_eq!(eng.ledger_path, "/tmp/eng1.jsonl", "ledger de l'engagement #1 = ledger courant");

        // idempotent : un 2e appel (scope/ledger DIFFÉRENTS) ne réécrit PAS l'engagement #1.
        ensure_default_engagement(&conn, &["changed.example".to_string()], "black", "/tmp/other.jsonl");
        let eng2 = load_engagement(&conn, 1).unwrap();
        assert_eq!(eng2.scope_in, vec!["a.example.com".to_string(), "*.b.example.com".to_string()],
            "idempotent : scope inchangé");
        assert_eq!(eng2.ledger_path, "/tmp/eng1.jsonl", "idempotent : ledger inchangé");
        let cnt: i64 = conn.query_row("SELECT COUNT(*) FROM engagement", [], |r| r.get(0)).unwrap();
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
        { let db = app.db(); let n: String = db.query_row("SELECT name FROM engagement WHERE id=2", [], |r| r.get(0)).unwrap();
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

    /// [TENANCY — migration zéro-perte] ensure_default_tenant sur une base au SCHEMA courant : crée le
    /// tenant #1, rattache TOUS les engagements existants au tenant #1, et sème un grant tenant #1 pour
    /// CHAQUE utilisateur existant (rôle dérivé du RBAC). Idempotent (ne réécrit pas si un tenant existe).
    #[test]
    fn ensure_default_tenant_seeds_and_backfills() {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(SCHEMA).expect("schema");
        migrate(&conn);
        // deux engagements + deux users AVANT toute provision tenant.
        conn.execute("INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path) VALUES(1,'e1','active','grey','{}','')", []).unwrap();
        conn.execute("INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path) VALUES(7,'e7','active','grey','{}','')", []).unwrap();
        conn.execute("INSERT INTO users(login,role,pass_hash,disabled,created) VALUES('root','admin','h',0,'')", []).unwrap();
        conn.execute("INSERT INTO users(login,role,pass_hash,disabled,created) VALUES('joe','viewer','h',0,'')", []).unwrap();

        ensure_default_tenant(&conn);
        // tenant #1 créé.
        let tcount: i64 = conn.query_row("SELECT COUNT(*) FROM tenant WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(tcount, 1, "tenant #1 (défaut) créé");
        // TOUS les engagements rattachés au tenant #1.
        let bad: i64 = conn.query_row("SELECT COUNT(*) FROM engagement WHERE tenant_id<>1", [], |r| r.get(0)).unwrap();
        assert_eq!(bad, 0, "tous les engagements existants -> tenant #1");
        // grants rétro-compat : chaque user existant accède au tenant #1, rôle dérivé du RBAC.
        let root_role: String = conn.query_row("SELECT g.role FROM tenant_grant g JOIN users u ON u.id=g.user_id WHERE u.login='root' AND g.tenant_id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(root_role, "tenant_admin", "admin -> tenant_admin");
        let joe_role: String = conn.query_row("SELECT g.role FROM tenant_grant g JOIN users u ON u.id=g.user_id WHERE u.login='joe' AND g.tenant_id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(joe_role, "tenant_viewer", "viewer -> tenant_viewer");

        // IDEMPOTENT : un 2e appel ne recrée rien ni n'écrase (renomme le tenant #1 -> doit rester).
        conn.execute("UPDATE tenant SET name='custom' WHERE id=1", []).unwrap();
        ensure_default_tenant(&conn);
        let n: String = conn.query_row("SELECT name FROM tenant WHERE id=1", [], |r| r.get(0)).unwrap();
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
        { let db = app.db(); let (role, dis): (String, i64) = db.query_row("SELECT role, disabled FROM users WHERE login='root'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
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
        { let db = app.db(); ensure_default_tenant(&db); }
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
        { let db = app.db(); ensure_default_tenant(&db); }
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
        { let db = app.db(); ensure_default_tenant(&db); }
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
        { let db = app.db(); assert!(db.query_row("SELECT 1 FROM engagement WHERE id=?", [new_id], |_| Ok(())).is_err(), "engagement supprimé de la base"); }

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
        { let db = app.db(); let st: String = db.query_row("SELECT status FROM engagement WHERE id=1", [], |r| r.get(0)).unwrap();
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
        let db = app.db();
        let job = db.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), ["run-1"], run_job_json).unwrap();
        let md = render_run_report_md(&db, "run-1", &job, None, None);
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
        drop(db);
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
        let db = app.db();
        let job = db.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), ["run-1"], run_job_json).unwrap();
        drop(db);
        let custody = build_ledger_custody(&app, "alice+high_impact");
        let db = app.db();
        let html = render_run_report_html(&db, "run-1", &job, None, &custody);
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
        drop(db);
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
            let db = app.db();
            let stored = settings_get(&db, "detection_source").expect("detection_source persisté");
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
            let db = app.db();
            let stored = settings_get(&db, "detection_source").expect("detection_source persisté");
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
        let db = app.db();
        let n: i64 = db.query_row("SELECT 1", [], |r| r.get(0)).expect("requête OK après poison");
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
            let db = app.db();
            // 1er probe : module recon dispo.
            upsert_probed_module(&db, "recon.httpx", false, false, true, "", "recon httpx");
            // l'admin DÉSACTIVE le connecteur + masque + retire du web (intention opérateur).
            db.execute("UPDATE module SET enabled=0, available_override=0, web_allowed=0 WHERE kind='recon.httpx'", []).unwrap();
            // re-probe (nouvelle version : gagne une capacité exploit, sonde toujours dispo, descr changée).
            upsert_probed_module(&db, "recon.httpx", true, false, true, "T1190", "recon httpx v2");
            let (enabled, ov, web, exploit, descr): (i64, Option<i64>, i64, i64, String) = db.query_row(
                "SELECT enabled, available_override, web_allowed, exploit, descr FROM module WHERE kind='recon.httpx'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap();
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
            let db = app.db();
            upsert_probed_module(&db, "recon.new", false, false, true, "", "neuf");
            let (enabled, ov): (i64, Option<i64>) = db.query_row(
                "SELECT enabled, available_override FROM module WHERE kind='recon.new'", [],
                |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
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
        { let db = app.db(); let sv: Value = serde_json::from_str(&settings_get(&db, "workflows").unwrap()).unwrap();
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
        { let db = app.db(); let n: i64 = db.query_row("SELECT COUNT(*) FROM finding", [], |r| r.get(0)).unwrap(); assert_eq!(n, 0, "un refus n'ingère rien"); }

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
        { let db = app.db(); let n: i64 = db.query_row("SELECT COUNT(*) FROM finding WHERE campaign='imp2'", [], |r| r.get(0)).unwrap(); assert_eq!(n, 0, "aucun finding hors scope inséré"); }

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

    // =============================================================================================
    // LEDGER VERIFY CLI — lecture seule, NON INTERACTIVE, RAPIDE (ne démarre PAS le serveur).
    // Régression : `forge-console ledger verify` retombait sur le boot serveur et PENDAIT.
    // =============================================================================================

    /// [ledger verify CLI] `run_ledger_cli(["verify","--ledger",path])` sur un ledger VALIDE renvoie 0,
    /// sur un ledger ALTÉRÉ renvoie 1, sur un ledger ABSENT renvoie 1, et une sous-commande absente/
    /// inconnue renvoie 2. Chaque appel se termine RAPIDEMENT (garde-fou anti-hang : < 10s, alors que
    /// le bug bootait le serveur ad vitam). Aucune I/O réseau, aucune base ouverte, aucun STDIN lu.
    #[test]
    fn ledger_verify_cli_fast_valid_tampered_absent() {
        use std::time::Instant;
        let dir = tmp_dir("forge-ledger-verify-cli");
        let path = format!("{dir}/engagement.jsonl");
        // ledger VALIDE : 2 entrées chaînées (même algo que le boot -> verify_ledger_chain OK).
        ledger_append_standalone(&path, "engagement.start", &json!({"marker": "ORIGINAL", "n": 1})).unwrap();
        ledger_append_standalone(&path, "console.detection.test", &json!({"reachable": false})).unwrap();

        // (1) VALIDE -> 0, et RAPIDE (pas de démarrage serveur : le test lui-même prouve l'absence de hang).
        let t0 = Instant::now();
        let code_ok = run_ledger_cli(&["verify".into(), "--ledger".into(), path.clone()]);
        let elapsed = t0.elapsed();
        assert_eq!(code_ok, 0, "ledger valide -> exit 0");
        assert!(elapsed < Duration::from_secs(10), "ledger verify doit être quasi-instantané (anti-hang), pris {elapsed:?}");

        // (1b) --json : sortie parsable, contrat historique (ok:true).
        let code_json = run_ledger_cli(&["verify".into(), "--ledger".into(), path.clone(), "--json".into()]);
        assert_eq!(code_json, 0, "verify --json ledger valide -> 0");

        // (2) ALTÉRÉ : on modifie le detail de la 1re entrée SANS recalculer son hash -> chaîne rompue.
        let tampered = std::fs::read_to_string(&path).unwrap().replace("ORIGINAL", "TAMPERED");
        std::fs::write(&path, tampered).unwrap();
        let code_bad = run_ledger_cli(&["verify".into(), "--ledger".into(), path.clone()]);
        assert_eq!(code_bad, 1, "ledger altéré -> exit 1 (rupture détectée)");

        // (3) ABSENT -> 1 (on ne peut pas vérifier un ledger manquant ; jamais un « OK » trompeur).
        let missing = format!("{dir}/does-not-exist.jsonl");
        assert_eq!(run_ledger_cli(&["verify".into(), "--ledger".into(), missing]), 1, "ledger absent -> exit 1");

        // (4) sous-commande absente/inconnue -> 2 (usage), JAMAIS de repli sur le démarrage serveur.
        assert_eq!(run_ledger_cli(&[]), 2, "aucune sous-commande -> exit 2 (usage)");
        assert_eq!(run_ledger_cli(&["frobnicate".into()]), 2, "sous-commande inconnue -> exit 2 (usage)");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

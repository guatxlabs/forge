// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — ÉTAT PARTAGÉ (`App`) + son substrat couplé, extrait de main.rs (PURE MOVE, stage
//! `state`). Regroupe la struct d'état `App` (+ son `impl` : `db()`/`recompute_auth_required()`/
//! `reload_detection_source()`/`detection_config()`/`invalidate_ledger_head()`/`provisioned()` …), les
//! structs de run vivant (`RunState`/`RunHandle`/`RunEvent`), le head du ledger console (`LedgerHead`),
//! l'objet `Engagement`, le `SCHEMA` SQLite + `migrate()` + les `ensure_default_*`/`populate_modules`,
//! la résolution des assets web/scope serveur (`resolve_web_dir`/`load_server_scope`), les accès
//! `settings_get`/`settings_set`/`now_epoch`, le sous-système DÉTECTION (source configurable + purple
//! coverage : `resolve_detection_source`/`collect_detections*`/`fetch_purple_coverage`/`purple_coverage`/
//! `detection_test`/`detection_source_get`/`detection_source_set`) et les helpers de run-report
//! (`run_report`/`engagement_ledger_for_run`/`append_run_ledger_path`/`chrono_now_compact`).
//!
//! Ré-exporté `pub(crate)` à la racine de crate (`pub(crate) use crate::state::*;`) pour que le
//! `build_router`/`main` de main.rs, TOUS les modules frères (`crate::App`/`crate::settings_get`/
//! `crate::now_epoch`/`crate::migrate`/`crate::resolve_web_dir` …) ET le bloc de tests inline
//! (`super::*`) résolvent ces items INCHANGÉS. PURE MOVE : corps/signatures identiques ; seule la
//! visibilité privée -> `pub(crate)` (App était à la racine, les frères voyaient ses champs privés ;
//! déplacée dans un sous-module frère, ses champs/méthodes doivent être `pub(crate)`) + le plumbing
//! `use` change. Tous les `#[cfg(...)]` préservés VERBATIM (build community par défaut byte-identique).
use crate::*;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, Mutex as AsyncMutex};

// Version produit — SOURCE DE VÉRITÉ UNIQUE : le fichier `VERSION` à la racine du repo, lu à la
// COMPILATION (`include_str!`). Le même fichier alimente le moteur Python (forge/__init__.py) et
// est vérifié en dérive par la CI (`make check-version`). `CARGO_MANIFEST_DIR` = `console/`, donc
// `../VERSION` = la racine. Un `\n` de fin est possible -> trim au point d'usage (forge_version()).
pub(crate) const FORGE_VERSION_RAW: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../VERSION"));

/// Version nettoyée (sans espaces/newline de fin), réutilisable partout (CLI `--version`,
/// JSON `/health`, pied de page de l'UI web). Reste `&'static` (sous-tranche de la const).
pub(crate) fn forge_version() -> &'static str {
    FORGE_VERSION_RAW.trim()
}

// SCHEMA de base (idempotent — execute_batch). Les ajouts de colonnes sur les tables existantes
// passent par `migrate()` (ALTER error-ignored) pour ne pas casser une base déjà peuplée.
pub(crate) const SCHEMA: &str = "
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

// SCHEMA POSTGRES (feature `store-postgres`) — MIROIR du `SCHEMA` SQLite ci-dessus AVEC les colonnes
// additives de `migrate()` déjà FUSIONNÉES en ligne (une base PG neuve n'a pas besoin du carve-out
// ALTER error-ignored : tout est créé d'un coup). Mapping des types :
//   INTEGER                              -> BIGINT
//   INTEGER PRIMARY KEY (auto-rowid)     -> BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY
//                                           (BY DEFAULT, pas ALWAYS : autorise l'INSERT d'un id/seq
//                                            EXPLICITE — requis pour ledger_entry.seq assignée par l'app
//                                            et pour les seeds id=1)
//   TEXT PRIMARY KEY / TEXT              -> inchangé (TEXT)
//   REAL                                 -> DOUBLE PRECISION
//   BLOB                                 -> BYTEA
//   booléens (INTEGER 0/1)               -> BIGINT (0/1) — PAS le type BOOL de PG (parité SQLite +
//                                           binding Param::Bool -> i64 0/1 du seam)
// Différences DDL SQLite-only DROPPÉES : `... ON CONFLICT IGNORE` sur les contraintes UNIQUE (clause de
// résolution SQLite inexistante en PG ; les INSERT qui en dépendaient ont été portés en `INSERT ...
// ON CONFLICT DO NOTHING` au Stage 1), et le fait que `INTEGER PRIMARY KEY` soit un alias de rowid.
// PÉRIMÈTRE : ce miroir couvre le SCHEMA de base state.rs (+ migrate). Les tables des modules ENTERPRISE
// créées paresseusement (scim_*, sso_*, idp_group_map…) restent gérées par leurs modules (flag-gated) —
// hors de ce const, comme elles sont hors du `SCHEMA` de base.
// `#[allow(dead_code)]` : depuis le durcissement FAIL-CLOSED (Stage 2b), le démarrage n'applique plus
// PG_SCHEMA (l'App reste sur SQLite). Ce const n'est plus référencé QUE par les tests d'intégration
// (`store.rs::pg_tests`, qui l'appliquent sur un vrai Postgres) — donc « unused » dans un build feature
// SANS tests. Il RESTE l'artefact de schéma faisant autorité pour le backend PG (câblé au Stage 2b).
#[cfg(feature = "store-postgres")]
#[allow(dead_code)]
pub(crate) const PG_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS campaign(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT, started TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS finding(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, title TEXT,
  severity TEXT, category TEXT, mitre TEXT, status TEXT, evidence TEXT, tool TEXT, poc TEXT,
  run_id TEXT DEFAULT '', fix TEXT DEFAULT '', cwe TEXT DEFAULT '', cvss_vector TEXT DEFAULT '',
  cvss_score DOUBLE PRECISION DEFAULT 0, engagement_id BIGINT NOT NULL DEFAULT 1,
  UNIQUE(campaign, target, title));
CREATE TABLE IF NOT EXISTS runrecord(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, kind TEXT,
  mitre TEXT, fired BIGINT, detail TEXT, run_id TEXT DEFAULT '', engagement_id BIGINT NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS panel(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT, query TEXT, viz TEXT DEFAULT 'table',
  position BIGINT DEFAULT 0, descr TEXT DEFAULT '', col_span BIGINT DEFAULT 1, updated TEXT DEFAULT '',
  dashboard_id BIGINT DEFAULT 1);
CREATE TABLE IF NOT EXISTS dashboard(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, descr TEXT DEFAULT '',
  position BIGINT DEFAULT 0, created TEXT DEFAULT '', updated TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS module(
  kind TEXT PRIMARY KEY, exploit BIGINT DEFAULT 0, destructive BIGINT DEFAULT 0,
  available BIGINT DEFAULT 1, mitre TEXT DEFAULT '', descr TEXT DEFAULT '',
  web_allowed BIGINT DEFAULT 0, enabled BIGINT NOT NULL DEFAULT 1,
  available_override BIGINT DEFAULT NULL);
CREATE TABLE IF NOT EXISTS roe_decision(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, ts TEXT, campaign TEXT, run_id TEXT,
  action_id TEXT, target TEXT, kind TEXT, verdict TEXT, exploit BIGINT DEFAULT 0,
  destructive BIGINT DEFAULT 0, reasons TEXT, engagement_id BIGINT NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS run_job(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, run_id TEXT UNIQUE, campaign TEXT, ts TEXT,
  status TEXT, mode TEXT, fired BIGINT DEFAULT 0, dry_run BIGINT DEFAULT 0, vetoed BIGINT DEFAULT 0,
  errors BIGINT DEFAULT 0, skipped_budget TEXT DEFAULT '[]', coverage_gaps TEXT DEFAULT '{}',
  detail TEXT DEFAULT '', pid BIGINT DEFAULT -1, started_by TEXT DEFAULT '', reason TEXT DEFAULT '',
  targets TEXT DEFAULT '[]', modules TEXT DEFAULT '[]', started TEXT DEFAULT '', finished TEXT DEFAULT '',
  exit_code BIGINT DEFAULT NULL, engagement_id BIGINT NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS ledger_entry(
  seq BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, ts TEXT, kind TEXT, detail TEXT, prev TEXT,
  hash TEXT, alg TEXT, sig TEXT);
CREATE TABLE IF NOT EXISTS run_log(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, run_id TEXT, ts TEXT, stream TEXT, line TEXT);
CREATE INDEX IF NOT EXISTS idx_run_log_run ON run_log(run_id, id);
CREATE TABLE IF NOT EXISTS users(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, login TEXT UNIQUE NOT NULL, role TEXT NOT NULL,
  pass_hash TEXT NOT NULL, disabled BIGINT DEFAULT 0, created TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS session(
  token_sha TEXT PRIMARY KEY, user_id BIGINT NOT NULL, created BIGINT NOT NULL, expires BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS engagement(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT, status TEXT DEFAULT 'active',
  mode TEXT DEFAULT 'grey', scope_json TEXT NOT NULL DEFAULT '{}', ledger_path TEXT NOT NULL DEFAULT '',
  classification TEXT, retention_policy TEXT, created TEXT DEFAULT '', updated TEXT DEFAULT '',
  tenant_id BIGINT NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS finding_template(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, vuln_class TEXT DEFAULT '',
  cwe TEXT DEFAULT '', severity TEXT DEFAULT 'INFO', title_tmpl TEXT DEFAULT '',
  description_tmpl TEXT DEFAULT '', remediation_tmpl TEXT DEFAULT '', refs TEXT DEFAULT '',
  created TEXT DEFAULT '', updated TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS tenant(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, status TEXT DEFAULT 'active',
  created TEXT DEFAULT '', updated TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS tenant_grant(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, user_id BIGINT NOT NULL, tenant_id BIGINT NOT NULL,
  role TEXT NOT NULL DEFAULT 'tenant_viewer', created TEXT DEFAULT '',
  UNIQUE(user_id, tenant_id));
CREATE INDEX IF NOT EXISTS idx_tenant_grant_user ON tenant_grant(user_id);
";

/// Migrations additives (ALTER) — chaque ALTER est error-ignored : si la colonne existe déjà
/// (base ancienne ou re-boot) SQLite renvoie une erreur qu'on absorbe. Idempotent.
pub(crate) fn migrate(db: &Connection) {
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
pub(crate) fn ensure_default_dashboard(store: &crate::store::Store) {
    let _ = store.execute(
        // DIALECT-NEUTRAL (Stage 2b) : `INSERT OR IGNORE` (SQLite-only) -> `INSERT … ON CONFLICT(id)
        // DO NOTHING` (portable SQLite+PG ; conflit sur la PK `id`, cf. SCHEMA/PG_SCHEMA). `datetime('now')`
        // (SQLite-only) -> `CAST(CURRENT_TIMESTAMP AS TEXT)` : sur SQLite CURRENT_TIMESTAMP rend le MÊME
        // texte `YYYY-MM-DD HH:MM:SS` que datetime('now') (CAST no-op sur une valeur déjà TEXT) ; sur PG
        // le CAST est requis pour lier un timestamptz dans une colonne TEXT (pas de cast d'assignation).
        "INSERT INTO dashboard(id,name,descr,position,created,updated)
         VALUES(1,'Défaut','Dashboard par défaut (rétro-compat)',0,CAST(CURRENT_TIMESTAMP AS TEXT),CAST(CURRENT_TIMESTAMP AS TEXT))
         ON CONFLICT(id) DO NOTHING",
        &crate::sql_params![],
    );
    // panels sans dashboard valide -> rattachés au défaut (ne casse jamais un panel existant).
    let _ = store.execute(
        "UPDATE panel SET dashboard_id=1
         WHERE dashboard_id IS NULL OR dashboard_id NOT IN (SELECT id FROM dashboard)",
        &crate::sql_params![],
    );
}

/// ENGAGEMENT résolu (vue en mémoire d'une ligne `engagement`) : le scope in/out DÉCODÉ depuis
/// `scope_json`, le `mode` effectif et le `ledger_path` DÉDIÉ. C'est CET objet (jamais les App globals)
/// que le run flow consomme : scope-guard = `scope_in`/`scope_out` de l'engagement (fail-closed),
/// journalisation dans `ledger_path` de l'engagement. Isolation : un run pour l'engagement A ne voit
/// que le scope de A.
#[derive(Clone, Debug)]
pub(crate) struct Engagement {
    pub(crate) id: i64,
    pub(crate) mode: String,
    pub(crate) scope_in: Vec<String>,
    pub(crate) scope_out: Vec<String>,
    pub(crate) ledger_path: String,
}

/// Extrait la liste de chaînes d'un champ tableau d'un scope_json (in_scope/out_scope). Absent/mal
/// formé => vide (fail-closed pour in_scope : un engagement sans in_scope ne lance rien).
pub(crate) fn scope_json_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// Charge un engagement par id : décode `scope_json` (in/out scope) et le `mode` (le `mode` du
/// scope_json prime sur la colonne `mode` s'il est présent — le scope reste la source autoritaire du
/// périmètre). None si l'id n'existe pas. Pure lecture (aucune écriture).
pub(crate) fn load_engagement(store: &crate::store::Store, id: i64) -> Option<Engagement> {
    let (mode_col, scope_json, ledger_path): (String, String, String) = store
        .query_row(
            "SELECT mode, scope_json, ledger_path FROM engagement WHERE id=?",
            &crate::sql_params![id],
            |r| Ok((r.get_str(0)?, r.get_str(1)?, r.get_str(2)?)),
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
pub(crate) fn ensure_default_engagement(store: &crate::store::Store, scope_in: &[String], scope_mode: &str, ledger_path: &str) {
    let count: i64 = store
        .query_row("SELECT COUNT(*) FROM engagement", &crate::sql_params![], |r| r.get_i64(0))
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
    let _ = store.execute(
        // DIALECT-NEUTRAL (Stage 2b) : `datetime('now')` (SQLite-only) -> `CAST(CURRENT_TIMESTAMP AS TEXT)`
        // (portable). L'INSERT explicite id=1 est déjà portable (PG : IDENTITY … BY DEFAULT autorise l'id
        // explicite ; SCHEMA : INTEGER PRIMARY KEY). Sur SQLite, valeur/format IDENTIQUES à datetime('now').
        "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
         VALUES(1,?,?,?,?,?,CAST(CURRENT_TIMESTAMP AS TEXT),CAST(CURRENT_TIMESTAMP AS TEXT))",
        &crate::sql_params!["Engagement par défaut", "active", scope_mode, scope_json, ledger_path],
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
pub(crate) fn ensure_default_tenant(store: &crate::store::Store) {
    let count: i64 = store
        .query_row("SELECT COUNT(*) FROM tenant", &crate::sql_params![], |r| r.get_i64(0))
        .unwrap_or(0);
    if count > 0 {
        return; // déjà provisionné — ne jamais écraser
    }
    let _ = store.execute(
        // DIALECT-NEUTRAL (Stage 2b) : `datetime('now')` -> `CAST(CURRENT_TIMESTAMP AS TEXT)` (portable ;
        // sur SQLite valeur/format IDENTIQUES). L'INSERT id=1 est déjà portable (garde early-return count>0).
        "INSERT INTO tenant(id,name,status,created,updated)
         VALUES(1,'Tenant par défaut','active',CAST(CURRENT_TIMESTAMP AS TEXT),CAST(CURRENT_TIMESTAMP AS TEXT))",
        &crate::sql_params![],
    );
    // filet défensif : tout engagement sans tenant valide -> tenant #1 (la colonne a déjà DEFAULT 1).
    let _ = store.execute(
        "UPDATE engagement SET tenant_id=1 WHERE tenant_id IS NULL OR tenant_id NOT IN (SELECT id FROM tenant)",
        &crate::sql_params![],
    );
    // rétro-compat : chaque utilisateur existant reçoit un grant vers le tenant #1 (rôle dérivé du RBAC).
    let _ = store.execute(
        // DIALECT-NEUTRAL (Stage 2b) : `INSERT OR IGNORE` -> `INSERT … ON CONFLICT(user_id,tenant_id) DO
        // NOTHING` (portable ; cible = la contrainte UNIQUE(user_id,tenant_id) que l'IGNORE couvrait, cf.
        // SCHEMA/PG_SCHEMA). `datetime('now')` -> `CAST(CURRENT_TIMESTAMP AS TEXT)`. Le `WHERE true` est
        // OBLIGATOIRE : sur un INSERT…SELECT, SQLite ne peut pas distinguer `FROM users ON CONFLICT…` d'un
        // JOIN `... ON <expr>` — la clause WHERE lève l'ambiguïté (idiome documenté). Valide aussi sur PG.
        "INSERT INTO tenant_grant(user_id,tenant_id,role,created)
         SELECT id, 1,
                CASE role WHEN 'admin' THEN 'tenant_admin' WHEN 'operator' THEN 'tenant_operator' ELSE 'tenant_viewer' END,
                CAST(CURRENT_TIMESTAMP AS TEXT)
           FROM users WHERE true
         ON CONFLICT(user_id,tenant_id) DO NOTHING",
        &crate::sql_params![],
    );
}

/// `web_allowed` : un module est lançable depuis l'UI web seulement s'il n'exploite pas, n'est pas
/// destructif, et n'est pas l'interception IDOR (qui tamper une requête en vol — réservé CLI/opérateur).
pub(crate) fn module_web_allowed(kind: &str, exploit: bool, destructive: bool) -> bool {
    !exploit && !destructive && kind != "evasion.idor_intercept"
}

/// INTENTION OPÉRATEUR de désactiver un connecteur (gouvernance, indépendante de la sonde host) :
/// vrai si `enabled=0` OU `available_override=Some(false)` (override explicite « indisponible »). Un
/// simple binaire absent (probed=0, sans override) N'EST PAS une désactivation opérateur — le moteur
/// le SKIP déjà via sa propre sonde. C'est CE set qu'on refuse dans validate_modules et qu'on injecte
/// dans scope.json `disabled_modules` (pour que le moteur SKIP même un outil PRÉSENT que l'opérateur a
/// désactivé). Fonction PURE (testable, aucun I/O).
pub(crate) fn module_operator_disabled(enabled: bool, available_override: Option<bool>) -> bool {
    !enabled || available_override == Some(false)
}

/// Disponibilité EFFECTIVE d'un connecteur = `enabled AND (available_override ?? probed_available)`.
/// Exposée au front (badge « effectif ») et cohérente avec module_operator_disabled : effective=false
/// dès que l'opérateur désactive (enabled=0 / override=0) OU que la sonde host est négative sans override.
/// Fonction PURE (testable, aucun I/O).
pub(crate) fn module_effectively_available(enabled: bool, available_override: Option<bool>, probed_available: bool) -> bool {
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
pub(crate) fn resolve_web_dir() -> String {
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
pub(crate) fn load_server_scope(pkg_dir: &str) -> (Vec<String>, String) {
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
pub(crate) fn populate_modules(store: &crate::store::Store) {
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
        upsert_probed_module(store, kind, exploit, destructive, available, mitre, descr);
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
pub(crate) fn upsert_probed_module(store: &crate::store::Store, kind: &str, exploit: bool, destructive: bool,
                        available: bool, mitre: &str, descr: &str) {
    let web_allowed = module_web_allowed(kind, exploit, destructive);
    let _ = store.execute(
        "INSERT INTO module(kind,exploit,destructive,available,mitre,descr,web_allowed)
         VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(kind) DO UPDATE SET exploit=excluded.exploit, destructive=excluded.destructive,
           available=excluded.available, mitre=excluded.mitre, descr=excluded.descr",
        &crate::sql_params![kind, exploit as i64, destructive as i64, available as i64, mitre, descr, web_allowed as i64],
    );
}

pub(crate) fn parse_modules_json(s: &str) -> Option<Vec<Value>> {
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
pub(crate) fn parse_modules_text(s: &str) -> Vec<Value> {
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
pub(crate) struct RunEvent {
    pub(crate) run_id: String,
    pub(crate) kind: String, // "log" | "status"
    pub(crate) payload: Value,
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
pub(crate) struct RunState {
    pub(crate) current: HashMap<i64, RunHandle>, // engagement_id -> run vivant DE CET engagement (au plus 1)
}

/// Slot d'un run vivant, rangé sous la clé `engagement_id` de `RunState.current`. `run_id` est
/// GLOBAL-unique (traçable, sert de garde anti-course à la libération) ; `pgid` = groupe de process
/// (setsid) pour cancel/watchdog (killpg de tout le sous-arbre).
pub(crate) struct RunHandle {
    pub(crate) run_id: String,
    pub(crate) pgid: i32, // group de process (setsid) -> kill group pour cancel/watchdog
}

#[derive(Clone)]
pub(crate) struct App {
    pub(crate) db: Arc<Mutex<Connection>>,
    pub(crate) db_path: Arc<String>,
    // ENTERPRISE STORE (Postgres, feature `store-postgres`) — client SESSION-PINNÉ partagé (un seul
    // client pour la vie de l'App : `execute(INSERT)`+`last_insert_id()` tombent sur la MÊME session,
    // cf. store.rs). `Some` UNIQUEMENT si FORGE_ENTERPRISE_STORE=postgres + FORGE_DB_URL et feature
    // compilée ; sinon `None` -> `store()` retombe sur SQLite (build community inchangé). Le champ
    // n'existe QUE sous la feature (struct byte-identique quand OFF).
    #[cfg(feature = "store-postgres")]
    pub(crate) pg: Option<Arc<Mutex<postgres::Client>>>,
    pub(crate) token_sha: Arc<String>,
    pub(crate) token_raw: Arc<String>,          // token bearer EN CLAIR — passé au moteur spawné pour /api/ingest
    pub(crate) user: Arc<String>,
    pub(crate) pass_hash: Arc<String>,          // argon2id ; vide = auth OFF (dev localhost)
    // GATE D'AUTH ENGAGÉE ? — cache recalculé au boot ET à chaque mutation de comptes (create/disable/
    // role-change/delete) pour éviter une requête DB par requête HTTP. `true` dès qu'un hash env est
    // posé (FORGE_CONSOLE_PASS_HASH) OU qu'au moins un compte activé existe en base : la gate s'engage
    // sur l'ÉTAT DB, pas seulement sur l'env (ferme le trou dev-open « comptes en base, env vide »).
    // FAIL-CLOSED : tant qu'un compte activé ou un hash existe, la gate reste engagée.
    pub(crate) auth_required: Arc<AtomicBool>,
    pub(crate) operator_hash: Arc<String>,      // argon2id du rôle OPÉRATEUR (C2) ; vide => FAIL-CLOSED (403 sur tout C2)
    pub(crate) allowed_hosts: Arc<Vec<String>>, // anti-DNS-rebinding
    pub(crate) ledger_path: Arc<String>,        // JSONL du ledger d'engagement (FORGE_CONSOLE_LEDGER)
    pub(crate) pkg_dir: Arc<String>,            // racine du paquet Forge (cwd du spawn `python -m forge.cli`)
    pub(crate) python: Arc<String>,            // interpréteur python (FORGE_PYTHON, défaut python3)
    pub(crate) scope_in: Arc<Vec<String>>,      // in_scope autorisé (recopié dans le scope du run, fail-closed)
    pub(crate) scope_mode: Arc<String>,         // mode du scope (white|grey|black) recopié tel quel
    // DÉTECTION (défensif, purple) : SOURCE de détection CONFIGURABLE (plugin), plus rien de codé en
    // dur. Objet JSON `{kind, endpoint?, auth?:{type,secret}, query?, mapping?}` chargé au boot depuis
    // `settings.detection_source`, avec REPLI rétro-compat sur l'env legacy PLUME_URL/PLUME_TOKEN
    // (traité comme `{kind:plume, endpoint:PLUME_URL, auth:{type:basic,secret:PLUME_TOKEN}}`). `kind`
    // absent/none => couverture en FAIL-OPEN LISIBLE (source_reachable:false, aucune métrique inventée).
    // Le SECRET (auth.secret) n'est JAMAIS renvoyé par un GET, ni journalisé, ni ledgerisé (rédigé).
    // Verrou RW : rechargé (reload_detection_source) après toute mutation de `settings.detection_source`.
    pub(crate) detection_source: Arc<std::sync::RwLock<Arc<Value>>>,
    pub(crate) run_timeout_secs: u64,           // watchdog (FORGE_RUN_TIMEOUT, défaut 1800s)
    pub(crate) run_state: Arc<AsyncMutex<RunState>>,
    /// RÉSERVATIONS de slot FIFO (CONC-1) — engagement_id dont un `run_create` a réservé le slot mais
    /// dont le run n'est PAS encore promu dans `run_state` (fenêtre fs-writes / DB insert / spawn /
    /// ledger). Mutex std SYNCHRONE tenu quelques MICROSECONDES uniquement (jamais à travers un
    /// `.await`) : c'est ce qui permet une libération CANCELLATION-SAFE via un guard RAII `Drop`
    /// (cf. runs.rs::RunReservation) — le slot est libéré sur retour normal, early-return, panic ET
    /// drop du future (déconnexion/annulation à un point d'await), là où une re-lock awaitée fuiterait.
    /// `run_cancel`/`runs_list`/`reconcile_runs`/superviseur n'y touchent JAMAIS (ils opèrent sur
    /// `run_state` = runs VIVANTS) : un slot réservé-non-encore-spawné leur est invisible (aucun
    /// pgid, aucun kill erroné). `Arc<Mutex<..>>` (et non `Mutex` nu) car App est `Clone`/`State<App>`
    /// est cloné par requête : tous les clones DOIVENT partager le MÊME set (sinon réservations perdues).
    pub(crate) run_reservations: Arc<Mutex<std::collections::HashSet<i64>>>,
    pub(crate) events: broadcast::Sender<RunEvent>, // bus SSE lock-free (clone du Sender)
    // Sérialise lecture-head -> calcul -> écriture du ledger JSONL (anti-race : deux appends
    // concurrents liraient le MÊME prev/seq et casseraient la chaîne SHA-256). Cache aussi le head
    // (prev,seq) pour éviter de relire tout le fichier à chaque append (O(n²) -> O(1) amorti).
    pub(crate) ledger_lock: Arc<Mutex<LedgerHead>>,
}

/// Head courant du ledger console (dernier hash + dernière seq), maintenu sous `ledger_lock`.
/// `loaded=false` => pas encore initialisé depuis le disque (lecture paresseuse au 1er append).
#[derive(Default)]
pub(crate) struct LedgerHead {
    pub(crate) prev: String,
    pub(crate) seq: i64,
    pub(crate) loaded: bool,
}

impl App {
    /// Verrouille la connexion SQLite en RÉCUPÉRANT un mutex empoisonné (un panic en section
    /// critique empoisonnait le Mutex et tout `.lock().unwrap()` ultérieur paniquait à son tour ->
    /// DoS API permanent). `into_inner()` reprend la garde : la connexion rusqlite reste utilisable
    /// (une requête échouée renvoie une Err, pas un état mémoire corrompu). Fail-open contrôlé.
    pub(crate) fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// PORTABLE DB SEAM (Stage 0) — acquires the SAME `Mutex<Connection>` guard `db()` does and hands
    /// it to a backend-agnostic `Store` (public API leaks no rusqlite type; a Postgres backend
    /// satisfies it at Stage 2 without touching call sites). Holds the lock for the `Store`'s lifetime,
    /// so a sequence of `store.execute/query` runs under ONE lock exactly like `let db = self.db();`
    /// followed by several `db.*` calls — locking granularity and concurrency semantics are unchanged.
    /// Same poisoned-mutex recovery as `db()`. Like `db()`, NEVER hold the returned `Store` across an
    /// `.await` (the guard is `!Send`). Modules migrate from `db()` to `store()` one at a time.
    pub(crate) fn store(&self) -> crate::store::Store<'_> {
        // POSTGRES (feature `store-postgres`) : si un client PG session-pinné est présent, le seam route
        // dessus (même modèle held-guard : on tient le Mutex du client pour la vie du Store). Sinon —
        // et TOUJOURS dans le build community (bloc non compilé) — on retombe sur SQLite, inchangé.
        #[cfg(feature = "store-postgres")]
        if let Some(pg) = self.pg.as_ref() {
            return crate::store::Store::postgres(pg.lock().unwrap_or_else(|e| e.into_inner()));
        }
        crate::store::Store::sqlite(self.db.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Vrai s'il existe AU MOINS un compte ACTIVÉ (`disabled=0`) dans la table `users`. Requête légère
    /// (`LIMIT 1`). Ne verrouille QUE le mutex DB : ne JAMAIS l'appeler en tenant déjà `self.db()`
    /// (deadlock). Un échec de lecture -> false (l'engagement de la gate retombe alors sur `pass_hash`).
    pub(crate) fn any_enabled_user(&self) -> bool {
        let store = self.store();
        store.query_row("SELECT 1 FROM users WHERE disabled=0 LIMIT 1", &crate::sql_params![], |_| Ok(())).is_ok()
    }

    /// Recalcule et met en cache `auth_required` : la gate d'auth s'engage si un hash d'env est posé
    /// (`FORGE_CONSOLE_PASS_HASH` non vide) OU si au moins un compte activé existe en base. À appeler
    /// au BOOT et après CHAQUE mutation de comptes pour que l'état DB pilote la gate sans requête par
    /// requête. FAIL-CLOSED : on n'ouvre jamais la gate tant qu'un compte activé ou un hash existe.
    /// Ne pas appeler en tenant `self.db()` (any_enabled_user reverrouille le mutex).
    pub(crate) fn recompute_auth_required(&self) {
        let required = !self.pass_hash.is_empty() || self.any_enabled_user();
        self.auth_required.store(required, Ordering::SeqCst);
    }

    /// Lecture O(1) du cache : la gate d'auth est-elle engagée ? (voir recompute_auth_required).
    pub(crate) fn auth_required(&self) -> bool {
        self.auth_required.load(Ordering::SeqCst)
    }

    /// Vrai s'il existe AU MOINS un compte ADMIN activé (`role='admin' AND disabled=0`). Distinct de
    /// any_enabled_user (qui compte TOUT rôle) : le wizard de 1er déploiement considère la console
    /// « provisionnée » dès qu'un ADMIN peut administrer (pas un simple viewer). Requête légère
    /// (`LIMIT 1`). Ne verrouille QUE le mutex DB (ne pas appeler en tenant déjà `self.db()`).
    pub(crate) fn any_enabled_admin(&self) -> bool {
        let store = self.store();
        store.query_row("SELECT 1 FROM users WHERE role='admin' AND disabled=0 LIMIT 1", &crate::sql_params![], |_| Ok(())).is_ok()
    }

    /// La console est-elle déjà PROVISIONNÉE ? Vrai si un admin activé existe en base OU si un hash
    /// d'amorçage env est posé (`FORGE_CONSOLE_PASS_HASH`). Pilote l'auto-désactivation du wizard de
    /// 1er déploiement : `POST /api/setup` se ferme (409) dès que `provisioned()` est vrai. Ne pas
    /// appeler en tenant déjà `self.db()` (any_enabled_admin reverrouille le mutex).
    pub(crate) fn provisioned(&self) -> bool {
        !self.pass_hash.is_empty() || self.any_enabled_admin()
    }

    /// Configuration COURANTE de la source de détection (clone bon-marché de l'`Arc<Value>` en cache).
    /// Récupère un verrou empoisonné (into_inner) : un panic passé ne doit pas geler la lecture purple.
    pub(crate) fn detection_config(&self) -> Arc<Value> {
        self.detection_source.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Recalcule le cache `detection_source` depuis `settings.detection_source` (repli env legacy
    /// PLUME_URL/PLUME_TOKEN si la clé est absente). À appeler au BOOT et après CHAQUE mutation de
    /// `settings.detection_source` (wizard/config admin) pour que la source pilote la couverture sans
    /// relire la table à chaque requête. Ne pas appeler en tenant déjà `self.db()` (relock du mutex DB).
    pub(crate) fn reload_detection_source(&self) {
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
    pub(crate) fn invalidate_ledger_head(&self) {
        let mut head = self.ledger_lock.lock().unwrap_or_else(|e| e.into_inner());
        head.loaded = false;
    }
}

pub(crate) fn gs(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}


// --- settings KV : configuration mutable d'administration (get/set avec horodatage) ---

/// Lit une clé de configuration dans la table `settings`. None si absente ou erreur DB (fail-soft en
/// LECTURE : une clé non provisionnée => valeur par défaut côté appelant, jamais de valeur inventée).
#[allow(dead_code)] // substrat consommé par les routes settings/setup/detection à venir
pub(crate) fn settings_get(db: &Connection, key: &str) -> Option<String> {
    db.query_row("SELECT value FROM settings WHERE key=?", [key], |r| r.get::<_, String>(0)).ok()
}

/// PORTABLE SEAM analogue of [`settings_get`] over `App::store()`. Byte-identical SQL/semantics: a
/// fail-soft LECTURE (absent key or read error -> `None`, never a fabricated value). Runtime callers
/// migrated off `app.db()` use this; the `&Connection` version above remains for tests (which lock the
/// DB directly) and the boot/CLI carve-outs.
pub(crate) fn settings_get_store(store: &crate::store::Store, key: &str) -> Option<String> {
    store
        .query_row("SELECT value FROM settings WHERE key=?", &crate::sql_params![key], |r| r.get_str(0))
        .ok()
}

/// Écrit (upsert) une clé de configuration avec l'horodatage `updated` courant. PRIMARY KEY sur `key`
/// => une seule ligne par clé (pas de doublon). Renvoie une erreur si l'écriture DB échoue (l'appelant
/// admin doit pouvoir la propager avant de ledgeriser). Mutations réservées à check_admin.
#[allow(dead_code)] // substrat consommé par les routes settings/setup/detection à venir
pub(crate) fn settings_set(db: &Connection, key: &str, value: &str) -> Result<(), String> {
    db.execute(
        "INSERT INTO settings(key,value,updated) VALUES(?,?,datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
        rusqlite::params![key, value],
    )
    .map(|_| ())
    .map_err(|e| format!("écriture settings échouée: {e}"))
}

/// PORTABLE SEAM analogue of [`settings_set`] over `App::store()`. Byte-identical SQL/params (verbatim
/// upsert; `datetime('now')` stays on SQLite, is dialect-mapped only on a Postgres backend) and the
/// same error text on failure. Runtime callers use this; the `&Connection` version above stays for
/// tests and the boot/CLI carve-outs.
pub(crate) fn settings_set_store(store: &crate::store::Store, key: &str, value: &str) -> Result<(), String> {
    store
        .execute(
            "INSERT INTO settings(key,value,updated) VALUES(?,?,datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
            &crate::sql_params![key, value],
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
pub(crate) fn session_ttl_secs() -> i64 {
    std::env::var("FORGE_CONSOLE_SESSION_TTL")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(3600) // 1 h par défaut
}

/// Epoch s courant (UTC). Sans dépendance chrono — SystemTime depuis l'UNIX_EPOCH.
pub(crate) fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}


/// Génère un token de session opaque (256 bits hex via CSPRNG OS). Le Result de getrandom est propagé
/// (panic) : un échec d'entropie produirait un token PRÉVISIBLE -> usurpation de session.
pub(crate) fn gen_session_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("CSPRNG (getrandom) indisponible — refus de générer une session faible");
    hex(&b)
}


/// Provisionne un compte dans la table `users` (argon2id). Idempotent vis-à-vis du login : si le login
/// existe déjà, MET À JOUR rôle + hash + réactive (disabled=0). Renvoie le rôle validé ou une erreur.
/// Utilisé par la sous-commande CLI `useradd`. Validation login/role stricte (fail-closed).
pub(crate) fn upsert_user(db: &Connection, login: &str, role: &str, pass_hash: &str) -> Result<String, String> {
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

/// PORTABLE SEAM analogue of [`upsert_user`] over `App::store()`. Same validation (login/role), same
/// verbatim upsert SQL/params and identical error text. Runtime handlers use this; the `&Connection`
/// version above stays for tests and the `console user` CLI carve-out (its own connection).
pub(crate) fn upsert_user_store(store: &crate::store::Store, login: &str, role: &str, pass_hash: &str) -> Result<String, String> {
    let login = validate_login(login)?;
    let role = validate_role(role)?;
    if pass_hash.is_empty() {
        return Err("hash de mot de passe vide".into());
    }
    store
        .execute(
            "INSERT INTO users(login,role,pass_hash,disabled,created)
         VALUES(?,?,?,0,datetime('now'))
         ON CONFLICT(login) DO UPDATE SET role=excluded.role, pass_hash=excluded.pass_hash, disabled=0",
            &crate::sql_params![&login, &role, pass_hash],
        )
        .map_err(|e| format!("écriture users échouée: {e}"))?;
    Ok(role)
}

pub(crate) async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

/// Vérifie le bearer token (sha256). Gate des écritures (ingest, panels).
pub(crate) fn check_token(app: &App, headers: &HeaderMap) -> bool {
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
pub(crate) fn parse_fire_ts(ts: &str) -> Option<i64> {
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
pub(crate) fn resolve_detection_source(db: &Connection) -> Value {
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
pub(crate) fn ds_kind(cfg: &Value) -> String {
    cfg.get("kind").and_then(|v| v.as_str()).unwrap_or("none").trim().to_string()
}

/// `endpoint` de la source (URL http(s):// ou chemin fichier selon le kind ; défaut vide, trim).
pub(crate) fn ds_endpoint(cfg: &Value) -> String {
    cfg.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
}

/// Type d'auth déclaré (`auth.type`, avec tolérance à la forme plate `auth_type` écrite par le
/// wizard). Défaut "none". NE renvoie JAMAIS le secret — juste le NOM du schéma (pour le ledger/log).
pub(crate) fn ds_auth_type(cfg: &Value) -> String {
    cfg.get("auth").and_then(|a| a.get("type")).and_then(|v| v.as_str())
        .or_else(|| cfg.get("auth_type").and_then(|v| v.as_str()))
        .unwrap_or("none").trim().to_string()
}

/// Secret d'auth (`auth.secret`) — MANIÉ COMME UN SECRET DE SESSION : lu UNIQUEMENT pour construire
/// l'en-tête d'auth du fetch et pour la rédaction ; jamais renvoyé/journalisé/ledgerisé.
pub(crate) fn ds_secret(cfg: &Value) -> String {
    cfg.get("auth").and_then(|a| a.get("secret")).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// Remplace toute occurrence du secret par `[secret rédigé]` dans un message destiné à une réponse/au
/// log/au ledger. Garde-fou défense-en-profondeur (les messages d'erreur n'échoient normalement pas le
/// secret) ; no-op si le secret est vide ou trop court pour être remplacé sans risque de sur-rédaction.
pub(crate) fn redact_secret(msg: &str, secret: &str) -> String {
    if secret.len() < 4 {
        return msg.to_string();
    }
    msg.replace(secret, "[secret rédigé]")
}

/// Liste FERMÉE des `kind` de source de détection acceptés (parité avec le registre du collecteur Python
/// `forge.collectors` + les kinds interrogés en Rust). `none` désactive la mesure (fail-open lisible).
/// Sert de garde-fou d'entrée sur POST /api/detection/source (fail-closed : un kind inconnu est refusé,
/// jamais persisté) et alimente le sélecteur de l'UI admin/wizard.
pub(crate) const DETECTION_KINDS: &[&str] = &[
    "none", "plume", "generic_http", "crowdsec", "elastic", "opensearch",
    "fortigate_syslog", "pfsense", "opnsense", "file_jsonl", "exec",
];

pub(crate) fn is_known_detection_kind(kind: &str) -> bool {
    DETECTION_KINDS.contains(&kind)
}

/// Copie RÉDIGÉE d'une config de source : retire le secret d'auth (`auth.secret`) et tout `secret` posé
/// à plat. Utilisée par GET /api/detection/source et la réponse de POST — le SECRET n'est JAMAIS renvoyé
/// (manié comme un secret de session). Tout le reste (kind/endpoint/auth.type/query/mapping) est conservé
/// pour permettre l'édition côté admin sans jamais re-rendre le secret.
pub(crate) fn redact_detection_config(cfg: &Value) -> Value {
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
pub(crate) fn apply_kept_secret(app: &App, cfg: &Value, keep_secret: bool) -> Value {
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


/// Corrélation PURE (testable, sans I/O) red-team(tiré) × blue-team(détecté).
///
/// - `fired` : techniques tirées par Forge -> (mitre, ts_epoch_du_tir Option). Une technique peut
///   apparaître plusieurs fois (plusieurs tirs) ; on prend le tir le PLUS RÉCENT pour le MTTD (le SOC
///   doit détecter le tir courant), et on compte les tirs.
/// - `detections` : map mitre -> (count_alertes, first_ts_epoch) renvoyée par Plume.
///
/// Renvoie l'objet JSON exposé par /api/purple/coverage (hors champ plume_reachable, ajouté par
/// le handler). detected/missed sont des intersections/différences STRICTES sur `mitre`.
pub(crate) fn compute_purple_coverage(
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
pub(crate) fn purple_fail_open(url: &str, fired: &[(String, Option<i64>)], reason: &str) -> Value {
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
pub(crate) fn read_fired_techniques(app: &App, eid: Option<i64>, extra_cond: Option<(&str, &str)>) -> Vec<(String, Option<i64>)> {
    let store = app.store();
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
    // LENIENT (query_lax) : un prepare échoué -> Err -> unwrap_or_default -> vec![] (à l'identique de
    // l'early-return d'avant) ; une ligne malformée est ignorée (filter_map(ok)). Bind des args &String
    // en TEXT, comme le `params_from_iter(args.iter())` d'origine.
    let params: Vec<crate::store::Param> = args.iter().map(|s| crate::store::Param::Text(s.clone())).collect();
    store
        .query_lax(&sql, &params, |r| {
            let mitre = r.get_opt_str(0)?.unwrap_or_default();
            let ts_raw = r.get_opt_str(1)?.unwrap_or_default();
            Ok((mitre, parse_fire_ts(&ts_raw)))
        })
        .unwrap_or_default()
}

/// Accès à une valeur JSON par CHEMIN POINTÉ ("a.b.c") ; None si un segment manque. Un chemin vide
/// renvoie la valeur racine. Sert au `mapping` des sources generic_http (champ natif -> mitre/ts/count).
pub(crate) fn json_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
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
pub(crate) fn json_path_str(v: &Value, path: &str) -> String {
    match json_path(v, path) {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.as_str().map(str::to_string).unwrap_or_default(),
        None => String::new(),
    }
}

/// Valeur au chemin pointé rendue en i64 (int, sinon f64 tronqué, sinon parse d'une string ; None si
/// absent/illisible).
pub(crate) fn json_path_i64(v: &Value, path: &str) -> Option<i64> {
    let n = json_path(v, path)?;
    n.as_i64()
        .or_else(|| n.as_f64().map(|f| f as i64))
        .or_else(|| n.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
}

/// Mapping IDENTITÉ de la réponse Plume `{detections:[{mitre,count,first_ts}]}` -> `[(mitre,count,ts)]`.
/// Réutilisé aussi pour la sortie NORMALISÉE du collecteur Python (même contrat de sortie).
pub(crate) fn parse_plume_detections(parsed: &Value) -> Vec<(String, i64, i64)> {
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
pub(crate) fn map_detections(parsed: &Value, mapping: Option<&Value>) -> Result<Vec<(String, i64, i64)>, String> {
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
pub(crate) fn generic_http_url(endpoint: &str, query: Option<&Value>, since: i64) -> String {
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
pub(crate) fn rust_http_collect(cfg: &Value, since: i64, is_plume: bool) -> Result<Vec<(String, i64, i64)>, String> {
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
pub(crate) async fn collect_via_python(app: &App, cfg: &Value, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
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
pub(crate) async fn collect_detections(app: &App, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
    let cfg = app.detection_config();
    collect_detections_with(app, &cfg, since).await
}

/// Dispatch sur `kind` d'une config source DONNÉE (utilisé aussi par POST /api/detection/test pour
/// tester une config fournie sans la persister). `plume`/`generic_http`(http) -> fetch Rust ;
/// generic_http(https) + kinds messy -> collecteur Python. Résultat -> jointure MITRE INCHANGÉE.
pub(crate) async fn collect_detections_with(app: &App, cfg: &Value, since: i64) -> Result<Vec<(String, i64, i64)>, String> {
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
pub(crate) async fn fetch_purple_coverage(app: &App, fired: Vec<(String, Option<i64>)>) -> Value {
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
pub(crate) async fn purple_coverage(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
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
pub(crate) async fn detection_test(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
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
pub(crate) async fn detection_source_get(State(app): State<App>, headers: HeaderMap) -> Response {
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
pub(crate) async fn detection_source_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
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
        // Écriture ISOLÉE (le bloc n'appelle aucun autre helper `&Connection`) -> routée par le seam pour
        // la portabilité PG. SQL/params/erreur VERBATIM de `settings_set` (INSERT..ON CONFLICT déjà
        // portable ; `datetime('now')` reste un point dialecte Stage-2). Le helper `settings_set(&Connection)`
        // est CONSERVÉ pour ses appelants boot-partagés (main.rs `settings_get` sur la conn de boot) et
        // interleaved (setup.rs `upsert_user` dans le même guard) — convertis en bloc au Stage 2.
        let store = app.store();
        let r = store
            .execute(
                "INSERT INTO settings(key,value,updated) VALUES(?,?,datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
                &crate::sql_params!["detection_source", cfg.to_string()],
            )
            .map(|_| ())
            .map_err(|e| format!("écriture settings échouée: {e}"));
        if let Err(e) = r {
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
pub(crate) async fn run_report(State(app): State<App>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    // format : md (DÉFAUT — rétro-compat), html (livrable client brandé), pdf (si outil dispo).
    let format = q.get("format").map(|s| s.as_str()).unwrap_or("md");
    // le run doit exister (sinon 404, comme run_detail). Le verrou DB est confiné dans ce bloc :
    // AUCUN MutexGuard rusqlite (!Send) ne doit survivre à l'await réseau plus bas.
    let (job, fired) = {
        // Verrou DB confiné à ce bloc `store` : il DROPPE avant read_fired_techniques (qui reprend le même
        // Mutex via app.store() -> sinon deadlock). query_row rend Err(NoRows) sur run inconnu -> 404.
        let job = {
            let store = app.store();
            match store.query_row(&format!("SELECT {RUN_JOB_COLS} FROM run_job WHERE run_id=?"), &crate::sql_params![&id], run_job_json) {
                Ok(v) => v,
                Err(_) => return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_run"}))).into_response(),
            }
        };
        // PURPLE : techniques TIRÉES par CE run (red) — lues après relâche du verrou. Le `run_id`
        // isole déjà les records d'un seul engagement -> pas de filtre engagement additionnel (None).
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
                let store = app.store();
                render_run_report_html(&store, &id, &job, Some(&purple), &custody)
            };
            ([("content-type", "text/html; charset=utf-8")], Html(html)).into_response()
        }
        "pdf" => {
            // PDF : depuis le HTML brandé, via un outil système SI présent (pas de dep lourde ajoutée).
            let html = {
                let store = app.store();
                render_run_report_html(&store, &id, &job, Some(&purple), &custody)
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
                let store = app.store();
                render_run_report_md(&store, &id, &job, Some(&purple), Some(&custody))
            };
            (StatusCode::OK, [("content-type", "text/markdown; charset=utf-8")], md).into_response()
        }
    }
}




/// Résout le `ledger_path` de l'engagement PROPRIÉTAIRE d'un run (via run_job.engagement_id ->
/// engagement.ledger_path). Défaut : App.ledger_path (engagement #1 / rétro-compat). ISOLATION : tout
/// acte console lié à un run (cancel, fin de run) est journalisé dans le ledger de SON engagement,
/// jamais celui d'un autre.
pub(crate) fn engagement_ledger_for_run(app: &App, run_id: &str) -> String {
    let store = app.store();
    store
        .query_row(
            "SELECT e.ledger_path FROM run_job j JOIN engagement e ON e.id=j.engagement_id WHERE j.run_id=?",
            &crate::sql_params![run_id],
            |r| r.get_str(0),
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
pub(crate) fn append_run_ledger_path(app: &App, ledger_path: &str, kind: &str, detail: Value) {
    if ledger_path == app.ledger_path.as_str() {
        append_console_ledger(app, kind, detail);
    } else {
        let _ = ledger_append_standalone(ledger_path, kind, &detail);
    }
}

/// Horodatage compact UTC pour les run_id, sans dépendance chrono : YYYYmmddHHMMSS dérivé du temps
/// unix (suffisant pour l'unicité combiné au token aléatoire).
pub(crate) fn chrono_now_compact() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

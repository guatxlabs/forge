// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — SCHÉMA DB + SEEDING, extrait de `state.rs` (PURE MOVE). Regroupe le `SCHEMA` SQLite de
//! base + son miroir `PG_SCHEMA` (feature `store-postgres`), les migrations additives `migrate()`, les
//! seeders idempotents rétro-compat (`ensure_default_dashboard`/`ensure_default_engagement`/
//! `ensure_default_tenant`), le recalage des séquences IDENTITY Postgres (`advance_pg_identity_sequences`/
//! `advance_pg_identity_sequences_all`) et le peuplement du registre de modules
//! (`populate_modules`/`upsert_probed_module`/`parse_modules_json`/`parse_modules_text`/`module_web_allowed`).
//!
//! Ré-exporté `pub(crate)` à la racine de crate (`pub(crate) use crate::schema::*;`) : le boot de main.rs,
//! les sous-commandes CLI (`crate::schema::PG_SCHEMA` / `crate::SCHEMA` / `crate::migrate` …) ET les tests
//! des modules frères résolvent ces items INCHANGÉS. PURE MOVE : corps/signatures/DDL IDENTIQUES ; seule la
//! localisation du fichier change. Tous les `#[cfg(feature = "store-postgres")]` préservés VERBATIM (build
//! community par défaut byte-identique).
//!
//! N.B. ce module ne glob-importe PAS `crate::*` : ses fns ne référencent que des chemins pleinement
//! qualifiés (`crate::store::Store`, `crate::sql_params!`) et ses propres voisins (`parse_modules_*`/
//! `upsert_probed_module`/`module_web_allowed`) — aucun symbole racine non qualifié.
use rusqlite::Connection;
use serde_json::{json, Value};

// SCHEMA de base (idempotent — execute_batch). Les ajouts de colonnes sur les tables existantes
// passent par `migrate()` (ALTER error-ignored) pour ne pas casser une base déjà peuplée.
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS campaign(id INTEGER PRIMARY KEY, name TEXT, started TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS finding(
  id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, title TEXT, severity TEXT,
  category TEXT, mitre TEXT, status TEXT, evidence TEXT, tool TEXT, poc TEXT,
  classification TEXT DEFAULT '', assignee INTEGER, triage TEXT DEFAULT 'new',
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
-- ENGAGEMENT_GRANT (ENTERPRISE — PER-ENGAGEMENT RBAC, readiness #14). Composable, MOST-SPECIFIC-WINS grant:
-- a row (user_id, engagement_id, role) OVERRIDES the user's tenant-wide tenant_grant FOR THAT ENGAGEMENT — so
-- a user can be tenant_operator on engagement A yet tenant_viewer on engagement B. Absent row => the
-- tenant-wide grant applies (EXISTING behaviour => this table empty = byte-identical). `role` ∈ {tenant_admin|
-- tenant_operator|tenant_viewer} (applicative). UNIQUE(user,engagement) => at most one engagement-specific
-- override per (user,engagement). FAIL-CLOSED (tenancy.rs::effective_engagement_role) : no grant at all
-- (engagement OR tenant) => no effective role => operate/admin DENIED. In COMMUNITY mode (flag OFF) the table
-- is INERT: the per-engagement gate is a no-op and the console-global role governs (byte-identical).
CREATE TABLE IF NOT EXISTS engagement_grant(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, engagement_id INTEGER NOT NULL,
  role TEXT NOT NULL DEFAULT 'tenant_viewer', created TEXT DEFAULT '',
  UNIQUE(user_id, engagement_id) ON CONFLICT IGNORE);
CREATE INDEX IF NOT EXISTS idx_engagement_grant_user ON engagement_grant(user_id);
CREATE INDEX IF NOT EXISTS idx_engagement_grant_eng ON engagement_grant(engagement_id);
-- SAVED VIEW (#8) : jeu de FILTRES sauvegardé de la vue Findings, PERSONNEL (scopé à `user_id` = login
-- d'attribution de l'appelant — un utilisateur ne voit/supprime JAMAIS les vues d'un autre, fail-closed).
-- `engagement_id` NULLABLE : NULL = vue GLOBALE (tous engagements) ; un id = vue rattachée à CET
-- engagement (proposée quand il est actif). `filter_json` = état de filtre opaque (severity/status/
-- target/campaign/…) rendu tel quel côté client. CRUD gouverné (create/delete=operator) + ledgerisé
-- `console.saved_view.*` — voir console/src/saved_views.rs.
CREATE TABLE IF NOT EXISTS saved_view(
  id INTEGER PRIMARY KEY, user_id TEXT NOT NULL, engagement_id INTEGER,
  name TEXT NOT NULL, filter_json TEXT NOT NULL DEFAULT '{}', created TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_saved_view_user ON saved_view(user_id);
-- LEADER LEASE (HA #10 Wave A — foundation, INERT) : bail de leadership PARTAGÉ, une ligne par `scope`
-- (aujourd'hui la seule = 'run-worker'). Le heartbeat HA (ha.rs, PG-only, opt-in FORGE_HA) fait un
-- acquire/renew ATOMIQUE en UN statement (INSERT … ON CONFLICT DO UPDATE … WHERE holder=me OR expiré …
-- RETURNING instance_id) : le porteur courant est `instance_id`, la prise datée par `acquired`, la
-- fraîcheur par `last_seen` (comparée au TTL). SUBSTRAT NEUTRE cette vague : AUCUN consumer ne gate encore
-- sur ce bail (reconcile/run/ledger inchangés). En COMMUNITY (single-instance, FORGE_HA jamais engagé) la
-- table reste VIDE et jamais lue/écrite -> comportement inchangé (table additive inerte, comme saved_view/
-- tenant). `BIGINT` pour acquired/last_seen (epoch s ; affinité INTEGER en SQLite -> parité PG_SCHEMA).
CREATE TABLE IF NOT EXISTS leader_lease(
  scope TEXT PRIMARY KEY, instance_id TEXT, acquired BIGINT, last_seen BIGINT);
-- HA INSTANCE HEARTBEAT (HA #10 Wave B — failover correctness) : liveness PAR-INSTANCE (une ligne par
-- réplica). CHAQUE instance HA (leader OU non) rafraîchit SON `last_seen` à chaque tick du heartbeat
-- (ha.rs) — contrairement à `leader_lease` (mono-ligne, seul le leader courant y figure), cette table
-- sait quels réplicas sont VIVANTS. Le failover-reap (reap_dead_leader_runs) ne réape un run 'running'
-- d'un AUTRE owner QUE si CET owner n'a plus de heartbeat frais (last_seen < now-TTL = mort) : un pair
-- VIVANT (flap : demoted mais process encore là) n'est JAMAIS réapé à tort. ADDITIVE + INERTE en
-- community (jamais écrite/lue sans HA opt-in) -> byte-identique.
CREATE TABLE IF NOT EXISTS ha_instance(
  instance_id TEXT PRIMARY KEY, last_seen BIGINT);
-- PRESENCE (HA #10 Wave C) : roster multi-opérateur PARTAGÉ cross-instance. Une ligne par CONNEXION SSE
-- (conn_id PK = token aléatoire par flux), portant le login/role, l'engagement où l'opérateur travaille,
-- l'`instance_id` qui héberge le flux, l'epoch de 1re connexion (`since`) et du dernier heartbeat
-- (`last_seen`, sert au GC TTL paresseux). Sous HA (opt-in FORGE_HA + Postgres) le PresenceRegistry écrit
-- ICI -> `GET /api/presence` sur N'IMPORTE quelle instance agrège les opérateurs de TOUS les réplicas.
-- En mono-instance/community le registre reste EN MÉMOIRE (byte-identique) et cette table n'est ni lue ni
-- écrite. ADDITIVE + INERTE en community.
CREATE TABLE IF NOT EXISTS presence(
  conn_id TEXT PRIMARY KEY, login TEXT NOT NULL, role TEXT NOT NULL,
  engagement_id BIGINT, instance_id TEXT, since BIGINT, last_seen BIGINT);
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
// CÂBLÉ AU BOOT (Stage 2b batch 5) : quand le backend ACTIF est Postgres (FORGE_ENTERPRISE_STORE=
// postgres + FORGE_DB_URL + feature compilée), le démarrage applique PG_SCHEMA via `app.store()` À LA
// PLACE de `execute_batch(SCHEMA)+migrate()` (qui restent la branche SQLite, sur la connexion de repli).
// Référencé aussi par les sous-commandes CLI PG (`useradd`/`seed-demo`) et les tests d'intégration
// (`store.rs::pg_tests`). C'est l'artefact de schéma faisant AUTORITÉ pour le backend Postgres.
#[cfg(feature = "store-postgres")]
pub(crate) const PG_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS campaign(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, name TEXT, started TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS finding(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, title TEXT,
  severity TEXT, category TEXT, mitre TEXT, status TEXT, evidence TEXT, tool TEXT, poc TEXT,
  run_id TEXT DEFAULT '', fix TEXT DEFAULT '', cwe TEXT DEFAULT '', cvss_vector TEXT DEFAULT '',
  cvss_score DOUBLE PRECISION DEFAULT 0, engagement_id BIGINT NOT NULL DEFAULT 1,
  classification TEXT DEFAULT '', assignee BIGINT, triage TEXT DEFAULT 'new',
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
  exit_code BIGINT DEFAULT NULL, engagement_id BIGINT NOT NULL DEFAULT 1,
  -- HA (#10 Wave B) : owner_instance = instance qui a SPAWNÉ le run (scope-guard du reconcile) ; NULL pour
  -- legacy/pending. spawn_spec = blob JSON RunSpawnSpec d'un run 'pending' (reconstruction par le leader).
  owner_instance TEXT DEFAULT NULL, spawn_spec TEXT DEFAULT '');
-- HA (#10 Wave B — fencing correctness) : INDEX UNIQUE PARTIEL « au plus UN run 'running' par engagement ».
-- C'est la GARDE AUTORITATIVE CROSS-INSTANCE : la transition -> 'running' (claim_run_running) échoue si un
-- autre run 'running' existe déjà pour le même engagement (double-spawn d'un leader périmé lors d'un flap)
-- -> pas de 2e moteur pour un même engagement. En mono-instance le FIFO garantit déjà cet invariant : l'index
-- ne se déclenche jamais (aucun changement de comportement).
CREATE UNIQUE INDEX IF NOT EXISTS uq_run_job_running_per_engagement ON run_job(engagement_id) WHERE status='running';
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
CREATE TABLE IF NOT EXISTS engagement_grant(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, user_id BIGINT NOT NULL, engagement_id BIGINT NOT NULL,
  role TEXT NOT NULL DEFAULT 'tenant_viewer', created TEXT DEFAULT '',
  UNIQUE(user_id, engagement_id));
CREATE INDEX IF NOT EXISTS idx_engagement_grant_user ON engagement_grant(user_id);
CREATE INDEX IF NOT EXISTS idx_engagement_grant_eng ON engagement_grant(engagement_id);
CREATE TABLE IF NOT EXISTS saved_view(
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, user_id TEXT NOT NULL, engagement_id BIGINT,
  name TEXT NOT NULL, filter_json TEXT NOT NULL DEFAULT '{}', created TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_saved_view_user ON saved_view(user_id);
-- LEADER LEASE (HA #10 Wave A) — MIROIR PG de la table SQLite ci-dessus. `scope` PK (pas d'IDENTITY :
-- clé métier 'run-worker'), instance_id TEXT, acquired/last_seen BIGINT (epoch s). C'est CETTE table que
-- le heartbeat HA (ha.rs) upsert atomiquement via le seam sur le backend Postgres actif (opt-in FORGE_HA).
CREATE TABLE IF NOT EXISTS leader_lease(
  scope TEXT PRIMARY KEY, instance_id TEXT, acquired BIGINT, last_seen BIGINT);
-- HA INSTANCE HEARTBEAT (HA #10 Wave B — failover correctness) : MIROIR PG de la table SQLite. Liveness
-- PAR-INSTANCE rafraîchie par CHAQUE réplica HA à son heartbeat ; le failover-reap ne réape un run d'un
-- autre owner que si cet owner n'a plus de heartbeat frais (mort). INERTE en community (opt-in FORGE_HA).
CREATE TABLE IF NOT EXISTS ha_instance(
  instance_id TEXT PRIMARY KEY, last_seen BIGINT);
-- PRESENCE (HA #10 Wave C) — MIROIR PG de la table SQLite. Roster multi-opérateur PARTAGÉ cross-instance
-- (une ligne par flux SSE, conn_id PK). Écrite par le PresenceRegistry PG-backé quand HA est engagé ;
-- inerte en community (registre en mémoire).
CREATE TABLE IF NOT EXISTS presence(
  conn_id TEXT PRIMARY KEY, login TEXT NOT NULL, role TEXT NOT NULL,
  engagement_id BIGINT, instance_id TEXT, since BIGINT, last_seen BIGINT);
";

// SCHEMA VERSION STAMP — version LOGIQUE du schéma DB, persistée dans `settings` (clé
// `schema_version`). MONOTONE : on l'INCRÉMENTE à chaque fois qu'un nouveau lot d'ALTER/CREATE
// additifs est ajouté à `migrate()` (source de vérité unique du DDL applicatif). `migrate()` la
// TAMPONNE (upsert) après avoir appliqué les migrations ; le boot Postgres la tamponne aussi après
// `PG_SCHEMA`+seed. Elle rend « à quelle version est cette base ? » RÉPONDABLE — base des upgrades sûrs
// (`forge-console status` / `upgrade` / `/health`). ADDITIVE : une base ANTÉRIEURE (clé absente) lit
// `None` et se voit tamponnée au 1er boot suivant la mise à jour (rétro-compat, jamais de valeur inventée).
pub(crate) const SCHEMA_VERSION: i64 = 1;
/// Clé de la table `settings` portant la version de schéma persistée (cf. [`SCHEMA_VERSION`]).
pub(crate) const SCHEMA_VERSION_KEY: &str = "schema_version";

/// Lit la version de schéma persistée depuis `settings` via le seam (`None` si absente/illisible —
/// base ANTÉRIEURE au stamp, jamais une valeur inventée). Utilisée par `/health` et `forge-console status`.
pub(crate) fn read_schema_version(store: &crate::store::Store) -> Option<i64> {
    crate::settings_get_store(store, SCHEMA_VERSION_KEY).and_then(|s| s.trim().parse::<i64>().ok())
}

/// Lit la version de schéma persistée depuis une connexion SQLite brute (contexte CLI hors seam :
/// `status`/`upgrade` ouvrent leur propre `Connection`). `None` si absente/illisible (base ANTÉRIEURE).
pub(crate) fn read_schema_version_conn(db: &Connection) -> Option<i64> {
    crate::settings_get(db, SCHEMA_VERSION_KEY).and_then(|s| s.trim().parse::<i64>().ok())
}

/// TAMPONNE la version de schéma COURANTE ([`SCHEMA_VERSION`]) dans `settings` via le seam (upsert
/// idempotent, horodaté). Appelée par le boot Postgres après `PG_SCHEMA`+seed (le chemin SQLite est
/// tamponné par `migrate()` lui-même, sur la connexion brute). No-op silencieux si l'écriture échoue
/// (fail-soft : un stamp manquant sera re-tenté au prochain boot ; il ne casse jamais l'amorçage).
/// Appelée UNIQUEMENT depuis le boot Postgres (feature-gated) ; en build community (SQLite seul) c'est
/// `migrate()` qui tamponne sur la connexion brute -> cette fn est alors inutilisée (allow dead_code).
#[cfg_attr(not(feature = "store-postgres"), allow(dead_code))]
pub(crate) fn stamp_schema_version(store: &crate::store::Store) {
    let _ = crate::settings_set_store(store, SCHEMA_VERSION_KEY, &SCHEMA_VERSION.to_string());
}

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
        // TLP 2.0 CLASSIFICATION (#15) : label de diffusion (CLEAR|GREEN|AMBER|AMBER+STRICT|RED) validé
        // À L'ÉCRITURE (contrainte APPLICATIVE, cf. norm_tlp) — la colonne reste TEXT libre au niveau SQL.
        // DEFAULT '' = non classifié (rétro-compat : les findings existants héritent d'un label vide).
        "ALTER TABLE finding ADD COLUMN classification TEXT DEFAULT ''",
        // OWNERSHIP (readiness P1-4) : `assignee` = user_id (users.id) DÉTENANT/RESPONSABLE du finding,
        // NULLABLE (NULL = non assigné, l'état par défaut rétro-compat : les findings existants restent non
        // assignés). Pointeur LÉGER (pas un moteur de workflow) ; l'attribution est GRANT-SCOPÉE À L'ÉCRITURE
        // (findings.rs : l'assigné doit avoir un grant sur l'engagement) — la colonne reste un INTEGER libre au
        // niveau SQL. Additif/error-ignored ; pas de DEFAULT (NULL implicite) — parité PG_SCHEMA (assignee BIGINT).
        "ALTER TABLE finding ADD COLUMN assignee INTEGER",
        // TRIAGE WORKFLOW : `triage` = état du CYCLE DE TRIAGE (new|triaging|confirmed|false_positive|
        // duplicate|resolved|reopened), SÉPARÉ du `status` (= statut de PREUVE : tested/vulnerable/…). Les
        // deux champs sont INDÉPENDANTS : une transition de triage ne touche jamais `status`. DEFAULT 'new'
        // BACKFILL les findings existants à l'état initial (rétro-compat) — additif/idempotent (error-ignored),
        // parité PG_SCHEMA (triage TEXT DEFAULT 'new'). Les transitions sont contraintes par une MATRICE FERMÉE
        // fail-closed à l'écriture (findings.rs::TRIAGE_TRANSITIONS) ; la colonne reste TEXT libre au niveau SQL.
        "ALTER TABLE finding ADD COLUMN triage TEXT DEFAULT 'new'",
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
        // HA (#10 Wave B — run leader). `owner_instance` = the instance_id that ACTUALLY SPAWNED this run
        // (set by claim_and_spawn when the run goes 'running'). NULL for legacy rows and for runs still
        // 'pending' (enqueued by a non-leader, not yet claimed). Under HA it SCOPES reconcile so an
        // instance only reaps/kills runs it owns (never a live peer's cross-host pgid). In single-instance
        // (non-HA) it stays NULL and reconcile reaps ALL running as today (byte-identical).
        "ALTER TABLE run_job ADD COLUMN owner_instance TEXT DEFAULT NULL",
        // `spawn_spec` = JSON blob of the FULLY-RESOLVED run request (RunSpawnSpec) stored ONLY when a
        // non-leader ENQUEUES a run 'pending' — everything the leader needs to reconstruct scope.json/
        // targets.json + argv and spawn it on claim. Empty '' for directly-spawned runs (leader/single-
        // instance never enqueue). Additive; unused in community (no non-leader path).
        "ALTER TABLE run_job ADD COLUMN spawn_spec TEXT DEFAULT ''",
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
    // ENGAGEMENT_GRANT (ENTERPRISE — PER-ENGAGEMENT RBAC, readiness #14) : table NEUVE re-créée ici
    // (idempotent, CREATE IF NOT EXISTS) en plus du SCHEMA, pour qu'une base ANTÉRIEURE l'obtienne au 1er
    // boot suivant la mise à jour (même discipline que `tenant_grant`). ADDITIVE + BEHAVIOUR-PRESERVING :
    // une base existante démarre avec la table VIDE => aucune override per-engagement => le grant tenant-wide
    // (ou, en community, le rôle global) s'applique EXACTEMENT comme avant. error-ignored.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS engagement_grant(
           id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, engagement_id INTEGER NOT NULL,
           role TEXT NOT NULL DEFAULT 'tenant_viewer', created TEXT DEFAULT '',
           UNIQUE(user_id, engagement_id) ON CONFLICT IGNORE)",
        [],
    );
    let _ = db.execute("CREATE INDEX IF NOT EXISTS idx_engagement_grant_user ON engagement_grant(user_id)", []);
    let _ = db.execute("CREATE INDEX IF NOT EXISTS idx_engagement_grant_eng ON engagement_grant(engagement_id)", []);
    // SAVED VIEW (#8) : re-créée ici (idempotent, CREATE IF NOT EXISTS) en plus du SCHEMA, pour qu'une
    // base ANTÉRIEURE à son introduction obtienne la table au 1er boot suivant la mise à jour (même
    // discipline que `engagement`/`settings`/`finding_template`/`tenant`). Table NEUVE (pas un ALTER de
    // colonne) : le migrateur Stage-3 (énumération dynamique de sqlite_master) la couvre automatiquement.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS saved_view(
           id INTEGER PRIMARY KEY, user_id TEXT NOT NULL, engagement_id INTEGER,
           name TEXT NOT NULL, filter_json TEXT NOT NULL DEFAULT '{}', created TEXT DEFAULT '')",
        [],
    );
    let _ = db.execute("CREATE INDEX IF NOT EXISTS idx_saved_view_user ON saved_view(user_id)", []);
    // LEADER LEASE (HA #10 Wave A) : re-créée ici (idempotent, CREATE TABLE IF NOT EXISTS) en plus du
    // SCHEMA, pour qu'une base ANTÉRIEURE à son introduction obtienne la table au 1er boot suivant la mise
    // à jour (même discipline que engagement/settings/saved_view). ADDITIVE + INERTE : une base existante
    // démarre avec la table VIDE ; aucun code community ne la lit/écrit (le heartbeat HA est PG-only +
    // opt-in FORGE_HA) -> comportement byte-identique. error-ignored.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS leader_lease(
           scope TEXT PRIMARY KEY, instance_id TEXT, acquired BIGINT, last_seen BIGINT)",
        [],
    );
    // HA INSTANCE HEARTBEAT (HA #10 Wave B) : re-créée ici (idempotent) en plus du SCHEMA, pour qu'une base
    // ANTÉRIEURE l'obtienne au 1er boot suivant la mise à jour (même discipline que leader_lease). ADDITIVE +
    // INERTE en community (jamais écrite/lue sans HA opt-in) -> byte-identique. error-ignored.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS ha_instance(
           instance_id TEXT PRIMARY KEY, last_seen BIGINT)",
        [],
    );
    // PRESENCE (HA #10 Wave C) : re-créée ici (idempotent) en plus du SCHEMA, pour qu'une base ANTÉRIEURE
    // l'obtienne au 1er boot suivant la mise à jour (même discipline que ha_instance/leader_lease). ADDITIVE
    // + INERTE en community (registre en mémoire ; jamais écrite/lue sans HA opt-in) -> byte-identique.
    let _ = db.execute(
        "CREATE TABLE IF NOT EXISTS presence(
           conn_id TEXT PRIMARY KEY, login TEXT NOT NULL, role TEXT NOT NULL,
           engagement_id BIGINT, instance_id TEXT, since BIGINT, last_seen BIGINT)",
        [],
    );
    // HA (#10 Wave B — fencing correctness) : INDEX UNIQUE PARTIEL « au plus UN run 'running' par
    // engagement » (garde autoritative cross-instance, cf. PG_SCHEMA). Créé APRÈS l'ALTER qui ajoute
    // `engagement_id` à run_job (sinon la colonne n'existe pas encore). SQLite supporte l'index partiel
    // (clause WHERE). Idempotent (IF NOT EXISTS) + error-ignored (si une base a par erreur 2 runs 'running'
    // pour un même engagement, la création est simplement sautée — best-effort, cohérent avec migrate()).
    // En mono-instance le FIFO garantit déjà l'invariant -> l'index ne se déclenche jamais (byte-identique).
    let _ = db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_run_job_running_per_engagement ON run_job(engagement_id) WHERE status='running'",
        [],
    );
    // SCHEMA VERSION STAMP : après avoir appliqué TOUTES les migrations additives ci-dessus (et créé la
    // table `settings`), on tamponne la version LOGIQUE courante ([`SCHEMA_VERSION`]). Upsert idempotent
    // (settings PK sur `key`) -> re-tamponné à chaque boot, sans doublon. C'est CE stamp que lisent
    // `/health`, `forge-console status` et le flux `upgrade` pour répondre « à quelle version est la base ».
    // fail-soft : une écriture échouée (base en lecture seule improbable ici) ne casse pas l'amorçage.
    let _ = crate::settings_set(db, SCHEMA_VERSION_KEY, &SCHEMA_VERSION.to_string());
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

/// POSTGRES UNIQUEMENT — recale les séquences IDENTITY des tables semées avec un id EXPLICITE au boot
/// (`dashboard` #1, `engagement` #1, `tenant` #1 — les SEULES tables où un seeder / le PG_SCHEMA écrit
/// un id littéral ; `panel`/`module`/`tenant_grant`/`scim_*` sont semés SANS id explicite, leur séquence
/// avance normalement). Sur Postgres ces colonnes `id` sont `GENERATED BY DEFAULT AS IDENTITY` : un INSERT
/// à id explicite N'AVANCE PAS la séquence, donc le PREMIER INSERT-sans-id au runtime régénère id=1 ->
/// `duplicate key` (HTTP 500). `setval(seq, max(id))` réaligne la séquence sur le max courant : le prochain
/// id GÉNÉRÉ vaut max(id)+1, plus aucune collision. `pg_get_serial_sequence(t,'id')` résout le nom de la
/// séquence de la colonne IDENTITY. `GREATEST(COALESCE(max(id),1),1)` borne à >=1 (setval exige un
/// argument >=1 ; table vide -> séquence à 1). Idempotent : re-`setval` à max(id) est stable, sûr à CHAQUE
/// boot. NO-OP en COMMUNITY/SQLite (`is_postgres()` const false -> early-return ; la branche PG est DCE,
/// binaire SQLite inchangé) — la séquence implicite du rowid SQLite est de toute façon correcte.
pub(crate) fn advance_pg_identity_sequences(store: &crate::store::Store) {
    if !store.is_postgres() {
        return;
    }
    for table in ["dashboard", "engagement", "tenant"] {
        let sql = format!(
            "SELECT setval(pg_get_serial_sequence('{t}','id'), (SELECT GREATEST(COALESCE(max(id),1),1) FROM {t}))",
            t = table
        );
        let _ = store.execute(&sql, &crate::sql_params![]);
    }
}

/// POSTGRES UNIQUEMENT — variante EXHAUSTIVE de [`advance_pg_identity_sequences`] pour la migration de
/// données (`migrate-store`). Là où la version boot ne recale que les 3 tables semées à id explicite, la
/// migration COPIE des ids explicites dans TOUTES les colonnes IDENTITY (id de chaque table + `seq` du
/// ledger_entry + tout `scim_*`/`sso_*` présent) : chacune doit être recalée sinon le PREMIER INSERT-sans-id
/// post-migration régénère un id déjà pris -> `duplicate key`. On DÉCOUVRE dynamiquement chaque colonne
/// IDENTITY du schéma courant via `information_schema.columns.is_identity='YES'` (couvre `id` ET `seq`, base
/// ET modules enterprise), puis `setval(seq, GREATEST(COALESCE(max(col),1),1))` sur chacune. Les noms
/// viennent du CATALOGUE (jamais d'entrée utilisateur) -> interpolation sûre. Renvoie la liste
/// `(table, colonne, valeur_de_séquence)` pour le rapport/preuve. NO-OP + `Ok(vec![])` en SQLite.
#[cfg(feature = "store-postgres")]
pub(crate) fn advance_pg_identity_sequences_all(
    store: &crate::store::Store,
) -> crate::store::StoreResult<Vec<(String, String, i64)>> {
    if !store.is_postgres() {
        return Ok(vec![]);
    }
    let cols = store.query(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema = current_schema() AND is_identity = 'YES' \
         ORDER BY table_name, column_name",
        &crate::sql_params![],
        |r| Ok((r.get_str(0)?, r.get_str(1)?)),
    )?;
    let mut out = Vec::with_capacity(cols.len());
    for (t, c) in cols {
        let sql = format!(
            "SELECT setval(pg_get_serial_sequence('{t}','{c}'), (SELECT GREATEST(COALESCE(max({c}),1),1) FROM {t}))"
        );
        let v = store.query_row(&sql, &crate::sql_params![], |r| r.get_i64(0))?;
        out.push((t, c, v));
    }
    Ok(out)
}

/// `web_allowed` : un module est lançable depuis l'UI web seulement s'il n'exploite pas, n'est pas
/// destructif, et n'est pas l'interception IDOR (qui tamper une requête en vol — réservé CLI/opérateur).
pub(crate) fn module_web_allowed(kind: &str, exploit: bool, destructive: bool) -> bool {
    !exploit && !destructive && kind != "evasion.idor_intercept"
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

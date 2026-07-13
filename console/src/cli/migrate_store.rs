// SPDX-License-Identifier: AGPL-3.0-only
//! `forge migrate-store` — migrateur gouverné SQLite -> Postgres (PURE MOVE depuis cli.rs).
// ===========================================================================================
// `forge migrate-store` (feature `store-postgres`) — MIGRATEUR DE DONNÉES GOUVERNÉ
// SQLite -> Postgres. Copie CHAQUE table du backend SQLite (source) vers un Postgres (cible) À
// TRAVERS LE SEAM (`Store`), en PRÉSERVANT les ids exacts et le typage par cellule (int/real/text/
// blob/null ; bool=0/1), en ORDRE de dépendance FK (parents avant enfants), puis RECALE toutes les
// séquences IDENTITY et VÉRIFIE le nombre de lignes table par table. Gouvernance : refuse d'écraser
// une cible non vide sans `--force` (avec `--force` -> TRUNCATE ... RESTART IDENTITY des tables cibles).
// `--dry-run` : lecture seule, n'écrit RIEN dans la cible. Émet un checkpoint ledger SIGNÉ (chaîné
// SHA-256, alg `sha256-console`, comme tout acte console) `console.store.migrate` traçant la provenance
// (source, cible RÉDIGÉE sans credentials, comptes par table, horodatage, drapeau dry-run).
//
// TOUT ce bloc est gardé `#[cfg(feature = "store-postgres")]` : le build community (défaut) ne le
// compile pas et reste BYTE-IDENTICAL + openssl-free. Aucune dépendance nouvelle (réutilise le seam
// postgres/rustls + l'infra ledger `ledger_append_standalone`/`verify_ledger_chain`).
// ===========================================================================================
use crate::*;
use serde_json::Value;

/// ORDRE de dépendance FK (tri topologique) — parents AVANT enfants. Dérivé des FK LOGIQUES de
/// `PG_SCHEMA` + des tables ENTERPRISE (aucune contrainte `REFERENCES` dure n'est déclarée, donc l'ordre
/// d'insertion est en fait libre côté contrainte ; on le fixe quand même pour la CORRECTION si des FK
/// sont un jour ajoutées et pour la lisibilité du rapport). Ce n'est PAS la liste autoritative des tables
/// à migrer — celle-ci est ÉNUMÉRÉE DYNAMIQUEMENT depuis `sqlite_master` (cf. `enumerate_source_tables`) ;
/// cette constante ne sert QUE de HINT d'ordonnancement (`order_migration_tables`). Couvre les 17 tables
/// de base de `PG_SCHEMA` PUIS les 5 tables enterprise créées paresseusement (`scim_*`/`sso_pending`/
/// `rbac_group_map`, hors `PG_SCHEMA` — matérialisées sur la cible par leurs modules via `ensure_pg_schema`).
/// Toute table source ABSENTE de ce hint est quand même migrée (appended à la fin par `order_migration_tables`)
/// ou hard-fail si la cible ne peut la créer — JAMAIS de skip silencieux.
#[cfg(feature = "store-postgres")]
const MIGRATE_STORE_FK_ORDER: &[&str] = &[
    // racines (aucun parent logique)
    "tenant",          // parent de engagement, rbac_group_map
    "users",           // parent de session, tenant_grant, scim_user, scim_group_member
    "dashboard",       // parent de panel
    "campaign",
    "module",
    "settings",
    "finding_template",
    "ledger_entry",
    // enfants (base)
    "engagement",      // -> tenant
    "tenant_grant",    // -> users, tenant
    "panel",           // -> dashboard
    "session",         // -> users
    "finding",         // -> engagement
    "runrecord",       // -> engagement
    "roe_decision",    // -> engagement
    "run_job",         // -> engagement
    "run_log",         // -> run_job (par run_id, FK souple)
    // tables ENTERPRISE (créées paresseusement, hors PG_SCHEMA ; dépendent de users/tenant déjà copiés)
    "scim_user",         // -> users (user_id = users.id, PK explicite)
    "scim_group",        // racine (id IDENTITY BY DEFAULT — recalée par advance_pg_identity_sequences_all)
    "scim_group_member", // -> scim_group, users
    "sso_pending",       // racine (PK state TEXT ; état d'auth OIDC éphémère)
    "rbac_group_map",    // -> tenant (tenant_id nullable ; mappings IdP-groupe -> rôle)
];

/// Convertit une cellule lue (`Value`, côté READ) en paramètre lié (`Param`, côté BIND) en préservant le
/// typage exact : Int->Int, Real->Real, Text->Text, Blob->Blob, Null->Null. Les booléens SQLite sont déjà
/// des `Int` 0/1 (SQLite n'a pas de classe bool) et se relient en BIGINT 0/1 côté PG (parité du schéma).
#[cfg(feature = "store-postgres")]
fn value_to_param(v: crate::store::Value) -> crate::store::Param {
    use crate::store::{Param, Value};
    match v {
        Value::Int(i) => Param::Int(i),
        Value::Real(f) => Param::Real(f),
        Value::Text(s) => Param::Text(s),
        Value::Blob(b) => Param::Blob(b),
        Value::Null => Param::Null,
    }
}

/// Noms de colonnes d'une table SQLite source, dans l'ordre du schéma (`PRAGMA table_info`). On copie
/// EXACTEMENT ces colonnes (INSERT nommé) -> aucune liste codée en dur, robuste à la dérive de schéma ;
/// PG mappe par NOM donc l'ordre interne de la cible est indifférent.
#[cfg(feature = "store-postgres")]
fn sqlite_table_columns(src: &crate::store::Store, table: &str) -> crate::store::StoreResult<Vec<String>> {
    // `PRAGMA table_info` renvoie (cid, name, type, notnull, dflt_value, pk) — le nom est en index 1.
    src.query(&format!("PRAGMA table_info({table})"), &crate::sql_params![], |r| r.get_str(1))
}

/// ÉNUMÈRE les tables UTILISATEUR de la source SQLite — l'ensemble AUTORITATIF à migrer, découvert
/// DYNAMIQUEMENT (jamais une liste codée en dur). `SELECT name FROM sqlite_master WHERE type='table'` ;
/// exclut les tables INTERNES SQLite (`sqlite_%` : `sqlite_sequence`, `sqlite_stat*`, etc.). Aucune table de
/// bookkeeping de migration n'existe côté console (les migrations additives passent par `ALTER TABLE`
/// error-ignored, pas par une table `schema_migrations`), donc `NOT LIKE 'sqlite_%'` suffit. C'est CE set
/// (et non les 22 du hint FK) qui pilote copie + vérif : une table enterprise créée paresseusement
/// (`scim_*`/`sso_pending`/`rbac_group_map`) présente dans la source est donc TOUJOURS reprise.
#[cfg(feature = "store-postgres")]
fn enumerate_source_tables(src: &crate::store::Store) -> crate::store::StoreResult<Vec<String>> {
    src.query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        &crate::sql_params![],
        |r| r.get_str(0),
    )
}

/// ÉNUMÈRE les tables présentes sur la CIBLE Postgres (`information_schema.tables` du schéma courant) —
/// sert au contrôle « la cible possède-t-elle CHAQUE table source ? » AVANT copie (no silent skip).
#[cfg(feature = "store-postgres")]
fn enumerate_dest_tables(store: &crate::store::Store) -> crate::store::StoreResult<Vec<String>> {
    store.query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()",
        &crate::sql_params![],
        |r| r.get_str(0),
    )
}

/// ORDONNE l'ensemble énuméré `src_tables` en ordre de dépendance FK : d'abord les tables connues dans
/// l'ordre de `MIGRATE_STORE_FK_ORDER` (parents avant enfants — filtrées à celles réellement présentes dans
/// la source), PUIS toute table source INCONNUE du hint, ajoutée à la fin (jamais droppée). Une table
/// inconnue échouera le contrôle de présence côté cible avec un message clair — jamais de skip silencieux.
#[cfg(feature = "store-postgres")]
fn order_migration_tables(src_tables: &[String]) -> Vec<String> {
    let mut ordered: Vec<String> = Vec::with_capacity(src_tables.len());
    for known in MIGRATE_STORE_FK_ORDER {
        if src_tables.iter().any(|t| t == known) {
            ordered.push((*known).to_string());
        }
    }
    for t in src_tables {
        if !MIGRATE_STORE_FK_ORDER.contains(&t.as_str()) {
            ordered.push(t.clone());
        }
    }
    ordered
}

/// Compte les lignes d'une table via le seam (source SQLite ou cible PG). `count(*)` -> entier.
#[cfg(feature = "store-postgres")]
fn count_rows(store: &crate::store::Store, table: &str) -> crate::store::StoreResult<i64> {
    store.query_row(&format!("SELECT count(*) FROM {table}"), &crate::sql_params![], |r| r.get_i64(0))
}

/// Compte les lignes cible en TOLÉRANT une table absente (renvoie 0) — pour le rapport `--dry-run` sur une
/// cible dont le schéma n'a pas (encore) été appliqué.
#[cfg(feature = "store-postgres")]
fn count_rows_lenient(store: &crate::store::Store, table: &str) -> i64 {
    count_rows(store, table).unwrap_or(0)
}

/// Une ligne du tableau de vérification : table, comptes source et cible.
#[cfg(feature = "store-postgres")]
struct MigTableCount {
    table: String,
    source: i64,
    dest: i64,
}

/// Rapport de migration renvoyé par le cœur, consommé par le checkpoint ledger + l'affichage.
#[cfg(feature = "store-postgres")]
struct MigrationReport {
    counts: Vec<MigTableCount>,
    identity: Vec<(String, String, i64)>,
    total_rows: i64,
}

/// Copie une table de la source vers la cible (dans la transaction `tx`), en préservant ids + typage.
/// Renvoie le nombre de lignes copiées. Colonnes lues dynamiquement (`PRAGMA table_info`), valeurs via
/// l'accesseur dynamique `Row::get_value` -> `Param` (typage exact conservé). INSERT nommé -> ids explicites
/// PRÉSERVÉS (la colonne IDENTITY est `GENERATED BY DEFAULT`, donc un id fourni est accepté tel quel).
#[cfg(feature = "store-postgres")]
fn copy_table(
    src: &crate::store::Store,
    tx: &crate::store::Tx,
    table: &str,
) -> crate::store::StoreResult<i64> {
    let cols = sqlite_table_columns(src, table)?;
    if cols.is_empty() {
        return Ok(0);
    }
    let col_list = cols.join(", ");
    let placeholders = vec!["?"; cols.len()].join(", ");
    let insert_sql = format!("INSERT INTO {table} ({col_list}) VALUES ({placeholders})");
    let select_sql = format!("SELECT {col_list} FROM {table}");
    let ncols = cols.len();
    // Lit toutes les lignes source en vecteurs de Param (typage exact), STRICT : une cellule illisible
    // sinke la migration (jamais de perte silencieuse). `query` (pas `query_lax`) -> échec dur au 1er souci.
    let rows: Vec<Vec<crate::store::Param>> = src.query(&select_sql, &crate::sql_params![], |row| {
        let mut binds = Vec::with_capacity(ncols);
        for i in 0..ncols {
            binds.push(value_to_param(row.get_value(i)?));
        }
        Ok(binds)
    })?;
    let mut copied = 0i64;
    for binds in &rows {
        tx.execute(&insert_sql, binds)?;
        copied += 1;
    }
    Ok(copied)
}

/// Cœur de la migration : applique le schéma cible (hors dry-run), vérifie la gouvernance (refuse une
/// cible non vide sans `--force`), copie toutes les tables en ordre FK dans UNE transaction, recale les
/// séquences IDENTITY, vérifie les comptes ligne à ligne, et COMMIT seulement si tout concorde (sinon
/// ROLLBACK -> aucune migration partielle silencieuse). `Ok(Some(report))` = migration effectuée/dry-run ;
/// `Ok(None)` = refus de gouvernance (cible non vide, pas de `--force`) ; `Err` = échec dur (comptes
/// discordants -> rollback, ou erreur IO/SQL).
#[cfg(feature = "store-postgres")]
fn migrate_store_core(
    src: &crate::store::Store,
    dst: &crate::store::Store,
    dry_run: bool,
    force: bool,
) -> crate::store::StoreResult<Option<MigrationReport>> {
    use crate::store::StoreError;

    // ENSEMBLE AUTORITATIF : CHAQUE table utilisateur de la source, énumérée DYNAMIQUEMENT depuis
    // `sqlite_master` (jamais une liste codée en dur) — couvre les tables enterprise créées paresseusement
    // (`scim_*`/`sso_pending`/`rbac_group_map`) si elles existent dans la source. Ordonnée en dépendance FK
    // (parents avant enfants ; toute table inconnue du hint est appended, jamais droppée).
    let src_tables = enumerate_source_tables(src)?;
    let tables = order_migration_tables(&src_tables);

    if dry_run {
        // LECTURE SEULE : n'applique PAS le schéma, n'écrit RIEN. Rapporte les comptes source (ce qui SERAIT
        // copié) + les comptes cible actuels (tolérant si une table n'existe pas côté cible).
        let mut counts = Vec::with_capacity(tables.len());
        let mut total = 0i64;
        for t in &tables {
            let s = count_rows(src, t)?;
            total += s;
            counts.push(MigTableCount { table: t.clone(), source: s, dest: count_rows_lenient(dst, t) });
        }
        return Ok(Some(MigrationReport { counts, identity: vec![], total_rows: total }));
    }

    // 1) Schéma cible idempotent (CREATE TABLE IF NOT EXISTS ...). Non destructif ; hors transaction pour
    //    que les tables persistent même si la copie rollback (elles servent aussi au compte de gouvernance).
    //    On applique le SCHÉMA DE BASE (`PG_SCHEMA`) PUIS les tables ENTERPRISE créées paresseusement via le
    //    chemin PG `ensure_schema` de chaque module (scim/sso/rbac) — sinon `scim_*`/`sso_pending`/
    //    `rbac_group_map` seraient absentes de la cible et la copie perdrait identités provisionnées + mappings
    //    d'autorisation IdP->rôle EN SILENCE. C'est ce que corrige ce bloc.
    dst.execute_batch(crate::schema::PG_SCHEMA)?;
    crate::scim::ensure_pg_schema(dst);
    crate::sso::ensure_pg_schema(dst);
    crate::rbac::ensure_pg_schema(dst);

    // 2) NO SILENT SKIP : toute table source ÉNUMÉRÉE encore ABSENTE de la cible après (1) (une table
    //    inconnue que ni `PG_SCHEMA` ni les modules enterprise ne créent) -> HARD-FAIL en la NOMMANT. On ne
    //    DEVINE JAMAIS un DDL (option sûre : plutôt échouer clairement que copier une table à la structure
    //    incertaine). Zéro écriture de données à ce stade -> rien à rollback, aucun checkpoint émis.
    let dest_tables = enumerate_dest_tables(dst)?;
    let missing: Vec<String> = tables.iter().filter(|t| !dest_tables.contains(*t)).cloned().collect();
    if !missing.is_empty() {
        return Err(StoreError::Backend(format!(
            "cible dépourvue de {} table(s) source (aucun schéma connu — base ou enterprise — ne les crée ; \
             migration REFUSÉE plutôt qu'un skip silencieux ou un DDL deviné) : {}",
            missing.len(),
            missing.join(", ")
        )));
    }

    // 3) GOUVERNANCE : si une table cible contient déjà des données -> refus sauf `--force`.
    let mut existing = 0i64;
    for t in &tables {
        existing += count_rows(dst, t)?;
    }
    if existing > 0 && !force {
        return Ok(None);
    }

    // 4) Copie atomique : TRUNCATE (si --force) -> copie ordre FK -> recale IDENTITY -> vérif -> commit.
    let report = dst.with_tx(|tx| {
        if force && existing > 0 {
            // TRUNCATE ... RESTART IDENTITY CASCADE remet les tables cibles à zéro ET réinitialise leurs
            // séquences ; les ids explicites recopiés puis `advance_pg_identity_sequences_all` fixent la suite.
            let all = tables.join(", ");
            tx.execute_batch(&format!("TRUNCATE {all} RESTART IDENTITY CASCADE"))?;
        }
        // Copie CHAQUE table énumérée (ensemble autoritatif de `sqlite_master`, PAS un sous-ensemble codé en
        // dur) — chaque table copiée est ensuite vérifiée source==cible ci-dessous.
        let mut counts = Vec::with_capacity(tables.len());
        let mut total = 0i64;
        for t in &tables {
            let copied = copy_table(src, tx, t)?;
            total += copied;
            counts.push(MigTableCount { table: t.clone(), source: copied, dest: 0 });
        }
        // Recale TOUTES les séquences IDENTITY (id + seq + scim_*/sso_* éventuels) — après insertion des
        // ids explicites, sinon le 1er INSERT-sans-id post-migration collisionne. ⚠️ CORRECTIF Stage-3 :
        // `setval` N'EST **PAS** transactionnel en Postgres — les modifications de séquence ne sont JAMAIS
        // annulées par un ROLLBACK (les séquences sont non-transactionnelles by design). Si la vérif des
        // comptes ci-dessous échoue et que `with_tx` rollback, les DONNÉES cibles sont bien restaurées mais
        // les séquences restent avancées. C'est INOFFENSIF ici : sur rollback la cible retourne à son état
        // pré-migration (vide, ou pré-`--force`), et un simple retry — soit `--force` (TRUNCATE ... RESTART
        // IDENTITY remet les séquences à zéro), soit sur une cible vide (le prochain `setval` les recale sur
        // max(id) réel) — reconverge. Aucune corruption : des séquences en avance ne produisent que des ids
        // plus grands, jamais de collision.
        let identity = crate::schema::advance_pg_identity_sequences_all(tx.store())?;
        // VÉRIFICATION : source vs cible, table par table (comptes relus DANS la transaction).
        let mut mismatch = false;
        for c in counts.iter_mut() {
            let dest = count_rows(tx.store(), &c.table)?;
            c.dest = dest;
            let src_n = count_rows(src, &c.table)?;
            c.source = src_n;
            if dest != src_n {
                mismatch = true;
            }
        }
        if mismatch {
            // Échec DUR -> `Err` déclenche le ROLLBACK de `with_tx` : la cible reste intacte (jamais de
            // migration partielle silencieuse). Le message liste les tables discordantes.
            let detail: Vec<String> = counts
                .iter()
                .filter(|c| c.source != c.dest)
                .map(|c| format!("{}(src={}, dst={})", c.table, c.source, c.dest))
                .collect();
            return Err(StoreError::Backend(format!("row-count mismatch: {}", detail.join(", "))));
        }
        Ok(MigrationReport { counts, identity, total_rows: total })
    })?;
    Ok(Some(report))
}

/// Imprime le tableau de vérification des comptes (table | source | cible | ok).
#[cfg(feature = "store-postgres")]
fn print_migration_counts(report: &MigrationReport) {
    let columns = vec!["table".to_string(), "source".to_string(), "dest".to_string(), "match".to_string()];
    let rows: Vec<Vec<String>> = report
        .counts
        .iter()
        .map(|c| {
            vec![
                c.table.clone(),
                c.source.to_string(),
                c.dest.to_string(),
                if c.source == c.dest { "OK".to_string() } else { "MISMATCH".to_string() },
            ]
        })
        .collect();
    print_table(&columns, &rows);
}

/// `forge migrate-store --to <postgres-url> [--from <sqlite-path>] [--dry-run] [--force]
///   [--ledger <path>]` — migrateur gouverné SQLite -> Postgres (feature `store-postgres`).
/// Codes de sortie : 0 = OK ; 1 = refus de gouvernance (cible non vide sans `--force`) OU comptes
/// discordants (rollback) ; 2 = usage / connexion / schéma ; 3 = migration COMMITTÉE mais checkpoint
/// ledger tamper-evident non écrit (gouvernance : jamais de succès sans checkpoint auditable).
#[cfg(feature = "store-postgres")]
pub(crate) fn run_migrate_store_cli(args: &[String]) -> i32 {
    let to_url = match cli_opt(args, "to").filter(|s| !s.is_empty()) {
        Some(u) => u,
        None => {
            eprintln!("usage: forge migrate-store --to <postgres-url> [--from <sqlite-path>] [--dry-run] [--force] [--ledger <path>]");
            eprintln!("  Migre le backend SQLite (source) vers Postgres (cible), ids + typage préservés,");
            eprintln!("  ordre FK, recalage IDENTITY, vérif des comptes, checkpoint ledger signé. `--dry-run`");
            eprintln!("  n'écrit RIEN. Sans `--force`, refuse d'écraser une cible non vide (idempotence).");
            return 2;
        }
    };
    let from = cli_opt(args, "from").filter(|s| !s.is_empty()).unwrap_or_else(cli_db_path);
    let dry_run = cli_flag(args, "dry-run");
    let force = cli_flag(args, "force");
    let ledger_path = cli_opt(args, "ledger")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("FORGE_CONSOLE_LEDGER").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "engagement.jsonl".to_string());

    let dest_redacted = redact_pg_url(&to_url);
    eprintln!("[forge] migrate-store: source SQLite='{from}' -> cible PG='{dest_redacted}'{}{}",
        if dry_run { "  [DRY-RUN]" } else { "" },
        if force { "  [--force]" } else { "" });

    // La source SQLite est ouverte en READ-ONLY (défense en profondeur : la migration ne mute JAMAIS la
    // source). Le client PG et la connexion source vivent sur le MÊME thread hors-runtime (`with_pg_store`)
    // — requis par le client postgres synchrone (connect + Drop pilotent leur propre `block_on`).
    let outcome: Result<crate::store::StoreResult<Option<MigrationReport>>, String> =
        with_pg_store(&to_url, |dst| {
            let src_conn = match crate::cli::cli_open_ro(&from) {
                Some(c) => c,
                None => return Err(crate::store::StoreError::Backend(format!("source SQLite illisible: {from}"))),
            };
            let src_mutex = std::sync::Mutex::new(src_conn);
            let src = crate::store::Store::sqlite(src_mutex.lock().unwrap_or_else(|e| e.into_inner()));
            migrate_store_core(&src, dst, dry_run, force)
        });

    let report = match outcome {
        Ok(Ok(Some(r))) => r,
        Ok(Ok(None)) => {
            eprintln!("[forge] migrate-store: REFUSÉ — la cible contient déjà des données.");
            eprintln!("  Relance avec --force pour ÉCRASER (TRUNCATE ... RESTART IDENTITY des tables cibles),");
            eprintln!("  ou --dry-run pour inspecter sans écrire. Aucune donnée n'a été touchée.");
            return 1;
        }
        Ok(Err(e)) => {
            // Inclut le rollback sur comptes discordants (message "row-count mismatch: ...").
            eprintln!("[forge] migrate-store: ÉCHEC — {e}");
            let es = e.to_string();
            return if es.contains("row-count mismatch") { 1 } else { 2 };
        }
        Err(e) => {
            eprintln!("[forge] migrate-store: {e}");
            return 2;
        }
    };

    // Ordre RÉEL des tables migrées (ensemble énuméré dynamiquement, en ordre FK) — dérivé du rapport, PAS
    // d'une constante : c'est la VRAIE liste reprise (base + enterprise), servie au rapport ET au checkpoint.
    let migrated_order: Vec<String> = report.counts.iter().map(|c| c.table.clone()).collect();

    // Rapport lisible : ordre FK + tableau de comptes + recalage des séquences.
    println!("[forge] migrate-store: ordre FK (parents -> enfants) :");
    println!("  {}", migrated_order.join(" -> "));
    if dry_run {
        println!("[forge] migrate-store [DRY-RUN] : lignes QUI SERAIENT copiées (source) vs cible actuelle :");
    } else {
        println!("[forge] migrate-store : vérification des comptes (source == cible) :");
    }
    print_migration_counts(&report);
    if !dry_run && !report.identity.is_empty() {
        println!("[forge] migrate-store : séquences IDENTITY recalées (table.colonne -> valeur) :");
        for (t, c, v) in &report.identity {
            println!("  {t}.{c} -> {v}");
        }
    }

    // CHECKPOINT LEDGER SIGNÉ (chaîné SHA-256, alg `sha256-console`, sig chaîne — comme tout acte console ;
    // un sig Ed25519 sur un kind `console.*` est INTERDIT par la garde alg<->kind, cf. compliance.rs). La
    // cible est RÉDIGÉE (aucun credential dans l'audit). Émis aussi en dry-run (trace qu'un dry-run a eu lieu).
    let per_table: Vec<Value> = report
        .counts
        .iter()
        .map(|c| serde_json::json!({"table": c.table, "source": c.source, "dest": c.dest}))
        .collect();
    let detail = serde_json::json!({
        "source": from,
        "dest": dest_redacted,
        "dry_run": dry_run,
        "forced": force,
        "total_rows": report.total_rows,
        "fk_order": migrated_order,
        "tables": per_table,
        "ts_unix": crate::state::chrono_now_compact(),
    });
    let checkpoint = crate::dbmigrate::ledger_append_standalone(&ledger_path, "console.store.migrate", &detail);
    match &checkpoint {
        Ok(hash) => {
            println!("[forge] migrate-store : checkpoint ledger '{ledger_path}' (console.store.migrate) signé, hash={hash}");
        }
        Err(e) => {
            eprintln!("[forge] migrate-store: AVERTISSEMENT — écriture du checkpoint ledger échouée: {e}");
        }
    }

    if dry_run {
        // DRY-RUN : AUCUNE donnée committée -> un échec de checkpoint n'a rien à « rendre invérifiable ».
        // On le signale (ci-dessus) mais on sort 0 : rien n'a été migré, il n'y a pas de succès à trahir.
        println!("[forge] migrate-store [DRY-RUN] terminé — AUCUNE écriture dans la cible.");
        return 0;
    }

    // GOUVERNANCE (correctif Stage-3) : la migration est COMMITTÉE mais son checkpoint tamper-evident
    // a ÉCHOUÉ -> ne JAMAIS rapporter un succès (exit 0). Une migration sans son checkpoint signé n'est
    // pas auditable : on sort NON-ZÉRO (3, distinct de 1=gouvernance/mismatch et 2=usage/connexion) pour
    // que l'orchestrateur/CI le traite comme un échec et exige la ré-émission manuelle du checkpoint.
    if checkpoint.is_err() {
        eprintln!("[forge] migrate-store: ÉCHEC GOUVERNANCE — {} ligne(s) migrée(s) et COMMITTÉE(s), mais le checkpoint ledger signé n'a PAS pu être écrit (ci-dessus). La migration N'EST PAS auditable ; exit non-zéro. Vérifie l'accessibilité/permissions du ledger '{ledger_path}' puis ré-émets le checkpoint console.store.migrate.", report.total_rows);
        return 3;
    }

    println!("[forge] migrate-store terminé — {} ligne(s) migrée(s), comptes vérifiés.", report.total_rows);
    0
}

// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — VUES DE REPORTING en LECTURE SEULE du modele ROUGE : PURE MOVE extrait de `findings.rs`.
//! Endpoints d'agregation ISOLES par engagement actif (`resolve_view_engagement_id`, fail-closed) :
//! `runrecords`, `campaigns`, `roe`, `coverage` (couverture ATT&CK) et `attack_matrix` (grille TACTIQUE x
//! TECHNIQUE kill-chain) + le catalogue de reference (`ATTACK_TACTICS`/`ATTACK_CATALOG`/`attack_tactic_for`/
//! `attack_sort_techs`). Aucune mutation ; un engagement ne voit JAMAIS les donnees d'un autre. Reutilise
//! App + les helpers de la racine (`resolve_view_engagement_id`/`paginate`) via `use crate::*`, re-exporte
//! `pub(crate)` a la racine — routes de build_router (`get(coverage)`, `get(attack_matrix)`, …) ET tests
//! inline (`super::*`) resolus INCHANGES. `coverage`/`attack_matrix` LIENT `engagement_id=?` (isolation).
use crate::*;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json};
use crate::store::Param;
use serde_json::{json, Value};
use std::collections::HashMap;

pub(crate) async fn runrecords(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : les runrecords de la vue sont ceux de l'engagement actif UNIQUEMENT (isolation).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    
    // `engagement_id` (entier résolu) LIÉ en 1er Param ; `fired=1` reste un littéral fixe (aucune valeur).
    let (mut conds, mut params): (Vec<String>, Vec<Param>) = (vec!["engagement_id=?".into()], vec![Param::Int(eid)]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?".into()); params.push(Param::Text(c.clone())); }
    if let Some(t) = q.get("target") { conds.push("target=?".into()); params.push(Param::Text(t.clone())); }
    if let Some(m) = q.get("mitre") { conds.push("mitre=?".into()); params.push(Param::Text(m.clone())); }
    if let Some(r) = q.get("run_id") { conds.push("run_id=?".into()); params.push(Param::Text(r.clone())); }
    if q.get("fired").map(|v| v == "1" || v == "true").unwrap_or(false) { conds.push("fired=1".into()); }
    let where_ = format!(" WHERE {}", conds.join(" AND "));
    let (limit, offset) = paginate(&q, 500, 2000);
    // LIMIT/OFFSET (entiers clampés) LIÉS en derniers placeholders.
    params.push(Param::Int(limit));
    params.push(Param::Int(offset));
    let sql = format!(
        "SELECT id,ts,campaign,target,kind,mitre,fired,detail,run_id FROM runrecord{where_} ORDER BY id DESC LIMIT ? OFFSET ?"
    );
    // `fired` est un entier (0/1) — colonne réelle ; on la rend telle quelle via une requête typée.
    // LENIENT: prepare échoué -> Err -> unwrap_or_default -> [] (idem early-return), lignes mal formées ignorées.
    let out: Vec<Value> = app.store()
        .query_lax(&sql, &params, |r| {
            Ok(json!({
                "id": r.get_i64(0)?,
                "ts": r.get_opt_str(1)?.unwrap_or_default(),
                "campaign": r.get_opt_str(2)?.unwrap_or_default(),
                "target": r.get_opt_str(3)?.unwrap_or_default(),
                "kind": r.get_opt_str(4)?.unwrap_or_default(),
                "mitre": r.get_opt_str(5)?.unwrap_or_default(),
                "fired": r.get_opt_i64(6)?.unwrap_or(0),
                "detail": r.get_opt_str(7)?.unwrap_or_default(),
                "run_id": r.get_opt_str(8)?.unwrap_or_default(),
            }))
        })
        .unwrap_or_default();
    Json(Value::Array(out))
}

pub(crate) async fn campaigns(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : `campaign` est un sous-label LIBRE AU SEIN d'un engagement — on n'agrège donc QUE
    // les campagnes de l'engagement actif (une même chaîne dans un autre engagement reste invisible ici).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    
    // Agrège depuis les findings (source réelle) + table campaign (métadonnées). Pas de JOIN strict :
    // on liste les campagnes vues côté findings + celles déclarées, avec leurs compteurs.
    // LENIENT: prepare échoué -> Err -> unwrap_or_default -> [] (idem early-return), lignes mal formées ignorées.
    let out: Vec<Value> = app.store()
        .query_lax(
            "SELECT campaign, COUNT(*) AS findings, MAX(ts) AS last_ts FROM finding WHERE campaign<>'' AND engagement_id=? GROUP BY campaign ORDER BY last_ts DESC",
            &crate::sql_params![eid],
            |r| {
                Ok(json!({
                    "campaign": r.get_str(0)?,
                    "findings": r.get_i64(1)?,
                    "last_ts": r.get_opt_str(2)?.unwrap_or_default(),
                }))
            },
        )
        .unwrap_or_default();
    Json(Value::Array(out))
}

pub(crate) async fn roe(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : les décisions du garde-fou sont celles de l'engagement actif UNIQUEMENT (isolation).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    
    // `engagement_id` (entier résolu) LIÉ en 1er Param ; filtres optionnels et LIMIT/OFFSET liés ensuite.
    let (mut conds, mut params): (Vec<String>, Vec<Param>) = (vec!["engagement_id=?".into()], vec![Param::Int(eid)]);
    if let Some(c) = q.get("campaign") { conds.push("campaign=?".into()); params.push(Param::Text(c.clone())); }
    if let Some(r) = q.get("run_id") { conds.push("run_id=?".into()); params.push(Param::Text(r.clone())); }
    if let Some(v) = q.get("verdict") { conds.push("verdict=?".into()); params.push(Param::Text(v.clone())); }
    let where_ = format!(" WHERE {}", conds.join(" AND "));
    let (limit, offset) = paginate(&q, 500, 2000);
    params.push(Param::Int(limit));
    params.push(Param::Int(offset));
    let sql = format!(
        "SELECT id,ts,campaign,run_id,action_id,target,kind,verdict,exploit,destructive,reasons FROM roe_decision{where_} ORDER BY id DESC LIMIT ? OFFSET ?"
    );
    // LENIENT: prepare échoué -> Err -> unwrap_or_default -> [] (idem early-return), lignes mal formées ignorées.
    let out: Vec<Value> = app.store()
        .query_lax(&sql, &params, |r| {
            // reasons stocké en JSON (array) — on le re-parse pour le rendre structuré au front.
            let reasons_raw: String = r.get_opt_str(10)?.unwrap_or_default();
            let reasons = serde_json::from_str::<Value>(&reasons_raw).unwrap_or(Value::String(reasons_raw));
            Ok(json!({
                "id": r.get_i64(0)?,
                "ts": r.get_opt_str(1)?.unwrap_or_default(),
                "campaign": r.get_opt_str(2)?.unwrap_or_default(),
                "run_id": r.get_opt_str(3)?.unwrap_or_default(),
                "action_id": r.get_opt_str(4)?.unwrap_or_default(),
                "target": r.get_opt_str(5)?.unwrap_or_default(),
                "kind": r.get_opt_str(6)?.unwrap_or_default(),
                "verdict": r.get_opt_str(7)?.unwrap_or_default(),
                "exploit": r.get_i64(8)? != 0,
                "destructive": r.get_i64(9)? != 0,
                "reasons": reasons,
            }))
        })
        .unwrap_or_default();
    Json(Value::Array(out))
}

pub(crate) async fn coverage(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : couverture ATT&CK de l'engagement actif UNIQUEMENT (engagement_id résolu, inliné).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    
    // filtre campaign optionnel (param lié). `engagement_id` (entier résolu) LIÉ AUSSI : il apparaît AVANT
    // `campaign=?` dans le SQL, donc son Param est en PREMIER (ordre des placeholders).
    let (sql, params): (String, Vec<Param>) = match q.get("campaign") {
        Some(c) => (
            "SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' AND engagement_id=? AND campaign=? GROUP BY mitre ORDER BY n DESC".to_string(),
            vec![Param::Int(eid), Param::Text(c.clone())],
        ),
        None => (
            "SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' AND engagement_id=? GROUP BY mitre ORDER BY n DESC".to_string(),
            vec![Param::Int(eid)],
        ),
    };
    // LENIENT: prepare échoué -> Err -> unwrap_or_default -> [] (idem early-return), lignes mal formées ignorées.
    let out: Vec<Value> = app.store()
        .query_lax(&sql, &params, |row| {
            Ok(json!({
                "mitre": row.get_str(0)?,
                "runs": row.get_i64(1)?,
                "fired": row.get_i64(2)?
            }))
        })
        .unwrap_or_default();
    Json(Value::Array(out))
}

// =====================================================================================
//  MATRICE ATT&CK PAR ENGAGEMENT (#P2-1) — grille TACTIQUE × TECHNIQUE (kill-chain), pas une simple
//  liste classée. Réutilise la couverture ENGAGEMENT-SCOPÉE (runrecord : runs=exercé, fired=détecté)
//  et range chaque technique dans sa colonne ATT&CK. Le CATALOGUE de référence (mêmes ids que
//  forge/techniques_data.py) fournit les cellules NON-EXERCÉES (la grille montre le tableau complet,
//  colonne vide = trou de couverture). Toute technique EXERCÉE dont l'id est hors catalogue tombe dans
//  « Unmapped/Other » — JAMAIS silencieusement supprimée (anti fabricated-completeness). Le MTTD est
//  fusionné côté client depuis /api/purple/coverage (best-effort). Aucun schéma, aucune dépendance.
// =====================================================================================

/// Colonnes ATT&CK Enterprise dans l'ordre du kill-chain (les 14 tactiques).
pub(crate) const ATTACK_TACTICS: [&str; 14] = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
];

/// Colonne hors kill-chain : techniques EXERCÉES à l'id inconnu (anti silent-drop).
pub(crate) const ATTACK_TACTIC_OTHER: &str = "Unmapped/Other";

/// Catalogue de référence : (technique_id ATT&CK, tactique). MIROIR FIGÉ de forge/techniques_data.py
/// (champ `mitre` -> `attck_tactic`). T1190 est canoniquement Initial Access (une entrée evasion.* le
/// taggue Defense Evasion — on retient la tactique ATT&CK canonique). Sert de grille de référence
/// (cellules NON-EXERCÉES) ; il n'est PAS engagement-scopé (c'est le tableau ATT&CK, pas des données).
pub(crate) const ATTACK_CATALOG: [(&str, &str); 25] = [
    ("T1046", "Discovery"),
    ("T1059", "Execution"),
    ("T1068", "Privilege Escalation"),
    ("T1110.001", "Credential Access"),
    ("T1190", "Initial Access"),
    ("T1204", "Execution"),
    ("T1204.001", "Execution"),
    ("T1210", "Lateral Movement"),
    ("T1212", "Credential Access"),
    ("T1406", "Discovery"),
    ("T1528", "Credential Access"),
    ("T1539", "Credential Access"),
    ("T1552.001", "Credential Access"),
    ("T1556", "Defense Evasion"),
    ("T1584.001", "Resource Development"),
    ("T1590", "Reconnaissance"),
    ("T1590.002", "Reconnaissance"),
    ("T1590.005", "Reconnaissance"),
    ("T1592.002", "Reconnaissance"),
    ("T1594", "Reconnaissance"),
    ("T1595", "Reconnaissance"),
    ("T1595.002", "Reconnaissance"),
    ("T1595.003", "Reconnaissance"),
    ("T1596", "Reconnaissance"),
    ("T1606", "Credential Access"),
];

/// Résout la tactique ATT&CK d'un id de technique. Ordre : (1) match exact ; (2) sous-technique
/// `T1595.003` -> base `T1595` ; (3) base `T1595` -> première sous-technique cataloguée `T1595.x`.
/// None => id vraiment hors catalogue -> l'appelant le range dans Unmapped/Other (jamais dropé).
pub(crate) fn attack_tactic_for(mitre: &str) -> Option<&'static str> {
    if let Some((_, t)) = ATTACK_CATALOG.iter().find(|(id, _)| *id == mitre) {
        return Some(t);
    }
    if let Some((base, _)) = mitre.split_once('.') {
        if let Some((_, t)) = ATTACK_CATALOG.iter().find(|(id, _)| *id == base) {
            return Some(t);
        }
    } else {
        let prefix = format!("{mitre}.");
        if let Some((_, t)) = ATTACK_CATALOG.iter().find(|(id, _)| id.starts_with(&prefix)) {
            return Some(t);
        }
    }
    None
}

/// Tri des techniques d'une colonne : EXERCÉES d'abord (les cellules « allumées » remontent), puis
/// par id croissant. Ordre déterministe -> rendu stable de la grille.
fn attack_sort_techs(v: &mut [Value]) {
    v.sort_by(|a, b| {
        let ea = a.get("exercised").and_then(|x| x.as_bool()).unwrap_or(false);
        let eb = b.get("exercised").and_then(|x| x.as_bool()).unwrap_or(false);
        eb.cmp(&ea).then_with(|| {
            let ia = a.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let ib = b.get("id").and_then(|x| x.as_str()).unwrap_or("");
            ia.cmp(ib)
        })
    });
}

pub(crate) async fn attack_matrix(State(app): State<App>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    // ENGAGEMENT : matrice de l'engagement actif UNIQUEMENT (engagement_id résolu, inliné) — mêmes
    // filtres que /api/coverage, donc AUCUNE fuite cross-engagement/tenant (le catalogue de référence
    // est statique, pas des données d'un autre engagement).
    let eid = resolve_view_engagement_id(&app, &headers, &q);
    // `engagement_id` (entier résolu) LIÉ, en PREMIER Param (apparaît avant `campaign=?`) ; campaign lié ensuite.
    let (sql, params): (String, Vec<Param>) = match q.get("campaign") {
        Some(c) => (
            "SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' AND engagement_id=? AND campaign=? GROUP BY mitre".to_string(),
            vec![Param::Int(eid), Param::Text(c.clone())],
        ),
        None => (
            "SELECT mitre, COUNT(*) n, COALESCE(SUM(fired),0) f FROM runrecord WHERE mitre<>'' AND engagement_id=? GROUP BY mitre".to_string(),
            vec![Param::Int(eid)],
        ),
    };
    // exercised = techniques réellement présentes dans les run-records de CET engagement.
    let rows: Vec<(String, i64, i64)> = app.store()
        .query_lax(&sql, &params, |row| Ok((row.get_str(0)?, row.get_i64(1)?, row.get_i64(2)?)))
        .unwrap_or_default();
    let mut exercised: HashMap<String, (i64, i64)> = HashMap::new();
    for (m, n, f) in rows {
        let e = exercised.entry(m).or_insert((0, 0));
        e.0 += n;
        e.1 += f;
    }

    // buckets tactique -> [cellules]. Une cellule = {id, exercised, detected(=fired>0), runs, fired}.
    let cell = |id: &str, ex: &HashMap<String, (i64, i64)>| -> Value {
        let (runs, fired) = ex.get(id).copied().unwrap_or((0, 0));
        json!({"id": id, "exercised": runs > 0, "detected": fired > 0, "runs": runs, "fired": fired})
    };
    let mut cells: HashMap<&str, Vec<Value>> = HashMap::new();
    let mut placed: std::collections::HashSet<String> = std::collections::HashSet::new();
    // 1) catalogue de référence -> cellule dans sa tactique (exercée OU non).
    for (id, tactic) in ATTACK_CATALOG.iter() {
        placed.insert((*id).to_string());
        cells.entry(tactic).or_default().push(cell(id, &exercised));
    }
    // 2) techniques EXERCÉES hors catalogue -> tactique résolue (repli sous-/base-technique) ou
    //    Unmapped/Other. On ne dépose JAMAIS silencieusement : chaque id exercé apparaît quelque part.
    let mut extra: Vec<(&String, (i64, i64))> =
        exercised.iter().filter(|(id, _)| !placed.contains(*id)).map(|(id, v)| (id, *v)).collect();
    extra.sort_by(|a, b| a.0.cmp(b.0));
    for (id, (runs, fired)) in extra {
        let tactic = attack_tactic_for(id).unwrap_or(ATTACK_TACTIC_OTHER);
        cells.entry(tactic).or_default().push(json!({
            "id": id, "exercised": runs > 0, "detected": fired > 0, "runs": runs, "fired": fired
        }));
    }

    // sortie ordonnée : les 14 colonnes du kill-chain TOUJOURS présentes (colonne vide = trou visible).
    let mut out: Vec<Value> = Vec::with_capacity(ATTACK_TACTICS.len() + 1);
    for tactic in ATTACK_TACTICS.iter() {
        let mut techs = cells.remove(*tactic).unwrap_or_default();
        attack_sort_techs(&mut techs);
        out.push(json!({"tactic": tactic, "techniques": techs}));
    }
    // Unmapped/Other -> seulement si non vide.
    if let Some(mut techs) = cells.remove(ATTACK_TACTIC_OTHER) {
        if !techs.is_empty() {
            attack_sort_techs(&mut techs);
            out.push(json!({"tactic": ATTACK_TACTIC_OTHER, "techniques": techs}));
        }
    }
    // défense en profondeur : toute clé résiduelle (tactique hors des 14 — ne devrait pas arriver)
    // est émise plutôt que perdue. Garantit qu'aucune technique n'est jamais silencieusement dropée.
    let mut leftover: Vec<&str> = cells.keys().copied().collect();
    leftover.sort_unstable();
    for k in leftover {
        if let Some(mut techs) = cells.remove(k) {
            if !techs.is_empty() {
                attack_sort_techs(&mut techs);
                out.push(json!({"tactic": k, "techniques": techs}));
            }
        }
    }
    Json(json!({"engagement_id": eid, "tactics": out}))
}

// =====================================================================================
//  TESTS — REPORTING : resolution de tactique ATT&CK (pure) + matrice tactique x technique
//  ENGAGEMENT-SCOPEE (exercice/detection par colonne, 14 colonnes kill-chain, anti silent-drop).
// =====================================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LedgerHead, RunEvent, RunState};
    use rusqlite::Connection;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{broadcast, Mutex as AsyncMutex};

    fn tmp_ledger(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "forge-fbulk-{}-{}-{}.jsonl",
            tag,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        p.to_string_lossy().into_owned()
    }

    fn test_app(ledger_path: &str) -> App {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(crate::SCHEMA).expect("schema");
        crate::migrate(&conn);
        let (events, _) = broadcast::channel::<RunEvent>(64);
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
            ledger_path: Arc::new(ledger_path.to_string()),
            pkg_dir: Arc::new("..".into()),
            python: Arc::new("python3".into()),
            scope_in: Arc::new(vec![]),
            scope_mode: Arc::new("grey".into()),
            detection_source: Arc::new(std::sync::RwLock::new(Arc::new(json!({"kind": "none"})))),
            run_timeout_secs: 1800,
            run_state: Arc::new(AsyncMutex::new(RunState { current: std::collections::HashMap::new() })),
            run_reservations: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            events,
            ledger_lock: Arc::new(Mutex::new(LedgerHead::default())),
        }
    }

    fn seed_engagement(app: &App, id: i64, name: &str) {
        let db = app.db();
        db.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(?,?, 'active','grey','{}','',datetime('now'),datetime('now'))",
            rusqlite::params![id, name],
        )
        .unwrap();
    }

    async fn to_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// attack_tactic_for : match exact, repli sous-technique -> base, repli base -> sous-technique,
    /// et None pour un id vraiment hors catalogue (rangé plus tard dans Unmapped/Other).
    #[test]
    fn attack_tactic_resolution() {
        assert_eq!(attack_tactic_for("T1190"), Some("Initial Access"));
        assert_eq!(attack_tactic_for("T1595.002"), Some("Reconnaissance"));
        // sous-technique inconnue -> tactique de la base cataloguée.
        assert_eq!(attack_tactic_for("T1595.999"), Some("Reconnaissance"));
        // base d'une sous-technique cataloguée -> tactique de la sous-technique.
        assert_eq!(attack_tactic_for("T1584"), Some("Resource Development"));
        assert_eq!(attack_tactic_for("T9999"), None);
    }

    fn seed_runrecord(app: &App, eid: i64, mitre: &str, fired: i64) {
        let db = app.db();
        db.execute(
            "INSERT INTO runrecord(ts,campaign,target,kind,mitre,fired,detail,run_id,engagement_id)
             VALUES(datetime('now'),'c','t.example','k',?,?,'','r',?)",
            rusqlite::params![mitre, fired, eid],
        )
        .unwrap();
    }
    fn col<'a>(v: &'a Value, tactic: &str) -> Option<&'a Vec<Value>> {
        v["tactics"].as_array()?.iter().find(|t| t["tactic"] == tactic)?["techniques"].as_array()
    }
    fn tech<'a>(techs: &'a [Value], id: &str) -> Option<&'a Value> {
        techs.iter().find(|t| t["id"] == id)
    }

    /// MATRICE : grille tactique × technique ENGAGEMENT-SCOPÉE. Vérifie (a) exercé×détecté par colonne,
    /// (b) 14 colonnes kill-chain toujours présentes, (c) cellules NON-EXERCÉES du catalogue, (d) id hors
    /// catalogue -> Unmapped/Other (jamais dropé), (e) AUCUNE fuite d'un autre engagement.
    #[tokio::test]
    async fn attack_matrix_scoped_bucketed_no_drop() {
        let led = tmp_ledger("amx");
        let app = test_app(&led);
        seed_engagement(&app, 1, "A");
        seed_engagement(&app, 2, "B");
        // engagement #1 : T1190 exercé+détecté (2 runs, 1 fired), T1595.002 exercé non détecté (1 run),
        // T9999 exercé+détecté mais id INCONNU (-> Unmapped/Other).
        seed_runrecord(&app, 1, "T1190", 1);
        seed_runrecord(&app, 1, "T1190", 0);
        seed_runrecord(&app, 1, "T1595.002", 0);
        seed_runrecord(&app, 1, "T9999", 1);
        // engagement #2 : T1046 détecté — NE DOIT PAS apparaître comme exercé dans la matrice de #1.
        seed_runrecord(&app, 2, "T1046", 1);

        let q1 = Query(HashMap::from([("engagement".to_string(), "1".to_string())]));
        let resp = attack_matrix(State(app.clone()), HeaderMap::new(), q1).await.into_response();
        let v = to_json(resp).await;
        assert_eq!(v["engagement_id"], 1);

        // (b) 14 colonnes kill-chain présentes + Unmapped/Other (car T9999).
        let names: Vec<String> = v["tactics"].as_array().unwrap().iter().map(|t| t["tactic"].as_str().unwrap().to_string()).collect();
        for t in ATTACK_TACTICS.iter() {
            assert!(names.contains(&t.to_string()), "colonne {t} manquante");
        }
        assert!(names.contains(&ATTACK_TACTIC_OTHER.to_string()), "Unmapped/Other présent car id inconnu exercé");

        // (a) Initial Access : T1190 exercé+détecté, runs=2, fired=1.
        let ia = tech(col(&v, "Initial Access").unwrap(), "T1190").unwrap();
        assert_eq!(ia["exercised"], true);
        assert_eq!(ia["detected"], true);
        assert_eq!(ia["runs"], 2);
        assert_eq!(ia["fired"], 1);

        // Reconnaissance : T1595.002 exercé non détecté ; T1590 catalogué mais NON exercé (cellule grise).
        let recon = col(&v, "Reconnaissance").unwrap();
        let scan = tech(recon, "T1595.002").unwrap();
        assert_eq!(scan["exercised"], true);
        assert_eq!(scan["detected"], false);
        let dns = tech(recon, "T1590").expect("catalogue T1590 présent même non exercé");
        assert_eq!(dns["exercised"], false, "cellule NON-EXERCÉE rendue (pas silencieusement omise)");

        // (e) T1046 (exercé dans #2) apparaît dans #1 comme NON exercé -> aucune fuite cross-engagement.
        let disc = tech(col(&v, "Discovery").unwrap(), "T1046").unwrap();
        assert_eq!(disc["exercised"], false, "donnée de l'engagement #2 NE fuit PAS dans #1");

        // (c/d) T9999 rangé dans Unmapped/Other (jamais dropé).
        let other = col(&v, ATTACK_TACTIC_OTHER).unwrap();
        assert!(tech(other, "T9999").is_some(), "id hors catalogue préservé");

        let _ = std::fs::remove_file(&led);
    }
}

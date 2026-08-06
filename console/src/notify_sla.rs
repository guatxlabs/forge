// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — SLA DE TRIAGE : détection périodique des findings EN RETARD + remontée par les
//! canaux DÉJÀ livrés (notification in-app, et son miroir webhook quand il est armé).
//!
//! Ce module est un ORDONNANCEUR, pas un canal. Il suit le patron maison de `backup_sched.rs` :
//! politique déclarative en `settings`, balayage périodique fail-open, ledgerisation des exécutions,
//! fail-closed quand la politique est absente. Il n'ouvre AUCUN chemin de sortie : la remontée passe
//! par `notifications::notify_sla_breach` -> `notifications::emit`, exactement comme une assignation
//! ou une transition de triage. Le miroir hors-processus (webhook) et TOUTES ses rédactions
//! (`redact::redact_secrets` puis `notify_channels::neutralize_urls`) sont donc hérités, pas réécrits.
//!
//! CE QUE « EN RETARD » VEUT DIRE (choix produit, dérivé des SEULS champs que le modèle porte déjà —
//! aucune colonne nouvelle) :
//!   « un finding dont le CYCLE DE TRIAGE est encore OUVERT (`triage` ∈ [`OPEN_TRIAGE`]) et dont l'âge
//!     depuis `finding.ts` dépasse le budget configuré POUR SA SÉVÉRITÉ. »
//!   - `triage` ∈ {new, triaging, reopened} = le finding attend encore une DÉCISION de triage. `confirmed`
//!     n'est PAS en retard : la décision est prise, ce qui reste est la remédiation — une autre horloge,
//!     qui exigerait un propriétaire de correctif que ce modèle n'a pas. `resolved`/`false_positive`/
//!     `duplicate` sont terminaux.
//!   - l'horloge part de `finding.ts` (date de création). C'est la seule date que la ligne porte : il n'y
//!     a pas de `triage_updated`, et en inventer une pour un SLA serait ajouter du modèle pour une
//!     fonction périphérique.
//!   - un `ts` illisible => JAMAIS en retard (fail-closed, même discipline que `compliance_policy`
//!     : sur une date ambiguë on ne déclenche rien plutôt que d'inventer une échéance).
//!
//! GOUVERNANCE (chaque garde a un test qui ROUGIT si on la retire) :
//!   1. OFF PAR DÉFAUT — aucune clé `settings.sla_policy` => `{enabled:false}` => le balayage est un
//!      NO-OP TOTAL (aucune requête de findings, aucune notification, aucune ligne de ledger). Miroir
//!      exact de `backup_policy` / `notify_channel`.
//!   2. AUCUN EGRESS NOUVEAU — la remontée entre par la porte des notifications. Le corps qui quitte
//!      éventuellement le processus subit les rédactions du canal (secrets PUIS URL de cible — une URL
//!      porte l'identifiant de la victime). Il n'y a ici ni socket, ni URL, ni secret.
//!   3. LEADER-ONLY — sous HA, N réplicas balayant la même table enverraient N notifications. Le
//!      balayage ne fait rien quand l'instance n'est pas leader. `is_leader` est un PARAMÈTRE (pas une
//!      lecture d'état global) — même discipline que `plan_delivery(cfg, allow_internal)` : la garde est
//!      testable de façon déterministe dans le build community, où `ha::is_leader` vaut toujours `true`.
//!   4. NE CASSE NI NE RALENTIT RIEN — le balayage tourne dans une tâche périodique détachée, hors du
//!      chemin d'un run ou d'une mutation. Toute erreur (table absente, politique illisible) est
//!      CAPTURÉE dans le rapport et ledgerisée ; un panic de la tâche bloquante est capté par le
//!      JoinHandle. Aucun chemin ne peut faire échouer un run.
//!   5. UNE SEULE NOTIFICATION PAR FINDING, JAMAIS DE RÉPÉTITION — la dédup est portée par la table
//!      `notification` elle-même (`NOT EXISTS … kind='finding.sla'`), donc dans la REQUÊTE : un finding
//!      déjà signalé n'est même pas candidat. Sans cela un balayage toutes les 15 min re-notifierait le
//!      même finding indéfiniment, et le plafond de balayage serait consommé par des lignes déjà traitées.
//!   6. GRANT-SCOPÉ / FAIL-CLOSED SUR LE DESTINATAIRE — hérité de `emit` : en enterprise, un destinataire
//!      sans grant sur l'engagement ne reçoit RIEN. Un finding en retard NON ASSIGNÉ n'a pas de
//!      destinataire : il est COMPTÉ mais ne notifie personne, sauf si un `escalate_to` (UN login, pas
//!      une diffusion) est explicitement configuré.
//!   7. LE PLAFOND NE REND PAS LE SLA INERTE, ET NE MENT PAS — [`MAX_SWEEP_ROWS`] borne les lignes LUES.
//!      Une ligne lue pour rien en cache une autre INDÉFINIMENT (`id ASC` est stable) : la requête ne lit
//!      donc que ce qui PEUT être en retard (triage ouvert + sévérité BUDGÉTÉE + jamais signalé), et ce
//!      qu'elle a dû tronquer, elle le DIT (`scanned`/`capped`, ledgerisés même sans notification). Une
//!      surveillance qui s'éteint en silence est pire que pas de surveillance : on croit être couvert.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Map, Value};
use std::time::Duration;

use crate::{admin_denied, append_console_ledger, attribution_login, check_admin, App};

/// Clé `settings` qui porte la politique SLA (une seule ligne, upsert admin).
pub(crate) const SETTINGS_KEY: &str = "sla_policy";

/// États de triage où le finding attend encore une DÉCISION — le seul ensemble sur lequel une horloge
/// de triage a du sens. Sous-ensemble STRICT de `findings::TRIAGE_STATES` (jeu fermé).
pub(crate) const OPEN_TRIAGE: &[&str] = &["new", "triaging", "reopened"];

/// Plafond dur du nombre de findings LUS par balayage. Borne le travail de fond ET le nombre de
/// notifications qu'un seul tick peut produire.
///
/// IL PORTE SUR LES LIGNES LUES, PAS SUR LES RETARDS TROUVÉS — d'où deux gardes, parce qu'une ligne
/// lue pour rien est une ligne qui en cache une autre, indéfiniment (`id ASC` est stable) :
///   - ce qui ne peut PAS être en retard ne doit pas être lu : la dédup (garde 5) écarte le déjà
///     signalé, et [`budgeted_severities`] écarte les sévérités SANS budget — sans quoi 500 findings
///     `LOW` d'id bas rendraient le SLA inerte À VIE sur les `CRITICAL` d'id supérieur ;
///   - ce qui reste tronqué se DIT : le rapport porte `scanned`/`capped` et un balayage tronqué est
///     ledgerisé même sans notification. « Rien en retard » et « je n'ai pas regardé » ne doivent
///     jamais se ressembler.
pub(crate) const MAX_SWEEP_ROWS: i64 = 500;

/// Borne d'un budget de sévérité (heures). ~10 ans : au-delà, ce n'est plus un SLA, c'est une faute de
/// frappe — et un budget absurde vaut mieux refusé à l'écriture que silencieusement inerte.
const MAX_BUDGET_HOURS: i64 = 87_600;

/// Variable d'ENV réglant la cadence du balayage (secondes). Même discipline que `FORGE_BACKUP_TICK_SECS`.
pub(crate) const TICK_ENV: &str = "FORGE_SLA_TICK_SECS";

/// Cadence par défaut du balayage : 15 min. Un SLA se compte en heures — inutile de scruter plus vite.
const TICK_DEFAULT_SECS: u64 = 900;

// =====================================================================================
//  POLITIQUE — lecture / validation (PURES, testables sans DB)
// =====================================================================================

/// Politique EFFECTIVE : `settings.sla_policy` si c'est un objet JSON valide, sinon le défaut FERMÉ
/// `{enabled:false}`. AUCUN repli par variable d'environnement — on n'arme pas un SLA par accident de
/// déploiement (miroir de `notify_channels::resolve_channel`).
pub(crate) fn resolve_policy(store: &crate::store::Store) -> Value {
    resolve_policy_from(crate::settings_get_store(store, SETTINGS_KEY))
}

/// Cœur PUR de la résolution (testable sans store). Toute valeur illisible/non-objet retombe sur le
/// défaut fermé — jamais sur une politique partiellement devinée.
pub(crate) fn resolve_policy_from(setting: Option<String>) -> Value {
    if let Some(s) = setting {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if v.is_object() {
                return v;
            }
        }
    }
    json!({"enabled": false})
}

/// La politique est-elle ARMÉE ? Exige `enabled:true` ET au moins un budget de sévérité STRICTEMENT
/// positif. Fail-closed : `enabled` seul, sans aucun budget, est INERTE (rien ne peut être « en retard »).
pub(crate) fn sla_enabled(policy: &Value) -> bool {
    policy.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)
        && crate::report_render::REPORT_SEVERITIES.iter().any(|s| budget_hours(policy, s) > 0)
}

/// Budget (heures) configuré pour `severity` — 0 si absent, nul, négatif ou non entier. 0 == « cette
/// sévérité n'a PAS de SLA » (jamais en retard), jamais « échéance immédiate ». PURE.
pub(crate) fn budget_hours(policy: &Value, severity: &str) -> i64 {
    let key = severity.trim().to_ascii_uppercase();
    policy
        .get("budgets")
        .and_then(|b| b.get(&key))
        .and_then(|v| v.as_i64())
        .filter(|&n| n > 0)
        .unwrap_or(0)
}

/// Sévérités dont le budget est STRICTEMENT positif — le SEUL ensemble sur lequel un retard est
/// possible. Les valeurs viennent du jeu FERMÉ [`crate::report_render::REPORT_SEVERITIES`] (jamais de
/// la base, jamais du corps HTTP) : ce qui part en paramètre lié est une constante du binaire. Vide =
/// politique inerte (rien ne peut être en retard) — l'appelant ne doit alors RIEN lire. PURE.
pub(crate) fn budgeted_severities(policy: &Value) -> Vec<&'static str> {
    crate::report_render::REPORT_SEVERITIES
        .iter()
        .copied()
        .filter(|s| budget_hours(policy, s) > 0)
        .collect()
}

/// Login à notifier pour un finding en retard NON ASSIGNÉ. Vide = personne (le finding est compté, pas
/// remonté). UN login, jamais une liste : un SLA ne doit pas devenir une diffusion.
pub(crate) fn escalate_to(policy: &Value) -> String {
    policy.get("escalate_to").and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
}

/// Valide une politique entrante et rend la forme CANONIQUE à persister. Fail-closed : tout champ
/// inconnu est REFUSÉ (aucune capacité surprise), les clés de `budgets` viennent du jeu FERMÉ des
/// sévérités, un budget doit être un entier de [0, [`MAX_BUDGET_HOURS`]].
pub(crate) fn validate_policy(policy: &Value) -> Result<Value, String> {
    const TOP: &[&str] = &["enabled", "budgets", "escalate_to"];
    let obj = policy.as_object().ok_or("la politique SLA doit être un objet")?;
    for k in obj.keys() {
        if !TOP.contains(&k.as_str()) {
            return Err(format!("champ inconnu '{k}' — refusé (politique déclarative bornée)"));
        }
    }
    let mut out = Map::new();
    out.insert("enabled".into(), json!(policy.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)));
    let mut budgets = Map::new();
    if let Some(b) = policy.get("budgets") {
        let bm = b.as_object().ok_or("'budgets' doit être un objet {SEVERITY: heures}")?;
        for (k, v) in bm {
            let up = k.trim().to_ascii_uppercase();
            if !crate::report_render::REPORT_SEVERITIES.contains(&up.as_str()) {
                return Err(format!(
                    "sévérité inconnue '{k}' — refusée ({})",
                    crate::report_render::REPORT_SEVERITIES.join("|")
                ));
            }
            let n = v.as_i64().ok_or_else(|| format!("budget de '{up}' : entier d'heures attendu"))?;
            if !(0..=MAX_BUDGET_HOURS).contains(&n) {
                return Err(format!("budget de '{up}' hors bornes (0..={MAX_BUDGET_HOURS} heures)"));
            }
            budgets.insert(up, json!(n));
        }
    }
    out.insert("budgets".into(), Value::Object(budgets));
    let esc = escalate_to(policy);
    if esc.len() > 128 || esc.contains('\0') || esc.contains('\r') || esc.contains('\n') {
        return Err("escalate_to trop long ou contenant un caractère interdit".into());
    }
    out.insert("escalate_to".into(), json!(esc));
    Ok(Value::Object(out))
}

// =====================================================================================
//  PRÉDICAT « EN RETARD » — PUR (aucune horloge lue, aucune I/O : `now` est un paramètre)
// =====================================================================================

/// Un finding est-il EN RETARD ? Rend `Some((age_secs, budget_secs))` si oui, `None` sinon.
///
/// FAIL-CLOSED sur les trois entrées douteuses : un `triage` hors [`OPEN_TRIAGE`] (terminal, ou
/// `confirmed` dont la décision est prise) ne l'est JAMAIS ; une sévérité sans budget non plus ; un `ts`
/// illisible non plus (`parse_ts_epoch` -> None). Un `ts` DANS LE FUTUR donne un âge négatif, donc pas
/// de retard — jamais une échéance inventée.
pub(crate) fn overdue(policy: &Value, severity: &str, triage: &str, ts: &str, now: i64) -> Option<(i64, i64)> {
    if !OPEN_TRIAGE.contains(&triage.trim().to_ascii_lowercase().as_str()) {
        return None;
    }
    let budget = budget_hours(policy, severity).checked_mul(3600)?;
    if budget <= 0 {
        return None;
    }
    let created = crate::compliance_policy::parse_ts_epoch(ts)?;
    let age = now.checked_sub(created)?;
    if age >= budget {
        Some((age, budget))
    } else {
        None
    }
}

// =====================================================================================
//  BALAYAGE
// =====================================================================================

/// Un finding en retard, réduit à ce qu'il faut pour notifier. Aucun champ de PREUVE (evidence/poc/
/// target) n'est chargé : ce qui n'est pas lu ne peut pas fuir.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct Overdue {
    pub(crate) id: i64,
    pub(crate) engagement_id: i64,
    pub(crate) title: String,
    pub(crate) severity: String,
    pub(crate) assignee: Option<i64>,
    pub(crate) age_secs: i64,
    pub(crate) budget_secs: i64,
}

/// Texte de la notification (in-app ; c'est LUI qui sera rédigé s'il part par le canal sortant). Porte
/// le finding, sa sévérité et le dépassement — de quoi agir, rien de plus.
pub(crate) fn breach_text(o: &Overdue) -> String {
    format!(
        "SLA de triage dépassé — finding #{} « {} » ({}) : {} h ouvertes, budget {} h",
        o.id,
        o.title,
        o.severity,
        o.age_secs / 3600,
        o.budget_secs / 3600
    )
}

/// Ce qu'un balayage a trouvé ET ce qu'il a réellement REGARDÉ. Les deux, parce que `breaches.len()`
/// seul ne dit pas si le plafond a mordu : un balayage qui bute sur [`MAX_SWEEP_ROWS`] sans trouver un
/// seul retard rendrait `0` — indiscernable d'une base saine.
pub(crate) struct Scan {
    /// Les findings EN RETARD retenus (déjà filtrés par le prédicat [`overdue`]).
    pub(crate) breaches: Vec<Overdue>,
    /// Nombre de lignes LUES. `>= limit` ⇒ la requête a été TRONQUÉE : il peut rester des retards non vus.
    pub(crate) scanned: i64,
}

/// Balaie les findings au triage OUVERT et rend ceux EN RETARD, borné à `limit`.
///
/// TROIS filtres, dans l'ordre où ils coûtent :
///   - `triage IN (…)` — seul un cycle OUVERT peut être en retard ;
///   - `UPPER(TRIM(severity)) IN (…)` — SEULES les sévérités qui ont un budget. Normalisation IDENTIQUE
///     à celle de [`budget_hours`] (trim + majuscules) : le pré-filtre SQL ne peut donc pas écarter une
///     ligne que le prédicat Rust aurait retenue. Sans lui, un `LOW` sans budget est candidat à jamais
///     et mange le plafond (cf. [`MAX_SWEEP_ROWS`]). Politique SANS budget ⇒ AUCUNE requête ;
///   - `only_unnotified` — la DÉDUP, DANS la requête (`NOT EXISTS` sur `notification.kind='finding.sla'`)
///     : le balayage réel ne voit que des findings jamais signalés (garde 5), tandis que l'aperçu admin
///     (GET) compte TOUT ce qui est en retard, y compris le déjà-signalé.
///
/// L'ÂGE, lui, reste filtré en Rust : `finding.ts` accepte trois formes (`@epoch`, entier nu, ISO-8601,
/// cf. `compliance_policy::parse_ts_epoch`) qu'aucune comparaison SQL portable ne classe correctement —
/// un pré-filtre sur la date écarterait des retards RÉELS. [`overdue`] reste l'autorité.
///
/// Les états de triage et les sévérités sont LIÉS en paramètres (jamais interpolés) ; seul le NOMBRE
/// de `?` est construit, et il vient de deux jeux fermés du binaire.
pub(crate) fn scan_overdue(
    store: &crate::store::Store,
    policy: &Value,
    now: i64,
    limit: i64,
    only_unnotified: bool,
) -> Result<Scan, String> {
    let sevs = budgeted_severities(policy);
    if sevs.is_empty() {
        // Aucun budget ⇒ rien ne PEUT être en retard. On ne lit pas la table (et on n'émet pas un
        // `IN ()` — syntaxe invalide sur les deux backends).
        return Ok(Scan { breaches: Vec::new(), scanned: 0 });
    }
    let triage_ph = vec!["?"; OPEN_TRIAGE.len()].join(",");
    let sev_ph = vec!["?"; sevs.len()].join(",");
    let dedup = if only_unnotified {
        " AND NOT EXISTS (SELECT 1 FROM notification n WHERE n.finding_id=finding.id AND n.kind=?)"
    } else {
        ""
    };
    let sql = format!(
        "SELECT id,engagement_id,title,severity,triage,ts,assignee FROM finding \
         WHERE triage IN ({triage_ph}) AND UPPER(TRIM(severity)) IN ({sev_ph}){dedup} ORDER BY id ASC LIMIT ?"
    );
    let mut params: Vec<crate::store::Param> = OPEN_TRIAGE.iter().map(|s| crate::store::Param::Text((*s).to_string())).collect();
    params.extend(sevs.iter().map(|s| crate::store::Param::Text((*s).to_string())));
    if only_unnotified {
        params.push(crate::store::Param::Text(crate::notifications::KIND_SLA.to_string()));
    }
    params.push(crate::store::Param::Int(limit));
    let rows: Vec<(i64, i64, String, String, String, String, Option<i64>)> = store
        .query_lax(&sql, &params, |r| {
            Ok((
                r.get_i64(0)?,
                r.get_opt_i64(1)?.unwrap_or(1),
                r.get_opt_str(2)?.unwrap_or_default(),
                r.get_opt_str(3)?.unwrap_or_default(),
                r.get_opt_str(4)?.unwrap_or_default(),
                r.get_opt_str(5)?.unwrap_or_default(),
                r.get_opt_i64(6)?,
            ))
        })
        .map_err(|e| format!("lecture des findings échouée: {e}"))?;
    let scanned = rows.len() as i64;
    let breaches = rows
        .into_iter()
        .filter_map(|(id, eid, title, severity, triage, ts, assignee)| {
            let (age_secs, budget_secs) = overdue(policy, &severity, &triage, &ts, now)?;
            Some(Overdue { id, engagement_id: eid, title, severity, assignee, age_secs, budget_secs })
        })
        .collect();
    Ok(Scan { breaches, scanned })
}

/// UN balayage. Rend un rapport JSON — et ne rend JAMAIS `Err` : toute défaillance est CAPTURÉE dans le
/// rapport (`error`) et ledgerisée, de sorte qu'aucun appelant ne peut être mis en échec par le SLA
/// (garde 4). L'ordre des refus est celui du moindre coût : politique éteinte (aucune requête), puis
/// leadership (aucune requête), puis seulement la lecture des findings.
///
/// `is_leader` est un PARAMÈTRE, jamais une lecture d'état global : la production passe
/// `ha::is_leader(&app)`, les tests passent une valeur explicite (garde 3).
pub(crate) fn sweep_once(app: &App, is_leader: bool) -> Value {
    let policy = {
        let store = app.store();
        resolve_policy(&store)
    };
    if !sla_enabled(&policy) {
        return json!({"skipped": true, "reason": "policy_disabled"});
    }
    // LEADER-ONLY : sous HA, N réplicas balayant la même table enverraient N notifications identiques.
    if !is_leader {
        return json!({"skipped": true, "reason": "not_leader"});
    }
    let now: i64 = crate::chrono_now_compact().parse().unwrap_or(0);
    // Destinataire de secours pour les findings NON ASSIGNÉS — résolu UNE fois par balayage, pas par
    // finding. Un login inconnu se résout à None => les non-assignés restent comptés, non remontés.
    let escalate = escalate_to(&policy);
    let escalate_uid: Option<i64> = if escalate.is_empty() {
        None
    } else {
        let store = app.store();
        store.query_row("SELECT id FROM users WHERE login=?", &crate::sql_params![escalate.clone()], |r| r.get_i64(0)).ok()
    };
    let scan = {
        let store = app.store();
        scan_overdue(&store, &policy, now, MAX_SWEEP_ROWS, true)
    };
    let Scan { breaches, scanned } = match scan {
        Ok(s) => s,
        Err(why) => {
            // FAIL-OPEN : on trace et on rend la main. Jamais de panic, jamais d'erreur propagée.
            append_console_ledger(app, "console.notify.sla.error", json!({"actor": "sla-sweeper", "why": why}));
            return json!({"error": why, "notified": 0});
        }
    };
    // TRONCATURE : le plafond porte sur les lignes LUES. `breaches.len()` ne peut pas la révéler (un
    // balayage tronqué qui ne trouve aucun retard rendrait 0) — seul `scanned` le peut.
    let capped = scanned >= MAX_SWEEP_ROWS;
    let mut notified = 0i64;
    let mut unassigned = 0i64;
    let mut suppressed = 0i64;
    for o in &breaches {
        let recipient = match o.assignee.or(escalate_uid) {
            Some(u) => u,
            None => {
                unassigned += 1; // en retard mais sans destinataire : compté, jamais diffusé.
                continue;
            }
        };
        // LA porte de sortie — la même que l'assignation et le triage. Grant-scopée, best-effort, et
        // c'est elle qui déclenche (ou non) le miroir webhook RÉDIGÉ. Aucun socket ici.
        if crate::notifications::notify_sla_breach(app, recipient, o.engagement_id, o.id, &breach_text(o)) {
            notified += 1;
        } else {
            suppressed += 1; // destinataire sans grant / insert refusé : jamais une erreur du balayage.
        }
    }
    // On ne ledgerise QUE les balayages qui ONT PRODUIT quelque chose : un tick toutes les 15 min qui ne
    // trouve rien n'est pas un événement d'audit, c'est du bruit qui noierait la chaîne. UNE exception :
    // un balayage TRONQUÉ, même muet, EST un événement — c'est le seul endroit où un exploitant peut
    // apprendre que son SLA regarde une fenêtre trop étroite plutôt qu'une base saine.
    if notified > 0 || capped {
        append_console_ledger(app, "console.notify.sla.sweep", json!({
            "actor": "sla-sweeper",
            "overdue": breaches.len(),
            "scanned": scanned,
            "notified": notified,
            "unassigned": unassigned,
            "suppressed": suppressed,
            "capped": capped,
        }));
    }
    json!({
        "overdue": breaches.len(),
        "scanned": scanned,
        "notified": notified,
        "unassigned": unassigned,
        "suppressed": suppressed,
        "capped": capped,
    })
}

/// Balayage PÉRIODIQUE. Miroir strict de `backup_sched::backup_scheduler_loop` : tick réglable par ENV,
/// travail exécuté en `spawn_blocking` (le balayage est synchrone et prend le Mutex de connexion — il ne
/// doit pas tenir un worker async), FAIL-OPEN de bout en bout (un panic de la tâche est capté par le
/// JoinHandle et ne fait JAMAIS tomber la console). Sans politique, chaque tick coûte une lecture de
/// `settings` et rien d'autre.
pub(crate) async fn sla_sweep_loop(app: App) {
    let tick = std::env::var(TICK_ENV).ok()
        .and_then(|s| s.parse::<u64>().ok()).filter(|&n| n > 0).unwrap_or(TICK_DEFAULT_SECS);
    loop {
        tokio::time::sleep(Duration::from_secs(tick)).await;
        // Leadership lu À CHAQUE tick (il peut basculer entre deux balayages, cf. bail HA).
        let leader = crate::ha::is_leader(&app);
        let app2 = app.clone();
        match tokio::task::spawn_blocking(move || sweep_once(&app2, leader)).await {
            Ok(report) => {
                let n = report.get("notified").and_then(|v| v.as_i64()).unwrap_or(0);
                if n > 0 {
                    println!("[forge] SLA — {n} finding(s) en retard signalé(s)");
                }
            }
            Err(join_err) => {
                eprintln!("[forge] balayage SLA : tâche interrompue (fail-open, console intacte): {join_err}");
            }
        }
    }
}

// =====================================================================================
//  HANDLERS ADMIN
// =====================================================================================

pub(crate) fn routes() -> Router<App> {
    Router::new().route("/api/notify/sla", get(sla_get).post(sla_set))
}

/// GET /api/notify/sla — ADMIN (fail-closed 403). Rend la politique, le jeu fermé des sévérités, et
/// `overdue_now` : le nombre de findings ACTUELLEMENT en retard, DÉJÀ SIGNALÉS COMPRIS. C'est un
/// APERÇU en LECTURE SEULE — il ne notifie rien — sans lequel un admin ne peut pas calibrer ses budgets
/// autrement qu'en armant la politique et en regardant qui se fait spammer.
pub(crate) async fn sla_get(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let now: i64 = crate::chrono_now_compact().parse().unwrap_or(0);
    let (policy, overdue_now, capped) = {
        let store = app.store();
        let policy = resolve_policy(&store);
        // Même plafond que le balayage — donc même devoir d'honnêteté : `overdue_now` est un compte
        // SUR UNE FENÊTRE, et `capped` dit quand cette fenêtre a été atteinte. Un aperçu qui affiche
        // « 0 en retard » sans dire qu'il s'est arrêté à 500 lignes ferait calibrer à l'aveugle.
        let scan = scan_overdue(&store, &policy, now, MAX_SWEEP_ROWS, false).ok();
        let n = scan.as_ref().map(|s| s.breaches.len() as i64).unwrap_or(0);
        let capped = scan.map(|s| s.scanned >= MAX_SWEEP_ROWS).unwrap_or(false);
        (policy, n, capped)
    };
    (
        StatusCode::OK,
        Json(json!({
            "policy": policy,
            "enabled": sla_enabled(&policy),
            "overdue_now": overdue_now,
            "capped": capped,
            "severities": crate::report_render::REPORT_SEVERITIES,
            "open_triage": OPEN_TRIAGE,
            "max_sweep_rows": MAX_SWEEP_ROWS,
        })),
    )
        .into_response()
}

/// POST /api/notify/sla — ADMIN (fail-closed 403). Persiste la politique VALIDÉE. Corps : `{policy:{…}}`
/// ou l'objet à plat. Ledgerise `console.notify.sla.set` (acteur + armement + budgets — aucune donnée de
/// cible n'est en jeu ici, une politique ne porte que des durées).
pub(crate) async fn sla_set(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let incoming: Value = match body.get("policy").filter(|v| v.is_object()) {
        Some(v) => v.clone(),
        None if body.is_object() => body.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request", "why": "corps attendu : {policy:{enabled,budgets,…}} ou l'objet à plat"})),
            )
                .into_response()
        }
    };
    let canon = match validate_policy(&incoming) {
        Ok(v) => v,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "sla_invalid", "why": why}))).into_response(),
    };
    {
        let store = app.store();
        if let Err(e) = crate::settings_set_store(&store, SETTINGS_KEY, &canon.to_string()) {
            drop(store);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "settings_write_failed", "why": e}))).into_response();
        }
    }
    append_console_ledger(&app, "console.notify.sla.set", json!({
        "actor": actor,
        "enabled": sla_enabled(&canon),
        "budgets": canon.get("budgets").cloned().unwrap_or(Value::Null),
        "escalate_to_set": !escalate_to(&canon).is_empty(),
    }));
    (StatusCode::OK, Json(json!({"policy": canon, "enabled": sla_enabled(&canon), "saved": true}))).into_response()
}

// =====================================================================================
//  CE QUI N'EST PAS CONSTRUIT, ET POURQUOI (décision, pas oubli)
//
//  HORLOGE DE REMÉDIATION (`confirmed` -> `resolved`) — non construite. Elle exigerait de savoir QUAND
//  le finding est entré en `confirmed` : le modèle ne porte pas cette date, et l'ajouter pour un SLA
//  reviendrait à faire porter au schéma une fonction périphérique. Le SLA livré est celui du TRIAGE.
//
//  RE-ARMEMENT APRÈS RÉOUVERTURE — non construit. La dédup est « une notification SLA par finding, à
//  vie ». Ré-armer sur une transition `resolved -> reopened` supposerait, là encore, une date de
//  transition. Le compromis retenu privilégie l'ABSENCE DE SPAM : un opérateur qui rouvre un finding
//  vient de le regarder.
//
//  DIFFUSION AUX ADMINS pour les findings non assignés — refusée. Un SLA qui écrit à tout le monde est
//  un SLA qu'on désactive. `escalate_to` nomme UN destinataire, explicitement, ou personne.
// =====================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// URL de cible portant l'identifiant d'une victime — ce qu'un titre de finding porte typiquement,
    /// et ce qui ne doit JAMAIS quitter le processus.
    const CANARY_URL: &str = "https://cible.example/account/8412/invoice";
    const CANARY_BEARER: &str = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW1lIn0.c2lnbmF0dXJl";

    fn policy(hours_high: i64) -> Value {
        json!({"enabled": true, "budgets": {"HIGH": hours_high}})
    }

    fn set_policy(app: &App, p: &Value) {
        let store = app.store();
        crate::settings_set_store(&store, SETTINGS_KEY, &p.to_string()).unwrap();
    }

    /// Insère un finding daté de `age_hours` dans le passé (le `ts` est écrit VERBATIM au format
    /// `YYYY-MM-DD HH:MM:SS`, celui que `datetime('now')` produit sur les deux backends).
    fn seed_finding(app: &App, eid: i64, title: &str, severity: &str, triage: &str, age_hours: i64) -> i64 {
        let now: i64 = crate::chrono_now_compact().parse().unwrap();
        let ts = epoch_to_ts(now - age_hours * 3600);
        let db = app.db();
        db.execute(
            "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,engagement_id,triage)
             VALUES(?,'c','t.example',?,?,'','T1','tested','','','',?,?)",
            rusqlite::params![ts, title, severity, eid, triage],
        )
        .unwrap();
        db.last_insert_rowid()
    }

    /// Epoch -> `YYYY-MM-DD HH:MM:SS` (UTC) via SQLite lui-même : pas de 2e implémentation calendaire.
    fn epoch_to_ts(epoch: i64) -> String {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.query_row("SELECT datetime(?, 'unixepoch')", rusqlite::params![epoch], |r| r.get::<_, String>(0)).unwrap()
    }

    /// Sème `n` findings au triage OUVERT en UNE transaction. Le plafond de balayage se compte en
    /// centaines : `MAX_SWEEP_ROWS` INSERT autonomes coûteraient plus cher que le test lui-même.
    fn seed_bulk(app: &App, eid: i64, prefix: &str, severity: &str, age_hours: i64, n: i64) {
        let now: i64 = crate::chrono_now_compact().parse().unwrap();
        let ts = epoch_to_ts(now - age_hours * 3600);
        let db = app.db();
        db.execute_batch("BEGIN").unwrap();
        {
            let mut st = db
                .prepare(
                    "INSERT INTO finding(ts,campaign,target,title,severity,category,mitre,status,evidence,tool,poc,engagement_id,triage)
                     VALUES(?,'c','t.example',?,?,'','T1','tested','','','',?,'new')",
                )
                .unwrap();
            for i in 0..n {
                st.execute(rusqlite::params![ts, format!("{prefix}-{i}"), severity, eid]).unwrap();
            }
        }
        db.execute_batch("COMMIT").unwrap();
    }

    fn seed_engagement(app: &App, id: i64) {
        let db = app.db();
        db.execute(
            "INSERT INTO engagement(id,name,status,mode,scope_json,ledger_path,created,updated)
             VALUES(?,'E','active','grey','{}','',datetime('now'),datetime('now'))",
            rusqlite::params![id],
        )
        .unwrap();
    }

    fn seed_user(app: &App, login: &str) -> i64 {
        {
            let db = app.db();
            crate::upsert_user(&db, login, "operator", &crate::hash_pw("pw")).unwrap();
        }
        testutil::uid_of(app, login)
    }

    fn assign(app: &App, fid: i64, uid: i64) {
        let db = app.db();
        db.execute("UPDATE finding SET assignee=? WHERE id=?", rusqlite::params![uid, fid]).unwrap();
    }

    fn notif_count(app: &App, uid: i64) -> i64 {
        let db = app.db();
        db.query_row(
            "SELECT COUNT(*) FROM notification WHERE user_id=? AND kind=?",
            rusqlite::params![uid, crate::notifications::KIND_SLA],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn ledger_text(path: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    // =============================================================================
    //  PRÉDICAT PUR — ce que « en retard » veut dire
    // =============================================================================

    /// Le budget est PAR SÉVÉRITÉ et la comparaison est un `>=` sur l'âge : 25 h sur un budget de 24 h
    /// est en retard, 23 h ne l'est pas, et une sévérité SANS budget ne l'est jamais — si vieille soit-elle.
    /// MUTATION : remplacer `age >= budget` par `age > 0` -> la 2e et la 3e assertion rougissent.
    #[test]
    fn overdue_is_per_severity_budget() {
        let now = 1_000_000_000i64;
        let p = policy(24);
        let ts = |h: i64| epoch_to_ts(now - h * 3600);
        assert!(overdue(&p, "HIGH", "new", &ts(25), now).is_some(), "25 h > budget 24 h");
        assert!(overdue(&p, "HIGH", "new", &ts(23), now).is_none(), "23 h < budget 24 h");
        assert!(overdue(&p, "LOW", "new", &ts(9999), now).is_none(), "LOW n'a AUCUN budget -> jamais en retard");
        let (age, budget) = overdue(&p, "high", "new", &ts(30), now).expect("sévérité insensible à la casse");
        assert_eq!(budget, 24 * 3600);
        assert!(age >= 30 * 3600 - 1);
    }

    /// Seul un triage OUVERT peut être en retard. `confirmed` (décision prise) et les états TERMINAUX ne
    /// le sont JAMAIS, si vieux soient-ils. MUTATION : retirer le filtre `OPEN_TRIAGE.contains(...)` de
    /// `overdue` -> ce test rougit (un finding `resolved` de 2 ans deviendrait « en retard »).
    #[test]
    fn only_open_triage_states_can_breach() {
        let now = 1_000_000_000i64;
        let p = policy(1);
        let old = epoch_to_ts(now - 9_000_000);
        for t in OPEN_TRIAGE {
            assert!(overdue(&p, "HIGH", t, &old, now).is_some(), "'{t}' est un état OUVERT");
        }
        for t in ["confirmed", "resolved", "false_positive", "duplicate"] {
            assert!(overdue(&p, "HIGH", t, &old, now).is_none(), "'{t}' ne doit JAMAIS être en retard");
        }
    }

    /// FAIL-CLOSED sur une date douteuse : un `ts` illisible ou situé dans le FUTUR ne déclenche rien.
    /// MUTATION : remplacer `parse_ts_epoch(ts)?` par un défaut `0` -> le cas illisible rougit (tout
    /// finding à date cassée deviendrait éternellement en retard).
    #[test]
    fn unparseable_or_future_ts_never_breaches() {
        let now = 1_000_000_000i64;
        let p = policy(1);
        assert!(overdue(&p, "HIGH", "new", "pas-une-date", now).is_none());
        assert!(overdue(&p, "HIGH", "new", "", now).is_none());
        assert!(overdue(&p, "HIGH", "new", &epoch_to_ts(now + 86_400), now).is_none(), "ts futur");
    }

    // =============================================================================
    //  GARDE 1 — OFF PAR DÉFAUT
    // =============================================================================

    /// Sans clé `settings.sla_policy`, la politique est FERMÉE et le balayage est un NO-OP TOTAL : aucune
    /// notification, aucune ligne de ledger — alors qu'un finding LARGEMENT en retard existe.
    /// MUTATION : faire défaut `enabled` à `true` dans `resolve_policy_from`/`sla_enabled` -> ce test rougit.
    #[test]
    fn off_by_default_is_a_total_noop() {
        let led = testutil::tmp_path("sla-off.jsonl");
        let app = testutil::test_app(&led);
        seed_engagement(&app, 1);
        let uid = seed_user(&app, "bob");
        let f = seed_finding(&app, 1, "vieux", "CRITICAL", "new", 9_000);
        assign(&app, f, uid);

        let p = resolve_policy_from(None);
        assert!(!sla_enabled(&p), "politique fermée par défaut");
        let r = sweep_once(&app, true);
        assert_eq!(r["reason"], "policy_disabled");
        assert_eq!(notif_count(&app, uid), 0, "aucune notification sans politique");
        assert!(ledger_text(&led).is_empty(), "un SLA éteint a produit une trace : {}", ledger_text(&led));
        let _ = std::fs::remove_file(&led);
    }

    /// `enabled:true` SANS aucun budget positif reste INERTE (fail-closed sur politique partielle) : rien
    /// ne peut être « en retard » quand aucune échéance n'est définie.
    #[test]
    fn enabled_without_budgets_stays_inert() {
        assert!(!sla_enabled(&json!({"enabled": true})));
        assert!(!sla_enabled(&json!({"enabled": true, "budgets": {}})));
        assert!(!sla_enabled(&json!({"enabled": true, "budgets": {"HIGH": 0}})));
        assert!(!sla_enabled(&json!({"budgets": {"HIGH": 4}})), "enabled absent => off");
        assert!(sla_enabled(&json!({"enabled": true, "budgets": {"HIGH": 4}})));
        // Une valeur de settings illisible retombe sur le défaut FERMÉ, jamais sur une politique devinée.
        assert!(!sla_enabled(&resolve_policy_from(Some("pas du json".into()))));
        assert!(!sla_enabled(&resolve_policy_from(Some("[1,2]".into()))), "non-objet => fermé");
    }

    // =============================================================================
    //  GARDE 3 — LEADER-ONLY (sous HA, N réplicas = N notifications)
    // =============================================================================

    /// Le MÊME état, avec la MÊME politique armée, produit une notification quand l'instance est leader
    /// et RIEN quand elle ne l'est pas. MUTATION : retirer le `if !is_leader { return … }` de
    /// `sweep_once` -> ce test rougit (chaque réplica notifierait).
    #[test]
    fn sweep_is_leader_only() {
        let led = testutil::tmp_path("sla-leader.jsonl");
        let app = testutil::test_app(&led);
        seed_engagement(&app, 1);
        let uid = seed_user(&app, "bob");
        let f = seed_finding(&app, 1, "en retard", "HIGH", "new", 48);
        assign(&app, f, uid);
        set_policy(&app, &policy(24));

        let r = sweep_once(&app, false);
        assert_eq!(r["reason"], "not_leader", "un non-leader ne balaie pas");
        assert_eq!(notif_count(&app, uid), 0, "un non-leader n'a notifié personne");

        let r = sweep_once(&app, true);
        assert_eq!(r["notified"], 1, "le leader, lui, notifie");
        assert_eq!(notif_count(&app, uid), 1);
        let _ = std::fs::remove_file(&led);
    }

    // =============================================================================
    //  GARDE 5 — UNE SEULE NOTIFICATION PAR FINDING
    // =============================================================================

    /// Trois balayages consécutifs sur le même finding en retard ne produisent QU'UNE notification.
    /// MUTATION : retirer la clause `NOT EXISTS (…)` de `scan_overdue` -> ce test rougit (3 notifications
    /// pour un seul finding ; en production, une toutes les 15 minutes indéfiniment).
    #[test]
    fn a_breach_notifies_once_not_every_tick() {
        let led = testutil::tmp_path("sla-once.jsonl");
        let app = testutil::test_app(&led);
        seed_engagement(&app, 1);
        let uid = seed_user(&app, "bob");
        let f = seed_finding(&app, 1, "en retard", "HIGH", "new", 48);
        assign(&app, f, uid);
        set_policy(&app, &policy(24));

        assert_eq!(sweep_once(&app, true)["notified"], 1);
        assert_eq!(sweep_once(&app, true)["notified"], 0, "2e balayage : rien de neuf");
        assert_eq!(sweep_once(&app, true)["notified"], 0, "3e balayage : toujours rien");
        assert_eq!(notif_count(&app, uid), 1, "exactement UNE notification SLA");
        // …et le finding n'est même plus CANDIDAT (la dédup est dans la requête, pas après).
        let now: i64 = crate::chrono_now_compact().parse().unwrap();
        let store = app.store();
        let p = resolve_policy(&store);
        assert_eq!(scan_overdue(&store, &p, now, MAX_SWEEP_ROWS, true).unwrap().breaches.len(), 0);
        assert_eq!(scan_overdue(&store, &p, now, MAX_SWEEP_ROWS, false).unwrap().breaches.len(), 1, "l'aperçu, lui, le compte");
        drop(store);
        let _ = std::fs::remove_file(&led);
    }

    // =============================================================================
    //  GARDE 5bis — LE PLAFOND NE DOIT PAS RENDRE LE SLA INERTE
    // =============================================================================

    /// [`MAX_SWEEP_ROWS`] borne les LIGNES LUES, pas les retards trouvés. Une sévérité SANS budget ne
    /// peut JAMAIS être en retard : si de tels findings restent candidats en SQL, ils consomment le
    /// plafond et un retard réel d'`id` supérieur n'est jamais vu — pas « ce tick-ci » mais À VIE
    /// (`id ASC` est stable, et rien ne les retire de la file : la dédup n'efface que le DÉJÀ NOTIFIÉ).
    /// C'est le SLA silencieusement inerte, la panne qui ne se voit pas.
    /// MUTATION : retirer le filtre de sévérité de `scan_overdue` -> ce test rougit (`notified` = 0).
    #[test]
    fn severities_without_budget_cannot_starve_the_sweep() {
        let led = testutil::tmp_path("sla-starve.jsonl");
        let app = testutil::test_app(&led);
        seed_engagement(&app, 1);
        let uid = seed_user(&app, "bob");
        // Bruit : un plafond ENTIER de findings LOW (aucun budget), ids 1..=MAX_SWEEP_ROWS.
        seed_bulk(&app, 1, "bruit", "LOW", 9_000, MAX_SWEEP_ROWS);
        // Le retard RÉEL arrive après — donc d'id supérieur au plafond.
        let f = seed_finding(&app, 1, "en retard", "HIGH", "new", 48);
        assign(&app, f, uid);
        set_policy(&app, &policy(24)); // budget HIGH seulement

        let r = sweep_once(&app, true);
        assert_eq!(r["notified"], 1, "le retard HIGH doit être vu malgré {MAX_SWEEP_ROWS} LOW sans budget: {r}");
        assert_eq!(notif_count(&app, uid), 1);
        assert_eq!(r["scanned"], 1, "seules les sévérités BUDGÉTÉES sont lues");

        // Le cas LIMITE du même filtre : une politique SANS aucun budget ne lit RIEN et rend un `Scan`,
        // jamais une erreur.
        // CE QUE CE TEST NE PROUVE PAS (mesuré, pas supposé) : retirer le court-circuit
        // `sevs.is_empty()` de `scan_overdue` LAISSE CE TEST VERT sur SQLite. `… IN ()` y est une
        // extension ACCEPTÉE (0 ligne, vérifié : SQLite 3.53), là où PostgreSQL la rejette comme une
        // erreur de syntaxe. Le court-circuit est donc une garde de PORTABILITÉ — c'est le build
        // `store-postgres` qui la rendrait rouge, pas celui-ci, et l'assertion ci-dessous ne vaut que
        // comme non-régression du contrat de retour (`Ok`, 0 ligne, 0 retard).
        {
            let store = app.store();
            let inert = scan_overdue(&store, &json!({"enabled": true}), 0, MAX_SWEEP_ROWS, false).unwrap();
            assert!(budgeted_severities(&json!({"enabled": true})).is_empty(), "prémisse : aucun budget");
            assert_eq!(inert.scanned, 0, "aucun budget => aucune ligne lue");
            assert!(inert.breaches.is_empty());
        }
        let _ = std::fs::remove_file(&led);
    }

    /// LE RÉSIDU, RENDU VISIBLE — le plafond porte sur les lignes LUES, et des findings d'une sévérité
    /// BUDGÉTÉE mais encore DANS les temps le consomment légitimement. Ce qui ne doit JAMAIS arriver,
    /// c'est que la troncature soit SILENCIEUSE : sans elle, « aucun retard » et « je n'ai pas regardé »
    /// sont indiscernables. Le rapport porte `scanned`/`capped`, et un balayage tronqué est LEDGERISÉ
    /// même sans notification.
    /// MUTATION : recalculer `capped` depuis `breaches.len()` (l'ancien calcul) -> ce test rougit
    /// (0 retard >= 500 est faux, alors que le balayage a bien buté sur le plafond).
    #[test]
    fn a_truncated_sweep_says_so_and_is_ledgered() {
        let led = testutil::tmp_path("sla-capped.jsonl");
        let app = testutil::test_app(&led);
        seed_engagement(&app, 1);
        // Un plafond entier de HIGH ENCORE DANS LES TEMPS (1 h sur un budget de 24 h) : budgétés, donc
        // légitimement lus, mais aucun n'est en retard.
        seed_bulk(&app, 1, "jeune", "HIGH", 1, MAX_SWEEP_ROWS);
        set_policy(&app, &policy(24));

        let r = sweep_once(&app, true);
        assert_eq!(r["overdue"], 0, "aucun retard trouvé");
        assert_eq!(r["scanned"], MAX_SWEEP_ROWS, "…mais le plafond a bel et bien mordu");
        assert_eq!(r["capped"], true, "un balayage tronqué le DIT: {r}");
        let l = ledger_text(&led);
        assert!(l.contains("console.notify.sla.sweep"), "troncature non tracée: {l}");
        assert!(l.contains("\"capped\":true"), "troncature non tracée: {l}");
        let _ = std::fs::remove_file(&led);
    }

    // =============================================================================
    //  GARDE 6 — DESTINATAIRE fail-closed (non assigné / sans grant)
    // =============================================================================

    /// Un finding en retard NON ASSIGNÉ est COMPTÉ mais ne notifie personne — sauf `escalate_to`
    /// explicitement configuré, qui reçoit alors. MUTATION : remplacer `o.assignee.or(escalate_uid)` par
    /// une diffusion (tous les admins) -> la 1re assertion rougit.
    #[test]
    fn unassigned_breach_escalates_only_when_configured() {
        let led = testutil::tmp_path("sla-unassigned.jsonl");
        let app = testutil::test_app(&led);
        seed_engagement(&app, 1);
        let boss = seed_user(&app, "boss");
        seed_finding(&app, 1, "orphelin", "HIGH", "new", 48);
        set_policy(&app, &policy(24));

        let r = sweep_once(&app, true);
        assert_eq!(r["overdue"], 1, "le retard est vu");
        assert_eq!(r["notified"], 0, "…mais personne n'est notifié sans destinataire");
        assert_eq!(r["unassigned"], 1, "…et il est COMPTÉ, pas silencieusement perdu");
        assert_eq!(notif_count(&app, boss), 0);

        // Avec escalate_to : le même retard atteint le destinataire NOMMÉ.
        set_policy(&app, &json!({"enabled": true, "budgets": {"HIGH": 24}, "escalate_to": "boss"}));
        let r = sweep_once(&app, true);
        assert_eq!(r["notified"], 1);
        assert_eq!(notif_count(&app, boss), 1);
        let _ = std::fs::remove_file(&led);
    }

    /// GRANT-SCOPÉ (enterprise) — la remontée passe par `notifications::emit`, donc un assigné SANS grant
    /// sur l'engagement ne reçoit RIEN et le balayage le compte comme `suppressed`. MUTATION : remplacer
    /// l'appel `notify_sla_breach` par un INSERT direct dans `notification` -> ce test rougit (le SLA
    /// contournerait l'isolation multi-tenant).
    #[test]
    fn breach_notification_is_grant_scoped() {
        let led = testutil::tmp_path("sla-grant.jsonl");
        let app = testutil::test_app(&led);
        seed_engagement(&app, 1);
        testutil::enable_enterprise_tenancy(&app);
        let outsider = seed_user(&app, "outsider");
        let f = seed_finding(&app, 1, "en retard", "HIGH", "new", 48);
        assign(&app, f, outsider);
        set_policy(&app, &policy(24));

        let r = sweep_once(&app, true);
        assert_eq!(r["overdue"], 1);
        assert_eq!(r["notified"], 0, "sans grant sur l'engagement : rien");
        assert_eq!(r["suppressed"], 1);
        assert_eq!(notif_count(&app, outsider), 0);

        // Avec le grant, le MÊME balayage remonte (le finding est resté candidat : rien n'a été écrit).
        testutil::grant_tenant(&app, outsider, 1, "tenant_viewer");
        assert_eq!(sweep_once(&app, true)["notified"], 1);
        assert_eq!(notif_count(&app, outsider), 1);
        let _ = std::fs::remove_file(&led);
    }

    // =============================================================================
    //  GARDE 4 — NE CASSE JAMAIS RIEN
    // =============================================================================

    /// Une base cassée — que ce soit la table LUE (`finding`) ou celle sur laquelle porte la dédup
    /// (`notification`) — ne fait PAS paniquer le balayage : il rend un rapport d'erreur et ledgerise.
    /// C'est la garantie « une tâche de fond ne peut rien faire tomber » : sans elle, la boucle mourrait
    /// silencieusement au premier tick et le SLA deviendrait inerte SANS que personne le sache.
    /// MUTATION : remplacer le `match` sur `scan_overdue` par un `.unwrap()` -> ce test rougit (panic).
    #[test]
    fn a_broken_store_is_a_report_not_a_panic() {
        for table in ["finding", "notification"] {
            let led = testutil::tmp_path(&format!("sla-broken-{table}.jsonl"));
            let app = testutil::test_app(&led);
            seed_engagement(&app, 1);
            let uid = seed_user(&app, "bob");
            let f = seed_finding(&app, 1, "en retard", "HIGH", "new", 48);
            assign(&app, f, uid);
            set_policy(&app, &policy(24));
            {
                let db = app.db();
                db.execute(&format!("DROP TABLE {table}"), []).unwrap();
            }
            let r = sweep_once(&app, true);
            assert!(r.get("error").is_some(), "[{table}] erreur CAPTURÉE dans le rapport: {r}");
            assert_eq!(r["notified"], 0, "[{table}]");
            assert!(ledger_text(&led).contains("console.notify.sla.error"), "[{table}] échec non tracé");
            let _ = std::fs::remove_file(&led);
        }
    }

    // =============================================================================
    //  GARDE 2 — AUCUN EGRESS NOUVEAU : ce qui part sur le fil est celui du canal, RÉDIGÉ
    // =============================================================================

    /// Serveur HTTP jetable sur loopback : lit UNE requête, répond 200, rend la requête brute.
    fn one_shot_server() -> (String, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().expect("accept");
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut buf = [0u8; 8192];
            let n = s.read(&mut buf).unwrap_or(0);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (format!("http://127.0.0.1:{port}/hook"), h)
    }

    /// BOUT EN BOUT — canal webhook ARMÉ, finding en retard dont le TITRE porte une URL de cible et un
    /// JWT : le balayage les fait remonter, et les octets REÇUS par le collecteur n'en portent AUCUN.
    /// C'est la preuve que le SLA emprunte le canal EXISTANT (donc ses rédactions) et n'ouvre pas une
    /// deuxième sortie. MUTATION : remplacer l'appel `notify_sla_breach` par un POST direct (ou retirer
    /// une des deux rédactions de `redact_outbound`) -> ce test rougit.
    #[tokio::test]
    async fn breach_egress_goes_through_the_redacted_channel() {
        testutil::allow_internal_integrations_once();
        let led = testutil::tmp_path("sla-wire.jsonl");
        let app = testutil::test_app(&led);
        seed_engagement(&app, 1);
        let uid = seed_user(&app, "bob");
        let f = seed_finding(&app, 1, &format!("IDOR sur {CANARY_URL} avec {CANARY_BEARER}"), "HIGH", "new", 48);
        assign(&app, f, uid);
        set_policy(&app, &policy(24));
        let (endpoint, handle) = one_shot_server();
        {
            let store = app.store();
            crate::settings_set_store(
                &store,
                crate::notify_channels::SETTINGS_KEY,
                &json!({"kind": "webhook", "enabled": true, "endpoint": endpoint}).to_string(),
            )
            .unwrap();
        }

        assert_eq!(sweep_once(&app, true)["notified"], 1);
        let raw = tokio::task::spawn_blocking(move || handle.join().expect("thread serveur")).await.unwrap();

        assert!(raw.starts_with("POST /hook HTTP/1.1"), "requête inattendue: {raw}");
        assert!(!raw.contains("cible.example"), "hôte de cible sur le fil: {raw}");
        assert!(!raw.contains("8412"), "identifiant de victime sur le fil: {raw}");
        assert!(!raw.contains("eyJhbGciOiJIUzI1NiJ9"), "JWT sur le fil: {raw}");
        assert!(raw.contains("finding.sla"), "l'événement utile est bien parti: {raw}");
        assert!(raw.contains("SLA de triage"), "le texte utile survit: {raw}");
        let _ = std::fs::remove_file(&led);
    }

    // =============================================================================
    //  VALIDATION D'ENTRÉE + HANDLERS
    // =============================================================================

    /// Fail-closed à l'écriture : champ inconnu, sévérité hors jeu fermé, budget non entier ou hors
    /// bornes -> REFUSÉS (donc jamais persistés, donc jamais actifs).
    #[test]
    fn policy_validation_is_fail_closed() {
        assert!(validate_policy(&json!({"enabled": true, "cmd": "rm"})).is_err(), "champ inconnu");
        assert!(validate_policy(&json!({"budgets": {"URGENT": 4}})).is_err(), "sévérité hors jeu fermé");
        assert!(validate_policy(&json!({"budgets": {"HIGH": "4"}})).is_err(), "budget non entier");
        assert!(validate_policy(&json!({"budgets": {"HIGH": -1}})).is_err(), "budget négatif");
        assert!(validate_policy(&json!({"budgets": {"HIGH": MAX_BUDGET_HOURS + 1}})).is_err(), "budget absurde");
        assert!(validate_policy(&json!({"escalate_to": "a\r\nb"})).is_err(), "CRLF");
        assert!(validate_policy(&json!([1])).is_err(), "non-objet");
        let ok = validate_policy(&json!({"enabled": true, "budgets": {"high": 4}, "escalate_to": " boss "})).unwrap();
        assert_eq!(ok["budgets"]["HIGH"], 4, "sévérité normalisée en majuscules");
        assert_eq!(ok["escalate_to"], "boss", "login trimé");
    }

    /// GET et POST sont ADMIN-ONLY (403 sans session admin) — une politique SLA décide qui reçoit quoi.
    /// MUTATION : retirer `check_admin` d'un des deux -> ce test rougit.
    #[tokio::test]
    async fn sla_routes_are_admin_only() {
        let led = testutil::tmp_path("sla-admin.jsonl");
        let app = testutil::test_app(&led);
        let anon = HeaderMap::new();
        assert_eq!(sla_get(State(app.clone()), anon.clone()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            sla_set(State(app.clone()), anon, Json(json!({"enabled": true}))).await.status(),
            StatusCode::FORBIDDEN
        );
        let _ = std::fs::remove_file(&led);
    }

    /// Aller-retour admin : la politique se pose, se relit, est ledgerisée, et l'aperçu `overdue_now`
    /// compte le retard SANS notifier personne (c'est une lecture).
    #[tokio::test]
    async fn admin_can_set_and_preview_the_policy() {
        let led = testutil::tmp_path("sla-admin-rt.jsonl");
        let app = testutil::test_app(&led);
        let adm = testutil::admin_session(&app, "adm");
        seed_engagement(&app, 1);
        let uid = seed_user(&app, "bob");
        let f = seed_finding(&app, 1, "en retard", "HIGH", "new", 48);
        assign(&app, f, uid);

        let r = sla_set(State(app.clone()), adm.clone(), Json(json!({"policy": {"enabled": true, "budgets": {"HIGH": 24}}}))).await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = testutil::resp_json(r).await;
        assert_eq!(b["enabled"], true);

        let b = testutil::resp_json(sla_get(State(app.clone()), adm).await).await;
        assert_eq!(b["policy"]["budgets"]["HIGH"], 24);
        assert_eq!(b["overdue_now"], 1, "l'aperçu voit le retard");
        assert_eq!(notif_count(&app, uid), 0, "un APERÇU ne notifie personne");
        assert!(ledger_text(&led).contains("console.notify.sla.set"), "politique non ledgerisée");
        let _ = std::fs::remove_file(&led);
    }

    /// Le ledger d'un balayage porte des COMPTEURS, jamais un titre de finding ni une cible.
    /// MUTATION : ledgeriser `breach_text(o)` ou `o.title` -> ce test rougit.
    #[test]
    fn sweep_ledger_carries_counters_not_content() {
        let led = testutil::tmp_path("sla-ledger.jsonl");
        let app = testutil::test_app(&led);
        seed_engagement(&app, 1);
        let uid = seed_user(&app, "bob");
        let f = seed_finding(&app, 1, &format!("IDOR sur {CANARY_URL}"), "HIGH", "new", 48);
        assign(&app, f, uid);
        set_policy(&app, &policy(24));

        assert_eq!(sweep_once(&app, true)["notified"], 1);
        let l = ledger_text(&led);
        assert!(l.contains("console.notify.sla.sweep"), "balayage non ledgerisé: {l}");
        assert!(l.contains("\"notified\":1"), "compteur absent: {l}");
        assert!(!l.contains("cible.example"), "URL de cible ledgerisée: {l}");
        assert!(!l.contains("IDOR sur"), "titre de finding ledgerisé: {l}");
        let _ = std::fs::remove_file(&led);
    }

    #[test]
    fn routes_build() {
        let _r: Router<App> = routes();
    }
}

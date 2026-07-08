//! Rendu des rapports d'engagement (run-report) — extrait de main.rs (PURE MOVE, Wave 2).
//! Purs constructeurs de chaînes : markdown (`render_run_report_md`) + HTML brandé autonome
//! (`render_run_report_html`, CSS `REPORT_CSS`), génération PDF via outil système présent
//! (`render_pdf_from_html`/`which_in_path`), helpers de prose du résumé exécutif (`prose_*`,
//! `sev_word`), et lecture read-only des lignes findings/verdicts nécessaires au rendu
//! (`read_finding_rows`, `campaign_notes`, `read_nonfire_verdicts`, `build_ledger_custody`).
//! AUCUNE mutation d'état App. Re-exporté `pub(crate)` à la racine de crate (main.rs) pour que
//! le module de tests inline (`super::*`) ET les appelants inter-modules (reports.rs →
//! `crate::render_pdf_from_html`, `crate::sev_css_class`, `crate::REPORT_CSS`) résolvent
//! INCHANGÉS. Le handler /api/runs/:id/report (`run_report`) reste dans main.rs et appelle ces
//! fonctions re-exportées.

use std::collections::HashMap;

use serde_json::Value;

use crate::{
    canon_json, cell_string, cvss_base_for_severity, extract_cwe, gen_token, html_escape,
    read_ledger_lines, sha_hex, App,
};

/// Génère un PDF depuis le HTML brandé en s'appuyant sur un outil SYSTÈME s'il est présent
/// (wkhtmltopdf ou weasyprint) — AUCUNE dépendance lourde n'est ajoutée au binaire. Retourne None si
/// aucun moteur n'est installé (l'appelant documente alors l'impression navigateur). Le HTML est passé
/// par STDIN (wkhtmltopdf `- -`) ou par un fichier temporaire (weasyprint) ; sortie sur stdout/fichier.
pub(crate) async fn render_pdf_from_html(html: &str) -> Option<Vec<u8>> {
    use tokio::io::AsyncWriteExt;
    // 1) wkhtmltopdf : lit le HTML sur stdin (`-`), écrit le PDF sur stdout (`-`). Préféré (rendu CSS).
    if which_in_path("wkhtmltopdf") {
        let mut child = tokio::process::Command::new("wkhtmltopdf")
            .args(["--quiet", "--print-media-type", "-", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(html.as_bytes()).await;
            drop(stdin); // EOF -> wkhtmltopdf termine sa lecture
        }
        let out = child.wait_with_output().await.ok()?;
        if out.status.success() && !out.stdout.is_empty() {
            return Some(out.stdout);
        }
        return None;
    }
    // 2) weasyprint : HTML d'entrée par fichier temp, PDF en sortie sur stdout (`-`).
    if which_in_path("weasyprint") {
        let dir = std::env::temp_dir().join(format!("forge-report-{}", gen_token()));
        let _ = std::fs::create_dir_all(&dir);
        let in_path = dir.join("report.html");
        if std::fs::write(&in_path, html).is_err() {
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        let out = tokio::process::Command::new("weasyprint")
            .arg(&in_path)
            .arg("-") // stdout
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .ok();
        let _ = std::fs::remove_dir_all(&dir);
        let out = out?;
        if out.status.success() && !out.stdout.is_empty() {
            return Some(out.stdout);
        }
        return None;
    }
    None
}

/// Vrai si `bin` est trouvable dans le PATH (lookup pur, sans shell). Sert à n'exposer ?format=pdf
/// que lorsqu'un moteur PDF est réellement installé (sinon on documente l'impression navigateur).
pub(crate) fn which_in_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p = dir.join(bin);
                std::fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Un finding tel que rendu dans le rapport (md ou html). CWE / CVSS sont des champs DÉDIÉS,
/// séparés de `category` (fourre-tout) et `mitre` (ATT&CK).
pub(crate) struct FindingRow {
    title: String,
    target: String,
    severity: String,
    category: String,
    cwe: String,
    cvss_vector: String,
    cvss_score: f64,
    mitre: String,
    status: String,
    tool: String,
    evidence: String,
    poc: String,
    fix: String,
}

impl FindingRow {
    /// Affichage CVSS compact « score (vecteur) ». Vide si ni score ni vecteur (ex INFO).
    fn cvss_display(&self) -> String {
        if self.cvss_score <= 0.0 && self.cvss_vector.is_empty() {
            return String::new();
        }
        if self.cvss_vector.is_empty() {
            return format!("{:.1}", self.cvss_score);
        }
        format!("{:.1} ({})", self.cvss_score, self.cvss_vector)
    }
}

/// Lit les findings d'un run dans l'ordre d'affichage (récents d'abord), avec CWE/CVSS séparés.
/// Rétro-compat : si la colonne `cwe` est vide (base ancienne / finding ingéré avant ce lot), on
/// dérive le CWE depuis `category` ; idem CVSS dérivé de la sévérité si absent. Lecture only.
pub(crate) fn read_finding_rows(store: &crate::store::Store, run_id: &str) -> Vec<FindingRow> {
    // LENIENT (query_lax) : miroir de `query_map(..).filter_map(ok).collect()` — prepare échoué ou ligne
    // malformée -> unwrap_or_default -> vec vide / ligne ignorée (parité stricte avec l'ancien idiom).
    store.query_lax(
        "SELECT title,target,severity,category,mitre,status,tool,evidence,poc,fix,cwe,cvss_vector,cvss_score \
         FROM finding WHERE run_id=? ORDER BY id DESC",
        &crate::sql_params![run_id],
        |r| {
            let category = r.get_opt_str(3)?.unwrap_or_default();
            let severity = r.get_opt_str(2)?.unwrap_or_default();
            let mut cwe = r.get_opt_str(10)?.unwrap_or_default();
            if cwe.is_empty() {
                cwe = extract_cwe(&category);
            }
            let mut cvss_vector = r.get_opt_str(11)?.unwrap_or_default();
            let mut cvss_score = r.get_opt_f64(12)?.unwrap_or(0.0);
            if cvss_vector.is_empty() && cvss_score <= 0.0 {
                let (v, s) = cvss_base_for_severity(&severity);
                cvss_vector = v.to_string();
                cvss_score = s;
            }
            Ok(FindingRow {
                title: r.get_opt_str(0)?.unwrap_or_default(),
                target: r.get_opt_str(1)?.unwrap_or_default(),
                severity,
                category,
                cwe,
                cvss_vector,
                cvss_score,
                mitre: r.get_opt_str(4)?.unwrap_or_default(),
                status: r.get_opt_str(5)?.unwrap_or_default(),
                tool: r.get_opt_str(6)?.unwrap_or_default(),
                evidence: r.get_opt_str(7)?.unwrap_or_default(),
                poc: r.get_opt_str(8)?.unwrap_or_default(),
                fix: r.get_opt_str(9)?.unwrap_or_default(),
            })
        },
    )
    .unwrap_or_default()
}

/// Notes d'engagement d'une campagne (table `campaign.notes`) — contexte client (cadre, ROE, objet
/// de la mission) à brancher dans l'executive summary. '' si la campagne n'a pas de métadonnées.
pub(crate) fn campaign_notes(store: &crate::store::Store, name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    // single-row query_row : NoRows -> Err -> .ok()==None (idem rusqlite) ; `notes` nullable -> get_opt_str.
    store.query_row(
        "SELECT notes FROM campaign WHERE name=? ORDER BY id DESC LIMIT 1",
        &crate::sql_params![name],
        |r| r.get_opt_str(0),
    )
    .ok()
    .flatten()
    .unwrap_or_default()
}

/// Annexe chaîne-de-custody : recalcule la chaîne SHA-256 du ledger (sans la clé) et retourne les
/// métadonnées d'audit (head, nb entrées, algo, validité, attribution actor du lot comptes). NE
/// vérifie PAS la signature (la console n'a pas la clé) — la vérif externe se fait via
/// `forge ledger verify --pubkey`. La clé publique éventuelle est lue via FORGE_CONSOLE_LEDGER_PUBKEY
/// (informative, jamais un secret).
pub(crate) struct LedgerCustody {
    path: String,
    entries: usize,
    head: String,
    alg: String,
    chain_ok: bool,
    why: String,
    pubkey: String,           // clé publique Ed25519 (hex) si exposée par l'opérateur, sinon ''
    actor: String,            // attribution = login source de vérité (started_by résolu) du run
    high_impact: bool,        // run armé haut-impact (opt-in honoré)
}

/// Re-vérifie la chaîne du ledger console (même algo que /api/ledger/verify) et assemble l'annexe
/// chaîne-de-custody pour le rapport. `started_by` = attribution du lot comptes (login résolu).
pub(crate) fn build_ledger_custody(app: &App, started_by: &str) -> LedgerCustody {
    const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let path = app.ledger_path.as_str().to_string();
    let pubkey = std::env::var("FORGE_CONSOLE_LEDGER_PUBKEY").unwrap_or_default();
    // attribution : `<login>` ou `<login>+high_impact` -> on sépare le login et le flag.
    let (actor, high_impact) = match started_by.strip_suffix("+high_impact") {
        Some(login) => (login.to_string(), true),
        None => (started_by.to_string(), false),
    };
    let entries = read_ledger_lines(&path);
    if entries.is_empty() {
        let exists = std::path::Path::new(&path).exists();
        return LedgerCustody {
            path, entries: 0, head: String::new(), alg: String::new(),
            chain_ok: exists, why: if exists { String::new() } else { "ledger absent".into() },
            pubkey, actor, high_impact,
        };
    }
    let mut prev = GENESIS.to_string();
    let mut head = GENESIS.to_string();
    let mut alg = String::new();
    let mut chain_ok = true;
    let mut why = String::new();
    for rec in &entries {
        let seq = rec.get("seq").cloned().unwrap_or(Value::Null);
        let ts = rec.get("ts").and_then(|v| v.as_str()).unwrap_or("");
        let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let detail = rec.get("detail").cloned().unwrap_or(Value::Null);
        let stored_prev = rec.get("prev").and_then(|v| v.as_str()).unwrap_or("");
        let stored_hash = rec.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        alg = rec.get("alg").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if stored_prev != prev {
            chain_ok = false;
            why = "chaînage rompu (prev)".into();
            break;
        }
        let seq_str = match &seq { Value::Number(num) => num.to_string(), Value::Null => String::new(), other => other.to_string() };
        let preimage = format!("{prev}|{seq_str}|{ts}|{kind}|{}", canon_json(&detail));
        if sha_hex(&preimage) != stored_hash {
            chain_ok = false;
            why = "hash recalculé != hash stocké (entrée altérée)".into();
            break;
        }
        prev = stored_hash.to_string();
        head = stored_hash.to_string();
    }
    LedgerCustody {
        path, entries: entries.len(), head, alg, chain_ok, why, pubkey, actor, high_impact,
    }
}

pub(crate) const REPORT_SEVERITIES: &[&str] = &["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

/// Phrase EN PROSE des comptes par sévérité (résumé exécutif). « Aucun finding » si rien.
pub(crate) fn prose_counts(by_sev: &HashMap<String, i64>) -> String {
    let total: i64 = by_sev.values().sum();
    if total == 0 {
        return "Aucun finding n'a été retenu sur cet engagement.".into();
    }
    // ordre décroissant de gravité, en ne citant que les sévérités présentes.
    let parts: Vec<String> = REPORT_SEVERITIES.iter().rev()
        .filter_map(|s| {
            let n = by_sev.get(*s).copied().unwrap_or(0);
            if n > 0 { Some(format!("{n} {}", sev_word(s, n))) } else { None }
        })
        .collect();
    format!(
        "L'évaluation a retenu {total} finding{} : {}.",
        if total > 1 { "s" } else { "" },
        parts.join(", "),
    )
}

/// Libellé de sévérité en français accordé au nombre (pour la prose).
pub(crate) fn sev_word(sev: &str, n: i64) -> String {
    let base = match sev {
        "CRITICAL" => "critique",
        "HIGH" => "élevé",
        "MEDIUM" => "moyen",
        "LOW" => "faible",
        _ => "informatif",
    };
    if n > 1 { format!("{base}s") } else { base.to_string() }
}

/// Phrase top-risques : cite les titres des findings les plus graves (CRITICAL puis HIGH), max 3.
pub(crate) fn prose_top_risks(rows: &[FindingRow]) -> String {
    let mut ranked: Vec<&FindingRow> = rows.iter()
        .filter(|f| matches!(f.severity.to_ascii_uppercase().as_str(), "CRITICAL" | "HIGH"))
        .collect();
    ranked.sort_by_key(|f| match f.severity.to_ascii_uppercase().as_str() { "CRITICAL" => 0, _ => 1 });
    if ranked.is_empty() {
        return "Aucun risque haut ou critique n'a été identifié sur le périmètre testé.".into();
    }
    let top: Vec<String> = ranked.iter().take(3)
        .map(|f| format!("« {} » sur `{}`", f.title, f.target))
        .collect();
    format!("Les risques prioritaires à traiter sont : {}.", top.join(" ; "))
}

/// Phrase posture : lecture synthétique du niveau de risque résiduel.
pub(crate) fn prose_posture(by_sev: &HashMap<String, i64>) -> String {
    let crit = by_sev.get("CRITICAL").copied().unwrap_or(0);
    let high = by_sev.get("HIGH").copied().unwrap_or(0);
    let med = by_sev.get("MEDIUM").copied().unwrap_or(0);
    if crit > 0 {
        "Posture : EXPOSÉE — au moins une vulnérabilité critique permet un impact direct ; remédiation immédiate recommandée.".into()
    } else if high > 0 {
        "Posture : À RENFORCER — des vulnérabilités élevées sont exploitables ; planifier une remédiation rapide.".into()
    } else if med > 0 {
        "Posture : ACCEPTABLE SOUS RÉSERVE — risques modérés à corriger dans le cycle de durcissement courant.".into()
    } else {
        "Posture : SOLIDE — aucun risque élevé ou critique sur le périmètre testé ; maintenir la surveillance.".into()
    }
}

/// Rend le markdown du rapport d'un run depuis les données console (miroir de build_report Python) :
/// synthèse par sévérité, findings détaillés, section transparence ROE (FIRE/DRY_RUN/VETO/erreurs),
/// section PURPLE (couverture de détection SOC) quand `purple` est fourni, et annexe chaîne-de-custody
/// (head du ledger, nb entrées, algo, clé publique, attribution actor) quand `custody` est fourni.
/// Les compteurs proviennent de run_job ; le détail des findings/verdicts des tables finding/roe_decision.
pub(crate) fn render_run_report_md(store: &crate::store::Store, run_id: &str, job: &Value, purple: Option<&Value>, custody: Option<&LedgerCustody>) -> String {
    const SEVERITIES: &[&str] = &["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
    let campaign = job.get("campaign").and_then(|v| v.as_str()).unwrap_or("");
    let mut out: Vec<String> = vec![
        format!("# Forge — rapport d'engagement (`{run_id}`)"),
        String::new(),
        format!(
            "- **Campagne** : {}  ·  **Mode** : {}  ·  **Statut** : {}",
            campaign,
            job.get("mode").and_then(|v| v.as_str()).unwrap_or("—"),
            job.get("status").and_then(|v| v.as_str()).unwrap_or("—"),
        ),
        format!(
            "- **Démarré** : {}  ·  **Terminé** : {}  ·  **Par** : {}",
            job.get("started").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—"),
            job.get("finished").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—"),
            job.get("started_by").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—"),
        ),
        String::new(),
    ];

    // --- synthèse findings par sévérité (sur les findings de CE run) ---
    let mut by_sev: HashMap<String, i64> = HashMap::new();
    let finding_rows = read_finding_rows(store, run_id);
    for f in &finding_rows {
        *by_sev.entry(f.severity.clone()).or_insert(0) += 1;
    }

    // --- Executive summary (prose) : scope, fenêtre temporelle, comptes par sévérité, top risques,
    //     posture. Contexte d'engagement = Campaign.notes si renseigné. ---
    out.push("## Résumé exécutif".into());
    out.push(String::new());
    let notes = campaign_notes(store, campaign);
    if !notes.is_empty() {
        out.push(format!("**Contexte d'engagement.** {notes}"));
        out.push(String::new());
    }
    let targets_list: Vec<String> = job.get("targets").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let scope_phrase = if targets_list.is_empty() { "le périmètre planifié".to_string() } else { format!("le périmètre {}", targets_list.join(", ")) };
    let started = job.get("started").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
        .or_else(|| job.get("ts").and_then(|v| v.as_str())).unwrap_or("(début non daté)");
    let finished = job.get("finished").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("(en cours / non daté)");
    out.push(format!(
        "Cet engagement a couvert {scope_phrase}, sur la fenêtre du {started} au {finished}, \
         en mode `{}`.",
        job.get("mode").and_then(|v| v.as_str()).unwrap_or("propose"),
    ));
    out.push(prose_counts(&by_sev));
    out.push(prose_top_risks(&finding_rows));
    out.push(prose_posture(&by_sev));
    out.push(String::new());

    out.push("## Synthèse".into());
    out.push(String::new());
    out.push("| Sévérité | # |".into());
    out.push("|---|---|".into());
    for s in SEVERITIES.iter().rev() {
        out.push(format!("| {s} | {} |", by_sev.get(*s).copied().unwrap_or(0)));
    }
    out.push(String::new());

    // --- findings détaillés ---
    out.push("## Findings".into());
    out.push(String::new());
    if finding_rows.is_empty() {
        out.push("_Aucun finding._".into());
        out.push(String::new());
    }
    fn dash(s: &str) -> &str {
        if s.is_empty() { "—" } else { s }
    }
    for f in &finding_rows {
        out.push(format!("### [{}] {} — `{}`", f.severity, f.title, f.target));
        // CWE et CVSS SÉPARÉS (distincts de la catégorie/ATT&CK).
        out.push(format!(
            "- **CWE** : {}  ·  **CVSS** : {}  ·  **ATT&CK** : {}",
            dash(&f.cwe), dash(&f.cvss_display()), dash(&f.mitre),
        ));
        out.push(format!("- **Catégorie** : {}  ·  **Statut** : {}  ·  **Outil** : {}", dash(&f.category), dash(&f.status), dash(&f.tool)));
        if !f.evidence.is_empty() {
            out.push(format!("- **Evidence** : {}", f.evidence));
        }
        if !f.poc.is_empty() {
            out.push(format!("- **PoC** : {}", f.poc));
        }
        if !f.fix.is_empty() {
            out.push(format!("- **Remediation** : {}", f.fix));
        }
        out.push(String::new());
    }

    // --- transparence ROE (anti-masquage) : compteurs run_job + détail roe_decision ---
    out.push("## Couverture & transparence (ROE / anti-masquage)".into());
    out.push(String::new());
    let geti = |k: &str| job.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    out.push(format!("- **Tirées (FIRE)** : {}", geti("fired")));
    out.push(format!("- **Simulées (DRY_RUN)** : {}", geti("dry_run")));
    out.push(format!("- **Refusées (VETO — hors scope / capacité non autorisée)** : {}", geti("vetoed")));
    out.push(format!("- **Erreurs / skips** : {}", geti("errors")));
    out.push(String::new());

    // détail des verdicts non-FIRE (DRY_RUN/VETO) — réutilise la table roe_decision de l'ingest.
    // LENIENT + early-return sur prepare échoué (parité stricte : l'ancien `db.prepare(..) Err => return
    // out.join("\n")` interrompait la fonction ENTIÈRE ; query_lax renvoie Err au même moment). Les lignes
    // malformées sont ignorées (query_lax = filter_map(ok)).
    let verdict_rows: Vec<(String, String, String, String)> = match store.query_lax(
        "SELECT verdict,kind,target,reasons FROM roe_decision WHERE run_id=? AND verdict<>'FIRE' ORDER BY id",
        &crate::sql_params![run_id],
        |r| {
            Ok((
                r.get_opt_str(0)?.unwrap_or_default(),
                r.get_opt_str(1)?.unwrap_or_default(),
                r.get_opt_str(2)?.unwrap_or_default(),
                r.get_opt_str(3)?.unwrap_or_default(),
            ))
        },
    ) {
        Ok(v) => v,
        Err(_) => return out.join("\n"),
    };
    if !verdict_rows.is_empty() {
        for (verdict, kind, target, reasons_raw) in &verdict_rows {
            // reasons stocké en JSON (array de chaînes) — on les joint, repli sur le brut.
            let reasons = serde_json::from_str::<Value>(reasons_raw)
                .ok()
                .and_then(|v| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>().join(" ; ")))
                .unwrap_or_else(|| reasons_raw.clone());
            out.push(format!("- `{verdict}` `{kind}` → `{target}` : {reasons}"));
        }
        out.push(String::new());
    }

    // --- coverage gaps + déférées par budget (depuis run_job, comme build_report) ---
    if let Some(gaps) = job.get("coverage_gaps").and_then(|g| g.as_object()) {
        if !gaps.is_empty() {
            out.push("**Classes jamais tentées**".into());
            for (tgt, miss) in gaps {
                let list = miss.as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
                    .unwrap_or_else(|| miss.to_string());
                out.push(format!("- `{tgt}` : {list}"));
            }
            out.push(String::new());
        }
    }
    if let Some(skipped) = job.get("skipped_budget").and_then(|s| s.as_array()) {
        if !skipped.is_empty() {
            out.push("**Déférées (budget)**".into());
            for a in skipped {
                out.push(format!("- {}", cell_string(a)));
            }
            out.push(String::new());
        }
    }

    // --- PURPLE : couverture de DÉTECTION (red tiré vs blue détecté). Optionnelle : présente
    // seulement si l'appelant a fourni la mesure (le rapport API la joint ; le test la passe None).
    if let Some(p) = purple {
        render_purple_section(&mut out, p);
    }

    // --- ANNEXE chaîne-de-custody : preuve d'intégrité de l'audit (ledger SHA-256) + attribution. ---
    if let Some(c) = custody {
        out.push("## Annexe — chaîne de custody".into());
        out.push(String::new());
        out.push(format!("- **Ledger** : `{}`", c.path));
        out.push(format!("- **Entrées** : {}", c.entries));
        out.push(format!("- **Algorithme** : {}", if c.alg.is_empty() { "—" } else { &c.alg }));
        out.push(format!("- **Head (dernier hash)** : `{}`", if c.head.is_empty() { "—" } else { &c.head }));
        let integrity = if c.chain_ok { "VALIDE (chaîne SHA-256 recalculée, chaînage cohérent)".to_string() }
            else { format!("ROMPUE — {}", if c.why.is_empty() { "intégrité non vérifiée".into() } else { c.why.clone() }) };
        out.push(format!("- **Intégrité** : {integrity}"));
        if !c.pubkey.is_empty() {
            out.push(format!("- **Clé publique (Ed25519)** : `{}`", c.pubkey));
        }
        // attribution du lot comptes : login source de vérité (started_by résolu).
        out.push(format!(
            "- **Attribution (acteur)** : `{}`{}",
            if c.actor.is_empty() { "—" } else { &c.actor },
            if c.high_impact { "  ·  opt-in HAUT-IMPACT honoré (run armé)" } else { "" },
        ));
        out.push(String::new());
        out.push("Vérification externe par un tiers, sans aucun secret (clé publique seule) :".into());
        out.push(String::new());
        let pk = if c.pubkey.is_empty() { "<clé_publique_hex>" } else { &c.pubkey };
        out.push(format!("```\nforge ledger verify --ledger {} --pubkey {pk}\n```", c.path));
        out.push(String::new());
    }

    out.join("\n")
}

/// Classe CSS de badge sévérité (couleurs Aurora) pour le rapport HTML.
pub(crate) fn sev_css_class(sev: &str) -> &'static str {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => "sev-crit",
        "HIGH" => "sev-high",
        "MEDIUM" => "sev-med",
        "LOW" => "sev-low",
        _ => "sev-info",
    }
}

/// LIVRABLE CLIENT — rapport d'engagement HTML BRANDÉ (thème Aurora GuatX/Forge + quetzal).
/// Document AUTONOME (CSS inlined, imprimable, `@media print`) : page de garde, sommaire, résumé
/// exécutif EN PROSE (scope, fenêtre, comptes par sévérité, top risques, posture, contexte
/// Campaign.notes), findings détaillés avec evidence/PoC/FIX + CWE/CVSS SÉPARÉS, transparence ROE,
/// couverture purple, et annexe chaîne-de-custody (head ledger, nb entrées, algo, clé publique,
/// commande `forge ledger verify --pubkey`, attribution actor). Tout texte dynamique est échappé HTML.
pub(crate) fn render_run_report_html(store: &crate::store::Store, run_id: &str, job: &Value, purple: Option<&Value>, custody: &LedgerCustody) -> String {
    let e = html_escape; // alias court
    let campaign = job.get("campaign").and_then(|v| v.as_str()).unwrap_or("");
    let mode = job.get("mode").and_then(|v| v.as_str()).unwrap_or("—");
    let status = job.get("status").and_then(|v| v.as_str()).unwrap_or("—");
    let started = job.get("started").and_then(|v| v.as_str()).filter(|s| !s.is_empty())
        .or_else(|| job.get("ts").and_then(|v| v.as_str())).unwrap_or("—");
    let finished = job.get("finished").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—");
    let started_by = job.get("started_by").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("—");
    let targets_list: Vec<String> = job.get("targets").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let finding_rows = read_finding_rows(store, run_id);
    let mut by_sev: HashMap<String, i64> = HashMap::new();
    for f in &finding_rows {
        *by_sev.entry(f.severity.clone()).or_insert(0) += 1;
    }
    let notes = campaign_notes(store, campaign);

    let mut h = String::with_capacity(16_384);
    h.push_str("<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    h.push_str(&format!("<title>Forge — rapport d'engagement {}</title>", e(run_id)));
    h.push_str(REPORT_CSS);
    h.push_str("</head><body>");

    // ----- barre d'actions (écran seulement) : impression / PDF -----
    h.push_str("<div class=\"toolbar noprint\">");
    h.push_str("<button type=\"button\" onclick=\"window.print()\">Imprimer / Enregistrer en PDF</button>");
    h.push_str("<a class=\"btn\" href=\"?format=pdf\">Télécharger PDF</a>");
    h.push_str("<a class=\"btn\" href=\"?format=md\">Markdown</a>");
    h.push_str("</div>");

    // ----- PAGE DE GARDE (quetzal + branding) -----
    h.push_str("<section class=\"cover\">");
    h.push_str("<img class=\"qz\" src=\"/quetzal.svg\" alt=\"\">");
    h.push_str("<div class=\"brand\">Guat<span class=\"x\">X</span> <span class=\"sub\">Forge</span></div>");
    h.push_str("<h1 class=\"cover-title\">Rapport d'engagement de sécurité</h1>");
    h.push_str(&format!("<div class=\"cover-camp\">{}</div>", e(if campaign.is_empty() { "(campagne sans nom)" } else { campaign })));
    h.push_str("<dl class=\"cover-meta\">");
    let cover_meta = [
        ("Run", run_id),
        ("Mode", mode),
        ("Statut", status),
        ("Fenêtre", &format!("{} → {}", started, finished)),
        ("Opérateur", started_by),
    ];
    for (k, v) in cover_meta {
        h.push_str(&format!("<dt>{}</dt><dd>{}</dd>", e(k), e(v)));
    }
    h.push_str("</dl>");
    h.push_str("<div class=\"cover-foot\">Document confidentiel — diffusion restreinte au commanditaire</div>");
    h.push_str("</section>");

    // ----- SOMMAIRE -----
    h.push_str("<nav class=\"toc\"><h2>Sommaire</h2><ol>");
    let mut toc = vec![
        ("exec", "Résumé exécutif"),
        ("synth", "Synthèse par sévérité"),
        ("findings", "Findings détaillés"),
        ("roe", "Couverture & transparence (ROE)"),
    ];
    if purple.map(|p| p.get("plume_reachable").and_then(|v| v.as_bool()).unwrap_or(false) || p.get("error").is_some()).unwrap_or(false) {
        toc.push(("purple", "Couverture détection (purple)"));
    }
    toc.push(("custody", "Annexe — chaîne de custody"));
    for (anchor, label) in &toc {
        h.push_str(&format!("<li><a href=\"#{}\">{}</a></li>", anchor, e(label)));
    }
    h.push_str("</ol></nav>");

    // ----- RÉSUMÉ EXÉCUTIF (prose) -----
    h.push_str("<section id=\"exec\" class=\"sec\"><h2>Résumé exécutif</h2>");
    if !notes.is_empty() {
        h.push_str(&format!("<p class=\"context\"><strong>Contexte d'engagement.</strong> {}</p>", e(&notes)));
    }
    let scope_phrase = if targets_list.is_empty() { "le périmètre planifié".to_string() }
        else { format!("le périmètre {}", e(&targets_list.join(", "))) };
    h.push_str(&format!(
        "<p>Cet engagement a couvert {scope_phrase}, sur la fenêtre du <strong>{}</strong> au <strong>{}</strong>, en mode <code>{}</code>.</p>",
        e(started), e(finished), e(mode),
    ));
    h.push_str(&format!("<p>{}</p>", e(&prose_counts(&by_sev))));
    h.push_str(&format!("<p>{}</p>", e(&prose_top_risks(&finding_rows))));
    let posture = prose_posture(&by_sev);
    let posture_cls = if posture.contains("EXPOSÉE") { "posture-bad" } else if posture.contains("RENFORCER") { "posture-warn" } else if posture.contains("ACCEPTABLE") { "posture-mid" } else { "posture-good" };
    h.push_str(&format!("<p class=\"posture {}\">{}</p>", posture_cls, e(&posture)));
    h.push_str("</section>");

    // ----- SYNTHÈSE par sévérité (cartes chiffrées) -----
    h.push_str("<section id=\"synth\" class=\"sec\"><h2>Synthèse par sévérité</h2><div class=\"sevgrid\">");
    for s in REPORT_SEVERITIES.iter().rev() {
        let n = by_sev.get(*s).copied().unwrap_or(0);
        h.push_str(&format!(
            "<div class=\"sevcard {}\"><div class=\"n\">{}</div><div class=\"l\">{}</div></div>",
            sev_css_class(s), n, e(s),
        ));
    }
    h.push_str("</div></section>");

    // ----- FINDINGS détaillés -----
    h.push_str("<section id=\"findings\" class=\"sec\"><h2>Findings détaillés</h2>");
    if finding_rows.is_empty() {
        h.push_str("<p class=\"muted\">Aucun finding retenu.</p>");
    }
    for f in &finding_rows {
        h.push_str("<article class=\"finding\">");
        h.push_str(&format!(
            "<h3><span class=\"sevbadge {}\">{}</span> {} <span class=\"tgt\">{}</span></h3>",
            sev_css_class(&f.severity), e(&f.severity), e(&f.title), e(&f.target),
        ));
        // taxonomie : CWE / CVSS / ATT&CK SÉPARÉS.
        h.push_str("<div class=\"taxo\">");
        h.push_str(&format!("<span class=\"chip\"><b>CWE</b> {}</span>", e(dash_or(&f.cwe))));
        h.push_str(&format!("<span class=\"chip\"><b>CVSS</b> {}</span>", e(dash_or(&f.cvss_display()))));
        h.push_str(&format!("<span class=\"chip\"><b>ATT&amp;CK</b> {}</span>", e(dash_or(&f.mitre))));
        h.push_str(&format!("<span class=\"chip\"><b>Catégorie</b> {}</span>", e(dash_or(&f.category))));
        h.push_str(&format!("<span class=\"chip\"><b>Statut</b> {}</span>", e(dash_or(&f.status))));
        h.push_str(&format!("<span class=\"chip\"><b>Outil</b> {}</span>", e(dash_or(&f.tool))));
        h.push_str("</div>");
        if !f.evidence.is_empty() {
            h.push_str(&format!("<div class=\"fld\"><div class=\"k\">Evidence</div><pre>{}</pre></div>", e(&f.evidence)));
        }
        if !f.poc.is_empty() {
            h.push_str(&format!("<div class=\"fld\"><div class=\"k\">PoC</div><pre>{}</pre></div>", e(&f.poc)));
        }
        // FIX (maintenant rempli) — mis en avant comme remédiation.
        if !f.fix.is_empty() {
            h.push_str(&format!("<div class=\"fld fix\"><div class=\"k\">Remédiation</div><div class=\"v\">{}</div></div>", e(&f.fix)));
        }
        h.push_str("</article>");
    }
    h.push_str("</section>");

    // ----- TRANSPARENCE ROE (anti-masquage) -----
    h.push_str("<section id=\"roe\" class=\"sec\"><h2>Couverture &amp; transparence (ROE / anti-masquage)</h2>");
    let geti = |k: &str| job.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    h.push_str("<div class=\"roegrid\">");
    for (lab, k) in [("Tirées (FIRE)", "fired"), ("Simulées (DRY_RUN)", "dry_run"), ("Refusées (VETO)", "vetoed"), ("Erreurs / skips", "errors")] {
        h.push_str(&format!("<div class=\"roebox\"><div class=\"n\">{}</div><div class=\"l\">{}</div></div>", geti(k), e(lab)));
    }
    h.push_str("</div>");
    // détail des verdicts non-FIRE.
    let verdicts = read_nonfire_verdicts(store, run_id);
    if !verdicts.is_empty() {
        h.push_str("<table class=\"vtab\"><thead><tr><th>Verdict</th><th>Kind</th><th>Cible</th><th>Raisons</th></tr></thead><tbody>");
        for (verdict, kind, target, reasons) in &verdicts {
            h.push_str(&format!(
                "<tr><td><span class=\"vbadge\">{}</span></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                e(verdict), e(kind), e(target), e(reasons),
            ));
        }
        h.push_str("</tbody></table>");
    }
    // classes jamais tentées + déférées budget.
    if let Some(gaps) = job.get("coverage_gaps").and_then(|g| g.as_object()).filter(|g| !g.is_empty()) {
        h.push_str("<h3>Classes jamais tentées</h3><ul>");
        for (tgt, miss) in gaps {
            let list = miss.as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_else(|| miss.to_string());
            h.push_str(&format!("<li><code>{}</code> : {}</li>", e(tgt), e(&list)));
        }
        h.push_str("</ul>");
    }
    if let Some(skipped) = job.get("skipped_budget").and_then(|s| s.as_array()).filter(|s| !s.is_empty()) {
        h.push_str("<h3>Déférées (budget)</h3><ul>");
        for a in skipped {
            h.push_str(&format!("<li>{}</li>", e(&cell_string(a))));
        }
        h.push_str("</ul>");
    }
    h.push_str("</section>");

    // ----- COUVERTURE PURPLE (si mesurée / fail-open lisible) -----
    if let Some(p) = purple {
        render_purple_section_html(&mut h, p);
    }

    // ----- ANNEXE chaîne-de-custody -----
    h.push_str("<section id=\"custody\" class=\"sec\"><h2>Annexe — chaîne de custody</h2>");
    h.push_str("<p class=\"muted\">Preuve d'intégrité de l'audit : chaîne de hachage SHA-256 du ledger d'engagement (chaque acte chaîné au précédent). L'attribution ci-dessous est la source de vérité du lot comptes (login résolu).</p>");
    h.push_str("<dl class=\"custody\">");
    let integrity = if custody.chain_ok { "VALIDE (chaîne SHA-256 recalculée, chaînage cohérent)".to_string() }
        else { format!("ROMPUE — {}", if custody.why.is_empty() { "intégrité non vérifiée".into() } else { custody.why.clone() }) };
    let actor_disp = if custody.actor.is_empty() { "—".to_string() }
        else if custody.high_impact { format!("{} (opt-in HAUT-IMPACT honoré — run armé)", custody.actor) }
        else { custody.actor.clone() };
    let mut custody_rows = vec![
        ("Ledger", custody.path.clone()),
        ("Entrées", custody.entries.to_string()),
        ("Algorithme", if custody.alg.is_empty() { "—".into() } else { custody.alg.clone() }),
        ("Head (dernier hash)", if custody.head.is_empty() { "—".into() } else { custody.head.clone() }),
        ("Intégrité", integrity),
        ("Attribution (acteur)", actor_disp),
    ];
    if !custody.pubkey.is_empty() {
        custody_rows.push(("Clé publique (Ed25519)", custody.pubkey.clone()));
    }
    for (k, v) in &custody_rows {
        h.push_str(&format!("<dt>{}</dt><dd><code>{}</code></dd>", e(k), e(v)));
    }
    h.push_str("</dl>");
    let pk = if custody.pubkey.is_empty() { "<clé_publique_hex>".to_string() } else { custody.pubkey.clone() };
    h.push_str("<p class=\"muted\">Vérification externe par un tiers, sans aucun secret (clé publique seule) :</p>");
    h.push_str(&format!("<pre class=\"cmd\">forge ledger verify --ledger {} --pubkey {}</pre>", e(&custody.path), e(&pk)));
    h.push_str("</section>");

    h.push_str("</body></html>");
    h
}

/// '—' si vide, sinon la chaîne telle quelle (pour l'affichage des champs taxonomie).
pub(crate) fn dash_or(s: &str) -> &str {
    if s.is_empty() { "—" } else { s }
}

/// Lit les verdicts non-FIRE (DRY_RUN/VETO) d'un run, raisons aplaties en une chaîne lisible.
pub(crate) fn read_nonfire_verdicts(store: &crate::store::Store, run_id: &str) -> Vec<(String, String, String, String)> {
    // LENIENT (query_lax) : prepare échoué -> vec vide, ligne malformée ignorée (idem query_map+filter_map).
    store.query_lax(
        "SELECT verdict,kind,target,reasons FROM roe_decision WHERE run_id=? AND verdict<>'FIRE' ORDER BY id",
        &crate::sql_params![run_id],
        |r| {
            let reasons_raw = r.get_opt_str(3)?.unwrap_or_default();
            let reasons = serde_json::from_str::<Value>(&reasons_raw).ok()
                .and_then(|v| v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>().join(" ; ")))
                .unwrap_or(reasons_raw);
            Ok((
                r.get_opt_str(0)?.unwrap_or_default(),
                r.get_opt_str(1)?.unwrap_or_default(),
                r.get_opt_str(2)?.unwrap_or_default(),
                reasons,
            ))
        },
    )
    .unwrap_or_default()
}

/// Section HTML « Couverture détection (purple) » — miroir HTML de render_purple_section.
/// FAIL-OPEN LISIBLE : si Plume injoignable, on l'indique et on n'invente aucune couverture.
pub(crate) fn render_purple_section_html(h: &mut String, p: &Value) {
    let e = html_escape;
    h.push_str("<section id=\"purple\" class=\"sec\"><h2>Couverture détection (purple)</h2>");
    let reachable = p.get("plume_reachable").and_then(|v| v.as_bool()).unwrap_or(false);
    if !reachable {
        // AUTONOME (standalone) : aucune source configurée -> état NORMAL (Forge n'en DÉPEND pas), pas une panne.
        if p.get("source_configured").and_then(|v| v.as_bool()) == Some(false) {
            h.push_str("<p class=\"muted\">Aucune source de détection configurée — Forge fonctionne en autonome (standalone). \
Connectez une source (Plume / CrowdSec / FortiGate / Elastic / fichier…) pour activer la boucle purple. Aucune couverture inventée.</p></section>");
            return;
        }
        let why = p.get("error").and_then(|v| v.as_str()).unwrap_or("source de détection injoignable");
        h.push_str(&format!("<p class=\"muted\">Mesure indisponible (fail-open) : {}. Aucune couverture inventée.</p></section>", e(why)));
        return;
    }
    let fired = p.get("techniques_fired").and_then(|v| v.as_i64()).unwrap_or(0);
    let detected = p.get("techniques_detected").and_then(|v| v.as_i64()).unwrap_or(0);
    let missed = p.get("techniques_missed").and_then(|v| v.as_i64()).unwrap_or(0);
    let rate = p.get("detection_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let mttd_avg = p.get("mttd_avg_secs").and_then(|v| v.as_f64());
    let mttd_max = p.get("mttd_max_secs").and_then(|v| v.as_i64());
    h.push_str("<ul class=\"plist\">");
    h.push_str(&format!("<li><b>Techniques tirées (red)</b> : {}</li>", fired));
    h.push_str(&format!("<li><b>Détectées par le SOC (blue)</b> : {} · <b>Taux</b> : {:.0}%</li>", detected, rate * 100.0));
    h.push_str(&format!("<li><b>Trous de détection</b> : {}</li>", missed));
    h.push_str(&format!(
        "<li><b>MTTD moyen</b> : {} · <b>MTTD max</b> : {}</li>",
        mttd_avg.map(|m| format!("{m:.0}s")).unwrap_or_else(|| "—".into()),
        mttd_max.map(|m| format!("{m}s")).unwrap_or_else(|| "—".into()),
    ));
    h.push_str("</ul>");
    if let Some(arr) = p.get("missed").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) {
        h.push_str("<h3>Techniques NON détectées (trous SOC)</h3><ul>");
        for m in arr {
            let mitre = m.get("mitre").and_then(|v| v.as_str()).unwrap_or("?");
            let fires = m.get("fires").and_then(|v| v.as_i64()).unwrap_or(0);
            h.push_str(&format!("<li><code>{}</code> (tirée {}×) — aucune alerte SOC</li>", e(mitre), fires));
        }
        h.push_str("</ul>");
    }
    if let Some(arr) = p.get("detected").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) {
        h.push_str("<h3>Techniques détectées (avec MTTD)</h3><ul>");
        for d in arr {
            let mitre = d.get("mitre").and_then(|v| v.as_str()).unwrap_or("?");
            let alert_count = d.get("alert_count").and_then(|v| v.as_i64()).unwrap_or(0);
            let mttd = d.get("mttd_secs").and_then(|v| v.as_i64());
            h.push_str(&format!(
                "<li><code>{}</code> — {} alerte(s), MTTD {}</li>",
                e(mitre), alert_count, mttd.map(|m| format!("{m}s")).unwrap_or_else(|| "—".into()),
            ));
        }
        h.push_str("</ul>");
    }
    h.push_str("</section>");
}

/// CSS du rapport HTML brandé — thème Aurora (palette GuatX/Forge), inliné pour un document AUTONOME.
/// `@media print` : page de garde isolée, sauts de page propres, masquage de la barre d'actions,
/// couleurs forcées (print-color-adjust) pour que les badges/posture restent lisibles en PDF.
pub(crate) const REPORT_CSS: &str = "<style>\n\
:root{--bg:#070b13;--card:#0c1422;--card2:#0a111d;--bd:#16202e;--hd:#eaf2fb;--fg:#cdd9e6;--mut:#8aa0b4;\
--acc:#2dd4bf;--acc-ink:#04201c;--acc-bg:#2dd4bf1a;--b1:#7ce8c3;--b2:#ffd9a3;--b3:#ffb3ab;\
--crit:#ff6b6b;--high:#ffa94d;--med:#ffd43b;--low:#74c0fc;--info:#8aa0b4;\
--sans:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;--mono:'JetBrains Mono',ui-monospace,monospace}\n\
*{box-sizing:border-box}\n\
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.6;font-size:14px;\
max-width:920px;margin:0 auto;padding:0 28px 64px}\n\
body::before{content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.16;filter:blur(48px);\
background:radial-gradient(42vw 42vw at 6% -8%,var(--b1),transparent 62%),\
radial-gradient(38vw 38vw at 102% 10%,var(--b2),transparent 62%),\
radial-gradient(36vw 36vw at 44% 116%,var(--b3),transparent 62%)}\n\
h1,h2,h3{color:var(--hd);font-weight:700;line-height:1.25}\n\
h2{font-size:20px;margin:32px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--bd)}\n\
h3{font-size:15px;margin:18px 0 8px}\n\
code{font-family:var(--mono);font-size:.92em;background:var(--card2);border:1px solid var(--bd);border-radius:5px;padding:1px 5px;color:var(--acc)}\n\
pre{font-family:var(--mono);font-size:12px;background:var(--card2);border:1px solid var(--bd);border-radius:8px;padding:10px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;color:var(--fg)}\n\
.muted{color:var(--mut)}\n\
.toolbar{display:flex;gap:10px;padding:16px 0;position:sticky;top:0;z-index:9}\n\
.toolbar button,.toolbar .btn{font-family:var(--sans);font-size:13px;background:var(--acc);color:var(--acc-ink);\
border:0;border-radius:9px;padding:8px 16px;cursor:pointer;font-weight:700;text-decoration:none}\n\
.toolbar .btn{background:var(--card);color:var(--fg);border:1px solid var(--bd);font-weight:500}\n\
.cover{min-height:88vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:40px 0}\n\
.cover .qz{width:128px;height:128px;filter:drop-shadow(0 6px 24px rgba(45,212,191,.25))}\n\
.cover .brand{font-size:34px;font-weight:800;letter-spacing:-.02em;margin-top:14px;color:var(--hd)}\n\
.cover .brand .x{color:var(--acc)}\n\
.cover .brand .sub{font-size:18px;font-weight:600;color:var(--mut);margin-left:6px}\n\
.cover-title{font-size:30px;margin:24px 0 6px}\n\
.cover-camp{font-size:18px;color:var(--acc);font-weight:600;margin-bottom:26px}\n\
.cover-meta{display:grid;grid-template-columns:auto auto;gap:5px 18px;font-size:14px;margin:0 auto;text-align:left}\n\
.cover-meta dt{color:var(--mut);font-weight:600}.cover-meta dd{margin:0;color:var(--fg);font-family:var(--mono);font-size:13px}\n\
.cover-foot{margin-top:34px;font-size:12px;color:var(--mut);letter-spacing:.04em;text-transform:uppercase}\n\
.toc{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px 22px;margin:28px 0}\n\
.toc h2{border:0;margin:0 0 6px;font-size:16px}\n\
.toc ol{margin:0;padding-left:20px}.toc a{color:var(--fg);text-decoration:none}.toc a:hover{color:var(--acc)}\n\
.sec{margin-top:8px}\n\
.context{background:var(--acc-bg);border-left:3px solid var(--acc);border-radius:0 8px 8px 0;padding:10px 14px}\n\
.posture{font-weight:700;border-radius:8px;padding:11px 14px;margin-top:14px}\n\
.posture-bad{background:rgba(255,107,107,.14);border:1px solid var(--crit);color:var(--crit)}\n\
.posture-warn{background:rgba(255,169,77,.14);border:1px solid var(--high);color:var(--high)}\n\
.posture-mid{background:rgba(255,212,59,.12);border:1px solid var(--med);color:var(--med)}\n\
.posture-good{background:var(--acc-bg);border:1px solid var(--acc);color:var(--acc)}\n\
.sevgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}\n\
.sevcard{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 8px;text-align:center}\n\
.sevcard .n{font-size:26px;font-weight:800;line-height:1}.sevcard .l{font-size:11px;color:var(--mut);margin-top:5px;text-transform:uppercase;letter-spacing:.05em}\n\
.sevcard.sev-crit{border-color:var(--crit)}.sevcard.sev-crit .n{color:var(--crit)}\n\
.sevcard.sev-high{border-color:var(--high)}.sevcard.sev-high .n{color:var(--high)}\n\
.sevcard.sev-med{border-color:var(--med)}.sevcard.sev-med .n{color:var(--med)}\n\
.sevcard.sev-low{border-color:var(--low)}.sevcard.sev-low .n{color:var(--low)}\n\
.finding{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px 18px;margin:14px 0;break-inside:avoid}\n\
.finding h3{margin:0 0 10px;display:flex;align-items:center;gap:9px;flex-wrap:wrap}\n\
.finding .tgt{font-family:var(--mono);font-size:12px;color:var(--mut);font-weight:500}\n\
.sevbadge{font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.04em;padding:3px 9px;border-radius:20px;text-transform:uppercase}\n\
.sevbadge.sev-crit{background:var(--crit);color:#1a0606}.sevbadge.sev-high{background:var(--high);color:#241201}\n\
.sevbadge.sev-med{background:var(--med);color:#241f01}.sevbadge.sev-low{background:var(--low);color:#031424}.sevbadge.sev-info{background:var(--info);color:#06101a}\n\
.taxo{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:10px}\n\
.chip{font-size:12px;background:var(--card2);border:1px solid var(--bd);border-radius:7px;padding:3px 9px;color:var(--fg)}\n\
.chip b{color:var(--mut);font-weight:600;margin-right:4px;font-size:11px;text-transform:uppercase;letter-spacing:.03em}\n\
.fld{margin:9px 0}.fld .k{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;font-weight:700;margin-bottom:3px}\n\
.fld.fix .v{background:var(--acc-bg);border:1px solid color-mix(in srgb,var(--acc) 30%,transparent);border-radius:8px;padding:9px 12px;color:var(--hd)}\n\
.roegrid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}\n\
.roebox{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px;text-align:center}\n\
.roebox .n{font-size:22px;font-weight:800;color:var(--hd)}.roebox .l{font-size:11px;color:var(--mut);margin-top:4px}\n\
.vtab,.custody dl{width:100%}\n\
.vtab{border-collapse:collapse;font-size:13px;margin:8px 0}\n\
.vtab th,.vtab td{border:1px solid var(--bd);padding:6px 10px;text-align:left;vertical-align:top}\n\
.vtab th{background:var(--card2);color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em}\n\
.vbadge{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--high)}\n\
.plist{margin:6px 0;padding-left:20px}.plist b{color:var(--mut);font-weight:600}\n\
dl.custody{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px}\n\
dl.custody dt{color:var(--mut);font-weight:600}dl.custody dd{margin:0;word-break:break-all}\n\
pre.cmd{border-color:var(--acc);color:var(--acc)}\n\
@media print{\n\
@page{margin:16mm}\n\
:root,body{background:#fff!important;color:#1a2330!important}\n\
*{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}\n\
body{max-width:none;padding:0}body::before{display:none}\n\
.noprint,.toolbar{display:none!important}\n\
.cover{min-height:auto;page-break-after:always;padding:18mm 0}\n\
.cover .brand,.cover-title,h1,h2,h3{color:#0c1a16!important}\n\
.toc{page-break-after:always}\n\
.sec,.finding{break-inside:avoid}\n\
h2{page-break-after:avoid}\n\
.finding,.sevcard,.roebox,.toc,.context,.posture,pre,.vtab th{background:#f6f8f7!important}\n\
code,.chip{background:#eef2f0!important;color:#0a6b56!important}\n\
.posture-good,pre.cmd{color:#0a6b56!important}\n\
}\n\
</style>";

/// Section markdown « Couverture détection (purple) » du rapport : detected / missed / MTTD.
/// FAIL-OPEN LISIBLE : si `plume_reachable=false`, on l'indique explicitement et on n'affiche
/// AUCUN détecté/raté (cohérent avec l'endpoint — un SOC muet n'est jamais « tout détecté »).
pub(crate) fn render_purple_section(out: &mut Vec<String>, p: &Value) {
    out.push("## Couverture détection (purple)".into());
    out.push(String::new());
    let reachable = p.get("plume_reachable").and_then(|v| v.as_bool()).unwrap_or(false);
    if !reachable {
        // AUTONOME (standalone) : aucune source de détection configurée -> état NORMAL et attendu (Forge
        // ne DÉPEND d'aucune source ; Plume/SIEM/IDS ne sont qu'un enrichissement optionnel), PAS une anomalie.
        if p.get("source_configured").and_then(|v| v.as_bool()) == Some(false) {
            out.push("_Aucune source de détection configurée — Forge fonctionne en autonome (standalone). \
Connectez une source (Plume / CrowdSec / FortiGate / Elastic / fichier…) pour activer la boucle purple. \
Aucune couverture n'est inventée._".into());
            out.push(String::new());
            return;
        }
        let why = p.get("error").and_then(|v| v.as_str()).unwrap_or("source de détection injoignable");
        out.push(format!("_Mesure indisponible (fail-open) : {why}. Aucune couverture inventée._"));
        out.push(String::new());
        return;
    }
    let fired = p.get("techniques_fired").and_then(|v| v.as_i64()).unwrap_or(0);
    let detected = p.get("techniques_detected").and_then(|v| v.as_i64()).unwrap_or(0);
    let missed = p.get("techniques_missed").and_then(|v| v.as_i64()).unwrap_or(0);
    let rate = p.get("detection_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let mttd_avg = p.get("mttd_avg_secs").and_then(|v| v.as_f64());
    let mttd_max = p.get("mttd_max_secs").and_then(|v| v.as_i64());
    out.push(format!("- **Techniques tirées (red)** : {fired}"));
    out.push(format!("- **Détectées par le SOC (blue)** : {detected}  ·  **Taux de détection** : {:.0}%", rate * 100.0));
    out.push(format!("- **Trous de détection (missed)** : {missed}"));
    out.push(format!(
        "- **MTTD moyen** : {}  ·  **MTTD max** : {}",
        mttd_avg.map(|m| format!("{m:.0}s")).unwrap_or_else(|| "—".into()),
        mttd_max.map(|m| format!("{m}s")).unwrap_or_else(|| "—".into()),
    ));
    out.push(String::new());
    // détail des trous de détection (priorité blue-team : ce que le SOC n'a PAS vu).
    if let Some(arr) = p.get("missed").and_then(|v| v.as_array()) {
        if !arr.is_empty() {
            out.push("**Techniques NON détectées (trous SOC)**".into());
            for m in arr {
                let mitre = m.get("mitre").and_then(|v| v.as_str()).unwrap_or("?");
                let fires = m.get("fires").and_then(|v| v.as_i64()).unwrap_or(0);
                out.push(format!("- `{mitre}` (tirée {fires}×) — aucune alerte SOC"));
            }
            out.push(String::new());
        }
    }
    // détail des détections (avec MTTD par technique).
    if let Some(arr) = p.get("detected").and_then(|v| v.as_array()) {
        if !arr.is_empty() {
            out.push("**Techniques détectées (avec MTTD)**".into());
            for d in arr {
                let mitre = d.get("mitre").and_then(|v| v.as_str()).unwrap_or("?");
                let alert_count = d.get("alert_count").and_then(|v| v.as_i64()).unwrap_or(0);
                let mttd = d.get("mttd_secs").and_then(|v| v.as_i64());
                out.push(format!(
                    "- `{mitre}` — {alert_count} alerte(s), MTTD {}",
                    mttd.map(|m| format!("{m}s")).unwrap_or_else(|| "—".into()),
                ));
            }
            out.push(String::new());
        }
    }
}

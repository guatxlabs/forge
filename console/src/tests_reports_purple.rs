// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — tests d'intégration : run-report md/html, cvss, html-escape, purple coverage, detection source, reports UI.
//! Fichier issu du découpage de `tests.rs` (STEP 2 du refactor archi, docs/ARCHITECTURE_REFACTOR_PLAN.md §1.2).
//! PURE MOVE : corps des tests byte-identiques ; préambule `use super::*` (racine de crate)
//! + `use crate::testutil::*` (fixtures hoistées en 2a) — mêmes résolutions qu'en inline.
use super::*;
use crate::testutil::*;

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

    /// [purple] compute_purple_coverage : detected-exact = même technique des deux côtés, missed =
    /// techniques tirées sans aucune couverture (ni exacte ni parente), MTTD = first_detection -
    /// dernier tir (tronqué >=0), agrégats. INVARIANT : detected + parent_approx + missed == fired.
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
        assert_eq!(cov["techniques_detected"], json!(2), "T1110 + T1190 détectées EXACTEMENT");
        assert_eq!(cov["techniques_parent_approx"], json!(0), "aucune sous-technique tirée ici");
        assert_eq!(cov["techniques_missed"], json!(1), "T1046 = trou de détection");
        // INVARIANT des trois états : chaque technique tirée tombe dans EXACTEMENT une case.
        assert_eq!(
            cov["techniques_detected"].as_i64().unwrap()
                + cov["techniques_parent_approx"].as_i64().unwrap()
                + cov["techniques_missed"].as_i64().unwrap(),
            cov["techniques_fired"].as_i64().unwrap(),
            "detected + parent_approx + missed == techniques_fired",
        );
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
        assert_eq!(t1110["state"], json!("detected-exact"), "l'état est NOMMÉ dans le contrat");
        assert_eq!(missed[0]["state"], json!("missed"));
    }

    /// [purple FAIL-OPEN] aucune détection (SOC muet, map vide) NE produit PAS « tout détecté » :
    /// toutes les techniques tirées tombent en missed, taux 0, aucun MTTD inventé (null).
    #[test]
    fn compute_purple_coverage_empty_detections_all_missed() {
        let fired = vec![("T1110".to_string(), Some(1000)), ("T1046".to_string(), Some(2000))];
        let det = std::collections::HashMap::new();
        let cov = compute_purple_coverage(&fired, &det);
        assert_eq!(cov["techniques_detected"], json!(0), "rien détecté");
        assert_eq!(cov["techniques_parent_approx"], json!(0), "aucune couverture parente non plus");
        assert_eq!(cov["techniques_missed"], json!(2), "tout en trou de détection");
        assert_eq!(cov["detection_rate"], json!(0.0));
        assert_eq!(cov["mttd_avg_secs"], Value::Null, "aucun MTTD inventé");
        assert_eq!(cov["mttd_max_secs"], Value::Null);
        assert!(cov["detected"].as_array().unwrap().is_empty());
    }

    /// [purple TROIS ÉTATS — PREUVE 1] Forge tire la SOUS-technique `T1110.001` (module `network.ssh`,
    /// devinette de mot de passe SSH) ; la source n'a de détection que sur la technique PARENTE `T1110`.
    ///
    /// L'état DOIT être `detected-parent-approx`, PAS `detected` — et `detection_rate` NE DOIT PAS
    /// bouger. Justification MESURÉE : les règles `T1110` livrées avec Plume sont bornées au MAIL
    /// (`source=mail`), bornées au WEB (`source=web status=401`) ou exigent la DISPERSION d'IP
    /// (`stats dc(src_ip)`) ; aucune n'attrape un brute-force SSH mono-source. Compter ce
    /// rapprochement comme « détecté » serait un faux positif, avec un MTTD entre le tir SSH et une
    /// alerte sans rapport.
    ///
    /// Le test ANCRE le taux : la MÊME campagne avec/sans le parent-approx donne le MÊME taux.
    #[test]
    fn parent_approx_is_not_detected_and_does_not_move_the_rate() {
        // T1190 tiré @1000 et détecté @1030 (le SEUL vrai détecté) ; T1110.001 tiré @2000, seule la
        // parente T1110 est couverte côté bleu.
        let fired = vec![
            ("T1190".to_string(), Some(1000)),
            ("T1110.001".to_string(), Some(2000)),
        ];
        let mut det = std::collections::HashMap::new();
        det.insert("T1190".to_string(), (2i64, 1030i64));
        det.insert("T1110".to_string(), (9i64, 2005i64)); // parente couverte, sous-technique NON
        let cov = compute_purple_coverage(&fired, &det);

        // (1) l'état est parent-approx, PAS detected.
        assert_eq!(cov["techniques_fired"], json!(2));
        assert_eq!(cov["techniques_detected"], json!(1), "SEUL T1190 est un detected-exact");
        assert_eq!(cov["techniques_parent_approx"], json!(1), "T1110.001 -> parent-approx");
        assert_eq!(cov["techniques_missed"], json!(0));
        let detected: Vec<&str> = cov["detected"].as_array().unwrap().iter()
            .map(|d| d["mitre"].as_str().unwrap()).collect();
        assert_eq!(detected, vec!["T1190"], "T1110.001 NE DOIT PAS être dans `detected`");
        assert!(cov["missed"].as_array().unwrap().is_empty(), "ce n'est pas non plus un `missed` muet");

        // (2) le parent-approx est EXPLOITABLE : liste dédiée, parente nommée, libellé explicite.
        let ap = &cov["parent_approx"].as_array().unwrap()[0];
        assert_eq!(ap["mitre"], json!("T1110.001"));
        assert_eq!(ap["state"], json!("detected-parent-approx"));
        assert_eq!(ap["parent"], json!("T1110"), "la technique parente est NOMMÉE");
        assert_eq!(ap["parent_alert_count"], json!(9), "les alertes de la parente restent lisibles");
        assert_eq!(ap["fires"], json!(1));
        let why = ap["why"].as_str().unwrap();
        assert!(why.contains("T1110.001") && why.contains("T1110"), "libellé explicite : {why}");
        assert!(why.contains("ne prouve pas"), "le libellé dit POURQUOI ce n'est pas un détecté : {why}");
        assert!(ap.get("mttd_secs").is_none(), "aucun MTTD n'est fabriqué sur un rapprochement approximatif");

        // (3) LE TAUX NE BOUGE PAS : 1 détecté exact / 2 tirées = 50 %.
        let rate = cov["detection_rate"].as_f64().unwrap();
        assert!((rate - 0.5).abs() < 1e-9, "taux = detected-exact/tirées = 1/2, obtenu {rate}");
        // ANCRAGE : retirer la couverture parente ne change PAS le taux (le parent-approx n'y entre
        // jamais) — seul l'état de T1110.001 passe de parent-approx à missed.
        let mut det_sans_parent = std::collections::HashMap::new();
        det_sans_parent.insert("T1190".to_string(), (2i64, 1030i64));
        let cov2 = compute_purple_coverage(&fired, &det_sans_parent);
        assert_eq!(cov2["detection_rate"], cov["detection_rate"],
            "la présence d'une règle PARENTE ne doit RIEN changer au taux vitrine");
        assert_eq!(cov2["techniques_missed"], json!(1), "sans parente, T1110.001 devient un vrai missed");
        assert_eq!(cov2["techniques_parent_approx"], json!(0));
    }

    /// [purple TROIS ÉTATS — PREUVE 2] Un tag `mitre` peut porter PLUSIEURS techniques séparées par
    /// espace/virgule/point-virgule (NORME SigmaHQ : plusieurs `attack.` par règle). Un tag
    /// `"T1595.002 T1046"` doit matcher LES DEUX clés, DES DEUX CÔTÉS de la jointure — sinon le
    /// corpus Sigma FABRIQUE de faux « missed ».
    #[test]
    fn multi_technique_tags_split_on_both_sides_of_the_join() {
        // éclatement pur (les 3 séparateurs + casse + dédup + tokens hors format ignorés).
        assert_eq!(mitre_techniques("T1595.002 T1046"), vec!["T1595.002", "T1046"]);
        assert_eq!(mitre_techniques("T1595.002,T1046"), vec!["T1595.002", "T1046"]);
        assert_eq!(mitre_techniques("T1595.002;T1046"), vec!["T1595.002", "T1046"]);
        assert_eq!(mitre_techniques("t1046 T1046"), vec!["T1046"], "casse normalisée + dédupliqué");
        assert_eq!(mitre_techniques("attack.t1046 TA0043 T1046"), vec!["T1046"],
            "tokens hors format `T####[.###]` ignorés");

        // (a) CÔTÉ BLEU : la source (règle Sigma) répond avec un tag composé ; les deux techniques
        // tirées SÉPARÉMENT par Forge doivent être détectées.
        let fired = vec![("T1595.002".to_string(), Some(1000)), ("T1046".to_string(), Some(1000))];
        let mut det = std::collections::HashMap::new();
        det.insert("T1595.002 T1046".to_string(), (4i64, 1060i64));
        let cov = compute_purple_coverage(&fired, &det);
        assert_eq!(cov["techniques_detected"], json!(2),
            "un tag bleu composé couvre LES DEUX techniques (sinon faux missed Sigma)");
        assert_eq!(cov["techniques_missed"], json!(0));
        assert_eq!(cov["detection_rate"], json!(1.0));

        // (b) CÔTÉ ROUGE : le run-record porte le tag composé ; il compte pour DEUX techniques tirées,
        // chacune jointe à sa détection.
        let fired2 = vec![("T1595.002 T1046".to_string(), Some(1000))];
        let mut det2 = std::collections::HashMap::new();
        det2.insert("T1046".to_string(), (1i64, 1030i64));
        let cov2 = compute_purple_coverage(&fired2, &det2);
        assert_eq!(cov2["techniques_fired"], json!(2), "un tag rouge composé = DEUX techniques tirées");
        assert_eq!(cov2["techniques_detected"], json!(1), "T1046 détectée");
        assert_eq!(cov2["techniques_missed"], json!(1), "T1595.002 reste un vrai trou");

        // (c) ANTI-SILENT-DROP : un tag vendeur/custom hors format n'est PAS perdu — il reste joint
        // verbatim (une technique tirée qui s'évapore rendrait l'angle mort INVISIBLE).
        let fired3 = vec![("vendor-custom-tech".to_string(), Some(1000))];
        let cov3 = compute_purple_coverage(&fired3, &std::collections::HashMap::new());
        assert_eq!(cov3["techniques_fired"], json!(1), "tag hors format conservé");
        assert_eq!(cov3["missed"].as_array().unwrap()[0]["mitre"], json!("vendor-custom-tech"));
    }

    /// [purple TROIS ÉTATS — PREUVE 3] Le MTTD n'est échantillonné QUE sur `detected-exact`. Un MTTD
    /// calculé sur un rapprochement APPROXIMATIF (règle parente) est un chiffre inventé : il daterait
    /// le tir de la sous-technique contre une alerte qui ne la concerne pas.
    #[test]
    fn mttd_ignores_parent_approx_samples() {
        // T1190 : tir @1000, détection exacte @1010 -> MTTD 10 (le SEUL échantillon légitime).
        // T1110.001 : tir @2000, seule la parente T1110 alerte @2500 -> un MTTD naïf vaudrait 500 et
        // ferait exploser moyenne (255) et max (500).
        let fired = vec![("T1190".to_string(), Some(1000)), ("T1110.001".to_string(), Some(2000))];
        let mut det = std::collections::HashMap::new();
        det.insert("T1190".to_string(), (1i64, 1010i64));
        det.insert("T1110".to_string(), (1i64, 2500i64));
        let cov = compute_purple_coverage(&fired, &det);
        assert_eq!(cov["mttd_avg_secs"].as_f64().unwrap(), 10.0,
            "MTTD moyen = 10s (T1190 seul) — le 500s du parent-approx NE DOIT PAS être échantillonné");
        assert_eq!(cov["mttd_max_secs"], json!(10), "MTTD max = 10s, pas 500s");

        // preuve par CONTRASTE : la MÊME campagne avec une détection EXACTE sur T1110.001 (au lieu de
        // la parente) produit bien, elle, un échantillon MTTD de 500.
        let mut det_exact = std::collections::HashMap::new();
        det_exact.insert("T1190".to_string(), (1i64, 1010i64));
        det_exact.insert("T1110.001".to_string(), (1i64, 2500i64));
        let cov2 = compute_purple_coverage(&fired, &det_exact);
        assert_eq!(cov2["mttd_max_secs"], json!(500), "la détection EXACTE, elle, est datée");
        assert_eq!(cov2["mttd_avg_secs"].as_f64().unwrap(), 255.0);
        assert_eq!(cov2["techniques_parent_approx"], json!(0));
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
        assert_eq!(v["techniques_parent_approx"], json!(0), "aucun parent-approx inventé non plus");
        assert_eq!(v["techniques_missed"], json!(0), "rien classé missed quand la mesure est impossible");
        assert_eq!(v["detection_rate"], json!(0.0));
        assert_eq!(v["mttd_avg_secs"], Value::Null);
        assert!(v["detected"].as_array().unwrap().is_empty());
        assert!(v["parent_approx"].as_array().unwrap().is_empty());
        assert!(v["missed"].as_array().unwrap().is_empty());
    }

    /// [purple report] render_purple_section : la section markdown reflète detected/missed/MTTD
    /// quand plume_reachable=true, et affiche le fail-open lisible (sans couverture inventée) sinon.
    #[test]
    fn render_purple_section_reachable_and_fail_open() {
        // cas joignable : section avec compteurs + trous.
        let cov = json!({
            "plume_reachable": true,
            "techniques_fired": 3, "techniques_detected": 1, "techniques_parent_approx": 1, "techniques_missed": 1,
            "detection_rate": 1.0 / 3.0, "mttd_avg_secs": 42.0, "mttd_max_secs": 42,
            "detected": [{"mitre": "T1110", "alert_count": 3, "mttd_secs": 42}],
            "parent_approx": [{"mitre": "T1110.001", "parent": "T1110", "fires": 1, "parent_alert_count": 3}],
            "missed": [{"mitre": "T1046", "fires": 1}],
        });
        let mut out: Vec<String> = Vec::new();
        render_purple_section(&mut out, &cov);
        let md = out.join("\n");
        assert!(md.contains("## Couverture détection (purple)"));
        assert!(md.contains("**Techniques tirées (red)** : 3"));
        assert!(md.contains("**Taux de détection** : 33%"), "taux = detected-exact / tirées : {md}");
        assert!(md.contains("`T1046` (tirée 1×) — aucune alerte SOC"), "trou de détection listé");
        assert!(md.contains("`T1110` — 3 alerte(s), MTTD 42s"), "détection avec MTTD listée");
        // le parent-approx est RENDU, dans sa propre section, explicitement hors du taux.
        assert!(md.contains("Couverture parente approximative"), "section parent-approx rendue : {md}");
        assert!(md.contains("`T1110.001`") && md.contains("seule la parente `T1110`"),
            "angle mort NOMMÉ (sous-technique tirée + parente couverte) : {md}");
        assert!(md.contains("NON comptée comme détectée"), "le rapport dit qu'elle n'est pas un détecté");

        // cas fail-open : la section l'indique explicitement, sans détecté/raté.
        let fo = purple_fail_open("", &[("T1110".to_string(), Some(1))], "PLUME_URL non configuré");
        let mut out2: Vec<String> = Vec::new();
        render_purple_section(&mut out2, &fo);
        let md2 = out2.join("\n");
        assert!(md2.contains("## Couverture détection (purple)"));
        assert!(md2.contains("Mesure indisponible (fail-open)"), "fail-open lisible dans le rapport");
        assert!(md2.contains("PLUME_URL non configuré"));
        assert!(!md2.contains("aucune alerte SOC"), "aucun trou inventé en fail-open");
        assert!(!md2.contains("Couverture parente approximative"), "aucun parent-approx inventé en fail-open");
    }

    /// [purple http] http_get_blocking : le SCHÉMA est un jeu fermé {http, https}. Un `https://` n'est
    /// PLUS refusé (le seam TLS le sert — un `PLUME_URL` en https est désormais légitime) : il échoue
    /// ici sur la RÉSOLUTION de l'hôte bidon, pas sur le schéma. Tout autre schéma reste refusé net,
    /// AVANT le moindre octet réseau.
    #[test]
    fn http_get_blocking_scheme_is_a_closed_set() {
        // Schéma hors jeu -> refus de PARSING (aucune résolution, aucune connexion).
        let e = http_get_blocking("ftp://plume:7000/x", &HttpAuth::None, Duration::from_millis(50))
            .expect_err("schéma hors jeu -> Err");
        assert!(e.contains("http:// ou https://"), "message lisible sur le jeu fermé, obtenu: {e}");
        // https accepté au parsing : l'échec restant est de RÉSOLUTION, plus un refus de schéma.
        let e = http_get_blocking(
            "https://plume-hote-inexistant.invalid:7000/api/coverage/detections",
            &HttpAuth::None,
            Duration::from_millis(50),
        )
        .expect_err("hôte .invalid -> Err de résolution");
        assert!(e.contains("résolution"), "https doit passer le parsing et échouer plus loin, obtenu: {e}");
    }

    // =============================================================================================
    // SOURCE DE DÉTECTION CONFIGURABLE (plugin) — refactor infra-agnostique de la boucle purple.
    // =============================================================================================

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
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn plume_source_yields_same_coverage_backcompat() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
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
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn generic_http_bearer_fetched_and_mapped() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
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
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV + les SLOTS process-globaux
    #[tokio::test]
    async fn unreachable_source_fails_open_readable() {
    // SÉRIALISEUR PROCESS-GLOBAL : ce test peut atteindre un spawn moteur, donc le compteur
    // process-global des slots (`EngineGate`). Sans ce verrou, deux tests parallèles se volent le
    // slot quand un autre test a posé FORGE_ENGINE_MAX_CONCURRENT=1 — flakiness MESURÉE avant ce
    // correctif (suite parallèle : 1 à 2 échecs aléatoires par run, y compris avant ce lot).
    let _engine_gate_guard = crate::testutil::env_lock();
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


    /// [S5-bis — borne de TEMPS sur le collecteur de détections] `GET /api/detection/coverage` (viewer)
    /// délègue au COLLECTEUR PYTHON pour les kinds « messy » : encore un process moteur par requête. Il
    /// doit être borné dans le temps comme les autres — sinon la même primitive (« un viewer spawne des
    /// process non bornés ») survit sur cette route. Sans borne, l'appel ne rend JAMAIS la main.
    #[cfg(unix)]
    #[allow(clippy::await_holding_lock)] // env_lock() sérialise l'ENV process-global
    #[tokio::test]
    async fn detection_collector_spawn_is_time_bounded() {
        let _g = env_lock();
        std::env::set_var("FORGE_ENGINE_TIMEOUT", "1");
        let path = tmp_path("forge-test-detbound");
        let mut app = test_app(&path);
        let stub = {
            use std::os::unix::fs::PermissionsExt;
            let p = tmp_path("forge-stub-det.sh");
            std::fs::write(&p, "#!/bin/sh\nsleep 30\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        app.python = Arc::new(stub.clone());
        let cfg = json!({"kind": "crowdsec", "endpoint": "http://127.0.0.1:9/", "auth_type": "none"});
        let started = std::time::Instant::now();
        let got = tokio::time::timeout(std::time::Duration::from_secs(10),
            collect_detections_with(&app, &cfg, 3600)).await;
        std::env::remove_var("FORGE_ENGINE_TIMEOUT");
        let got = got.expect("le collecteur de détections DOIT être borné dans le temps — aucune réponse rendue");
        assert!(got.is_err(), "moteur coupé à la borne -> erreur fail-open lisible");
        assert!(started.elapsed() < std::time::Duration::from_secs(8), "réponse rendue à la borne");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&stub);
    }

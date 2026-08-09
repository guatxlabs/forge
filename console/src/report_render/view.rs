// SPDX-License-Identifier: AGPL-3.0-or-later
//! Couche de VUE du rapport de run — MIROIR RUST de `forge/report_view.py` (+ les normaliseurs de
//! `forge/triage.py` dont elle dépend).
//!
//! POURQUOI CE FICHIER EXISTE. `forge/report.py` a été refondu (verdict en tête, « Actionnable — à
//! reporter », « Signal à qualifier », « Couverture NON vérifiée », annexe derrière une ligne de
//! COMPTABILITÉ) parce qu'une campagne réelle a émis **5318 findings dont 5306 INFO** : un rapport qui
//! noie 12 LOW et **479 trous de couverture** sous 5306 lignes n'est pas un rapport, c'est un journal.
//! `console/src/report_render.rs` DUPLIQUE ce rendu en Rust et n'avait pas suivi : l'utilisateur de la
//! console recevait toujours le journal. Ce module porte la couche de VUE côté console.
//!
//! POURQUOI PORTER PLUTÔT QUE DÉLÉGUER (voie mesurée, pas supposée) :
//!   - la console ne possède AUCUN markdown produit par Python : le spawn moteur
//!     (`console/src/runs_proc.rs`) lance `python -m forge.cli campaign …` SANS `--report`, et rien
//!     n'est stocké ;
//!   - elle rend le rapport de runs qu'elle n'a JAMAIS lancés (ingest CLI `--console`, import
//!     `findings_bulk`, `finding_templates`) : pour ceux-là il n'y a pas et il n'y a jamais eu d'objet
//!     `engine` à qui demander un rapport ;
//!   - déléguer à Python au moment de la LECTURE est précédenté (`reports::render_docx_via_python`)
//!     mais ce chemin **dégrade en 501 quand python est absent** — acceptable pour un format
//!     secondaire, PAS pour `GET /api/runs/:id/report` (défaut `md`), qui est LE livrable console ;
//!   - le rapport console porte ce que Python ne PEUT pas produire (matrice de détection Plume + MTTD,
//!     annexe chaîne-de-custody) : le rapport Python pointe explicitement VERS la console pour ça.
//!
//! LE RISQUE ASSUMÉ EST LA RE-DÉRIVE, et il est traité là où il se traite : par un garde-fou de parité
//! qui MORD (`tests_reports_purple::report_view_parity_python_vs_rust_same_corpus`) — un corpus UNIQUE
//! rendu par les DEUX moteurs, squelettes comparés, et toute section Python non miroitée doit être
//! DÉCLARÉE avec sa raison. C'est l'absence d'un tel garde-fou — pas la duplication — qui a laissé la
//! dérive passer (l'ancien test n'assertait que cinq sous-chaînes).
//!
//! INVARIANTS PORTÉS ICI (identiques au Python, non négociables) :
//!   1. rien n'est masqué en silence — ce qui est replié est COMPTÉ, NOMMÉ, et on dit où le récupérer ;
//!   2. les `skipped` REMONTENT (trous de couverture, pas du bruit) — avant toute annexe ;
//!   3. la sévérité vient du FINDING, jamais du rendu (aucun sur-classement pour remplir une section) ;
//!   4. un rapport partiel s'ANNONCE partiel (`run_job.status` ∈ timeout/cancelled/failed/running).
//!
//! Pur : aucune I/O, aucune mutation d'état App. Stdlib seule (aucune dépendance `regex` dans ce
//! crate — les normaliseurs de `triage.py` sont ré-implémentés par balayage de caractères, et le
//! garde-fou de parité les confronte au vrai moteur Python sur le corpus partagé).

use super::FindingRow;

// --- vues (miroir de report_view.VIEWS / DEFAULT_VIEW) ---------------------------------------------
pub(crate) const VIEW_PENTEST: &str = "pentest";
pub(crate) const VIEW_BOUNTY: &str = "bounty";
/// Défaut SÛR (identique au Python) : annexe EXHAUSTIVE, rien n'est replié.
pub(crate) const DEFAULT_VIEW: &str = VIEW_PENTEST;
/// Override par-run — MÊME nom de variable que le moteur (`report_view.ENV_VIEW`) : poser
/// `FORGE_REPORT_VIEW=bounty` replie DES DEUX CÔTÉS, jamais d'un seul.
pub(crate) const ENV_VIEW: &str = "FORGE_REPORT_VIEW";

pub(crate) const SEVERITIES: [&str; 5] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const MEDIUM_RANK: usize = 2;
const LOW_RANK: usize = 1;

/// Statuts qui valent PREUVE (posés uniquement par le chemin sanctionné du moteur).
pub(crate) const PROVEN_STATUSES: [&str; 3] = ["vulnerable", "submitted", "accepted"];
/// « je n'ai PAS pu vérifier » — trou de couverture, jamais du bruit.
pub(crate) const UNVERIFIED_STATUS: &str = "skipped";
/// hit d'un outil tiers sur sa PROPRE sévérité — à qualifier, JAMAIS présenté comme prouvé.
pub(crate) const TOOL_REPORTED_STATUS: &str = "reported_by_tool";

/// Bornes d'AFFICHAGE des listes d'exemples. Elles bornent le VOLUME DE TEXTE d'une ligne, jamais le
/// nombre d'items : le total exact est TOUJOURS imprimé à côté (« 12 occurrences » + « +4 autre(s) »).
pub(crate) const MAX_OCCURRENCE_EXAMPLES: usize = 8;
pub(crate) const MAX_REASON_EXAMPLES: usize = 4;

/// Glose de statut (miroir de `report_view._STATUS_GLOSS`) — un `tested` DIT qu'aucune exploitabilité
/// n'est démontrée, au lieu de laisser le lecteur le supposer.
fn status_gloss(status: &str) -> &'static str {
    match status {
        "vulnerable" => "PROUVÉ exploitable par un oracle Forge",
        "submitted" => "prouvé, soumis au programme",
        "accepted" => "prouvé, accepté par le programme",
        "reported_by_tool" => {
            "signalé par un OUTIL TIERS sur sa propre sévérité — **NON validé manuellement**"
        }
        "tested" => "testé — **aucune exploitabilité démontrée** par Forge",
        "not_vulnerable" => "testé négatif",
        "informative" => "informatif",
        "invalid" => "invalide",
        "skipped" => "**NON VÉRIFIÉ** — le module n'a pas pu s'exécuter",
        _ => "",
    }
}

/// Vue effective. Miroir de `report_view.resolve_view`, PRIVÉ des niveaux que la console n'a pas
/// (pas de `scope.json` côté console) : explicite > `$FORGE_REPORT_VIEW` > défaut. Une valeur inconnue
/// est IGNORÉE (repli sur le niveau suivant), jamais une erreur.
pub(crate) fn resolve_view(explicit: Option<&str>) -> &'static str {
    let from_env = std::env::var(ENV_VIEW).unwrap_or_default();
    for candidate in [explicit.unwrap_or(""), from_env.as_str()] {
        match candidate.trim().to_ascii_lowercase().as_str() {
            VIEW_PENTEST => return VIEW_PENTEST,
            VIEW_BOUNTY => return VIEW_BOUNTY,
            _ => {}
        }
    }
    DEFAULT_VIEW
}

pub(crate) fn sev_rank(sev: &str) -> usize {
    let s = sev.trim().to_ascii_uppercase();
    SEVERITIES.iter().position(|x| *x == s).unwrap_or(0)
}

// --- (1) BUCKETS ------------------------------------------------------------------------------------

/// Les quatre seaux, DÉRIVÉS du finding, jamais inventés (miroir exact de `report_view.bucket_of`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bucket {
    /// sévérité ≥ MEDIUM **ou** statut prouvé — ce qu'un opérateur doit lire EN PREMIER.
    Exploitable,
    /// LOW / signalé par un outil tiers — signal réel, exploitabilité NON démontrée.
    Qualify,
    /// statut `skipped` — TROU DE COUVERTURE. Testé EN PREMIER : jamais rabattu dans le bruit.
    Unverified,
    /// le reste (INFO de cartographie) — l'annexe.
    Recon,
}

/// Seau d'UN finding. Ordre de test = ordre de PRIORITÉ (identique au Python) : `unverified` d'abord,
/// pour qu'un trou de couverture ne retombe JAMAIS dans le bruit quelle que soit sa sévérité.
/// NE dépend PAS d'un score de bruit : c'est exactement le bug que la refonte Python a corrigé.
pub(crate) fn bucket_of(severity: &str, status: &str) -> Bucket {
    let st = status.trim().to_ascii_lowercase();
    if st == UNVERIFIED_STATUS {
        return Bucket::Unverified;
    }
    let rank = sev_rank(severity);
    if rank >= MEDIUM_RANK || PROVEN_STATUSES.contains(&st.as_str()) {
        return Bucket::Exploitable;
    }
    if rank >= LOW_RANK || st == TOOL_REPORTED_STATUS {
        return Bucket::Qualify;
    }
    Bucket::Recon
}

/// PARTITION des indices d'entrée en quatre seaux : chaque index apparaît dans EXACTEMENT un seau et
/// l'union couvre `0..rows.len()`. Ordre d'entrée préservé.
#[derive(Debug, Default)]
pub(crate) struct Buckets {
    pub(crate) exploitable: Vec<usize>,
    pub(crate) qualify: Vec<usize>,
    pub(crate) unverified: Vec<usize>,
    pub(crate) recon: Vec<usize>,
}

pub(crate) fn bucket_findings(rows: &[FindingRow]) -> Buckets {
    let mut b = Buckets::default();
    for (i, f) in rows.iter().enumerate() {
        match bucket_of(&f.severity, &f.status) {
            Bucket::Exploitable => b.exploitable.push(i),
            Bucket::Qualify => b.qualify.push(i),
            Bucket::Unverified => b.unverified.push(i),
            Bucket::Recon => b.recon.push(i),
        }
    }
    b
}

// --- normaliseurs (miroir de forge/triage.py, sans dépendance regex) -------------------------------

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Miroir de `triage.normalize_title` : URLs / IPv4[:port] / hex longs / nombres remplacés par des
/// jetons stables, casse et espaces normalisés. `Endpoint in-scope : http://a/x?id=3` et
/// `… http://b/y?id=9` -> MÊME gabarit. L'ORDRE des substitutions est celui du Python (url, host, hex,
/// nombre) : le changer changerait les gabarits (une IP dans une URL serait comptée deux fois).
pub(crate) fn normalize_title(text: &str) -> String {
    let lowered = text.to_lowercase();
    let s = replace_urls(&lowered);
    let s = replace_hostports(&s);
    let s = replace_word_runs(&s, |run| run.len() >= 8 && run.chars().all(|c| c.is_ascii_hexdigit()), "<hex>");
    let s = replace_word_runs(&s, |run| run.chars().all(|c| c.is_ascii_digit()), "<n>");
    collapse_ws(&s)
}

/// `https?://\S+` -> `<url>` (\S+ greedy : tout jusqu'au prochain blanc).
fn replace_urls(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        let rest: String = b[i..].iter().take(8).collect();
        let scheme_len = if rest.starts_with("http://") {
            7
        } else if rest.starts_with("https://") {
            8
        } else {
            0
        };
        if scheme_len > 0 {
            out.push_str("<url>");
            i += scheme_len;
            while i < b.len() && !b[i].is_whitespace() {
                i += 1;
            }
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// `\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b` -> `<host>`. Le `\b` de tête impose que le motif commence en
/// début de suite de caractères-mot ; le `\b` de queue, qu'il s'y termine.
fn replace_hostports(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        let at_boundary = i == 0 || !is_word_char(b[i - 1]);
        if at_boundary && b[i].is_ascii_digit() {
            if let Some(end) = match_ipv4(&b, i) {
                // `\b` de queue : le caractère suivant doit être non-mot (ou la fin).
                if end >= b.len() || !is_word_char(b[end]) {
                    out.push_str("<host>");
                    i = end;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Fin (exclusive) d'un `(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?` démarrant en `start`, ou None.
fn match_ipv4(b: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    for octet in 0..4 {
        let d0 = i;
        while i < b.len() && i - d0 < 3 && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == d0 {
            return None;
        }
        if octet < 3 {
            if i >= b.len() || b[i] != '.' {
                return None;
            }
            i += 1;
        }
    }
    // port optionnel `:\d+`
    if i < b.len() && b[i] == ':' {
        let p0 = i + 1;
        let mut j = p0;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > p0 {
            i = j;
        }
    }
    Some(i)
}

/// Remplace toute SUITE MAXIMALE de caractères-mot satisfaisant `pred` par `token`. C'est la sémantique
/// exacte de `\b…\b` de Python quand la classe interne est incluse dans les caractères-mot : le motif
/// doit couvrir la suite ENTIÈRE (sinon un `\b` manque à une extrémité).
fn replace_word_runs<F: Fn(&str) -> bool>(s: &str, pred: F, token: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        if !is_word_char(b[i]) {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_word_char(b[i]) {
            i += 1;
        }
        let run: String = b[start..i].iter().collect();
        if pred(&run) {
            out.push_str(token);
        } else {
            out.push_str(&run);
        }
    }
    out
}

/// `\s+` -> ' ' puis `strip` (miroir du dernier passage de `normalize_title`).
fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            in_ws = true;
        } else {
            if in_ws && !out.is_empty() {
                out.push(' ');
            }
            in_ws = false;
            out.push(c);
        }
    }
    out
}

/// Clé de TECHNIQUE (miroir de `triage._technique_key`) : CWE dédié, sinon category, sinon tool.
fn technique_key(f: &FindingRow) -> String {
    for v in [&f.cwe, &f.category, &f.tool] {
        let t = v.trim();
        if !t.is_empty() {
            return t.to_lowercase();
        }
    }
    String::new()
}

/// Signature de GABARIT (miroir de `triage.template_key`) : (sévérité, technique, titre normalisé).
pub(crate) fn template_key(f: &FindingRow) -> (String, String, String) {
    (
        f.severity.to_ascii_uppercase(),
        technique_key(f),
        normalize_title(&f.title),
    )
}

// --- (2) GROUPES (1 vuln × N endpoints) -------------------------------------------------------------

/// Un ITEM de rapport : un gabarit + TOUTES ses occurrences. `rep` = plus petit index d'origine
/// (déterministe, comme le triage) ; `members` rend la comptabilité vérifiable (aucune occurrence ne
/// peut disparaître sans faire tomber l'invariant de partition).
#[derive(Debug, Clone)]
pub(crate) struct Item {
    pub(crate) rep: usize,
    pub(crate) members: Vec<usize>,
}

impl Item {
    pub(crate) fn count(&self) -> usize {
        self.members.len()
    }
}

/// Regroupe par GABARIT -> « 1 vuln × N endpoints ». Tri : sévérité DESC, occurrences DESC, index du
/// représentant ASC (déterministe — miroir de `report_view.group_items`).
pub(crate) fn group_items(rows: &[FindingRow], idxs: &[usize]) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut seen: Vec<((String, String, String), usize)> = Vec::new(); // clé -> position dans `items`
    for &i in idxs {
        let key = template_key(&rows[i]);
        match seen.iter().find(|(k, _)| *k == key) {
            Some((_, pos)) => items[*pos].members.push(i),
            None => {
                seen.push((key, items.len()));
                items.push(Item { rep: i, members: vec![i] });
            }
        }
    }
    items.sort_by(|a, b| {
        let (sa, sb) = (sev_rank(&rows[a.rep].severity), sev_rank(&rows[b.rep].severity));
        sb.cmp(&sa)
            .then(b.count().cmp(&a.count()))
            .then(a.members[0].cmp(&b.members[0]))
    });
    items
}

// --- (3) PLAN D'ANNEXE + INVARIANT ANTI-MASQUAGE ----------------------------------------------------

/// Un gabarit REPLIÉ : compté, nommé, récupérable.
#[derive(Debug, Clone)]
pub(crate) struct FoldedGroup {
    pub(crate) label: String,
    pub(crate) severity: String,
    pub(crate) representative: usize,
    pub(crate) members: Vec<usize>,
    pub(crate) example_target: String,
}

/// Ce que l'annexe RENDRA et ce qu'elle REPLIE — avec de quoi le VÉRIFIER (miroir de `AnnexPlan`).
#[derive(Debug, Default)]
pub(crate) struct AnnexPlan {
    pub(crate) rendered: Vec<usize>,
    pub(crate) folded_groups: Vec<FoldedGroup>,
    pub(crate) total: usize,
    pub(crate) view: &'static str,
}

impl AnnexPlan {
    /// Nombre de findings repliés — dérivé de la COMPTABILITÉ DES GROUPES, PAS de
    /// `total - rendered.len()`. C'est cette INDÉPENDANCE des deux dérivations qui rend `check()`
    /// capable de rougir : muter l'une seule les fait diverger.
    pub(crate) fn folded(&self) -> usize {
        self.folded_groups.iter().map(|g| g.members.len()).sum()
    }

    /// `(ok, explication)`. Fail-LOUD : l'appelant RENDRA l'explication dans le rapport si `ok` est
    /// faux — jamais de rattrapage silencieux.
    pub(crate) fn check(&self) -> (bool, String) {
        let mut seen: Vec<usize> = self.rendered.clone();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        if seen.len() != before {
            return (false, format!("{} finding(s) rendu(s) en double dans l'annexe", before - seen.len()));
        }
        let mut folded_idx: Vec<usize> = self.folded_groups.iter().flat_map(|g| g.members.clone()).collect();
        folded_idx.sort_unstable();
        let declared = self.folded();
        folded_idx.dedup();
        let overlap = folded_idx.iter().filter(|i| seen.binary_search(i).is_ok()).count();
        if overlap > 0 {
            return (false, format!("{overlap} finding(s) à la fois rendu(s) ET replié(s) (comptés deux fois)"));
        }
        let mut union: Vec<usize> = seen.iter().chain(folded_idx.iter()).copied().collect();
        union.sort_unstable();
        let missing = self.total.saturating_sub(union.len());
        let extra = union.iter().filter(|i| **i >= self.total).count();
        if union.len() != self.total || extra > 0 {
            return (
                false,
                format!(
                    "comptabilité CASSÉE : {missing} finding(s) NI rendu(s) NI replié(s) \
                     (disparus en silence), {extra} indice(s) inconnu(s)"
                ),
            );
        }
        if declared != folded_idx.len() {
            return (
                false,
                format!(
                    "comptabilité CASSÉE : tailles de groupes repliés déclarées={declared} \
                     mais {} membre(s) distinct(s) listés",
                    folded_idx.len()
                ),
            );
        }
        (
            true,
            format!(
                "{} rendu(s) + {} replié(s) = {} émis (partition exacte, aucune suppression)",
                self.rendered.len(),
                declared,
                self.total
            ),
        )
    }
}

/// Construit le plan d'annexe pour `view`. `keep` = indices DÉJÀ présentés en tête (actionnables /
/// non vérifiés) : en vue `bounty` ils ne sont JAMAIS repliés. En vue `pentest` (défaut), `rendered`
/// = TOUS les indices et `folded == 0` : l'annexe est exhaustive.
pub(crate) fn annex_plan(rows: &[FindingRow], view: &'static str, keep: &[usize]) -> AnnexPlan {
    let n = rows.len();
    let mut plan = AnnexPlan { total: n, view, ..Default::default() };
    if view != VIEW_BOUNTY {
        plan.rendered = (0..n).collect();
        return plan;
    }
    let mut seen_rep: Vec<((String, String, String), usize)> = Vec::new();
    let mut folded: Vec<((String, String, String), FoldedGroup)> = Vec::new();
    for i in 0..n {
        if keep.contains(&i) {
            plan.rendered.push(i);
            continue;
        }
        let key = template_key(&rows[i]);
        match seen_rep.iter().find(|(k, _)| *k == key) {
            None => {
                seen_rep.push((key, i));
                plan.rendered.push(i);
            }
            Some((_, rep)) => {
                let rep = *rep;
                match folded.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, g)) => g.members.push(i),
                    None => folded.push((
                        key,
                        FoldedGroup {
                            label: {
                                let l = normalize_title(&rows[rep].title);
                                if l.is_empty() { "(sans titre)".into() } else { l }
                            },
                            severity: {
                                let s = rows[rep].severity.to_ascii_uppercase();
                                if s.is_empty() { "INFO".into() } else { s }
                            },
                            representative: rep,
                            members: vec![i],
                            example_target: txt(&rows[rep].target),
                        },
                    )),
                }
            }
        }
    }
    plan.folded_groups = folded.into_iter().map(|(_, g)| g).collect();
    plan.folded_groups.sort_by(|a, b| b.members.len().cmp(&a.members.len()).then(a.representative.cmp(&b.representative)));
    plan
}

// --- (4) RENDU ---------------------------------------------------------------------------------------

/// Texte d'un champ, passé par la surface UNIQUE de rédaction (miroir de `report_view._txt` ->
/// `forge.redact`). Défense en profondeur : le rapport ne peut pas rendre un secret laissé passer.
pub(crate) fn txt(v: &str) -> String {
    crate::redact::redact_secrets(v)
}

fn dash(s: &str) -> String {
    if s.trim().is_empty() { "—".to_string() } else { s.to_string() }
}

/// Méthode HTTP DÉDUITE d'une commande PoC `curl`, ou '' si non déductible (miroir de
/// `report_view.http_method_from_poc`). AUCUNE invention : `-X` explicite, `-I` -> HEAD,
/// `-d/--data/-F/--form` -> POST, `curl` nu -> GET. Tout autre outil -> ''.
pub(crate) fn http_method_from_poc(poc: &str) -> String {
    if let Some(m) = find_dash_x(poc) {
        return m;
    }
    if !contains_curl(poc) {
        return String::new();
    }
    if has_head_flag(poc) {
        return "HEAD".into();
    }
    if has_body_flag(poc) {
        return "POST".into();
    }
    "GET".into()
}

/// `(?:^|\s)-X\s+([A-Za-z]{3,7})\b`
fn find_dash_x(p: &str) -> Option<String> {
    let b: Vec<char> = p.chars().collect();
    let mut i = 0usize;
    while i + 1 < b.len() {
        let at_start = i == 0 || b[i - 1].is_whitespace();
        if at_start && b[i] == '-' && b[i + 1] == 'X' {
            let mut j = i + 2;
            let ws0 = j;
            while j < b.len() && b[j].is_whitespace() {
                j += 1;
            }
            if j > ws0 {
                let m0 = j;
                while j < b.len() && b[j].is_ascii_alphabetic() && j - m0 < 7 {
                    j += 1;
                }
                let len = j - m0;
                // `\b` de queue : le caractère suivant ne doit pas être un caractère-mot.
                let bounded = j >= b.len() || !is_word_char(b[j]);
                if (3..=7).contains(&len) && bounded {
                    return Some(b[m0..j].iter().collect::<String>().to_ascii_uppercase());
                }
            }
        }
        i += 1;
    }
    None
}

/// `(?:^|\s|/)curl(?:\s|$)`
fn contains_curl(p: &str) -> bool {
    let b: Vec<char> = p.chars().collect();
    for i in 0..b.len() {
        if i + 4 > b.len() {
            break;
        }
        let head_ok = i == 0 || b[i - 1].is_whitespace() || b[i - 1] == '/';
        let word: String = b[i..i + 4].iter().collect();
        let tail_ok = i + 4 == b.len() || b[i + 4].is_whitespace();
        if head_ok && word == "curl" && tail_ok {
            return true;
        }
    }
    false
}

/// `(?:^|\s)-[a-zA-Z]*I(?:\s|$)`
fn has_head_flag(p: &str) -> bool {
    let b: Vec<char> = p.chars().collect();
    let mut i = 0usize;
    while i < b.len() {
        let at_start = i == 0 || b[i - 1].is_whitespace();
        if at_start && b[i] == '-' {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }
            // le dernier caractère alphabétique doit être 'I' et être suivi d'un blanc ou de la fin.
            if j > i + 1 && b[j - 1] == 'I' && (j >= b.len() || b[j].is_whitespace()) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// `(?:^|\s)(?:--data(?:-raw|-binary|-urlencode)?|-d|--form|-F)(?:\s|=)`
fn has_body_flag(p: &str) -> bool {
    const FLAGS: [&str; 7] = ["--data-urlencode", "--data-binary", "--data-raw", "--data", "--form", "-d", "-F"];
    let b: Vec<char> = p.chars().collect();
    for i in 0..b.len() {
        let at_start = i == 0 || b[i - 1].is_whitespace();
        if !at_start {
            continue;
        }
        for f in FLAGS {
            let fl: Vec<char> = f.chars().collect();
            if i + fl.len() <= b.len() && b[i..i + fl.len()] == fl[..] {
                let k = i + fl.len();
                if k >= b.len() || b[k].is_whitespace() || b[k] == '=' {
                    return true;
                }
            }
        }
    }
    false
}

/// « MÉTHODE URL » quand les DEUX sont déductibles du PoC, sinon '' (miroir de `request_line`).
pub(crate) fn request_line(f: &FindingRow) -> String {
    let poc = txt(&f.poc);
    let method = http_method_from_poc(&poc);
    if method.is_empty() {
        return String::new();
    }
    match first_url(&poc) {
        Some(u) => format!("{method} {}", u.trim_end_matches('\'').trim_end_matches('"')),
        None => String::new(),
    }
}

/// `https?://[^\s'"]+`
fn first_url(p: &str) -> Option<String> {
    let b: Vec<char> = p.chars().collect();
    for i in 0..b.len() {
        let rest: String = b[i..].iter().take(8).collect();
        let n = if rest.starts_with("https://") { 8 } else if rest.starts_with("http://") { 7 } else { 0 };
        if n > 0 {
            let mut j = i + n;
            while j < b.len() && !b[j].is_whitespace() && b[j] != '\'' && b[j] != '"' {
                j += 1;
            }
            return Some(b[i..j].iter().collect());
        }
    }
    None
}

/// « N occurrence(s) sur M cible(s) distincte(s) » + exemples bornés + reste EXPLICITEMENT compté.
fn occurrence_line(rows: &[FindingRow], item: &Item) -> String {
    let mut tgts: Vec<String> = Vec::new();
    for &i in &item.members {
        let t = {
            let v = txt(&rows[i].target);
            if v.is_empty() { "—".to_string() } else { v }
        };
        if !tgts.contains(&t) {
            tgts.push(t);
        }
    }
    let shown = tgts.len().min(MAX_OCCURRENCE_EXAMPLES);
    let rest = tgts.len() - shown;
    let mut body = tgts[..shown].iter().map(|t| format!("`{t}`")).collect::<Vec<_>>().join(", ");
    if rest > 0 {
        body.push_str(&format!(" · **+{rest} autre(s)**"));
    }
    format!("{} occurrence(s) sur {} cible(s) distincte(s) : {body}", item.count(), tgts.len())
}

/// Bloc d'UN item actionnable, à la forme attendue par un triager : titre, sévérité, CWE/CVSS,
/// endpoint + méthode, reproduction, COMMANDE REJOUABLE, observation, correctif, occurrences.
/// N'assemble QUE des champs EXISTANTS de la ligne finding — AUCUNE sévérité relevée, aucun impact
/// inventé : un statut non prouvé le DIT.
pub(crate) fn render_item(out: &mut Vec<String>, rows: &[FindingRow], item: &Item, num: usize, scope_line: &str) {
    let f = &rows[item.rep];
    let sev = {
        let s = f.severity.to_ascii_uppercase();
        if s.is_empty() { "INFO".to_string() } else { s }
    };
    let title = {
        let t = txt(&f.title);
        if t.is_empty() { "(sans titre)".to_string() } else { t }
    };
    let status = {
        let s = f.status.trim().to_ascii_lowercase();
        if s.is_empty() { "tested".to_string() } else { s }
    };
    let gloss = status_gloss(&status);
    let evidence = dash(&txt(&f.evidence));
    let fix = dash(&txt(&f.fix));
    let poc = txt(&f.poc);
    let cvss = dash(&f.cvss_display());
    let cwe = {
        let c = txt(&f.cwe);
        if c.is_empty() { dash(&txt(&f.category)) } else { c }
    };

    out.push(format!("### A{num} · [{sev}] {title}"));
    out.push(String::new());
    out.push("| | |".into());
    out.push("|---|---|".into());
    out.push(format!("| **Sévérité** | {sev} |"));
    out.push(format!("| **CWE** | {cwe} |"));
    out.push(format!("| **CVSS (base, indicatif)** | {cvss} |"));
    out.push(format!("| **ATT&CK** | {} |", dash(&txt(&f.mitre))));
    out.push(format!("| **Statut** | `{status}` — {} |", if gloss.is_empty() { "—" } else { gloss }));
    out.push(format!("| **Module** | `{}` |", dash(&txt(&f.tool))));
    out.push(format!("| **Cible** | `{}` |", dash(&txt(&f.target))));
    let req = request_line(f);
    if !req.is_empty() {
        out.push(format!("| **Requête** | `{req}` *(méthode déduite du PoC)* |"));
    }
    out.push(format!("| **Occurrences** | {} |", occurrence_line(rows, item)));
    out.push(String::new());

    out.push("**Reproduction**".into());
    out.push(String::new());
    let mut step = 1;
    if !scope_line.is_empty() {
        out.push(format!("{step}. Se placer sur le périmètre AUTORISÉ de l'engagement : {scope_line}."));
        step += 1;
    }
    if poc.is_empty() {
        out.push(format!("{step}. _Aucune commande rejouable enregistrée par le module pour ce finding._"));
    } else {
        out.push(format!("{step}. Rejouer la commande ci-dessous (telle quelle, elle est celle qu'a tirée Forge)."));
    }
    step += 1;
    out.push(format!("{step}. Observer : {evidence}"));
    out.push(String::new());
    if !poc.is_empty() {
        out.push("**Commande rejouable**".into());
        out.push(String::new());
        out.push("```bash".into());
        out.push(poc);
        out.push("```".into());
        out.push(String::new());
    }
    out.push(format!("**Observation (preuve brute)** : {evidence}"));
    out.push(String::new());
    if PROVEN_STATUSES.contains(&status.as_str()) {
        out.push("**Impact** : exploitabilité DÉMONTRÉE (statut prouvé par un oracle Forge). Voir la preuve ci-dessus.".into());
    } else {
        out.push(format!(
            "**Impact** : **non démontré** — statut `{status}`. Forge n'a pas prouvé l'exploitabilité ; \
             à qualifier manuellement avant toute soumission."
        ));
    }
    out.push(String::new());
    out.push(format!("**Correctif suggéré** : {fix}"));
    out.push(String::new());
}

/// Section **Verdict** — ce qu'un opérateur lit EN PREMIER, en une ligne. La ligne de tête est DÉRIVÉE
/// du corpus, jamais gonflée. `partial` (run coupé) la CORRIGE : sur un plan qui n'a pas tourné en
/// entier, « rien d'actionnable » est une CONCLUSION FAUSSE.
pub(crate) fn render_verdict(
    out: &mut Vec<String>,
    rows: &[FindingRow],
    b: &Buckets,
    items_expl: &[Item],
    items_qual: &[Item],
    view: &str,
    partial: Option<&str>,
) {
    let (n_expl, n_qual, n_unver, n_recon) = (b.exploitable.len(), b.qualify.len(), b.unverified.len(), b.recon.len());
    out.push("## Verdict".into());
    out.push(String::new());
    if n_expl > 0 {
        let top = &rows[items_expl[0].rep];
        out.push(format!(
            "> **{n_expl} finding(s) actionnable(s)** (sévérité ≥ MEDIUM ou exploitabilité prouvée). \
             Le plus grave : **[{}] {}** sur `{}` — détail en §« Actionnable — à reporter ».",
            top.severity.to_ascii_uppercase(),
            txt(&top.title),
            txt(&top.target),
        ));
    } else if let Some(cause) = partial {
        out.push(format!(
            "> **Rien d'actionnable DANS LA FRACTION DU PLAN QUI A TOURNÉ** — et le plan n'a **pas** \
             tourné en entier : run **INTERROMPU** ({cause}), {}. **Ne pas en conclure « rien trouvé »** : \
             ce verdict ne porte que sur les actions exécutées.",
            coverage_ratio_console()
        ));
    } else {
        out.push(
            "> **Rien d'actionnable trouvé.** Aucun finding de sévérité ≥ MEDIUM, aucune exploitabilité \
             prouvée. Ce qui suit est du signal à qualifier, des trous de couverture et du bruit de \
             reconnaissance — présentés comme tels, sans sur-classement."
                .into(),
        );
    }
    out.push(String::new());
    out.push(format!(
        "- **Actionnable** (≥ MEDIUM ou prouvé) : **{n_expl}**{}",
        if n_expl > 0 { format!(" → {} item(s) distinct(s)", items_expl.len()) } else { String::new() }
    ));
    out.push(format!(
        "- **À qualifier** (LOW / signalé par un outil, exploitabilité NON démontrée) : **{n_qual}**{}",
        if n_qual > 0 { format!(" → {} item(s) distinct(s)", items_qual.len()) } else { String::new() }
    ));
    out.push(format!(
        "- **Couverture NON vérifiée** (`skipped` — le module n'a pas pu conclure) : **{n_unver}**{}",
        if n_unver > 0 { " ⚠️ *ce sont des trous de couverture, pas du bruit*" } else { "" }
    ));
    out.push(format!(
        "- **Bruit de reconnaissance** (INFO) : **{n_recon}** — relégué en annexe, intégralement compté."
    ));
    out.push(format!("- **Total émis** : **{}** findings (vue `{view}`).", rows.len()));
    if let Some(cause) = partial {
        out.push(format!(
            "- **⚠️ Plan INCOMPLET** : {} — run interrompu ({cause}).",
            coverage_ratio_console()
        ));
    }
    out.push(String::new());
}

/// Phrase de couverture d'un run interrompu, VUE DE LA CONSOLE. Le moteur, lui, connaît
/// « X exécutées sur Y planifiées » (`interrupt.interruption_record`) ; la console ne reçoit PAS ces
/// compteurs (`forge/console_client.py::build_payload` ne les transmet pas). On dit donc ce qu'on sait
/// et on dit qu'on IGNORE le reste — miroir du repli honnête de `report_view.coverage_ratio` quand le
/// dénominateur est inconnu. Un ratio fabriqué serait exactement le faux réconfort qu'on combat.
fn coverage_ratio_console() -> String {
    "nombre d'actions exécutées inconnu (la console ne reçoit pas les compteurs de plan du moteur)".into()
}

/// Section **Couverture NON vérifiée** — les `skipped`, PROMUS avant tout le bruit. Un `skipped` dit
/// « je n'ai PAS pu vérifier » : sur une cible protégée c'est l'information la PLUS importante, parce
/// qu'elle BORNE ce que l'absence de finding permet de conclure. Regroupé PAR MODULE.
pub(crate) fn render_unverified(out: &mut Vec<String>, rows: &[FindingRow], idxs: &[usize]) {
    out.push("## Couverture NON vérifiée (trous de couverture)".into());
    out.push(String::new());
    if idxs.is_empty() {
        out.push(
            "_Aucun module n'a échoué à s'exécuter : la couverture annoncée par le plan a été \
             effectivement tentée._"
                .into(),
        );
        out.push(String::new());
        return;
    }
    // groupes ORDONNÉS par première apparition (déterminisme sans dépendance à un ordre de hachage).
    let mut order: Vec<String> = Vec::new();
    let mut groups: Vec<(usize, Vec<String>, Vec<String>)> = Vec::new(); // (n, reasons, targets)
    for &i in idxs {
        let tool = {
            let t = txt(&rows[i].tool);
            if t.is_empty() { "(module inconnu)".to_string() } else { t }
        };
        let kind = match tool.rsplit_once(':') {
            Some((_, tail)) => tail.to_string(),
            None => tool,
        };
        let pos = match order.iter().position(|k| *k == kind) {
            Some(p) => p,
            None => {
                order.push(kind);
                groups.push((0, Vec::new(), Vec::new()));
                order.len() - 1
            }
        };
        groups[pos].0 += 1;
        let reason = normalize_title(&txt(&rows[i].title));
        if !reason.is_empty() && !groups[pos].1.contains(&reason) {
            groups[pos].1.push(reason);
        }
        let t = txt(&rows[i].target);
        if !t.is_empty() && !groups[pos].2.contains(&t) {
            groups[pos].2.push(t);
        }
    }
    out.push(format!(
        "**{} finding(s) `skipped`** — {} module(s) n'ont PAS pu conclure. Une absence de finding sur \
         ces classes ne vaut donc **pas** une absence de vulnérabilité.",
        idxs.len(),
        order.len()
    ));
    out.push(String::new());
    out.push("| Module | Occurrences | Cibles | Raison(s) rapportée(s) |".into());
    out.push("|---|---|---|---|".into());
    let mut idx_order: Vec<usize> = (0..order.len()).collect();
    idx_order.sort_by(|a, b| groups[*b].0.cmp(&groups[*a].0).then(order[*a].cmp(&order[*b])));
    for p in idx_order {
        let (n, reasons, targets) = &groups[p];
        let shown = reasons.len().min(MAX_REASON_EXAMPLES);
        let more = reasons.len() - shown;
        let mut rtxt = reasons[..shown]
            .iter()
            .map(|r| r.chars().take(90).collect::<String>())
            .collect::<Vec<_>>()
            .join(" ; ");
        if more > 0 {
            rtxt.push_str(&format!(" · **+{more} autre(s)**"));
        }
        out.push(format!("| `{}` | {n} | {} | {rtxt} |", order[p], targets.len()));
    }
    out.push(String::new());
}

/// Rend une SÉRIE d'items actionnables. Renvoie le prochain numéro. AUCUNE borne : un item actionnable
/// n'est JAMAIS tronqué (le troncage est réservé aux listes d'exemples, toujours comptées).
pub(crate) fn render_actionable(
    out: &mut Vec<String>,
    rows: &[FindingRow],
    items: &[Item],
    heading: &str,
    intro: &str,
    scope_line: &str,
    start: usize,
) -> usize {
    out.push(heading.into());
    out.push(String::new());
    if items.is_empty() {
        out.push(intro.into());
        out.push(String::new());
        return start;
    }
    let mut num = start;
    for it in items {
        render_item(out, rows, it, num, scope_line);
        num += 1;
    }
    num
}

/// Ligne de COMPTABILITÉ de l'annexe — la garde « rien n'est masqué en silence », RENDUE. Dit combien
/// l'annexe rend, combien elle replie, et **où les retrouver**. Si l'invariant de partition tombe, on
/// n'essaie PAS de rattraper : on l'imprime en clair, en tête de section (fail-loud).
pub(crate) fn render_annex_accounting(out: &mut Vec<String>, plan: &AnnexPlan) {
    let (ok, why) = plan.check();
    if !ok {
        out.push(format!(
            "> ⚠️ **COMPTABILITÉ DE L'ANNEXE CASSÉE — {why}.** Ce rapport ne peut pas garantir \
             l'exhaustivité de son annexe : traiter le ledger (`kind=finding`) comme source de vérité \
             et signaler ce bug."
        ));
        out.push(String::new());
        return;
    }
    if plan.view == VIEW_BOUNTY && plan.folded() > 0 {
        out.push(format!(
            "> **{} finding(s) rendus ici, {} repliés** (= {} émis au total). Les repliés sont des \
             occurrences supplémentaires des gabarits listés ci-dessous — **aucun n'est supprimé** : \
             les rejouer avec `FORGE_REPORT_VIEW=pentest`, ou les lire dans le ledger signé (entrées \
             `kind=finding`).",
            plan.rendered.len(),
            plan.folded(),
            plan.total
        ));
        out.push(String::new());
        out.push("| Gabarit replié | Sévérité | Occurrences repliées | Exemple de cible |".into());
        out.push("|---|---|---|---|".into());
        for g in &plan.folded_groups {
            out.push(format!(
                "| {} | {} | {} | `{}` |",
                g.label.chars().take(70).collect::<String>(),
                g.severity,
                g.members.len(),
                g.example_target.chars().take(60).collect::<String>()
            ));
        }
        out.push(String::new());
    } else {
        out.push(format!(
            "> **{} finding(s) rendus, {} repliés** (= {} émis au total) — vue `{}` : rien n'est replié, \
             l'annexe est exhaustive.",
            plan.rendered.len(),
            plan.folded(),
            plan.total,
            plan.view
        ));
        out.push(String::new());
    }
}

/// EN-TÊTE D'HONNÊTETÉ D'UN RAPPORT PARTIEL — miroir de `report._interruption_banner`, dérivé de la
/// SEULE chose que la console sait : `run_job.status`. Un run `timeout`/`cancelled`/`failed`/`running`
/// n'a PAS couvert son plan ; un rapport tronqué qui ressemble à un rapport complet est PIRE que pas
/// de rapport. `None` sur un run terminé normalement -> rapport inchangé.
pub(crate) fn partial_cause(status: &str) -> Option<&'static str> {
    match status.trim().to_ascii_lowercase().as_str() {
        "timeout" => Some("budget dépassé (timeout)"),
        "cancelled" | "canceled" => Some("annulé par un opérateur"),
        "failed" => Some("échec du moteur"),
        "running" => Some("run ENCORE EN COURS — rapport pris à chaud"),
        _ => None,
    }
}

pub(crate) fn render_partial_banner(out: &mut Vec<String>, cause: &str) {
    out.push(format!("> ⚠️ **RAPPORT PARTIEL — RUN INTERROMPU ({cause}).**"));
    out.push(format!("> {}.", coverage_ratio_console()));
    out.push(
        "> **Ce rapport ne couvre QUE ce qui a tourné.** Une absence de finding n'y vaut **pas** une \
         absence de vulnérabilité : ce qui n'a pas été tenté n'a reçu AUCUN verdict, ni positif ni \
         négatif. Les modules qui n'ont pas pu conclure sont en §« Couverture NON vérifiée (trous de \
         couverture) »."
            .into(),
    );
    out.push(String::new());
}

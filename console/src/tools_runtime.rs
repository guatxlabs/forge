// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — CYCLE DE VIE DES OUTILS depuis l'UI (brique 4 de `docs/TOOLS_LIFECYCLE.md`).
//!
//! Le socle existe déjà et n'est PAS redéfini ici : le manifeste unique (`forge/tools.json`, SHA256
//! épinglé PAR ARCHITECTURE), l'installeur gouverné (`forge/toolsinstall.py` — intégrité obligatoire,
//! pin requis avant tout octet réseau, HTTPS strict, no-shell, pose atomique, ledger sinon REFUS) et la
//! CLI (`forge tools list|install|update|remove`). Ce module n'ajoute AUCUNE capacité : il expose CELLES
//! QUI SONT DÉJÀ GOUVERNÉES, à travers une API admin auditée, pour qu'un opérateur n'ait plus à faire
//! `docker compose exec … forge tools install …`.
//!
//! LA GARANTIE À NE PAS ANNULER — un téléchargement non épinglé doit rester INEXPRIMABLE, pas « refusé ».
//! `toolsinstall.install()` n'a AUCUN paramètre `url`/`sha256`/`digest` : la source est CALCULÉE depuis
//! le manifeste, qui EST l'allowlist. Une route qui exposerait un champ libre (URL, digest, version)
//! rouvrirait précisément le trou que le manifeste ferme. D'où la forme retenue ici :
//!
//!   * le corps accepté est EXACTEMENT `{action, name}` — tout autre champ est REFUSÉ (400) avant le
//!     moindre spawn. `url`, `sha256`, `digest`, `version` ne sont pas « ignorés » : ils font échouer la
//!     requête, avec un message qui NOMME la garantie (test dédié + preuve par mutation) ;
//!   * `action` vient d'un jeu FERMÉ (`install|update|remove`) ;
//!   * `name` doit être un identifiant sûr ET **figurer dans le manifeste tel que le MOTEUR le rapporte**
//!     (`forge tools list --json`). Si cette sonde n'aboutit pas, la mutation est REFUSÉE — on ne
//!     transmet jamais un nom qu'on n'a pas pu confronter à l'allowlist ;
//!   * l'argv est FIXE et intégralement construit ici (jamais de shell, jamais de champ libre concaténé).
//!
//! GOUVERNANCE : ADMIN-ONLY (`check_admin`, fail-closed 403 — installer un BINAIRE est au moins aussi
//! privilégié que déclarer un outil via `/api/tools`, qui est déjà admin-only ; et cela exige une
//! attribution INDIVIDUELLE, jamais un secret partagé « bootstrap »). Chaque mutation est LEDGERISÉE
//! côté console (`console.tools.install|update|remove`) — en PLUS de l'entrée `tools.install` que
//! l'installeur écrit lui-même, avec le digest vérifié. Le spawn passe par le SEUL helper borné
//! (`bounded_engine_output` : budget de temps, plafond de concurrence, cap d'octets, kill de groupe).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};

use crate::{admin_denied, append_console_ledger, attribution_login, check_admin, App};

/// Jeu FERMÉ des actions exposées. `list` n'y est pas : c'est la LECTURE (GET), qui n'exécute rien.
pub(crate) const ACTIONS: &[&str] = &["install", "update", "remove"];

/// Champs acceptés dans le corps d'une mutation. La liste est FERMÉE et c'est tout l'intérêt : elle ne
/// contient ni `url`, ni `sha256`, ni `digest`, ni `version` — ces notions n'ont pas de représentation
/// dans cette API, donc pas de chemin d'entrée.
const ALLOWED_BODY_FIELDS: &[&str] = &["action", "name"];

/// Longueur max d'un nom d'outil (les noms du manifeste font < 16 caractères).
const MAX_NAME_LEN: usize = 64;

// =================================================================================================
//  VALIDATION D'ENTRÉE — PURE, fail-closed, testable sans moteur ni DB
// =================================================================================================

/// Un nom d'outil ACCEPTABLE en FORME : `[a-z0-9._-]`, non vide, borné, ne commence PAS par `-`
/// (hygiène anti-drapeau : une valeur ne doit jamais pouvoir être prise pour une option) et sans `..`
/// ni séparateur de chemin. C'est une condition NÉCESSAIRE, pas suffisante : l'appartenance au
/// manifeste est vérifiée séparément (cf. [`check_in_manifest`]).
pub(crate) fn is_safe_tool_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && !s.starts_with('-')
        && !s.contains("..")
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// Valide le corps d'une mutation et rend `(action, name)`. FAIL-CLOSED sur TOUT champ inconnu — c'est
/// ce refus, et non un filtrage silencieux, qui rend `url`/`sha256`/`digest` INEXPRIMABLES : une requête
/// qui tente d'épingler autre chose que le manifeste ÉCHOUE, bruyamment, avant tout spawn.
pub(crate) fn validate_request(body: &Value) -> Result<(String, String), String> {
    let obj = body.as_object().ok_or("le corps doit être un objet {action, name}")?;
    for k in obj.keys() {
        if !ALLOWED_BODY_FIELDS.contains(&k.as_str()) {
            return Err(format!(
                "champ '{k}' refusé — cette API n'accepte QUE {{action, name}}. La source et le digest \
                 viennent du manifeste (forge/tools.json) : il n'existe aucun paramètre d'URL, de \
                 version ou d'empreinte, ici comme dans `forge tools`. Bumper le manifeste est la seule \
                 voie vers une autre version."
            ));
        }
    }
    let action = obj.get("action").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !ACTIONS.contains(&action.as_str()) {
        return Err(format!("action '{action}' inconnue (install|update|remove)"));
    }
    let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !is_safe_tool_name(&name) {
        return Err(format!(
            "nom d'outil '{name}' invalide — attendu un nom du manifeste ([a-z0-9._-], sans '-' initial)"
        ));
    }
    Ok((action, name))
}

/// Le nom est-il DANS l'allowlist (le manifeste, tel que le moteur le rapporte) ? `names` provient de la
/// sonde `forge tools list --json`, pas d'une liste recopiée ici : il n'existe qu'UNE source de vérité.
pub(crate) fn check_in_manifest(names: &[String], name: &str) -> Result<(), String> {
    if names.iter().any(|n| n == name) {
        return Ok(());
    }
    Err(format!(
        "outil '{name}' absent du manifeste — seules les entrées de forge/tools.json sont installables \
         (allowlist de source). Connus : {}",
        names.join(", ")
    ))
}

/// argv FIXE du sous-processus moteur. Tous les tokens sont soit LITTÉRAUX, soit une des quatre valeurs
/// VALIDÉES (`action` du jeu fermé, `name` du manifeste, `actor` de la session, `ledger` de la config
/// serveur). Aucun champ de la requête n'atterrit ailleurs, et aucun n'est concaténé dans un token.
pub(crate) fn build_argv(action: &str, name: &str, actor: &str, ledger: &str) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "-m".into(),
        "forge.cli".into(),
        "tools".into(),
        action.into(),
        name.into(),
        "--json".into(),
        "--ledger".into(),
        ledger.into(),
    ];
    // `--actor` n'est qu'une estampille de ledger. Un login est déjà validé à la création du compte ;
    // on re-garde quand même la forme (anti-drapeau) plutôt que de faire confiance en aval.
    if !actor.is_empty() && !actor.starts_with('-') && !actor.contains('\0') {
        v.push("--actor".into());
        v.push(actor.into());
    }
    v
}

// =================================================================================================
//  SONDE MOTEUR (bornée) — lecture de l'état des outils
// =================================================================================================

/// Lance `python3 -m forge.cli tools <args>` SOUS LES BORNES du moteur (budget de temps, plafond de
/// concurrence, cap d'octets, kill de groupe). Rend `(stdout, rc)` ou une raison NOMMÉE.
async fn run_tools_cli(app: &App, args: &[String]) -> Result<(String, i32), String> {
    let mut cmd = tokio::process::Command::new(app.python.as_str());
    cmd.args(args).current_dir(app.pkg_dir.as_str());
    let budget = std::time::Duration::from_secs(crate::engine_timeout_secs());
    match crate::bounded_engine_output(&crate::ENGINE_OPERATOR_GATE, cmd, budget, crate::ENGINE_TEXT_MAX_BYTES, None).await {
        Ok(o) => Ok((String::from_utf8_lossy(&o.stdout).into_owned(), o.status.code().unwrap_or(-1))),
        Err(e) => Err(e.why()),
    }
}

/// État des outils du manifeste (`forge tools list --json`, LECTURE SEULE : la CLI n'exécute AUCUN
/// outil — la version installée vient du reçu déposé à l'installation).
async fn probe_status(app: &App) -> Result<Vec<Value>, String> {
    let args: Vec<String> = ["-m", "forge.cli", "tools", "list", "--json"].iter().map(|s| s.to_string()).collect();
    let (out, rc) = run_tools_cli(app, &args).await?;
    if rc != 0 {
        return Err(format!("`forge tools list` rc={rc}"));
    }
    // La sortie peut porter des lignes de diagnostic avant le JSON : on prend la DERNIÈRE ligne qui
    // parse en tableau (même prudence que le parseur de `modules --json`).
    for line in out.lines().rev() {
        if let Ok(Value::Array(a)) = serde_json::from_str::<Value>(line.trim()) {
            return Ok(a);
        }
    }
    Err("sortie de `forge tools list --json` illisible (pas de tableau JSON)".to_string())
}

/// Noms du manifeste extraits d'un état sondé. PURE.
pub(crate) fn manifest_names(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .filter_map(|r| r.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect()
}

// =================================================================================================
//  HANDLERS
// =================================================================================================

pub(crate) fn routes() -> Router<App> {
    Router::new().route("/api/tools/runtime", get(runtime_list).post(runtime_action))
}

/// GET /api/tools/runtime — ADMIN (fail-closed 403). État par outil : version cible du manifeste,
/// version installée (lue dans le reçu), résolution PATH, provenance, et si l'outil est ÉPINGLÉ pour
/// l'architecture courante. N'EXÉCUTE aucun outil et n'installe rien. Une sonde qui n'aboutit pas est
/// DITE (`probe_error`) au lieu d'être rendue comme une liste vide.
pub(crate) async fn runtime_list(State(app): State<App>, headers: HeaderMap) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    match probe_status(&app).await {
        Ok(rows) => (StatusCode::OK, Json(json!({"tools": rows, "actions": ACTIONS}))).into_response(),
        Err(why) => (
            StatusCode::OK,
            Json(json!({
                "tools": [],
                "actions": ACTIONS,
                "probe_error": why,
                "why": "état des outils indisponible (moteur injoignable) — aucune action n'est proposée tant que l'allowlist du manifeste n'a pas pu être lue",
            })),
        )
            .into_response(),
    }
}

/// POST /api/tools/runtime `{action, name}` — ADMIN (fail-closed 403), LEDGERISÉ.
///
/// Ordre des gardes (tout ce qui peut refuser le fait avant le moindre spawn D'ACTION) :
///   1. session admin ; 2. corps EXACTEMENT `{action, name}` (tout autre champ = 400) ; 3. action du jeu
///   fermé + forme du nom ; 4. appartenance au manifeste, confrontée à la sonde du moteur (sonde
///   indisponible => REFUS) ; 5. argv FIXE, spawn borné ; 6. ledger `console.tools.<action>`.
pub(crate) async fn runtime_action(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !check_admin(&app, &headers) {
        return admin_denied().into_response();
    }
    let actor = attribution_login(&app, &headers);
    let (action, name) = match validate_request(&body) {
        Ok(v) => v,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "tool_request_invalid", "why": why}))).into_response(),
    };
    // ALLOWLIST : le nom doit figurer dans le manifeste TEL QUE LE MOTEUR LE RAPPORTE. Sonde indisponible
    // => on refuse (fail-closed) : on ne transmet pas un nom qu'on n'a pas pu confronter à l'allowlist.
    let names = match probe_status(&app).await {
        Ok(rows) => manifest_names(&rows),
        Err(why) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "manifest_unavailable", "why": format!("manifeste illisible ({why}) — action refusée")})),
            )
                .into_response()
        }
    };
    if let Err(why) = check_in_manifest(&names, &name) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "tool_unknown", "why": why}))).into_response();
    }
    let argv = build_argv(&action, &name, &actor, app.ledger_path.as_str());
    let (out, rc) = match run_tools_cli(&app, &argv).await {
        Ok(v) => v,
        Err(why) => {
            append_console_ledger(&app, &format!("console.tools.{action}"), json!({
                "actor": actor, "name": name, "action": action, "ok": false, "why": why,
            }));
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": "engine_unavailable", "why": why}))).into_response();
        }
    };
    // La CLI rend un objet JSON d'issue en `--json` ; en cas de refus elle sort en rc=1 avec un texte.
    let result: Value = out
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str::<Value>(l.trim()).ok().filter(|v| v.is_object()))
        .unwrap_or(Value::Null);
    let ok = rc == 0;
    // LEDGER CONSOLE : qui a demandé quoi, et l'issue. Le digest vérifié + l'URL sont déjà écrits par
    // l'installeur lui-même (`tools.install`, signé moteur) — on ne les recopie pas, on les référence.
    append_console_ledger(&app, &format!("console.tools.{action}"), json!({
        "actor": actor,
        "name": name,
        "action": action,
        "ok": ok,
        "rc": rc,
        "result": result.get("action").cloned().unwrap_or(Value::Null),
        "version": result.get("version").cloned().unwrap_or(Value::Null),
    }));
    if ok {
        (StatusCode::OK, Json(json!({"ok": true, "action": action, "name": name, "result": result}))).into_response()
    } else {
        // Le REFUS de l'installeur (digest non concordant, pin absent, dir non inscriptible, ledger
        // injoignable) est rendu TEL QUEL : c'est un diagnostic, pas une erreur interne à masquer.
        let msg = out.lines().rev().find(|l| l.contains("REFUS")).unwrap_or("").trim().to_string();
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "action": action, "name": name, "rc": rc,
                        "why": if msg.is_empty() { format!("`forge tools {action}` rc={rc}") } else { msg }})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    // =============================================================================
    //  LA GARANTIE : une source non épinglée est INEXPRIMABLE, pas « refusée »
    // =============================================================================

    /// Aucun champ d'URL / d'empreinte / de version n'a de représentation : chacun fait ÉCHOUER la
    /// requête. MUTATION : retirer la boucle `ALLOWED_BODY_FIELDS` de `validate_request` -> ce test
    /// rougit (les champs seraient silencieusement ignorés, ce qui est le début d'une régression :
    /// quelqu'un finirait par les brancher).
    #[test]
    fn no_url_digest_or_version_can_even_be_expressed() {
        for smuggle in [
            json!({"action": "install", "name": "nuclei", "url": "http://evil.example/x.zip"}),
            json!({"action": "install", "name": "nuclei", "sha256": "00".repeat(32)}),
            json!({"action": "install", "name": "nuclei", "digest": "sha256:dead"}),
            json!({"action": "install", "name": "nuclei", "version": "9.9.9"}),
            json!({"action": "install", "name": "nuclei", "manifest": {"url": "http://evil"}}),
        ] {
            let e = validate_request(&smuggle).unwrap_err();
            assert!(e.contains("refusé"), "champ libre accepté : {smuggle} -> {e}");
            assert!(e.contains("manifeste"), "le refus doit NOMMER la garantie : {e}");
        }
        // La forme légitime, elle, passe.
        assert_eq!(
            validate_request(&json!({"action": "install", "name": "nuclei"})).unwrap(),
            ("install".to_string(), "nuclei".to_string())
        );
    }

    /// L'argv construit ne contient QUE le squelette fixe + les valeurs validées. Il n'y a aucun token
    /// dérivé d'un champ libre, et aucune option d'URL/digest — la CLI n'en a d'ailleurs pas.
    #[test]
    fn argv_is_fixed_and_carries_no_source_parameter() {
        let argv = build_argv("install", "nuclei", "alice", "/data/ledger/x.jsonl");
        assert_eq!(
            argv,
            vec!["-m", "forge.cli", "tools", "install", "nuclei", "--json", "--ledger", "/data/ledger/x.jsonl", "--actor", "alice"]
        );
        for tok in &argv {
            let t = tok.to_ascii_lowercase();
            assert!(!t.contains("--url") && !t.contains("--sha") && !t.contains("--digest"), "token de source: {tok}");
        }
        // Un acteur qui ressemblerait à un drapeau n'est pas transmis (hygiène anti-option-injection).
        let argv = build_argv("remove", "httpx", "-oN/tmp/pwned", "/l.jsonl");
        assert!(!argv.iter().any(|t| t.starts_with("-oN")), "acteur-drapeau transmis: {argv:?}");
        assert!(!argv.contains(&"--actor".to_string()));
    }

    /// Actions hors jeu fermé et noms mal formés sont refusés (dont un nom-drapeau et une traversée).
    #[test]
    fn action_and_name_are_closed_and_shaped() {
        assert!(validate_request(&json!({"action": "exec", "name": "nuclei"})).is_err());
        assert!(validate_request(&json!({"action": "list", "name": "nuclei"})).is_err(), "list est une LECTURE (GET)");
        for bad in ["-oN", "../../etc/passwd", "nu clei", "NUCLEI", "", "a/b"] {
            assert!(
                validate_request(&json!({"action": "install", "name": bad})).is_err(),
                "nom accepté à tort: {bad:?}"
            );
        }
        assert!(is_safe_tool_name("nuclei") && is_safe_tool_name("gau") && is_safe_tool_name("feroxbuster"));
    }

    /// L'allowlist EST le manifeste : un nom bien formé mais absent est refusé, en nommant les connus.
    /// MUTATION : faire rendre `Ok(())` à `check_in_manifest` -> ce test rougit.
    #[test]
    fn only_manifest_names_pass_the_allowlist() {
        let names: Vec<String> = ["httpx", "nuclei"].iter().map(|s| s.to_string()).collect();
        assert!(check_in_manifest(&names, "nuclei").is_ok());
        let e = check_in_manifest(&names, "curl").unwrap_err();
        assert!(e.contains("absent du manifeste") && e.contains("httpx"), "refus peu informatif: {e}");
    }

    /// `manifest_names` lit les noms de la sonde (source unique), sans liste recopiée côté console.
    #[test]
    fn manifest_names_come_from_the_probe() {
        let rows = vec![json!({"name": "httpx", "version": "1.6.9"}), json!({"version": "x"}), json!({"name": "gau"})];
        assert_eq!(manifest_names(&rows), vec!["httpx".to_string(), "gau".to_string()]);
    }

    // =============================================================================
    //  GOUVERNANCE — gate + refus AVANT tout spawn
    // =============================================================================

    /// GET et POST sont ADMIN-ONLY. MUTATION : retirer `check_admin` d'un des deux -> ce test rougit.
    #[tokio::test]
    async fn runtime_routes_are_admin_only() {
        let led = testutil::tmp_path("toolsrt-admin.jsonl");
        let app = testutil::test_app(&led);
        let anon = HeaderMap::new();
        assert_eq!(runtime_list(State(app.clone()), anon.clone()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            runtime_action(State(app.clone()), anon, Json(json!({"action": "install", "name": "nuclei"}))).await.status(),
            StatusCode::FORBIDDEN
        );
        let _ = std::fs::remove_file(&led);
    }

    /// Un corps portant une URL est refusé 400 par le HANDLER — donc AVANT toute sonde et tout spawn
    /// (aucune ligne de ledger, aucun process). La garantie n'est pas seulement dans la fonction pure :
    /// elle est appliquée sur le chemin réel, en premier.
    #[tokio::test]
    async fn smuggled_url_is_refused_by_the_handler_before_any_spawn() {
        let led = testutil::tmp_path("toolsrt-smuggle.jsonl");
        let app = testutil::test_app(&led);
        let adm = testutil::admin_session(&app, "adm");
        let r = runtime_action(
            State(app.clone()),
            adm,
            Json(json!({"action": "install", "name": "nuclei", "url": "http://evil.example/x.zip"})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let b = testutil::resp_json(r).await;
        assert_eq!(b["error"], "tool_request_invalid");
        assert!(
            std::fs::read_to_string(&led).unwrap_or_default().is_empty(),
            "un refus de forme a produit une trace : un spawn a donc eu lieu"
        );
        let _ = std::fs::remove_file(&led);
    }

    #[test]
    fn routes_build() {
        let _r: Router<App> = routes();
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Enterprise flag helpers — the ONE copy of the "is this enterprise feature engaged?" logic that
//! sso / tenancy / compliance / scim each carried verbatim. Behaviour is byte-for-byte the historical
//! per-module code: env truthy (1|true|on|yes, case-insensitive) OR the per-DB config key in
//! {on,1,true,yes}. Community default = OFF (every gated route stays 404, byte-identical).

use crate::App;

/// Prefix of the RETIRED advanced-module variables. They were renamed `FORGE_ADVANCED_<suffix>`
/// WITHOUT an alias: the old name engages nothing.
pub(crate) const RETIRED_ENV_PREFIX: &str = "FORGE_ENTERPRISE_";
/// Suffixes that have a `FORGE_ADVANCED_<suffix>` successor. Mirrors `forge/signing.py::RENAMED_ENV_SUFFIXES`.
pub(crate) const RENAMED_ENV_SUFFIXES: [&str; 5] = ["STORE", "COMPLIANCE", "SSO", "TENANCY", "SCIM"];

/// Retired-name gate, run before ANY other start-up step (server or CLI). A `FORGE_ENTERPRISE_*`
/// variable that is merely PRESENT (whatever its value, even empty) makes the console refuse to start:
/// ignoring it in silence would leave tenant isolation, SSO or compliance OFF for whoever upgrades
/// without reading. `Err` names each variable found and its new name, never a value. Pure over the
/// variable NAMES it is given, so the whole contract is unit-testable without touching the environment.
pub(crate) fn retired_env_gate<I, S>(names: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut found: Vec<String> = names
        .into_iter()
        .filter(|n| n.as_ref().starts_with(RETIRED_ENV_PREFIX))
        .map(|n| n.as_ref().to_string())
        .collect();
    if found.is_empty() {
        return Ok(());
    }
    found.sort();
    let parts: Vec<String> = found
        .iter()
        .map(|name| {
            let suffix = &name[RETIRED_ENV_PREFIX.len()..];
            if RENAMED_ENV_SUFFIXES.contains(&suffix) {
                format!("{name} -> rename it to FORGE_ADVANCED_{suffix}")
            } else {
                format!("{name} -> no successor, remove it")
            }
        })
        .collect();
    Err(format!(
        "retired environment variable(s) still set: {}. The FORGE_ENTERPRISE_* names are no longer read \
         (renamed FORGE_ADVANCED_*, no alias); refusing to start rather than run with an advanced module \
         silently off. See docs/UPGRADE.md §7.",
        parts.join("; ")
    ))
}

/// [`retired_env_gate`] over the names of the PROCESS environment (`vars_os`, so a variable whose value
/// is not UTF-8 is still seen).
pub(crate) fn retired_env_gate_from_process() -> Result<(), String> {
    retired_env_gate(std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()))
}

/// Truthy env read (1|true|on|yes, case-insensitive). Absent/other => false.
pub(crate) fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"))
        .unwrap_or(false)
}

/// Is an enterprise feature ENGAGED?  `env_truthy(env_key)` OR the per-DB config key `setting_key`
/// reads one of {on,1,true,yes}. Reproduces EXACTLY each module's former `enabled()` body. Per-DB so
/// tests toggle it in isolation.
pub(crate) fn enterprise_enabled(app: &App, env_key: &str, setting_key: &str) -> bool {
    if env_truthy(env_key) {
        return true;
    }
    let store = app.store();
    matches!(
        crate::settings_get_store(&store, setting_key).as_deref(),
        Some("on") | Some("1") | Some("true") | Some("yes")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFUSAL_SSO: &str = "retired environment variable(s) still set: FORGE_ENTERPRISE_SSO -> rename it to \
         FORGE_ADVANCED_SSO. The FORGE_ENTERPRISE_* names are no longer read (renamed FORGE_ADVANCED_*, no \
         alias); refusing to start rather than run with an advanced module silently off. See \
         docs/UPGRADE.md §7.";

    /// GATE CONTRACT : ancien nom présent -> refus au message exact ; nouveaux noms ou aucun -> démarrage.
    #[test]
    fn retired_env_gate_contract() {
        assert_eq!(retired_env_gate(["PATH", "FORGE_ENTERPRISE_SSO"]), Err(REFUSAL_SSO.to_string()));
        assert_eq!(retired_env_gate(["PATH", "HOME"]), Ok(()), "aucun des deux noms : démarrage inchangé");
        let new_names: Vec<String> = RENAMED_ENV_SUFFIXES.iter().map(|s| format!("FORGE_ADVANCED_{s}")).collect();
        assert_eq!(retired_env_gate(&new_names), Ok(()), "les nouveaux noms ne sont pas refusés");
        // Le nouveau nom posé À CÔTÉ ne lève pas le refus : l'ancien reste une intention à corriger.
        assert!(retired_env_gate(["FORGE_ADVANCED_SSO", "FORGE_ENTERPRISE_SSO"]).is_err());
        // Tous nommés, triés, chacun avec son successeur ; un suffixe inconnu n'en a pas.
        let mut all: Vec<String> = RENAMED_ENV_SUFFIXES.iter().map(|s| format!("FORGE_ENTERPRISE_{s}")).collect();
        all.push("FORGE_ENTERPRISE_UNKNOWN".into());
        let e = retired_env_gate(&all).expect_err("refus");
        for s in RENAMED_ENV_SUFFIXES {
            assert!(e.contains(&format!("FORGE_ENTERPRISE_{s} -> rename it to FORGE_ADVANCED_{s}")), "{s}: {e}");
        }
        assert!(e.contains("FORGE_ENTERPRISE_UNKNOWN -> no successor, remove it"), "{e}");
        // Un préfixe proche n'est pas confondu.
        assert_eq!(retired_env_gate(["FORGE_ENTERPRISE", "XFORGE_ENTERPRISE_SSO"]), Ok(()));
    }

    // Les témoins « nouveau nom -> module actif » posent une variable d'ENV : dans le binaire de test,
    // l'ENV est partagé par des tests parallèles qui lisent `sso::enabled` & co SANS verrou. Ils tournent
    // donc dans un PROCESSUS ENFANT (ce même binaire de test, relancé sur le seul corps ci-dessous), qui
    // reçoit son environnement dès le départ : aucune écriture d'ENV dans le processus partagé.
    const CHILD_EXPECT: &str = "FORGE_TEST_FLAGS_CHILD_EXPECT";
    const CHILD_BODY: &str = "flags::tests::child_process_body_module_flags";

    /// Corps exécuté par l'ENFANT seulement (sans `FORGE_TEST_FLAGS_CHILD_EXPECT`, il rend la main).
    #[test]
    fn child_process_body_module_flags() {
        let Ok(expect) = std::env::var(CHILD_EXPECT) else { return };
        let want = expect == "on";
        let app = crate::testutil::test_app(&crate::testutil::tmp_path("flags-child-ledger"));
        assert_eq!(crate::sso::enabled(&app), want, "sso");
        assert_eq!(crate::tenancy::enabled(&app), want, "tenancy");
        assert_eq!(crate::compliance::enabled(&app), want, "compliance");
        assert_eq!(crate::scim::enabled(&app), want, "scim");
        #[cfg(feature = "store-postgres")]
        assert_eq!(crate::cli::cli_pg_url().is_some(), want, "store");
    }

    fn run_child(env: &[(String, &str)], expect: &str) {
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("test binary"));
        cmd.args([CHILD_BODY, "--exact", "--test-threads=1"]);
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().into_owned();
            if k.starts_with("FORGE_ADVANCED_") || k.starts_with(RETIRED_ENV_PREFIX) || k == "FORGE_DB_URL" {
                cmd.env_remove(k);
            }
        }
        cmd.env(CHILD_EXPECT, expect).env("FORGE_DB_URL", "postgres://forge@192.0.2.10/forge");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("spawn child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "enfant en échec ({env:?}):\n{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
        assert!(stdout.contains("1 passed"), "l'enfant n'a pas joué le corps ({env:?}):\n{stdout}");
    }

    fn names(prefix: &str) -> Vec<(String, &'static str)> {
        RENAMED_ENV_SUFFIXES
            .iter()
            .map(|s| (format!("{prefix}{s}"), if *s == "STORE" { "postgres" } else { "1" }))
            .collect()
    }

    #[test]
    fn new_names_engage_the_modules_old_names_do_not() {
        run_child(&names("FORGE_ADVANCED_"), "on");
        run_child(&names(RETIRED_ENV_PREFIX), "off");
        run_child(&[], "off");
    }

    // BRANCHEMENT de la garde : la fonction pure ne suffit pas, il faut que `main` l'appelle. Ce test est
    // à la fois le parent et l'enfant : relancé avec `FORGE_TEST_ENTRY_CHILD`, il appelle le VRAI point
    // d'entrée `crate::main()`, qui lit l'argv du harnais (le nom du test) et l'ENV posé par le parent.
    // Le message est exigé, pas seulement le code : sans la garde, cet argv tombe sur « sous-commande
    // inconnue », qui sort AUSSI en code 2.
    const ENTRY_CHILD: &str = "FORGE_TEST_ENTRY_CHILD";
    const ENTRY_TEST: &str = "flags::tests::real_entry_point_refuses_a_retired_name";

    #[test]
    fn real_entry_point_refuses_a_retired_name() {
        if std::env::var_os(ENTRY_CHILD).is_some() {
            crate::main(); // sort par `std::process::exit` ; ne revient pas si la garde mord
            return;
        }
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("test binary"));
        cmd.args([ENTRY_TEST, "--exact", "--test-threads=1", "--nocapture"]);
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().into_owned();
            if k.starts_with("FORGE_ADVANCED_") || k.starts_with(RETIRED_ENV_PREFIX) {
                cmd.env_remove(k);
            }
        }
        cmd.env(ENTRY_CHILD, "1").env("FORGE_ENTERPRISE_SSO", "1");
        let out = cmd.output().expect("spawn child");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "code de sortie du point d'entrée:\n{stderr}");
        assert!(
            stderr.contains("[forge] FATAL retired environment variable(s) still set: FORGE_ENTERPRISE_SSO"),
            "le refus doit venir de la garde, pas d'un autre code 2:\n{stderr}"
        );
    }
}

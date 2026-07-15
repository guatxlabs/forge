// SPDX-License-Identifier: AGPL-3.0-only
//! `*_FILE` secret indirection (12-factor / Docker & k8s secrets) — "the key shouldn't be next to
//! the door". Lets a secret's PLAINTEXT live in a mounted, root-owned Secret FILE instead of a
//! `.env` sitting beside the app; the env then holds a PATH, not the secret.
//!
//! `secret_from_env(NAME)` resolves a single secret, in precedence order:
//!
//! - `NAME` set & NON-EMPTY: its value (the direct env path; COMMUNITY DEFAULT — byte-identical).
//! - else `NAME_FILE` set: READ that file, `trim_end` (a trailing `\n` in a Docker/k8s secret file
//!   must NOT corrupt the token/passphrase), and return it. Unreadable/missing file -> `None` + a
//!   stderr warning that names the VAR (NEVER the value).
//! - else: `None`.
//!
//! FAIL-SOFT: an unreadable `NAME_FILE` never panics and never yields a silent empty secret — it
//! returns `None` so the caller's own fallback (auto-generate / fail-closed refusal) engages instead
//! of a weakened-auth empty string. The secret value is NEVER logged.

/// Resolve a secret from the environment with `*_FILE` fallback. See module docs for the full
/// precedence + rationale. Returns `None` when neither `name` (non-empty) nor a readable `name_FILE`
/// is present. The returned string is the direct env value verbatim, OR the file contents with
/// trailing whitespace/newlines removed. Never logs the secret value.
pub(crate) fn secret_from_env(name: &str) -> Option<String> {
    // 1) Direct env var wins when set & non-empty (community default path — unchanged).
    if let Ok(v) = std::env::var(name) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    // 2) `<NAME>_FILE` indirection: the env holds a PATH; the secret lives in the mounted file.
    let file_var = format!("{name}_FILE");
    let path = std::env::var(&file_var).ok().filter(|p| !p.is_empty())?;
    match std::fs::read_to_string(&path) {
        // Trim trailing whitespace/newline: Docker/k8s secret files conventionally end with a `\n`
        // that must not be baked into the token/passphrase. Leading bytes are preserved verbatim.
        Ok(s) => Some(s.trim_end().to_string()),
        Err(e) => {
            // FAIL-SOFT: name the VAR + the io error KIND only — never the path contents / secret.
            eprintln!(
                "[forge] avertissement : {file_var} illisible ({}) — secret non résolu (fail-soft, aucune valeur exposée)",
                e.kind()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::secret_from_env;
    use std::io::Write;

    // Unique var names per test (env is process-global; the suite runs threaded) — no cross-test race.
    fn write_temp_secret(contents: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("forge-secret-{}-{}", std::process::id(), crate::gen_token()));
        let mut f = std::fs::File::create(&p).expect("create temp secret");
        f.write_all(contents.as_bytes()).expect("write temp secret");
        p.to_string_lossy().to_string()
    }

    #[test]
    fn direct_var_returns_value() {
        let var = "FORGE_TEST_SECRET_DIRECT_A";
        std::env::set_var(var, "direct-value");
        assert_eq!(secret_from_env(var).as_deref(), Some("direct-value"));
        std::env::remove_var(var);
    }

    #[test]
    fn file_returns_trimmed_contents_when_only_file_set() {
        let var = "FORGE_TEST_SECRET_FILE_B";
        std::env::remove_var(var);
        // Trailing newline + spaces MUST be trimmed (Docker secret file convention).
        let path = write_temp_secret("s3cr3t-from-file  \n\n");
        std::env::set_var(format!("{var}_FILE"), &path);
        assert_eq!(secret_from_env(var).as_deref(), Some("s3cr3t-from-file"));
        std::env::remove_var(format!("{var}_FILE"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn direct_var_takes_precedence_over_file() {
        let var = "FORGE_TEST_SECRET_PREC_C";
        let path = write_temp_secret("from-file");
        std::env::set_var(var, "from-env");
        std::env::set_var(format!("{var}_FILE"), &path);
        // Direct env var wins — the *_FILE path is only a FALLBACK (community default unchanged).
        assert_eq!(secret_from_env(var).as_deref(), Some("from-env"));
        std::env::remove_var(var);
        std::env::remove_var(format!("{var}_FILE"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_both_is_none() {
        let var = "FORGE_TEST_SECRET_NONE_D";
        std::env::remove_var(var);
        std::env::remove_var(format!("{var}_FILE"));
        assert_eq!(secret_from_env(var), None);
    }

    #[test]
    fn empty_direct_var_falls_through_to_file() {
        let var = "FORGE_TEST_SECRET_EMPTY_E";
        let path = write_temp_secret("file-wins-over-empty-env");
        // Empty direct var is treated as UNSET (never a silent empty secret) -> file is consulted.
        std::env::set_var(var, "");
        std::env::set_var(format!("{var}_FILE"), &path);
        assert_eq!(secret_from_env(var).as_deref(), Some("file-wins-over-empty-env"));
        std::env::remove_var(var);
        std::env::remove_var(format!("{var}_FILE"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unreadable_file_is_fail_soft_none_not_panic() {
        let var = "FORGE_TEST_SECRET_UNREADABLE_F";
        std::env::remove_var(var);
        // Point *_FILE at a path that does not exist -> read fails -> None (no panic), warning logged.
        std::env::set_var(
            format!("{var}_FILE"),
            "/nonexistent/forge/secret/path/does-not-exist",
        );
        assert_eq!(secret_from_env(var), None);
        std::env::remove_var(format!("{var}_FILE"));
    }
}

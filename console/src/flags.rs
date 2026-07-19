// SPDX-License-Identifier: AGPL-3.0-or-later
//! Enterprise flag helpers — the ONE copy of the "is this enterprise feature engaged?" logic that
//! sso / tenancy / compliance / scim each carried verbatim. Behaviour is byte-for-byte the historical
//! per-module code: env truthy (1|true|on|yes, case-insensitive) OR the per-DB config key in
//! {on,1,true,yes}. Community default = OFF (every gated route stays 404, byte-identical).

use crate::App;

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

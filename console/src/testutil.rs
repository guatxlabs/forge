// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — HELPERS DE TEST PARTAGÉS (hoistés depuis le `mod tests` inline de main.rs :
//! ils servaient plusieurs sous-systèmes — backup/dbmigrate/cli en plus de main.rs — et sont
//! désormais mutualisés ici plutôt que dupliqués. `#[cfg(test)]` : aucun code émis hors tests.
//! Corps IDENTIQUES à l'original ; seule la visibilité (`pub(crate)`) est ajoutée pour l'accès
//! cross-module. Les modules consommateurs font `use crate::testutil::*` dans leur `mod tests`.
#![cfg(test)]
use crate::*;
use axum::http::HeaderMap;
use rusqlite::Connection;
use serde_json::Value;

    /// Verrou global sérialisant les tests qui LISENT/ÉCRIVENT des variables d'ENV partagées
    /// (FORGE_ALLOW_API_MIGRATE / FORGE_CONSOLE_IMPORT_DIR) — l'ENV du process est global, donc ces
    /// tests ne doivent pas courir en parallèle. Empoisonnement ignoré (into_inner) : un panic
    /// antérieur ne doit pas bloquer les suivants.
    pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Engage l'escape-hatch SSRF (`FORGE_ALLOW_INTERNAL_INTEGRATIONS=1`) UNE SEULE FOIS pour TOUT le
    /// binaire de test (`Once` => pas de course set_var/getenv). Les mocks OIDC des tests SSO bindent
    /// 127.0.0.1 (cibles loopback LÉGITIMEMENT internes) ; la garde d'intégration les refuserait sinon.
    /// On ne l'unset JAMAIS : c'est l'état partagé DÉSIRÉ (aucun test n'attend le refus PAR l'env — le
    /// refus est prouvé par les fonctions PURES `reject_internal_addr`/`integration_ip_denied`). En
    /// production la garde reste pleinement active (ce helper n'existe qu'en `#[cfg(test)]`).
    pub(crate) fn allow_internal_integrations_once() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| std::env::set_var(crate::ALLOW_INTERNAL_INTEGRATIONS_ENV, "1"));
    }

    pub(crate) fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        let uniq = format!("{}-{}-{}", name, std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        p.push(uniq);
        p.to_string_lossy().into_owned()
    }

    /// Crée un dossier temporaire unique.
    pub(crate) fn tmp_dir(name: &str) -> String {
        let d = tmp_path(name);
        std::fs::create_dir_all(&d).expect("mkdir tmp");
        d
    }

    /// Sème une base SOURCE au schéma ANCIEN : `finding` SANS les colonnes additives (cwe/run_id/…),
    /// et PAS de table settings/users. La migration doit l'upgrader EN PLACE (SCHEMA + migrate()).
    pub(crate) fn seed_old_source_db(path: &str) {
        let c = Connection::open(path).expect("open src db");
        c.execute_batch(
            "CREATE TABLE finding(id INTEGER PRIMARY KEY, ts TEXT, campaign TEXT, target TEXT, title TEXT,
                severity TEXT, category TEXT, mitre TEXT, status TEXT, evidence TEXT, tool TEXT, poc TEXT);",
        )
        .expect("old schema");
        c.execute(
            "INSERT INTO finding(id,title,target,campaign) VALUES(1,'old-finding','h.example','c1')",
            [],
        )
        .expect("insert old row");
    }

    /// Récupère l'id d'un compte par login (helper de test).
    pub(crate) fn uid_of(app: &App, login: &str) -> i64 {
        let db = app.db();
        db.query_row("SELECT id FROM users WHERE login=?", [login], |r| r.get(0)).unwrap()
    }

    /// Construit un HeaderMap avec un Authorization: Bearer <tok> (utilisé pour simuler une session).
    pub(crate) fn bearer_headers(tok: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {tok}").parse().unwrap());
        h
    }

    /// Consomme une Response axum et parse son corps JSON (helper de test).
    pub(crate) async fn resp_json(r: Response) -> Value {
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&b).unwrap_or(Value::Null)
    }

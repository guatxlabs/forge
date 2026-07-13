// SPDX-License-Identifier: AGPL-3.0-only
//! Forge console — BLOBSTORE SEAM pour artefacts (archive de backup offsite, exports/évidence).
//!
//! SEAM ADDITIF. Le build PAR DÉFAUT (community) ne compile QUE `LocalFsBlobStore` (système de
//! fichiers, AUCUNE dépendance nouvelle) : le chemin par défaut (aucun artefact configuré) ne change
//! RIEN au comportement existant. L'implémentation S3/MinIO (`S3BlobStore`) ET sa dépendance vivent
//! DERRIÈRE la feature OPT-IN `object-store` (`cargo build --features object-store`), openssl-free
//! (rust-s3 en `sync-rustls-tls` -> attohttpc + rustls/ring, ZÉRO openssl). Quand la feature n'est PAS
//! compilée, tout le code S3 disparaît (cfg-gated) -> binaire par défaut inchangé.
//!
//! MODÈLE : un artefact est référencé par URL/clé (jamais stocké en BLOB dans la base). La sélection
//! runtime privilégie S3 UNIQUEMENT si la feature est compilée ET l'ENV S3 est configuré ; sinon le
//! store local (toujours disponible). Aucun secret n'est journalisé/ledgerisé (les rapports ne
//! contiennent que backend/bucket/clé/URL — jamais access/secret key).
//
// `dead_code` autorisé au niveau MODULE : dans le build PAR DÉFAUT (community), le seam BlobStore
// (trait + `LocalFsBlobStore`) est EXPOSÉ pour un futur producteur d'artefacts local mais n'a pas
// encore d'appelant runtime hors feature (le SEUL producteur câblé — l'offsite S3 — est gardé par
// `object-store`). Le seam est bien VIVANT sous la feature (offsite s3 + CLI blob-selftest) ET dans les
// tests (round-trip local). Même discipline que les helpers `#[allow(dead_code)] // conservé pour les
// tests` du reste de la console. `json`/`Value` ne servent qu'au code S3 -> import gardé par la feature.
#![allow(dead_code)]

#[cfg(feature = "object-store")]
use serde_json::{json, Value};

/// Store d'artefacts backend-agnostique. Les artefacts sont référencés par URL/clé (jamais des BLOBs
/// en base). `put` renvoie une référence stockée (URL `file://…` en local, URL http(s) endpoint/bucket/
/// clé en S3). Toutes les méthodes échouent proprement (Result) — jamais de panic.
pub(crate) trait BlobStore {
    /// Stocke `bytes` sous `key` (type MIME `content_type`) ; renvoie une référence/URL stockée.
    fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<String, String>;
    /// Récupère les octets sous `key`. Err si absent/illisible.
    fn get(&self, key: &str) -> Result<Vec<u8>, String>;
    /// Vrai si un objet existe sous `key` (sans télécharger le corps).
    fn exists(&self, key: &str) -> Result<bool, String>;
    /// Supprime l'objet sous `key` (idempotent : absent -> Ok).
    fn delete(&self, key: &str) -> Result<(), String>;
    /// Libellé du backend pour logs/ledger (jamais un secret) : "local_fs" | "s3".
    fn backend(&self) -> &'static str;
}

/// Valide+joint une clé d'artefact sous une racine, FAIL-CLOSED contre la traversée de chemin : rejette
/// une clé vide, tout composant vide/`.`/`..`, un backslash ou un NUL, et toute clé absolue (le 1er
/// composant serait vide). Renvoie le chemin joint (toujours SOUS `root`).
fn safe_join(root: &str, key: &str) -> Result<std::path::PathBuf, String> {
    if key.is_empty() {
        return Err("blob key vide".to_string());
    }
    for comp in key.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(format!("blob key invalide (composant '{comp}') — traversée refusée"));
        }
        if comp.contains('\\') || comp.contains('\0') {
            return Err("blob key invalide (caractère interdit '\\' ou NUL)".to_string());
        }
    }
    Ok(std::path::Path::new(root).join(key))
}

/// Dossier de blobs par défaut : `FORGE_BLOB_DIR` si posé/non vide ; sinon un `blobs/` sibling de la
/// base (dossier de `FORGE_CONSOLE_DB`) ; sinon `./blobs`. Aucune valeur codée en dur ailleurs.
pub(crate) fn default_blob_dir() -> String {
    if let Ok(d) = std::env::var("FORGE_BLOB_DIR") {
        if !d.is_empty() {
            return d;
        }
    }
    let db = crate::cli_db_path();
    std::path::Path::new(&db)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.join("blobs").to_string_lossy().into_owned())
        .unwrap_or_else(|| "blobs".to_string())
}

/// Store d'artefacts sur SYSTÈME DE FICHIERS (DÉFAUT — toujours compilé). Écrit sous `root` de façon
/// quasi-atomique (réutilise `backup_write_atomic`) ; référence renvoyée = URL `file://<abspath>`.
/// `content_type` est ignoré (pas de métadonnées disque) — parité fonctionnelle avec S3 côté octets.
pub(crate) struct LocalFsBlobStore {
    root: String,
}

impl LocalFsBlobStore {
    pub(crate) fn new(root: &str) -> Self {
        Self { root: root.to_string() }
    }
    /// URL `file://` absolue (best-effort) d'un chemin joint — sert de référence stockée.
    fn file_url(path: &std::path::Path) -> String {
        let abs = std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .into_owned();
        format!("file://{abs}")
    }
}

impl BlobStore for LocalFsBlobStore {
    fn put(&self, key: &str, bytes: &[u8], _content_type: &str) -> Result<String, String> {
        let path = safe_join(&self.root, key)?;
        let path_str = path.to_string_lossy().into_owned();
        // écriture quasi-atomique (tmp sibling + rename + fsync) — mode 0600 (artefact potentiellement chiffré).
        crate::backup_write_atomic(&path_str, bytes, 0o600)?;
        Ok(Self::file_url(&path))
    }
    fn get(&self, key: &str) -> Result<Vec<u8>, String> {
        let path = safe_join(&self.root, key)?;
        std::fs::read(&path).map_err(|e| format!("lecture blob '{}' échouée: {e}", path.to_string_lossy()))
    }
    fn exists(&self, key: &str) -> Result<bool, String> {
        let path = safe_join(&self.root, key)?;
        Ok(std::fs::metadata(&path).map(|m| m.is_file()).unwrap_or(false))
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        let path = safe_join(&self.root, key)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // idempotent
            Err(e) => Err(format!("suppression blob '{}' échouée: {e}", path.to_string_lossy())),
        }
    }
    fn backend(&self) -> &'static str {
        "local_fs"
    }
}

// ===========================================================================================
// S3 / MinIO — DERRIÈRE la feature `object-store` UNIQUEMENT. rust-s3 en `sync-rustls-tls` : client
// SYNCHRONE (attohttpc, colle au modèle bloquant du moteur backup, appelé via spawn_blocking) + TLS
// rustls/ring (AUCUN openssl). Path-style forcé (MinIO). Config 100 % ENV (aucun secret en base/ledger).
// ===========================================================================================

/// Config S3/MinIO lue depuis l'ENV (aucun secret persisté en base/ledger). `region` par défaut
/// `us-east-1` (MinIO ignore la région mais SigV4 l'exige). Voir DEPLOYMENT.md.
#[cfg(feature = "object-store")]
pub(crate) struct S3Config {
    pub(crate) endpoint: String,
    pub(crate) bucket: String,
    pub(crate) region: String,
    pub(crate) access_key: String,
    pub(crate) secret_key: String,
}

/// Construit une [`S3Config`] depuis l'ENV. `None` si l'un des champs REQUIS
/// (`FORGE_BLOB_S3_ENDPOINT`/`BUCKET`/`ACCESS_KEY`/`SECRET_KEY`) est absent/vide -> la sélection
/// runtime retombe sur le store local. `FORGE_BLOB_S3_REGION` est optionnel (défaut `us-east-1`).
#[cfg(feature = "object-store")]
pub(crate) fn s3_config_from_env() -> Option<S3Config> {
    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
    let endpoint = env("FORGE_BLOB_S3_ENDPOINT")?;
    let bucket = env("FORGE_BLOB_S3_BUCKET")?;
    let access_key = env("FORGE_BLOB_S3_ACCESS_KEY")?;
    let secret_key = env("FORGE_BLOB_S3_SECRET_KEY")?;
    let region = env("FORGE_BLOB_S3_REGION").unwrap_or_else(|| "us-east-1".to_string());
    Some(S3Config { endpoint, bucket, region, access_key, secret_key })
}

/// Store d'artefacts S3/MinIO. `bucket` = client rust-s3 en path-style (MinIO). `endpoint`/`bucket_name`
/// conservés pour construire l'URL de référence renvoyée par `put` (endpoint/bucket/clé — aucun secret).
#[cfg(feature = "object-store")]
pub(crate) struct S3BlobStore {
    bucket: Box<s3::Bucket>,
    endpoint: String,
    bucket_name: String,
}

#[cfg(feature = "object-store")]
impl S3BlobStore {
    /// Construit un client S3 path-style (MinIO) depuis la config. Erreur propre si les credentials ou
    /// l'endpoint sont invalides (fail-closed). Aucune I/O réseau ici (la connexion est paresseuse).
    pub(crate) fn new(cfg: &S3Config) -> Result<Self, String> {
        let region = s3::Region::Custom {
            region: cfg.region.clone(),
            endpoint: cfg.endpoint.clone(),
        };
        let creds = s3::creds::Credentials::new(
            Some(&cfg.access_key),
            Some(&cfg.secret_key),
            None,
            None,
            None,
        )
        .map_err(|e| format!("credentials S3 invalides: {e}"))?;
        let bucket = s3::Bucket::new(&cfg.bucket, region, creds)
            .map_err(|e| format!("init du bucket S3 '{}' échouée: {e}", cfg.bucket))?
            .with_path_style(); // MinIO : addressing path-style (endpoint/bucket/clé, pas de vhost DNS)
        Ok(Self {
            bucket,
            endpoint: cfg.endpoint.clone(),
            bucket_name: cfg.bucket.clone(),
        })
    }
    /// URL de référence (endpoint/bucket/clé) — DÉTERMINISTE, sans secret. Pour l'affichage/le ledger.
    fn url(&self, key: &str) -> String {
        format!(
            "{}/{}/{}",
            self.endpoint.trim_end_matches('/'),
            self.bucket_name,
            key.trim_start_matches('/')
        )
    }
}

#[cfg(feature = "object-store")]
impl BlobStore for S3BlobStore {
    fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<String, String> {
        let resp = self
            .bucket
            .put_object_with_content_type(key, bytes, content_type)
            .map_err(|e| format!("S3 put '{key}' échoué: {e}"))?;
        let code = resp.status_code();
        if !(200..300).contains(&code) {
            return Err(format!("S3 put '{key}' status HTTP {code}"));
        }
        Ok(self.url(key))
    }
    fn get(&self, key: &str) -> Result<Vec<u8>, String> {
        let resp = self
            .bucket
            .get_object(key)
            .map_err(|e| format!("S3 get '{key}' échoué: {e}"))?;
        let code = resp.status_code();
        if !(200..300).contains(&code) {
            return Err(format!("S3 get '{key}' status HTTP {code}"));
        }
        Ok(resp.to_vec())
    }
    fn exists(&self, key: &str) -> Result<bool, String> {
        let (_hdr, code) = self
            .bucket
            .head_object(key)
            .map_err(|e| format!("S3 head '{key}' échoué: {e}"))?;
        Ok((200..300).contains(&code))
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        let resp = self
            .bucket
            .delete_object(key)
            .map_err(|e| format!("S3 delete '{key}' échoué: {e}"))?;
        let code = resp.status_code();
        // 2xx = supprimé ; 404 = déjà absent (idempotent). Tout autre code = erreur.
        if !(200..300).contains(&code) && code != 404 {
            return Err(format!("S3 delete '{key}' status HTTP {code}"));
        }
        Ok(())
    }
    fn backend(&self) -> &'static str {
        "s3"
    }
}

/// SÉLECTION RUNTIME du BlobStore actif : S3 UNIQUEMENT si la feature `object-store` est compilée ET
/// l'ENV S3 est configuré ; sinon le store LOCAL (toujours disponible). Un S3 configuré-mais-invalide
/// (mauvais credentials/endpoint) fait remonter son erreur (pas de repli silencieux) ; un S3 NON
/// configuré retombe proprement sur le local. Dans le build par défaut, le bloc S3 n'existe pas ->
/// renvoie toujours le store local.
// `dead_code` autorisé : dans le build PAR DÉFAUT (community) le SEUL appelant (`run_blob_selftest_cli`)
// est gardé par la feature `object-store`, donc cette fonction n'a pas d'appelant runtime hors feature.
// Elle reste exposée (seam) pour le futur câblage d'un producteur d'artefacts local. Sous la feature,
// elle est bien vivante (CLI blob-selftest).
#[allow(dead_code)]
pub(crate) fn select_blob_store() -> Result<Box<dyn BlobStore>, String> {
    #[cfg(feature = "object-store")]
    if let Some(cfg) = s3_config_from_env() {
        return Ok(Box::new(S3BlobStore::new(&cfg)?));
    }
    Ok(Box::new(LocalFsBlobStore::new(&default_blob_dir())))
}

/// Expédie l'archive `archive_path` vers le BlobStore S3/MinIO (destination offsite `kind:"s3"`).
/// Lit l'archive (déjà CHIFFRÉE par le moteur backup), la PUT sous une clé (préfixe optionnel
/// `key_prefix` de la politique + nom de fichier de l'archive), renvoie un rapport SANS secret
/// (bucket/clé/URL/octets). Fail-closed si l'ENV S3 est absent. Les credentials ne sont JAMAIS dans le
/// rapport/ledger. N'existe QUE sous la feature `object-store` (l'appelant `ship_offsite` gate l'arm).
#[cfg(feature = "object-store")]
pub(crate) fn ship_offsite_s3(offsite: &Value, archive_path: &str) -> Result<Value, String> {
    let cfg = s3_config_from_env().ok_or_else(|| {
        "offsite s3 : config S3 absente — définir FORGE_BLOB_S3_ENDPOINT/BUCKET/ACCESS_KEY/SECRET_KEY (fail-closed)".to_string()
    })?;
    let store = S3BlobStore::new(&cfg)?;
    let bytes = std::fs::read(archive_path)
        .map_err(|e| format!("offsite s3 : lecture de l'archive '{archive_path}' échouée: {e}"))?;
    let base = std::path::Path::new(archive_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(crate::backup_archive_name);
    let prefix = offsite
        .get("key_prefix")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_matches('/');
    let key = if prefix.is_empty() {
        base.clone()
    } else {
        format!("{prefix}/{base}")
    };
    let url = store.put(&key, &bytes, "application/octet-stream")?;
    Ok(json!({
        "shipped": true,
        "kind": "s3",
        "bucket": cfg.bucket,
        "key": key,
        "url": url,
        "bytes": bytes.len(),
    }))
}

/// `forge blob-selftest [--key <key>] [--no-delete]` — ROUND-TRIP du BlobStore ACTIF (S3 si
/// configuré+feature, sinon local) : PUT d'un petit payload -> GET -> compare octets -> EXISTS ->
/// (DELETE sauf `--no-delete`) -> EXISTS. Imprime un rapport JSON. Code 0 si put+get(octets identiques)
/// +exists OK, 1 sinon. Sert de PREUVE de l'aller-retour (MinIO/local) sans démarrer le serveur.
/// N'existe QUE sous la feature `object-store` (câblé dans le dispatch CLI de main.rs sous la même feature).
#[cfg(feature = "object-store")]
pub(crate) fn run_blob_selftest_cli(args: &[String]) -> i32 {
    // `--file <path>` : exerce le PRODUCTEUR CÂBLÉ (offsite backup -> S3) `ship_offsite_s3` avec un
    // artefact RÉEL (p.ex. l'archive de backup chiffrée), puis GET la clé et compare aux octets du
    // fichier. Preuve de bout en bout du chemin offsite s3 (le même code que le scheduler appelle).
    if let Some(file) = crate::cli_opt(args, "file").filter(|s| !s.is_empty()) {
        let prefix = crate::cli_opt(args, "key-prefix").unwrap_or_default();
        let offsite = json!({"kind": "s3", "key_prefix": prefix});
        let report = match ship_offsite_s3(&offsite, &file) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[forge] blob-selftest --file: ship_offsite_s3 échoué: {e}");
                return 1;
            }
        };
        let key = report.get("key").and_then(|v| v.as_str()).unwrap_or("").to_string();
        // GET back via le store actif + compare aux octets d'origine.
        let store = match select_blob_store() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[forge] blob-selftest --file: init store échouée: {e}");
                return 1;
            }
        };
        let orig = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[forge] blob-selftest --file: lecture '{file}' échouée: {e}");
                return 1;
            }
        };
        let got = match store.get(&key) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[forge] blob-selftest --file: GET '{key}' échoué: {e}");
                return 1;
            }
        };
        let matched = got == orig;
        let out = json!({
            "ok": matched,
            "mode": "offsite_s3_producer",
            "shipped": report,
            "orig_bytes": orig.len(),
            "get_bytes": got.len(),
            "bytes_match": matched,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into()));
        return if matched { 0 } else { 1 };
    }
    let key = crate::cli_opt(args, "key")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("selftest/forge-blob-{}.bin", crate::tmp_nonce()));
    let keep = crate::cli_flag(args, "no-delete");
    let store = match select_blob_store() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[forge] blob-selftest: init du store échouée: {e}");
            return 1;
        }
    };
    let backend = store.backend();
    let payload = format!("forge blob selftest {} nonce={}", crate::chrono_now_compact(), crate::tmp_nonce()).into_bytes();

    let url = match store.put(&key, &payload, "application/octet-stream") {
        Ok(u) => u,
        Err(e) => {
            eprintln!("[forge] blob-selftest: PUT échoué: {e}");
            return 1;
        }
    };
    let got = match store.get(&key) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[forge] blob-selftest: GET échoué: {e}");
            return 1;
        }
    };
    let matched = got == payload;
    let exists_after_put = store.exists(&key).unwrap_or(false);
    let (deleted, exists_after_delete) = if keep {
        (false, exists_after_put)
    } else {
        let d = store.delete(&key).is_ok();
        (d, store.exists(&key).unwrap_or(true))
    };

    let report = json!({
        "ok": matched && exists_after_put,
        "backend": backend,
        "key": key,
        "url": url,
        "put_bytes": payload.len(),
        "get_bytes": got.len(),
        "bytes_match": matched,
        "exists_after_put": exists_after_put,
        "deleted": deleted,
        "exists_after_delete": exists_after_delete,
        "kept": keep,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into()));
    if matched && exists_after_put {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> String {
        std::env::temp_dir()
            .join(format!("forge-blob-test-{}", crate::tmp_nonce()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn local_fs_roundtrip_put_get_exists_delete() {
        let root = tmp_root();
        let store = LocalFsBlobStore::new(&root);
        assert_eq!(store.backend(), "local_fs");
        let key = "evidence/report-1.bin";
        assert!(!store.exists(key).unwrap());
        let data = b"forge artifact bytes \x00\x01\x02";
        let url = store.put(key, data, "application/octet-stream").unwrap();
        assert!(url.starts_with("file://"));
        assert!(store.exists(key).unwrap());
        assert_eq!(store.get(key).unwrap(), data);
        store.delete(key).unwrap();
        assert!(!store.exists(key).unwrap());
        // delete idempotent (déjà absent -> Ok).
        store.delete(key).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn local_fs_rejects_path_traversal() {
        let root = tmp_root();
        let store = LocalFsBlobStore::new(&root);
        for bad in ["../escape", "a/../../etc/passwd", "/abs/key", "", "a/./b", "a\\b"] {
            assert!(store.put(bad, b"x", "application/octet-stream").is_err(), "clé traversante acceptée: {bad}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn default_blob_dir_honors_env() {
        // NB : test d'ENV — sérialisé implicitement (pas d'autre test touchant FORGE_BLOB_DIR).
        std::env::set_var("FORGE_BLOB_DIR", "/tmp/forge-blob-custom");
        assert_eq!(default_blob_dir(), "/tmp/forge-blob-custom");
        std::env::remove_var("FORGE_BLOB_DIR");
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — PRIMITIVES CRYPTO/FORMAT de sauvegarde : KDF argon2id, AEAD XChaCha20-Poly1305,
//! en-tête d'archive auto-descriptif (lié en AAD), tar pur Rust, sha256. Extrait de `backup.rs`
//! (PURE MOVE, behavior-neutral — corps bit-à-bit identiques). Isole le chemin cryptographique
//! (encrypt/decrypt/derive_key/nonce/header) pour un test indépendant. Aucune logique modifiée.
use crate::hex;
use argon2::{Algorithm, Argon2, Version};
// `Params` est re-exporté pub(crate) : outre son usage local (KDF), le module de tests de main.rs le
// résout via `super::*` (glob re-export `pub(crate) use crate::backup::*` -> `crate::backup_crypto::*`)
// — inchangé après le move.
pub(crate) use argon2::Params;
use sha2::{Digest, Sha256};

// ===========================================================================================
// SAUVEGARDE / RESTAURATION CHIFFRÉE — `forge backup` / `forge restore`.
//
// Une archive de sauvegarde regroupe TROIS actifs sensibles couplés (mêmes trois que la migration) :
//   1) un snapshot COHÉRENT de la base SQLite (VACUUM INTO — copie défragmentée d'une source READ-ONLY) ;
//   2) le ledger JSONL d'engagement (chaîne SHA-256 tamper-evident) ;
//   3) la clé de signature `.ed25519` (0600) — SANS elle, la chaîne signée devient invérifiable.
// La clé privée de signature ET la base voyagent DANS l'archive -> l'archive est TOUJOURS chiffrée :
// il n'existe AUCUN chemin de sortie en clair. Une passphrase est OBLIGATOIRE (fail-closed si absente).
//
// CRYPTO (pur Rust, aucune dép C) :
//   passphrase --argon2id(salt 16o aléatoire)--> clé 32o --XChaCha20-Poly1305(nonce 24o aléatoire)-->
//   ciphertext authentifié. L'en-tête (magic|version|params argon2|salt|nonce) est écrit EN CLAIR
//   devant le ciphertext ET lié comme DONNÉE ASSOCIÉE (AAD) de l'AEAD : altérer l'en-tête OU le corps
//   fait échouer le tag Poly1305. La passphrase / la clé dérivée ne sont JAMAIS stockées/loggées/ledgerisées.
//
// INTÉGRITÉ : la chaîne du ledger est vérifiée AVANT le backup (abort sur rupture) et APRÈS le restore ;
// chaque fichier porte son sha256 dans `manifest.json`, re-vérifié au restore. Le restore REFUSE
// d'écraser un install non vide sans `--force`. Chaque backup/restore est TRACÉ au ledger (métadonnées
// seules — jamais la passphrase/clé). Voie CLI = invocation locale de confiance (admin-gated par l'accès hôte).
// ===========================================================================================

pub(crate) const BACKUP_MAGIC: &[u8; 8] = b"FORGEBK1"; // repère de format (8 octets) — "FORGE backup v1"
pub(crate) const BACKUP_VERSION: u8 = 1; // version du format d'en-tête/archive
pub(crate) const BACKUP_SCHEMA_VERSION: u64 = 1; // version du schéma du manifest.json (contenu logique)
pub(crate) const BACKUP_KEY_LEN: usize = 32; // clé AEAD dérivée (XChaCha20-Poly1305 exige 32 octets)
pub(crate) const BACKUP_SALT_LEN: usize = 16; // sel argon2id (aléatoire par archive)
pub(crate) const BACKUP_NONCE_LEN: usize = 24; // nonce XChaCha20 (24 octets — grande marge anti-collision)
// noms d'entrée canoniques dans l'archive tar.
pub(crate) const BACKUP_ENTRY_MANIFEST: &str = "manifest.json";
pub(crate) const BACKUP_ENTRY_DB: &str = "db.sqlite";
pub(crate) const BACKUP_ENTRY_LEDGER: &str = "engagement.jsonl";
pub(crate) const BACKUP_ENTRY_KEY: &str = "signing.ed25519";

/// sha256 hex d'un buffer d'octets (les fichiers de l'archive ne sont pas forcément UTF-8 -> on ne
/// peut pas réutiliser sha_hex(&str)). Réutilise le même hex(...) que le reste de la console.
pub(crate) fn sha256_hex_bytes(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex(&h.finalize())
}

/// Valide les paramètres argon2id (m/t/p) issus d'un EN-TÊTE — qui est MALLÉABLE avant authentification
/// (la clé dérive AVANT la vérif du tag AEAD -> impossible d'authentifier les params d'abord). Bornes
/// délibérément CONSERVATRICES, bien en-deçà des limites u32 : un en-tête corrompu/malveillant produit
/// alors une Err PROPRE au lieu d'un panic (multiply-overflow en debug) ou d'une allocation démesurée
/// (release) — pas de DoS. Nos archives n'écrivent QUE les params argon2 par défaut (petits), donc une
/// archive légitime passe toujours.
pub(crate) fn backup_validate_kdf_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<(), String> {
    if !(8..=4_194_304).contains(&m_cost) {
        return Err(format!("m_cost argon2 hors bornes sûres: {m_cost}"));
    }
    if !(1..=16_384).contains(&t_cost) {
        return Err(format!("t_cost argon2 hors bornes sûres: {t_cost}"));
    }
    if !(1..=16_777_215).contains(&p_cost) {
        return Err(format!("p_cost argon2 hors bornes sûres: {p_cost}"));
    }
    Ok(())
}

/// Dérive une clé AEAD 32o depuis une passphrase + un sel, avec argon2id (Algorithme id, v0x13) aux
/// paramètres passés (m/t/p) — DÉTERMINISTE : mêmes (passphrase, sel, params) -> même clé (indispensable
/// pour re-dériver au restore). PUR : aucune I/O, aucun log. La clé n'est jamais renvoyée à l'appelant
/// au-delà du buffer 32o (jamais ledgerisée/loggée).
pub(crate) fn backup_derive_key(passphrase: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<[u8; BACKUP_KEY_LEN], String> {
    backup_validate_kdf_params(m_cost, t_cost, p_cost)?; // évite panic/DoS sur params d'en-tête malléables
    let params = Params::new(m_cost, t_cost, p_cost, Some(BACKUP_KEY_LEN))
        .map_err(|e| format!("paramètres argon2 invalides: {e}"))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; BACKUP_KEY_LEN];
    a.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("dérivation argon2id échouée: {e}"))?;
    Ok(key)
}

/// Sérialise l'en-tête d'archive EN CLAIR (auto-descriptif, lié comme AAD de l'AEAD) :
///   magic(8) | version(1) | m_cost(4 LE) | t_cost(4 LE) | p_cost(4 LE) | salt_len(1) | salt | nonce_len(1) | nonce
pub(crate) fn backup_build_header(m_cost: u32, t_cost: u32, p_cost: u32, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(8 + 1 + 12 + 1 + salt.len() + 1 + nonce.len());
    h.extend_from_slice(BACKUP_MAGIC);
    h.push(BACKUP_VERSION);
    h.extend_from_slice(&m_cost.to_le_bytes());
    h.extend_from_slice(&t_cost.to_le_bytes());
    h.extend_from_slice(&p_cost.to_le_bytes());
    h.push(salt.len() as u8);
    h.extend_from_slice(salt);
    h.push(nonce.len() as u8);
    h.extend_from_slice(nonce);
    h
}

/// Params argon2id extraits d'un en-tête + longueur totale de l'en-tête (offset du ciphertext).
pub(crate) struct BackupHeader {
    pub(crate) m_cost: u32,
    pub(crate) t_cost: u32,
    pub(crate) p_cost: u32,
    pub(crate) salt: [u8; BACKUP_SALT_LEN],
    pub(crate) nonce: [u8; BACKUP_NONCE_LEN],
    pub(crate) header_len: usize,
}

/// Parse+valide l'en-tête en tête d'archive. Rejette un magic/version inconnus et tout troncage.
/// N'effectue AUCUN déchiffrement (juste la structure) — l'authenticité est prouvée par le tag AEAD.
pub(crate) fn backup_parse_header(archive: &[u8]) -> Result<BackupHeader, String> {
    if archive.len() < 8 || &archive[0..8] != BACKUP_MAGIC {
        return Err("magic invalide — ce fichier n'est pas une archive Forge backup".to_string());
    }
    let mut o = 8usize;
    let ver = *archive.get(o).ok_or_else(|| "en-tête tronqué (version)".to_string())?;
    o += 1;
    if ver != BACKUP_VERSION {
        return Err(format!("version d'archive non supportée: {ver} (attendu {BACKUP_VERSION})"));
    }
    let rd_u32 = |a: &[u8], off: usize| -> Result<u32, String> {
        let s = a.get(off..off + 4).ok_or_else(|| "en-tête tronqué (paramètres argon2)".to_string())?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    let m_cost = rd_u32(archive, o)?; o += 4;
    let t_cost = rd_u32(archive, o)?; o += 4;
    let p_cost = rd_u32(archive, o)?; o += 4;
    let salt_len = *archive.get(o).ok_or_else(|| "en-tête tronqué (salt_len)".to_string())? as usize;
    o += 1;
    if salt_len != BACKUP_SALT_LEN {
        return Err(format!("longueur de sel inattendue: {salt_len} (attendu {BACKUP_SALT_LEN})"));
    }
    let salt_slice = archive.get(o..o + salt_len).ok_or_else(|| "en-tête tronqué (sel)".to_string())?;
    let mut salt = [0u8; BACKUP_SALT_LEN];
    salt.copy_from_slice(salt_slice);
    o += salt_len;
    let nonce_len = *archive.get(o).ok_or_else(|| "en-tête tronqué (nonce_len)".to_string())? as usize;
    o += 1;
    if nonce_len != BACKUP_NONCE_LEN {
        return Err(format!("longueur de nonce inattendue: {nonce_len} (attendu {BACKUP_NONCE_LEN})"));
    }
    let nonce_slice = archive.get(o..o + nonce_len).ok_or_else(|| "en-tête tronqué (nonce)".to_string())?;
    let mut nonce = [0u8; BACKUP_NONCE_LEN];
    nonce.copy_from_slice(nonce_slice);
    o += nonce_len;
    Ok(BackupHeader { m_cost, t_cost, p_cost, salt, nonce, header_len: o })
}

/// Chiffre `plaintext` (l'archive tar) : génère sel+nonce CSPRNG, dérive la clé argon2id, chiffre en
/// XChaCha20-Poly1305 avec l'en-tête lié en AAD. Renvoie header || ciphertext‖tag. Passphrase vide
/// REFUSÉE (fail-closed). Il n'existe PAS de variante non chiffrée.
pub(crate) fn backup_encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    if passphrase.is_empty() {
        return Err("passphrase vide — refus de chiffrer (fail-closed)".to_string());
    }
    // paramètres argon2 par DÉFAUT du crate (auto-descriptifs dans l'en-tête -> re-dérivables au restore).
    let dp = Params::default();
    let (m_cost, t_cost, p_cost) = (dp.m_cost(), dp.t_cost(), dp.p_cost());
    let mut salt = [0u8; BACKUP_SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| format!("CSPRNG (sel) indisponible: {e}"))?;
    let mut nonce = [0u8; BACKUP_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG (nonce) indisponible: {e}"))?;
    let mut key = backup_derive_key(passphrase, &salt, m_cost, t_cost, p_cost)?;
    let header = backup_build_header(m_cost, t_cost, p_cost, &salt, &nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("clé AEAD invalide: {e}"))?;
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &header })
        .map_err(|_| "chiffrement AEAD échoué".to_string())?;
    // hygiène : efface la clé dérivée du stack dès qu'elle n'est plus nécessaire (le cipher en détient
    // sa propre copie interne, zeroizée à son Drop). La clé n'a JAMAIS quitté ce périmètre.
    for b in key.iter_mut() { *b = 0; }
    let mut out = header;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Déchiffre une archive produite par backup_encrypt. Parse l'en-tête, re-dérive la clé, vérifie le tag
/// AEAD (en-tête en AAD). Une MAUVAISE passphrase OU un octet altéré (en-tête ou corps) => Err propre
/// (tag Poly1305 invalide) — l'appelant n'écrit alors RIEN. Passphrase vide REFUSÉE (fail-closed).
pub(crate) fn backup_decrypt(archive: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    if passphrase.is_empty() {
        return Err("passphrase vide — refus de déchiffrer (fail-closed)".to_string());
    }
    let hdr = backup_parse_header(archive)?;
    let header = &archive[..hdr.header_len];
    let ct = &archive[hdr.header_len..];
    let mut key = backup_derive_key(passphrase, &hdr.salt, hdr.m_cost, hdr.t_cost, hdr.p_cost)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("clé AEAD invalide: {e}"))?;
    let pt = cipher
        .decrypt(XNonce::from_slice(&hdr.nonce), Payload { msg: ct, aad: header })
        .map_err(|_| "déchiffrement AEAD échoué — mauvaise passphrase ou archive altérée (tag invalide)".to_string());
    for b in key.iter_mut() { *b = 0; }
    pt
}

/// Construit une archive tar (pur Rust) à partir d'entrées (nom, octets) — mode 0600, mtime 0 (sortie
/// déterministe). L'ordre des entrées est préservé. Renvoie les octets tar bruts (avant chiffrement).
pub(crate) fn backup_build_tar(files: &[(&str, &[u8])]) -> Result<Vec<u8>, String> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o600);
        header.set_mtime(0);
        // append_data pose le chemin PUIS recalcule le checksum de l'en-tête tar (cksum interne).
        builder
            .append_data(&mut header, name, *data)
            .map_err(|e| format!("écriture de l'entrée tar '{name}' échouée: {e}"))?;
    }
    builder.into_inner().map_err(|e| format!("finalisation de l'archive tar échouée: {e}"))
}

/// Extrait toutes les entrées d'une archive tar en mémoire (nom -> octets). Aucune écriture disque.
pub(crate) fn backup_extract_tar(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    use std::io::Read;
    let mut ar = tar::Archive::new(std::io::Cursor::new(bytes));
    let mut out = Vec::new();
    let iter = ar.entries().map_err(|e| format!("lecture de l'archive tar impossible: {e}"))?;
    for entry in iter {
        let mut e = entry.map_err(|e| format!("entrée tar illisible: {e}"))?;
        let path = e
            .path()
            .map_err(|e| format!("chemin d'entrée tar illisible: {e}"))?
            .to_string_lossy()
            .into_owned();
        let mut buf = Vec::new();
        e.read_to_end(&mut buf).map_err(|e| format!("lecture du contenu tar '{path}' échouée: {e}"))?;
        out.push((path, buf));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [BACKUP crypto] la KDF argon2id est déterministe (mêmes passphrase+sel+params -> même clé) mais
    /// sensible à la passphrase, et deux archives du MÊME plaintext diffèrent (sel+nonce aléatoires).
    #[test]
    fn backup_kdf_deterministic_and_archives_use_fresh_salt_nonce() {
        let salt = [7u8; BACKUP_SALT_LEN];
        let dp = Params::default();
        let k1 = backup_derive_key("pw", &salt, dp.m_cost(), dp.t_cost(), dp.p_cost()).unwrap();
        let k2 = backup_derive_key("pw", &salt, dp.m_cost(), dp.t_cost(), dp.p_cost()).unwrap();
        let k3 = backup_derive_key("other", &salt, dp.m_cost(), dp.t_cost(), dp.p_cost()).unwrap();
        assert_eq!(k1, k2, "KDF déterministe (re-dérivable au restore)");
        assert_ne!(k1, k3, "passphrase différente -> clé différente");
        assert_ne!(k1, [0u8; BACKUP_KEY_LEN], "clé non tous-zeros");

        let pt = b"payload identique".to_vec();
        let a = backup_encrypt(&pt, "pw").unwrap();
        let b = backup_encrypt(&pt, "pw").unwrap();
        assert_ne!(a, b, "sel+nonce aléatoires -> chiffrés distincts pour un même plaintext");
        assert_eq!(backup_decrypt(&a, "pw").unwrap(), pt, "round-trip AEAD (a)");
        assert_eq!(backup_decrypt(&b, "pw").unwrap(), pt, "round-trip AEAD (b)");
        assert!(backup_encrypt(&pt, "").is_err(), "passphrase vide REFUSÉE (fail-closed)");
        assert!(backup_decrypt(&a, "").is_err(), "passphrase vide REFUSÉE au déchiffrement");
    }
}

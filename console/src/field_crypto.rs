// SPDX-License-Identifier: AGPL-3.0-or-later
//! Forge console — CHIFFREMENT DE CHAMP AU REPOS du MATÉRIEL D'AUTHENTIFICATION d'engagement.
//!
//! Le décideur a tranché : « pas de clair ». Le volet réseau est couvert (seam TLS, `tls.rs`). Ce
//! module couvre le REPOS pour la seule donnée de la base qui soit un CREDENTIAL VIVANT : le bloc
//! `auth` du `scope_json` d'un engagement (`engagements.rs`), qui porte les bearers, cookies et
//! valeurs d'en-tête des comptes de TEST de l'opérateur — c'est-à-dire des sessions authentifiées sur
//! l'estate d'un client.
//!
//! POURQUOI PAS SQLCIPHER ICI. Le chiffrement INTÉGRAL existe déjà (feature `encryption`), mais il
//! exige un backend crypto système/openssl À LA COMPILATION : l'activer par défaut casserait
//! l'openssl-freedom du build. Le chiffrement de CHAMP, lui, se fait avec la pile AEAD PUR RUST DÉJÀ
//! EMBARQUÉE dans le build par défaut (`chacha20poly1305` + `argon2`, deps NON optionnelles — celles
//! qui chiffrent les archives de sauvegarde). Coût : ZÉRO nouvelle dépendance. Les deux couches se
//! COMPOSENT (SQLCipher par-dessus des champs scellés reste valide et testé).
//!
//! ZÉRO RÉIMPLÉMENTATION D'AEAD : la KDF (`backup_derive_key`, argon2id) et le cœur AEAD
//! (`aead_seal`/`aead_open`, XChaCha20-Poly1305) sont ceux de `backup_crypto.rs`, EXTRAITS pour être
//! partagés. Il n'existe qu'UNE implémentation de crypto symétrique dans la console.
//!
//! ── FORMAT D'ENVELOPPE (auto-descriptif, une CHAÎNE JSON — le schéma DB est inchangé) ─────────────
//!   "forge:fenc1:" || base64( MAGIC(6) | VERSION(1) | salt(16) | nonce(24) | ciphertext‖tag )
//! L'en-tête est lié en AAD : altérer le sel, le nonce ou le corps fait échouer le tag Poly1305.
//! Le MAGIC domaine-sépare une enveloppe de CHAMP d'une archive de SAUVEGARDE (`FORGEBK1`) : une
//! enveloppe ne peut pas être présentée comme une archive, ni l'inverse.
//!
//! ── CLÉ ───────────────────────────────────────────────────────────────────────────────────────────
//! `FORGE_FIELD_KEY`, résolue par le motif MAISON `<VAR>_FILE` (`secret_env.rs`) : le secret peut
//! vivre dans un fichier Docker/k8s monté root, l'env ne portant qu'un CHEMIN. La clé AEAD est DÉRIVÉE
//! (argon2id) de cette passphrase + du sel de l'enveloppe, et MÉMOÏSÉE par (sel, empreinte de
//! passphrase) : une dérivation par sel et par processus, pas une par champ.
//!
//! ── FAIL-CLOSED (le point délicat — cf. docs/DEPLOYMENT.md §1.6) ──────────────────────────────────
//! Le principe directeur : **l'échec doit être LISIBLE, jamais un effacement discret** (on a corrigé
//! un bug où le contexte auth s'effaçait en silence, et ça a coûté une campagne).
//!   - ÉCRITURE de matériel EN CLAIR sans clé  => REFUS (`ERR_KEY_MISSING`) — l'appelant rend un 503
//!     nommant la variable. On ne persiste JAMAIS un credential en clair « en attendant ».
//!   - LECTURE d'un matériel SCELLÉ sans clé (ou avec la mauvaise) => REFUS (`ERR_KEY_MISSING` /
//!     `ERR_UNSEAL`) — le run REFUSE de démarrer plutôt que de partir avec un contexte VIDE.
//!   - AUCUN matériel à sceller (bloc `idor_targets`-seul) ou matériel DÉJÀ scellé => AUCUNE clé
//!     requise : un opérateur qui n'arme pas de contexte auth n'est JAMAIS puni (no-op strict).
//!   - Valeur NON enveloppée à la lecture => rendue TELLE QUELLE (base pas encore migrée) : un
//!     upgrade en place ne casse rien. L'état est SURFACÉ (`at_rest` du résumé + avertissement de
//!     boot), jamais tu.
//!
//! ── PÉRIMÈTRE MESURÉ ──────────────────────────────────────────────────────────────────────────────
//! SCELLÉ : `accounts[].bearer`, `accounts[].cookies` (chaîne ou valeurs de la map),
//! `accounts[].headers[*]` (les VALEURS ; les NOMS restent en clair — ils ne sont pas secrets et
//! l'éditeur les ré-affiche SANS la clé).
//! NON SCELLÉ, DÉLIBÉRÉMENT : `label` et `idor_targets[]` (`url`/`owner`/`marker`) — l'API les
//! re-sert DÉJÀ en clair à l'éditeur (`auth_summary_json`) ; les sceller rendrait l'éditeur illisible
//! sans la clé sans protéger un seul credential. `users.pass_hash` (argon2id) et `session.token_sha`
//! (SHA-256) ne sont PAS chiffrés : ce sont des empreintes à sens unique, pas du matériel rejouable.

use serde_json::{json, Map, Value};

use crate::backup_crypto::{aead_open, aead_seal, backup_derive_key, BACKUP_KEY_LEN, BACKUP_NONCE_LEN, BACKUP_SALT_LEN};

/// Variable d'environnement portant la passphrase de chiffrement de champ. Résolue via
/// `secret_from_env` -> `FORGE_FIELD_KEY_FILE` est le repli fichier (Docker/k8s secret).
pub(crate) const KEY_VAR: &str = "FORGE_FIELD_KEY";

/// Préfixe TEXTUEL d'une enveloppe. Choisi pour être reconnaissable à l'œil dans un dump et
/// impossible à confondre avec un bearer/cookie légitime.
const ENVELOPE_PREFIX: &str = "forge:fenc1:";

/// Repère de format binaire (domaine-séparé de `FORGEBK1`, le magic des archives de sauvegarde).
const FIELD_MAGIC: &[u8; 6] = b"FGFLD1";
const FIELD_VERSION: u8 = 1;
/// MAGIC(6) + VERSION(1) + salt(16) + nonce(24).
const HEADER_LEN: usize = 6 + 1 + BACKUP_SALT_LEN + BACKUP_NONCE_LEN;

/// REFUS fail-closed : une opération EXIGE la clé de champ et elle est absente. Constante EXACTE (pas
/// un motif) : les appelants la comparent par ÉGALITÉ pour rendre un code HTTP dédié (`is_key_missing`)
/// plutôt que de renifler une sous-chaîne.
pub(crate) const ERR_KEY_MISSING: &str = "clé de chiffrement de champ absente — poser FORGE_FIELD_KEY (ou FORGE_FIELD_KEY_FILE) ; refus de manier du matériel d'authentification en clair (fail-closed)";

/// REFUS fail-closed : une enveloppe existe mais ne s'ouvre pas (mauvaise clé, ou octets altérés).
pub(crate) const ERR_UNSEAL: &str = "matériel d'authentification scellé ILLISIBLE — la clé FORGE_FIELD_KEY ne correspond pas au chiffré stocké (ou celui-ci est altéré) ; refus de continuer avec un contexte d'authentification vide (fail-closed)";

/// Vrai si `msg` est le refus « clé absente ». Sert aux handlers HTTP à distinguer un 503 (défaut de
/// CONFIGURATION serveur) d'un 400 (requête mal formée) — l'opérateur doit savoir lequel des deux.
pub(crate) fn is_key_missing(msg: &str) -> bool {
    msg == ERR_KEY_MISSING
}

/// Passphrase de champ résolue depuis l'environnement (avec repli `<VAR>_FILE`), ou `None`. Une valeur
/// blanche est traitée comme ABSENTE (jamais une clé « vide » silencieuse — même discipline que
/// `secret_from_env`, qui refuse déjà la chaîne vide).
pub(crate) fn key_from_env() -> Option<String> {
    crate::secret_from_env(KEY_VAR).filter(|s| !s.trim().is_empty())
}

// =====================================================================================
//  DÉRIVATION MÉMOÏSÉE — une passe argon2id par (sel, passphrase) et par processus
// =====================================================================================

/// Une entrée du cache de dérivation : (sel de l'enveloppe, empreinte SHA-256 de la passphrase, clé
/// AEAD dérivée). L'empreinte, et non la passphrase, sert d'identité — le secret n'est jamais recopié
/// dans la structure globale.
type CachedKey = ([u8; BACKUP_SALT_LEN], [u8; 32], [u8; BACKUP_KEY_LEN]);

/// Cache borné (sel, empreinte de passphrase) -> clé AEAD. argon2id coûte ~50 ms : sans cache, ouvrir
/// un bloc de N champs en coûterait N. Borné à `CACHE_MAX` avec éviction FIFO — aucune croissance non
/// bornée même après de nombreuses rotations de sel.
static KEY_CACHE: std::sync::Mutex<Vec<CachedKey>> = std::sync::Mutex::new(Vec::new());
const CACHE_MAX: usize = 16;

/// Dérive (ou relit du cache) la clé AEAD pour (passphrase, sel). L'empreinte SHA-256 de la passphrase
/// sert de clé de cache : la passphrase elle-même n'est jamais recopiée dans la structure globale.
fn derive_cached(passphrase: &str, salt: &[u8; BACKUP_SALT_LEN]) -> Result<[u8; BACKUP_KEY_LEN], String> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(passphrase.as_bytes());
    let mut pass_id = [0u8; 32];
    pass_id.copy_from_slice(&h.finalize());

    if let Ok(cache) = KEY_CACHE.lock() {
        if let Some((_, _, k)) = cache.iter().find(|(s, p, _)| s == salt && p == &pass_id) {
            return Ok(*k);
        }
    }
    // Paramètres argon2id PAR DÉFAUT du crate — les MÊMES que l'archive de sauvegarde. Ils ne sont pas
    // écrits dans l'enveloppe (contrairement au backup, dont l'en-tête les porte) : une enveloppe de
    // champ est produite et consommée par LA MÊME version du binaire, la version du format (`fenc1`)
    // les fixe. Un changement de paramètres passera donc par une V2 de format, jamais en silence.
    let dp = crate::backup_crypto::Params::default();
    let key = backup_derive_key(passphrase, salt, dp.m_cost(), dp.t_cost(), dp.p_cost())?;
    if let Ok(mut cache) = KEY_CACHE.lock() {
        if cache.len() >= CACHE_MAX {
            cache.remove(0); // FIFO — borne dure, jamais de croissance illimitée
        }
        cache.push((*salt, pass_id, key));
    }
    Ok(key)
}

// =====================================================================================
//  ENVELOPPE — primitives sur UNE chaîne (PURES : la passphrase est passée, jamais lue de l'env)
// =====================================================================================

/// Vrai si `s` porte le préfixe d'enveloppe (donc : est du chiffré au repos, pas un credential clair).
pub(crate) fn is_sealed(s: &str) -> bool {
    s.starts_with(ENVELOPE_PREFIX)
}

/// SCELLE une chaîne sous (passphrase, sel) avec un nonce CSPRNG frais. L'en-tête complet est lié en
/// AAD. PURE hors CSPRNG. Ne journalise RIEN.
fn seal_str(plain: &str, passphrase: &str, salt: &[u8; BACKUP_SALT_LEN]) -> Result<String, String> {
    use base64::Engine as _;
    let mut nonce = [0u8; BACKUP_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG (nonce de champ) indisponible: {e}"))?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(FIELD_MAGIC);
    header.push(FIELD_VERSION);
    header.extend_from_slice(salt);
    header.extend_from_slice(&nonce);
    let mut key = derive_cached(passphrase, salt)?;
    let body = aead_seal(&key, &nonce, &header, plain.as_bytes());
    for b in key.iter_mut() { *b = 0; } // hygiène : la clé ne survit pas à son usage sur ce stack
    let mut payload = header;
    payload.extend_from_slice(&body?);
    Ok(format!("{ENVELOPE_PREFIX}{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(&payload)))
}

/// OUVRE une enveloppe. Toute anomalie (préfixe/base64/magic/version/troncage/tag) rend `Err` : il
/// n'existe AUCUN chemin qui rende un plaintext non authentifié, ni qui rende la chaîne chiffrée
/// elle-même comme si c'était le credential.
fn unseal_str(env: &str, passphrase: &str) -> Result<String, String> {
    use base64::Engine as _;
    let b64 = env.strip_prefix(ENVELOPE_PREFIX).ok_or_else(|| ERR_UNSEAL.to_string())?;
    let payload = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(b64.as_bytes())
        .map_err(|_| ERR_UNSEAL.to_string())?;
    if payload.len() < HEADER_LEN || &payload[0..6] != FIELD_MAGIC || payload[6] != FIELD_VERSION {
        return Err(ERR_UNSEAL.to_string());
    }
    let mut salt = [0u8; BACKUP_SALT_LEN];
    salt.copy_from_slice(&payload[7..7 + BACKUP_SALT_LEN]);
    let mut nonce = [0u8; BACKUP_NONCE_LEN];
    nonce.copy_from_slice(&payload[7 + BACKUP_SALT_LEN..HEADER_LEN]);
    let mut key = derive_cached(passphrase, &salt)?;
    let out = aead_open(&key, &nonce, &payload[..HEADER_LEN], &payload[HEADER_LEN..]);
    for b in key.iter_mut() { *b = 0; }
    let plain = out.map_err(|_| ERR_UNSEAL.to_string())?;
    String::from_utf8(plain).map_err(|_| ERR_UNSEAL.to_string())
}

// =====================================================================================
//  BLOC `auth` — parcours des FEUILLES de matériel (bearer / cookies / valeurs d'en-tête)
// =====================================================================================

/// Applique `f` à chaque FEUILLE de matériel d'authentification d'un bloc `auth` canonique, en place.
/// Le parcours est la DÉFINITION du périmètre chiffré : ce qui n'est pas visité ici reste en clair
/// (labels, `idor_targets`, NOMS d'en-têtes — cf. le doc du module). Un `Err` de `f` avorte tout : le
/// bloc n'est jamais rendu à MOITIÉ transformé.
fn map_material<F>(auth: &Value, mut f: F) -> Result<Value, String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let mut out = auth.clone();
    let accounts = match out.get_mut("accounts").and_then(|a| a.as_array_mut()) {
        Some(a) => a,
        None => return Ok(out),
    };
    for acc in accounts.iter_mut() {
        let o = match acc.as_object_mut() {
            Some(o) => o,
            None => continue,
        };
        if let Some(Value::String(b)) = o.get("bearer") {
            let v = f(b)?;
            o.insert("bearer".into(), Value::String(v));
        }
        // `cookies` accepte DEUX formes (contrat moteur) : la chaîne 'a=b; c=d' ENTIÈRE, ou une map
        // dont seules les VALEURS sont secrètes (les noms de cookie ne le sont pas).
        match o.get("cookies").cloned() {
            Some(Value::String(c)) => {
                let v = f(&c)?;
                o.insert("cookies".into(), Value::String(v));
            }
            Some(Value::Object(m)) => {
                let mut nm = Map::new();
                for (k, val) in m {
                    match val {
                        Value::String(s) => nm.insert(k, Value::String(f(&s)?)),
                        other => nm.insert(k, other),
                    };
                }
                o.insert("cookies".into(), Value::Object(nm));
            }
            _ => {}
        }
        if let Some(Value::Object(m)) = o.get("headers").cloned() {
            let mut nm = Map::new();
            for (k, val) in m {
                match val {
                    Value::String(s) => nm.insert(k, Value::String(f(&s)?)),
                    other => nm.insert(k, other),
                };
            }
            o.insert("headers".into(), Value::Object(nm));
        }
    }
    Ok(out)
}

/// Collecte l'état AU REPOS des feuilles de matériel d'un bloc `auth` : (nb scellées, nb en clair).
/// PURE, ne nécessite AUCUNE clé — c'est ce qui permet à l'éditeur et à l'avertissement de boot de
/// dire la vérité sur l'état du chiffrement sans pouvoir déchiffrer quoi que ce soit.
pub(crate) fn material_census(auth: &Value) -> (usize, usize) {
    let (mut sealed, mut clear) = (0usize, 0usize);
    let _ = map_material(auth, |s| {
        if is_sealed(s) { sealed += 1 } else { clear += 1 }
        Ok(s.to_string())
    });
    (sealed, clear)
}

// =====================================================================================
//  ÉCHÉANCE DU MATÉRIEL — tampon NON SECRET posé au scellement, lisible SANS la clé
//
//  POURQUOI ICI, ET PAS DANS L'ÉDITEUR. Une session morte se manifestait jusqu'ici par un rapport
//  PROPRE et VIDE en fin de campagne. Pour la voir AVANT de lancer, il faut savoir si le matériel
//  est périmé — or au repos il est SCELLÉ : ni l'éditeur ni le lanceur ne peuvent le lire (ils n'ont
//  pas la clé, et c'est le but). Le SEUL instant où la console voit le clair est le SCELLEMENT.
//  On y calcule donc, une fois, la date de péremption AUTO-DÉCLARÉE du jeton (claim `exp` d'un JWT)
//  et on la range à côté du label.
//
//  POURQUOI C'EST SÛR DE LA STOCKER EN CLAIR. `exp` est un HORODATAGE, pas du matériel : il ne
//  rejoue rien, ne signe rien, ne s'authentifie nulle part. Il vit avec `label` et `idor_targets`,
//  déjà délibérément en clair (cf. le périmètre mesuré en tête de module). L'invariant « aucun
//  nouveau champ de MATÉRIEL persisté en clair » est donc tenu : ce champ n'est pas du matériel.
//  Un lecteur de la base apprend QUAND un jeton expire — valeur d'exploitation nulle.
//
//  AUCUNE VÉRIFICATION DE SIGNATURE : on ne valide pas le jeton, on LIT sa date. Miroir EXACT de
//  `forge/session.py::jwt_expiry` (le moteur refait le calcul sur le clair au tir — la console ne
//  fait pas autorité, elle AVERTIT). Un cookie opaque -> aucune échéance -> champ absent = INCONNU,
//  jamais « expiré » : on n'accuse pas sans preuve.
// =====================================================================================

/// Grâce (s) avant de déclarer un matériel périmé : notre horloge peut être EN AVANCE sur celle du
/// serveur. Pousse la déclaration PLUS TARD, jamais plus tôt. Miroir de `session._EXPIRY_GRACE`.
const EXPIRY_GRACE_SECS: i64 = 60;

/// `exp` (epoch s) du PAYLOAD d'un JWT, ou `None` (absent, illisible, non-JWT). PURE, ne panique
/// jamais. Un JWT commence toujours par le base64url de `{"` -> `eyJ` ; on ne décode donc que ce qui
/// en a la forme, jamais un cookie opaque quelconque.
pub(crate) fn jwt_exp(s: &str) -> Option<i64> {
    use base64::Engine as _;
    if !s.starts_with("eyJ") {
        return None;
    }
    let seg = s.split('.').nth(1)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(seg.as_bytes()).ok()?;
    let payload: Value = serde_json::from_slice(&raw).ok()?;
    match payload.get("exp")? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        _ => None, // `exp` non numérique -> INCONNU (jamais une date fabriquée)
    }
}

/// Échéance la PLUS PROCHE parmi les feuilles de matériel EN CLAIR d'UN compte, ou `None`.
/// Réutilise `map_material` (la définition UNIQUE du périmètre de matériel) sur un bloc à un seul
/// compte : impossible que la lecture d'échéance et le chiffrement divergent sur « qu'est-ce qu'une
/// feuille de matériel ». Les feuilles DÉJÀ scellées sont ignorées (illisibles sans la clé).
fn account_expiry(acc: &Value) -> Option<i64> {
    let mut best: Option<i64> = None;
    let _ = map_material(&json!({"accounts": [acc.clone()]}), |s| {
        if !is_sealed(s) {
            if let Some(e) = jwt_exp(s) {
                best = Some(best.map_or(e, |b: i64| b.min(e)));
            }
        }
        Ok(s.to_string())
    });
    best
}

/// POSE (ou RETIRE) le tampon `exp` sur chaque compte portant du matériel EN CLAIR.
///
/// - compte avec ≥1 feuille EN CLAIR  => `exp` RECALCULÉ depuis ce clair : posé s'il est lisible,
///   RETIRÉ sinon. C'est ce qui empêche un client de MENTIR en postant un `exp` arbitraire à côté
///   d'un jeton : le matériel fraîchement fourni fait toujours foi ;
/// - compte entièrement SCELLÉ (matériel repris tel quel à l'édition) => INTOUCHÉ, le tampon posé
///   lors d'un scellement précédent est PRÉSERVÉ (il ne peut plus être recalculé sans la clé).
pub(crate) fn stamp_auth_expiry(auth: &Value) -> Value {
    let mut out = auth.clone();
    let Some(accounts) = out.get_mut("accounts").and_then(|a| a.as_array_mut()) else { return out };
    for acc in accounts.iter_mut() {
        let (_, clear) = material_census(&json!({"accounts": [acc.clone()]}));
        if clear == 0 {
            continue; // rien de lisible ici : on PRÉSERVE le tampon existant
        }
        let exp = account_expiry(acc);
        if let Some(o) = acc.as_object_mut() {
            match exp {
                Some(e) => { o.insert("exp".into(), json!(e)); }
                None => { o.remove("exp"); }
            }
        }
    }
    out
}

/// LABELS des comptes dont le tampon `exp` est DÉPASSÉ à l'instant `now` (grâce incluse). PURE et
/// SANS CLÉ : c'est ce qui permet à l'éditeur ET au lanceur de dire la vérité sur un matériel qu'ils
/// ne peuvent pas lire. Un compte sans tampon (cookie opaque, base pas encore re-scellée) n'est
/// JAMAIS listé — inconnu n'est pas expiré.
pub(crate) fn auth_expired_labels(auth: &Value, now: i64) -> Vec<String> {
    auth.get("accounts")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|acc| acc.get("exp").and_then(Value::as_i64).is_some_and(|e| e + EXPIRY_GRACE_SECS <= now))
                .map(|acc| acc.get("label").and_then(Value::as_str).unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// SCELLE le matériel EN CLAIR d'un bloc `auth` canonique. IDEMPOTENT : une feuille DÉJÀ enveloppée est
/// laissée telle quelle (c'est ce qui rend la fusion d'édition et la migration ré-exécutables sans
/// double chiffrement). Toutes les feuilles scellées lors d'UN appel partagent UN sel (donc UNE
/// dérivation argon2id) et ont chacune leur PROPRE nonce.
///
/// FAIL-CLOSED : `key = None` ET au moins une feuille en clair => `Err(ERR_KEY_MISSING)`. `key = None`
/// mais RIEN à sceller (bloc `idor_targets`-seul, ou déjà entièrement scellé) => `Ok` inchangé : un
/// opérateur sans contexte auth n'a JAMAIS besoin de poser une clé.
pub(crate) fn seal_auth_block(auth: &Value, key: Option<&str>) -> Result<Value, String> {
    // ÉCHÉANCE : le scellement est le DERNIER instant où la console voit le matériel EN CLAIR — donc
    // le seul où la date de péremption peut être lue. On la tamponne AVANT de chiffrer (cf. le bloc
    // « ÉCHÉANCE DU MATÉRIEL » ci-dessus). Sans matériel clair, `stamp_auth_expiry` est un no-op
    // strict : le bloc rendu reste byte-identique et aucune clé n'est requise.
    let auth = &stamp_auth_expiry(auth);
    let (_, clear) = material_census(auth);
    if clear == 0 {
        return Ok(auth.clone()); // rien à faire — aucune clé requise (no-op strict)
    }
    let passphrase = key.ok_or_else(|| ERR_KEY_MISSING.to_string())?;
    let mut salt = [0u8; BACKUP_SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| format!("CSPRNG (sel de champ) indisponible: {e}"))?;
    map_material(auth, |s| {
        if is_sealed(s) {
            Ok(s.to_string())
        } else {
            seal_str(s, passphrase, &salt)
        }
    })
}

/// OUVRE le matériel scellé d'un bloc `auth` pour le point d'USAGE (le `scope.json` 0600 du run).
///
/// FAIL-CLOSED : une feuille enveloppée + `key = None` => `Err(ERR_KEY_MISSING)` ; une feuille
/// enveloppée qui n'ouvre pas => `Err(ERR_UNSEAL)`. Dans les deux cas l'appelant REFUSE le run — il
/// ne part JAMAIS avec un contexte d'authentification vide ou partiel.
///
/// PASS-THROUGH : une feuille NON enveloppée est rendue telle quelle, sans exiger de clé — c'est ce
/// qui permet à une base pas encore migrée de continuer à fonctionner après un upgrade en place.
pub(crate) fn unseal_auth_block(auth: &Value, key: Option<&str>) -> Result<Value, String> {
    let (sealed, _) = material_census(auth);
    if sealed == 0 {
        return Ok(auth.clone()); // rien de scellé — aucune clé requise (base pas encore migrée)
    }
    let passphrase = key.ok_or_else(|| ERR_KEY_MISSING.to_string())?;
    map_material(auth, |s| {
        if is_sealed(s) {
            unseal_str(s, passphrase)
        } else {
            Ok(s.to_string())
        }
    })
}

/// Étiquette AU REPOS d'un bloc `auth`, pour l'éditeur : `sealed` (tout chiffré), `plaintext` (rien),
/// `mixed` (base à moitié migrée), `none` (aucune feuille de matériel — bloc `idor_targets`-seul).
/// C'est le canal qui rend l'état LISIBLE dans le produit, sans jamais exiger la clé.
pub(crate) fn at_rest_label(auth: &Value) -> &'static str {
    match material_census(auth) {
        (0, 0) => "none",
        (_, 0) => "sealed",
        (0, _) => "plaintext",
        _ => "mixed",
    }
}

// =====================================================================================
//  SECRETS D'INTÉGRATION — un CHAMP unique dans une config `settings` (JSON)
// =====================================================================================
//
//  Les trois secrets d'INTÉGRATION (jeton de source de détection, jeton de canal de notification,
//  `client_secret` SSO) vivent dans la table `settings`, chacun à UN chemin de champ dans son objet
//  de config. Ils avaient été écartés du premier lot de chiffrement pour une raison TECHNIQUE réelle :
//  les sceller EXIGE de rendre leurs chemins de lecture FAILLIBLES — or `sso::load_config` rendait un
//  `Option`, et un déchiffrement échoué y serait devenu « SSO non configuré », c'est-à-dire exactement
//  la dégradation SILENCIEUSE que ce module interdit. L'ordre a donc été : d'abord rendre les chemins
//  faillibles avec un échec LISIBLE, ensuite sceller. Ce bloc est la seconde moitié.
//
//  ZÉRO nouvelle crypto : [`seal_str`] / [`unseal_str`] ci-dessus, MÊME clé (`FORGE_FIELD_KEY`), MÊME
//  format d'enveloppe `forge:fenc1:` que le matériel d'authentification d'engagement.

/// Chemin du secret dans une config de SOURCE DE DÉTECTION (`settings.detection_source`).
pub(crate) const DS_SECRET_PATH: &[&str] = &["auth", "secret"];
/// Chemin du secret dans une config de CANAL DE NOTIFICATION (`settings.notify_channel`) — même forme.
pub(crate) const CH_SECRET_PATH: &[&str] = &["auth", "secret"];
/// Chemin du `client_secret` dans la config OIDC (`settings.sso_config`) — à plat, pas sous `auth`.
pub(crate) const SSO_SECRET_PATH: &[&str] = &["client_secret"];

/// Valeur BRUTE du champ (telle qu'AU REPOS : possiblement une enveloppe). Ne déchiffre RIEN et n'exige
/// AUCUNE clé — c'est ce qui permet aux booléens `secret_set` et à la réinjection `keep_secret` de
/// fonctionner sans jamais manipuler le plaintext.
pub(crate) fn config_field_raw(cfg: &Value, path: &[&str]) -> String {
    let mut cur = cfg;
    for k in path {
        match cur.get(k) {
            Some(v) => cur = v,
            None => return String::new(),
        }
    }
    cur.as_str().unwrap_or("").to_string()
}

/// Applique `f` à la valeur du champ `path` et rend la config MODIFIÉE. Champ absent ou vide => la
/// config est rendue INCHANGÉE (rien à transformer — jamais une clé exigée pour une config sans secret).
fn map_config_field<F>(cfg: &Value, path: &[&str], f: F) -> Result<Value, String>
where
    F: FnOnce(&str) -> Result<String, String>,
{
    debug_assert!(!path.is_empty(), "chemin de champ vide");
    let cur = config_field_raw(cfg, path);
    if cur.is_empty() {
        return Ok(cfg.clone());
    }
    let next = f(&cur)?;
    // Descente en écriture : chaque segment intermédiaire DOIT déjà être un objet — il l'est, puisque
    // `config_field_raw` vient d'y lire une chaîne non vide.
    let mut out = cfg.clone();
    let mut node = &mut out;
    for k in &path[..path.len() - 1] {
        node = node.get_mut(k).ok_or_else(|| "chemin de champ disparu".to_string())?;
    }
    let last = path[path.len() - 1];
    node.as_object_mut()
        .ok_or_else(|| "conteneur de champ non-objet".to_string())?
        .insert(last.to_string(), Value::String(next));
    Ok(out)
}

/// SCELLE le secret d'une config d'intégration. IDEMPOTENT (une valeur DÉJÀ enveloppée est laissée
/// telle quelle — c'est ce qui rend la migration et la réinjection `keep_secret` rejouables sans
/// double chiffrement). Config SANS secret => no-op strict, AUCUNE clé requise.
///
/// FAIL-CLOSED : un secret EN CLAIR à sceller et `key = None` => `Err(ERR_KEY_MISSING)`. On refuse de
/// persister un credential en clair en faisant croire au chiffrement.
pub(crate) fn seal_config_secret(cfg: &Value, path: &[&str], key: Option<&str>) -> Result<Value, String> {
    map_config_field(cfg, path, |cur| {
        if is_sealed(cur) {
            return Ok(cur.to_string());
        }
        let passphrase = key.ok_or_else(|| ERR_KEY_MISSING.to_string())?;
        let mut salt = [0u8; BACKUP_SALT_LEN];
        getrandom::fill(&mut salt).map_err(|e| format!("CSPRNG (sel de champ) indisponible: {e}"))?;
        seal_str(cur, passphrase, &salt)
    })
}

/// OUVRE le secret d'une config d'intégration, au POINT D'USAGE (construction de l'en-tête d'auth,
/// POST au token endpoint, passage au collecteur Python).
///
/// FAIL-CLOSED, et c'est TOUT L'INTÉRÊT de l'ordre suivi : une enveloppe + `key = None` =>
/// `Err(ERR_KEY_MISSING)` ; une enveloppe qui n'ouvre pas => `Err(ERR_UNSEAL)`. L'appelant REFUSE alors
/// l'opération avec une raison NOMMÉE — il ne repart JAMAIS avec un secret vide, ce qui se présenterait
/// comme « pas d'authentification configurée » (source de détection anonyme, SSO non configuré) et
/// serait indistinguable d'un problème de configuration.
///
/// PASS-THROUGH : une valeur NON enveloppée est rendue telle quelle, sans exiger de clé — une base pas
/// encore migrée continue de fonctionner après un upgrade en place.
pub(crate) fn open_config_secret(cfg: &Value, path: &[&str], key: Option<&str>) -> Result<Value, String> {
    map_config_field(cfg, path, |cur| {
        if !is_sealed(cur) {
            return Ok(cur.to_string());
        }
        let passphrase = key.ok_or_else(|| ERR_KEY_MISSING.to_string())?;
        unseal_str(cur, passphrase)
    })
}

// =====================================================================================
//  MIGRATION AU BOOT — les bases existantes portent du matériel EN CLAIR
// =====================================================================================

/// Rapport de la passe de migration : combien d'engagements portent du matériel, combien ont été
/// SCELLÉS pendant cette passe, et combien restent EN CLAIR (clé absente).
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct MigrationReport {
    pub(crate) with_material: usize,
    pub(crate) sealed_now: usize,
    pub(crate) still_plaintext: usize,
    pub(crate) unreadable: usize,
}

/// Scelle le matériel d'authentification EN CLAIR déjà présent dans `engagement.scope_json`.
/// IDEMPOTENTE (rejouable à chaque boot sans effet ni double chiffrement) et portable sur les deux
/// backends (passe par le seam `Store`).
///
/// POURQUOI ELLE EXISTE : chiffrer À L'ÉCRITURE sans traiter le passé laisserait les anciennes lignes
/// lisibles tout en affichant un système « chiffré au repos » — donner l'ILLUSION du chiffrement est
/// pire que ne pas chiffrer. Une base upgradée est donc convertie AU BOOT, en place.
///
/// SANS CLÉ : on ne convertit rien (impossible), et on ne casse rien non plus — on COMPTE le clair
/// restant pour que l'appelant l'annonce BRUYAMMENT. Le clair n'est jamais tu.
pub(crate) fn migrate_seal_engagement_auth(store: &crate::store::Store, key: Option<&str>) -> MigrationReport {
    let mut rep = MigrationReport::default();
    // lecture lax : une ligne au scope_json illisible est SAUTÉE (jamais un boot cassé par une donnée
    // héritée mal formée) — elle ne porte alors pas de bloc auth exploitable de toute façon.
    let rows = store
        .query_lax(
            "SELECT id, scope_json FROM engagement ORDER BY id",
            &[],
            |r| Ok((r.get_i64(0)?, r.get_opt_str(1)?.unwrap_or_default())),
        )
        .unwrap_or_default();
    for (id, scope_json) in rows {
        let mut v: Value = match serde_json::from_str(&scope_json) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let auth = match v.get("auth") {
            Some(a) if a.is_object() => a.clone(),
            _ => continue,
        };
        let (sealed, clear) = material_census(&auth);
        if sealed + clear == 0 {
            continue; // bloc `idor_targets`-seul : aucun credential, rien à chiffrer
        }
        rep.with_material += 1;
        if clear == 0 {
            continue; // déjà entièrement scellé
        }
        let Some(passphrase) = key else {
            rep.still_plaintext += 1; // pas de clé : on ne peut pas convertir — l'appelant le CRIE
            continue;
        };
        match seal_auth_block(&auth, Some(passphrase)) {
            Ok(sealed_block) => {
                v["auth"] = sealed_block;
                // Écriture CIBLÉE (une ligne, une colonne). Un échec laisse la ligne EN CLAIR et est
                // compté comme tel : jamais un rapport « migré » sur une écriture qui n'a pas pris.
                if store
                    .execute("UPDATE engagement SET scope_json=? WHERE id=?", &crate::sql_params![v.to_string(), id])
                    .is_ok()
                {
                    rep.sealed_now += 1;
                } else {
                    rep.still_plaintext += 1;
                }
            }
            Err(_) => rep.unreadable += 1,
        }
    }
    rep
}

/// Les TROIS lignes `settings` qui portent un secret d'INTÉGRATION, avec le chemin de leur champ.
/// Liste FERMÉE : ajouter une intégration porteuse de secret sans l'inscrire ici la laisserait EN CLAIR
/// au repos, et `settings_secrets_inventory_covers_every_module_key` le fait ROUGIR.
pub(crate) const SETTINGS_SECRETS: &[(&str, &[&str])] = &[
    ("detection_source", DS_SECRET_PATH),
    ("notify_channel", CH_SECRET_PATH),
    ("sso.config", SSO_SECRET_PATH),
];

/// Scelle les secrets d'INTÉGRATION en clair déjà présents dans la table `settings` (jeton de source de
/// détection, jeton de canal, `client_secret` SSO). Même contrat que
/// [`migrate_seal_engagement_auth`] : IDEMPOTENTE, portable sur les deux backends, et SANS CLÉ elle ne
/// convertit rien mais COMPTE le clair restant pour que l'appelant l'annonce BRUYAMMENT.
///
/// POURQUOI AU BOOT : chiffrer à l'écriture sans traiter le passé laisserait les lignes existantes
/// lisibles tout en affichant un système « chiffré au repos ». Une base upgradée est convertie en place.
pub(crate) fn migrate_seal_settings_secrets(store: &crate::store::Store, key: Option<&str>) -> MigrationReport {
    let mut rep = MigrationReport::default();
    for (skey, path) in SETTINGS_SECRETS {
        let Some(raw) = crate::settings_get_store(store, skey) else { continue };
        let Ok(cfg) = serde_json::from_str::<Value>(&raw) else { continue };
        let cur = config_field_raw(&cfg, path);
        if cur.is_empty() {
            continue; // config sans secret (ou clé absente) : rien à chiffrer
        }
        rep.with_material += 1;
        if is_sealed(&cur) {
            continue; // déjà scellé
        }
        let Some(passphrase) = key else {
            rep.still_plaintext += 1; // pas de clé : on ne peut pas convertir — l'appelant le CRIE
            continue;
        };
        match seal_config_secret(&cfg, path, Some(passphrase)) {
            Ok(sealed) => {
                // Écriture CIBLÉE. Un échec laisse la ligne EN CLAIR et est compté comme tel : jamais
                // un rapport « migré » sur une écriture qui n'a pas pris.
                if crate::settings_set_store(store, skey, &sealed.to_string()).is_ok() {
                    rep.sealed_now += 1;
                } else {
                    rep.still_plaintext += 1;
                }
            }
            Err(_) => rep.unreadable += 1,
        }
    }
    rep
}

/// Ligne d'ÉTAT du scellement des secrets d'INTÉGRATION au boot. Même discipline que
/// [`boot_status_line`] : `None` quand aucune intégration ne porte de secret (boot byte-identique),
/// sinon on annonce — et BRUYAMMENT quand le clair subsiste.
pub(crate) fn settings_boot_status_line(rep: &MigrationReport, key_present: bool) -> Option<String> {
    if rep.with_material == 0 {
        return None;
    }
    if !key_present {
        return Some(format!(
            "[forge] ⚠️ SECRETS D'INTÉGRATION EN CLAIR AU REPOS — {} configuration(s) (source de détection / canal de notification / SSO) portent un secret, et {KEY_VAR} n'est pas posée : ils RESTENT en clair dans la table settings. Poser {KEY_VAR} (ou {KEY_VAR}_FILE) puis redémarrer pour les chiffrer en place.",
            rep.with_material
        ));
    }
    if rep.unreadable > 0 {
        return Some(format!(
            "[forge] ⚠️ CHIFFREMENT DE CHAMP (intégrations) — {} configuration(s) avec secret ; {} scellée(s) à ce boot ; {} ILLISIBLE(S) (la clé {KEY_VAR} ne correspond pas au chiffré stocké) : l'intégration concernée REFUSERA de partir plutôt que de se présenter sans authentification.",
            rep.with_material, rep.sealed_now, rep.unreadable
        ));
    }
    Some(format!(
        "[forge] CHIFFREMENT DE CHAMP (intégrations) — {} configuration(s) avec secret, chiffré AU REPOS (clé {KEY_VAR}) ; {} scellée(s) à ce boot.",
        rep.with_material, rep.sealed_now
    ))
}

/// Ligne d'ÉTAT à imprimer au boot. Le silence n'est jamais une option : soit on annonce que le
/// matériel est scellé, soit on annonce BRUYAMMENT qu'il ne l'est pas et pourquoi. `None` quand aucun
/// engagement ne porte de matériel d'authentification (cas de l'immense majorité des installs) — le
/// boot reste alors STRICTEMENT silencieux, byte-identique.
pub(crate) fn boot_status_line(rep: &MigrationReport, key_present: bool) -> Option<String> {
    if rep.with_material == 0 {
        return None;
    }
    if !key_present {
        return Some(format!(
            "[forge] ⚠️ MATÉRIEL D'AUTHENTIFICATION EN CLAIR AU REPOS — {} engagement(s) portent des credentials de compte de test, et {KEY_VAR} n'est pas posée : ils RESTENT en clair dans la base. Poser {KEY_VAR} (ou {KEY_VAR}_FILE) puis redémarrer pour les chiffrer en place. Tant que la clé manque, toute écriture de nouveau matériel est REFUSÉE (503 field_key_missing).",
            rep.with_material
        ));
    }
    if rep.unreadable > 0 {
        return Some(format!(
            "[forge] ⚠️ CHIFFREMENT DE CHAMP — {} engagement(s) avec matériel ; {} scellé(s) à ce boot ; {} ILLISIBLE(S) (la clé {KEY_VAR} ne correspond pas au chiffré stocké) : les runs de ces engagements REFUSERONT de démarrer plutôt que de partir sans contexte d'authentification.",
            rep.with_material, rep.sealed_now, rep.unreadable
        ));
    }
    Some(format!(
        "[forge] CHIFFREMENT DE CHAMP ARMÉ — {} engagement(s) avec matériel d'authentification, chiffré AU REPOS (XChaCha20-Poly1305 + argon2id, clé {KEY_VAR}) ; {} scellé(s) à ce boot.",
        rep.with_material, rep.sealed_now
    ))
}

/// Clé de champ du PROCESSUS DE TEST. Voir [`test_install_process_key`].
#[cfg(test)]
pub(crate) const TEST_PROCESS_KEY: &str = "cle-de-champ-du-processus-de-test";

/// Installe `FORGE_FIELD_KEY` dans l'environnement DU PROCESSUS DE TEST, une seule fois.
///
/// L'environnement est GLOBAL au processus et la suite tourne en multi-thread : muter une variable
/// d'env dans un test est normalement une course. Ce helper est sûr parce qu'il ne fait que POSER,
/// TOUJOURS la même valeur, et ne l'ENLÈVE JAMAIS — deux appels concurrents écrivent le même octet.
/// Il est réservé aux tests qui traversent un HANDLER HTTP (seul endroit qui lit l'env). Tous les cas
/// FAIL-CLOSED « clé absente » sont couverts par l'API PURE (`key` passée en paramètre), justement pour
/// qu'AUCUN test n'ait besoin que la variable soit absente — sans quoi les deux familles se
/// marcheraient dessus selon l'ordre d'exécution.
#[cfg(test)]
pub(crate) fn test_install_process_key() -> &'static str {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| std::env::set_var(KEY_VAR, TEST_PROCESS_KEY));
    TEST_PROCESS_KEY
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "passphrase-de-champ-de-test";

    fn block() -> Value {
        json!({
            "accounts": [
                {"label": "attacker", "bearer": "BEARER-CANARY", "headers": {"X-CSRF": "HDR-CANARY"}},
                {"label": "victim", "cookies": "sid=COOKIE-CANARY"},
                {"label": "third", "cookies": {"sid": "MAP-COOKIE-CANARY"}}
            ],
            "idor_targets": [{"url": "https://app.test/api/me", "owner": "victim", "marker": "MK"}]
        })
    }

    /// [PÉRIMÈTRE] Le scellement couvre EXACTEMENT le matériel d'auth : bearer, cookies (chaîne ET
    /// valeurs de map), valeurs d'en-tête. Les labels, les NOMS d'en-têtes/de cookies et les
    /// `idor_targets` restent EN CLAIR (l'éditeur les ré-affiche sans la clé). Le round-trip est
    /// LOSSLESS. MUTATION-PROVABLE : retirer une branche de `map_material` laisse le canari
    /// correspondant en clair -> ROUGE.
    #[test]
    fn seal_covers_the_material_and_only_the_material() {
        let sealed = seal_auth_block(&block(), Some(KEY)).expect("scellement");
        let blob = sealed.to_string();
        for canary in ["BEARER-CANARY", "HDR-CANARY", "COOKIE-CANARY", "MAP-COOKIE-CANARY"] {
            assert!(!blob.contains(canary), "matériel '{canary}' encore EN CLAIR après scellement: {blob}");
        }
        // structure non secrète PRÉSERVÉE en clair (sinon l'éditeur devient illisible sans la clé)
        assert_eq!(sealed["accounts"][0]["label"], json!("attacker"), "label en clair");
        assert!(sealed["accounts"][0]["headers"].get("X-CSRF").is_some(), "NOM d'en-tête en clair");
        assert!(sealed["accounts"][2]["cookies"].get("sid").is_some(), "NOM de cookie en clair");
        assert_eq!(sealed["idor_targets"][0]["url"], json!("https://app.test/api/me"), "cible en clair");
        assert_eq!(at_rest_label(&sealed), "sealed");
        // round-trip LOSSLESS
        let back = unseal_auth_block(&sealed, Some(KEY)).expect("ouverture");
        assert_eq!(back, block(), "round-trip lossless (valeurs VERBATIM)");
    }

    /// [FAIL-CLOSED — ÉCRITURE] Sceller du matériel EN CLAIR SANS clé est REFUSÉ (jamais persisté en
    /// clair « en attendant »). Mais un bloc SANS matériel (cibles seules) ou DÉJÀ scellé n'exige
    /// AUCUNE clé — l'opérateur qui n'arme pas de contexte auth n'est pas puni.
    /// MUTATION-PROVABLE : remplacer le `ok_or_else(ERR_KEY_MISSING)` par un repli en clair -> ROUGE.
    #[test]
    fn write_without_key_is_refused_but_only_when_there_is_material() {
        let e = seal_auth_block(&block(), None).expect_err("clair + pas de clé => REFUS");
        assert_eq!(e, ERR_KEY_MISSING, "refus typé (mappé en 503 par le handler)");
        assert!(is_key_missing(&e));

        let targets_only = json!({"accounts": [], "idor_targets": [{"url": "https://a.test/x", "owner": "", "marker": ""}]});
        assert_eq!(seal_auth_block(&targets_only, None).expect("no-op"), targets_only, "aucun matériel => aucune clé requise");

        let already = seal_auth_block(&block(), Some(KEY)).unwrap();
        assert_eq!(seal_auth_block(&already, None).expect("no-op"), already, "déjà scellé => aucune clé requise (idempotent)");
    }

    /// [FAIL-CLOSED — LECTURE] Un matériel SCELLÉ ne s'ouvre NI sans clé NI avec la mauvaise clé : dans
    /// les deux cas c'est une `Err` typée, JAMAIS un bloc vide/partiel ni le chiffré rendu tel quel.
    /// C'est LA garde qui empêche un run de partir avec un contexte d'authentification effacé.
    /// MUTATION-PROVABLE : rendre la valeur enveloppée au lieu d'une Err quand la clé manque -> ROUGE.
    #[test]
    fn read_without_or_with_wrong_key_refuses_never_empties() {
        let sealed = seal_auth_block(&block(), Some(KEY)).unwrap();
        let e = unseal_auth_block(&sealed, None).expect_err("scellé + pas de clé => REFUS");
        assert_eq!(e, ERR_KEY_MISSING);
        let e = unseal_auth_block(&sealed, Some("mauvaise-clé")).expect_err("mauvaise clé => REFUS");
        assert_eq!(e, ERR_UNSEAL, "tag AEAD invalide -> refus, jamais un contexte vide");
        // le chiffré n'est JAMAIS rendu comme s'il était le credential
        let bearer = sealed["accounts"][0]["bearer"].as_str().unwrap();
        assert!(is_sealed(bearer) && !bearer.contains("BEARER-CANARY"));
    }

    /// [MIGRATION / UPGRADE EN PLACE] Un bloc MIXTE (une base à moitié migrée) : les feuilles en clair
    /// passent telles quelles à la lecture (rien ne casse), et un nouveau scellement ne re-chiffre QUE
    /// le clair (idempotence). L'état est LISIBLE via `at_rest_label` — jamais tu.
    #[test]
    fn mixed_block_reads_through_and_seals_only_the_clear_leaves() {
        let sealed = seal_auth_block(&block(), Some(KEY)).unwrap();
        let mut mixed = sealed.clone();
        mixed["accounts"][0]["bearer"] = json!("PLAINTEXT-LEFTOVER"); // feuille non migrée
        assert_eq!(at_rest_label(&mixed), "mixed", "l'état à moitié migré est SURFACÉ");
        let read = unseal_auth_block(&mixed, Some(KEY)).expect("lecture d'un bloc mixte");
        assert_eq!(read["accounts"][0]["bearer"], json!("PLAINTEXT-LEFTOVER"), "clair rendu tel quel");
        assert_eq!(read["accounts"][1]["cookies"], json!("sid=COOKIE-CANARY"), "scellé ouvert");
        let remigrated = seal_auth_block(&mixed, Some(KEY)).expect("re-scellement");
        assert_eq!(at_rest_label(&remigrated), "sealed", "la migration complète le bloc");
        assert_eq!(
            remigrated["accounts"][1]["cookies"], mixed["accounts"][1]["cookies"],
            "une feuille DÉJÀ scellée n'est PAS re-chiffrée (idempotent)"
        );
        // Attendu = le bloc d'origine AVEC la feuille non migrée (qui portait une AUTRE valeur) : la
        // migration chiffre ce qu'elle trouve, elle ne restaure pas une valeur antérieure.
        let mut expected = block();
        expected["accounts"][0]["bearer"] = json!("PLAINTEXT-LEFTOVER");
        assert_eq!(unseal_auth_block(&remigrated, Some(KEY)).unwrap(), expected, "round-trip après migration");
    }

    /// [AEAD] L'en-tête (sel+nonce) est lié en AAD et le format est domaine-séparé : altérer un octet
    /// du chiffré OU de l'en-tête fait échouer le tag ; deux scellements du même clair diffèrent
    /// (nonce frais) ; une archive de SAUVEGARDE n'est pas acceptée comme enveloppe de champ.
    #[test]
    fn envelope_is_tamper_evident_nonce_fresh_and_domain_separated() {
        let a = seal_str("meme-valeur", KEY, &[3u8; BACKUP_SALT_LEN]).unwrap();
        let b = seal_str("meme-valeur", KEY, &[3u8; BACKUP_SALT_LEN]).unwrap();
        assert_ne!(a, b, "nonce frais => deux chiffrés distincts pour le même clair");
        assert_eq!(unseal_str(&a, KEY).unwrap(), "meme-valeur");

        // altération d'UN caractère du corps base64 => tag invalide (ou base64 invalide) => Err
        let mut bad = a.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert!(unseal_str(&bad, KEY).is_err(), "un octet altéré => refus (AAD/tag)");

        // une ARCHIVE de sauvegarde (magic FORGEBK1) n'est pas une enveloppe de champ
        use base64::Engine as _;
        let archive = crate::backup_crypto::backup_encrypt(b"payload", KEY).unwrap();
        let disguised = format!("{ENVELOPE_PREFIX}{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(&archive));
        assert!(unseal_str(&disguised, KEY).is_err(), "magic de sauvegarde REFUSÉ côté champ (domaine séparé)");
        // ... et un texte qui n'est pas une enveloppe du tout
        assert!(unseal_str("pas-une-enveloppe", KEY).is_err());
    }

    /// [KDF] La dérivation est mémoïsée mais reste CORRECTE : deux passphrases différentes sur le même
    /// sel donnent des clés différentes (pas de collision de cache), et le cache reste borné.
    #[test]
    fn derivation_cache_is_keyed_by_passphrase_and_salt() {
        let salt = [9u8; BACKUP_SALT_LEN];
        let k1 = derive_cached("aaa", &salt).unwrap();
        let k2 = derive_cached("bbb", &salt).unwrap();
        let k1b = derive_cached("aaa", &salt).unwrap();
        assert_ne!(k1, k2, "le cache ne confond JAMAIS deux passphrases sur un même sel");
        assert_eq!(k1, k1b, "même (passphrase, sel) => même clé (mémoïsation correcte)");
        let k3 = derive_cached("aaa", &[10u8; BACKUP_SALT_LEN]).unwrap();
        assert_ne!(k1, k3, "sel différent => clé différente");
        assert!(KEY_CACHE.lock().unwrap().len() <= CACHE_MAX, "cache BORNÉ");
    }
}

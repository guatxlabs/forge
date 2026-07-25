# Référence de configuration

> [Sommaire](README.md) · Voir aussi : [Installation](INSTALLATION.md) ·
> [Premier déploiement](FIRST_DEPLOYMENT.md) · [Administration](ADMINISTRATION.md) ·
> [Modèle de sécurité](SECURITY_MODEL.md)

Forge se configure à **deux niveaux complémentaires** :

1. **Variables d'environnement** — fixées **au déploiement** (image / `.env` / EnvironmentFile
   systemd). Elles pilotent le bind, les chemins d'état, les secrets d'amorçage, les services
   pilotés. Gabarit commenté : [`../.env.example`](../.env.example).
2. **Table `settings`** (SQLite) — configurée **dans l'UI** (wizard de 1er boot ou
   *Administration*), réservée admin, **ledgerisée**. Elle porte la source de détection, la politique
   opérateur, la politique de sauvegarde, etc. **Rien n'y est codé en dur.**

> Sûreté : les défauts laissent Forge **INERTE** et en **loopback**. Rien n'est armé. Les secrets
> ([SECRET]) ne doivent JAMAIS être committés ; garder `.env` en `0600`.

---

## 1. Variables d'environnement

### 1.1 Console — bind, chemins d'état, session

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_CONSOLE_ADDR` | Adresse de bind API/UI. **Jamais** `0.0.0.0` sans reverse-proxy + auth + host-allowlist. | `127.0.0.1:7100` (binaire) · `0.0.0.0:7100` (image, réseau isolé) | `127.0.0.1:7100` |
| `FORGE_CONSOLE_DB` | Chemin du store SQLite. | `forge.db` | `/data/db/forge.db` |
| `FORGE_CONSOLE_LEDGER` | Chemin du ledger d'engagement (JSONL). | `engagement.jsonl` | `/data/ledger/engagement.jsonl` |
| `FORGE_CONSOLE_SCOPE` | Chemin du scope/ROE **actif** (in_scope vide = INERTE). Pré-filtre fail-closed des cibles lançables depuis le web. | `<pkg_dir>/scope.json` | `/data/scope/scope.json` |
| `FORGE_CONSOLE_WEB` | Racine des assets UI servis en fallback. | résolu auto (`console/web`) | `/opt/forge/console/web` |
| `FORGE_CONSOLE_USER` | Identifiant du rôle **viewer** (Basic auth). | `forge` | `forge` |
| `FORGE_CONSOLE_SESSION_TTL` | Durée de vie d'une session (s). **C'est la valeur effective** de la TTL de session. | `3600` | `1800` |
| `FORGE_CONSOLE_HOST` | Allowlist `Host` anti-DNS-rebinding (CSV) si exposé via proxy. `localhost`/`127.0.0.1`/`::1` sont toujours acceptés. | *(vide)* | `console.exemple.test` |
| `FORGE_CONSOLE_LEDGER_PUBKEY` | Clé publique Ed25519 (hex 64) pour la vérif côté console. **Publique, non secrète.** | *(vide)* | `a1b2…` |

### 1.2 Console — secrets d'authentification / RBAC

Vides ⇒ **mode dev localhost-ouvert** pour le viewer, token d'ingestion **généré au boot**, rôle
opérateur **non provisionné** (C2 fermé). Renseigner pour un déploiement durci (ou tout provisionner
via le [wizard](FIRST_DEPLOYMENT.md)).

| Variable | Sens | Défaut | Comment l'obtenir |
|---|---|---|---|
| `FORGE_CONSOLE_TOKEN` | **[SECRET]** Bearer d'**ingestion** (canal moteur→console). Sinon généré au boot (éphémère). | *(auto)* | `openssl rand -hex 16` |
| `FORGE_CONSOLE_PASS_HASH` | **[SECRET]** Hash argon2id du rôle **viewer** (Basic). Sa présence engage la gate d'auth. | *(vide)* | `forge hashpw '<pw>'` |
| `FORGE_CONSOLE_OPERATOR_HASH` | **[SECRET]** Hash argon2id du rôle **opérateur** C2 (en-tête `X-Forge-Operator`). Vide = **C2 fermé** (fail-closed). | *(vide)* | `forge hashpw-operator '<pw>'` |

> **Attribution individuelle** : l'administration (`check_admin`) **n'accepte PAS** de repli
> env-hash — elle exige une **session admin** nommée (créée via le wizard ou `forge useradd
> <login> admin`). Les hashes env sont un mécanisme d'**amorçage headless** (viewer/opérateur).

### 1.3 Moteur Python — spawn & timeouts

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_PKG_DIR` | Racine du package python `forge` spawné par la console (cwd du spawn). | `..` | `/opt/forge` |
| `FORGE_PYTHON` | Interpréteur pour `python3 -m forge.cli`. | `python3` | `python3` |
| `FORGE_RUN_TIMEOUT` | Budget max (s) d'un run C2-light (watchdog). | `1800` (binaire) · `900` (image) | `900` |
| `FORGE_CONSOLE_URL` | Cible d'ingestion `POST /api/ingest` pour le **client Python** (`campaign`, `demo_ingest`, `doctor`). Doit matcher `FORGE_CONSOLE_ADDR`. | `http://127.0.0.1:7100` | `http://127.0.0.1:7100` |
| `FORGE_LEDGER_KEY` | **[SECRET]** Matériel de clé de signature du ledger côté moteur. Vide = clé locale auto-générée (`<base>.ed25519`, `0600`). | *(vide)* | *(matériel de clé)* |
| `PYTHONPATH` / `PYTHONUNBUFFERED` | Résolution du package `forge` / logs non bufferisés (fixés par l'image/systemd). | image | `/opt/forge` / `1` |

### 1.4 Chiffrement au repos (image `encryption` uniquement)

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_DB_KEY` | **[SECRET]** Clé SQLCipher. La console émet `PRAGMA key` **avant toute requête**. Sans elle (sur build chiffré), la base est **illisible** (fail-closed). **Ignorée** sur le build par défaut (base en clair). | *(vide)* | *(passphrase forte)* |

Voir [`MIGRATION.md`](MIGRATION.md) Runbook B et [Installation §6](INSTALLATION.md#6-image-encryption-chiffrement-au-repos--sqlcipher-opt-in).

### 1.5 Migration via API (opt-in, pré-provision)

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_ALLOW_API_MIGRATE` | Ouvre `POST /api/setup/migrate` (sinon **403** — la CLL `forge migrate` reste l'UX primaire). | *(off)* | `1` |
| `FORGE_CONSOLE_IMPORT_DIR` | Racine allowlistée des chemins d'import de la migration API (anti path-traversal). | *(racine de données)* | `/import` |

### 1.6 Sauvegardes programmées

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_BACKUP_TICK_SECS` | Période de réveil du scheduler de sauvegarde. | `60` | `60` |
| `FORGE_BACKUP_PASSPHRASE` | **[SECRET]** Passphrase du backup **programmé**. **Le NOM de cette variable** est référencé par `backup_policy.passphrase_env` (jamais la passphrase en DB). | *(vide)* | *(passphrase)* |

Détails : [`BACKUP.md`](BACKUP.md).

### 1.7 Boucle purple — source de détection (legacy / collecteur)

La source se configure **de préférence dans l'UI** (`settings.detection_source`, §2). Les variables
ci-dessous sont des **replis** :

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `PLUME_URL` | **[PURPLE]** Préréglage rétro-compat `kind=plume` (utilisé seulement si `settings.detection_source` est absent). `http://` interne uniquement. | *(vide = purple OFF)* | `http://plume-internal:8000` |
| `PLUME_TOKEN` | **[SECRET][PURPLE]** Basic auth = `base64("user:pass")`. | *(vide)* | `dXNlcjpwYXNz` |
| `FORGE_DETECTION_SOURCE` | **[SECRET]** Spécification JSON complète d'une source (kinds « riches » : https/mTLS/exec). La console la passe **par ENV** au collecteur Python (jamais en argv). | *(vide)* | `{"kind":"crowdsec",…}` |

Modèle complet et préréglages : [`DETECTION.md`](DETECTION.md). Prérequis Plume :
[`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).

### 1.8 Couche accès/évasion (browser-automation, optionnelle)

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_BROWSER_URL` | Service Camoufox + Xvfb pour les modules `evasion.*`. Injoignable = connecteur inerte. | `http://localhost:8080` (image : `http://browser-automation:8080`) | `http://browser-automation:8080` |

### 1.9 Connecteurs opérateur (optionnels)

Vides/injoignables ⇒ connecteur inerte à fire-time (aucune capacité offensive embarquée).

| Variable | Sens | Défaut |
|---|---|---|
| `MSF_RPC_HOST` | Hôte msfrpcd. | `127.0.0.1` |
| `MSF_RPC_PORT` | Port RPC msfrpcd. | `55553` |
| `MSF_RPC_USER` | Utilisateur RPC. | `msf` |
| `MSF_RPC_SSL` | TLS vers msfrpcd. | `true` |
| `MSF_RPC_PASS` | **[SECRET]** Mot de passe RPC (`msfrpcd -P`). | *(vide)* |
| `MSF_RPC_TOKEN` | **[SECRET]** Token RPC permanent (alternative au user/pass). | *(vide)* |
| `BURP_API_URL` | Base REST API Burp. | `http://127.0.0.1:1337` |
| `BURP_API_KEY` | **[SECRET]** Clé API Burp (souvent intégrée à l'URL). | *(vide)* |

### 1.10 Build-time (image)

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_TOOLS_PROFILE` | `--build-arg` : `full` (httpx/nuclei/subfinder vérifiés SHA256 + moteur PDF weasyprint) ou `mini` (les omet). | `full` | `mini` |

Voir [Installation §1](INSTALLATION.md#1-profils-dimage--mini-vs-full).

---

## 2. Table `settings` (configurée dans l'UI, ledgerisée)

Clés de la table SQLite `settings`, mutées via l'API (admin) ou le wizard. **Aucune valeur codée en
dur** : une clé absente = comportement par défaut, jamais une valeur inventée.

| Clé | Sens | Défaut | Écrite par |
|---|---|---|---|
| `detection_source` | Objet `DetectionSource` (source de la boucle purple). Secret d'auth **write-only** (jamais renvoyé). | *(absente = purple OFF, fail-open lisible)* | wizard · `POST /api/detection/source` · `POST /api/setup` |
| `operator_policy` | Politique du rôle opérateur (C2). Champ clé : `source_cidrs` (allowlist d'IP client). Absent/vide = **aucune restriction** source. | *(absente)* | wizard · `POST /api/setup` |
| `backup_policy` | Politique de sauvegarde programmée/offsite (`enabled`, `interval_secs`, `retention`, `passphrase_env`, `staging_dir`, `offsite`). Secrets rédigés au GET. | *(absente = aucune sauvegarde programmée)* | `POST /api/backup/policy` |
| `backup_last_run` | Horodatage interne du dernier tick de sauvegarde dû (état du scheduler). | *(absente)* | scheduler (interne) |
| `session_ttl` | TTL de session **persistée** par le wizard/setup (substrat de config). La durée **effective** est pilotée par `FORGE_CONSOLE_SESSION_TTL` (§1.1). | *(absente)* | `POST /api/setup` |
| `trusted_proxy` | CIDR(s) du/des proxy(ies) amont de confiance. Un `X-Forwarded-For` n'est honoré **que** si le pair TCP tombe dans l'un d'eux ; sinon repli **fail-closed** sur le pair TCP. Une valeur non-CIDR ⇒ XFF ignoré. | *(absente = XFF non honoré)* | admin (settings) |

### Gouvernance des modules (table `module`)

Distincte de `settings` : la table `module` porte le **catalogue** (peuplé au boot depuis `forge
modules`) **et** la gouvernance par connecteur, mutée par `POST /api/modules/:kind` (admin,
ledgerisé) :

| Champ | Sens | Effet |
|---|---|---|
| `enabled` (bool) | Connecteur activé/désactivé. | `enabled=false` ⇒ SKIP au tir (comme un outil absent), **même si le binaire est présent**. |
| `web_allowed` (bool) | Le connecteur peut être lancé depuis le web (C2-light). | Contrôle le plancher `web_allowed` des modules sélectionnables via `/api/run`. |
| `available_override` (bool\|null) | Force/efface l'état de disponibilité affiché (3 états : inchangé / effacé / forcé). | Reflète la disponibilité dans l'UI. |

Voir [Administration → Gouvernance des connecteurs](ADMINISTRATION.md#3-gouvernance-des-connecteurs-installerdésinstaller).

---

## 3. Qu'est-ce qui est configurable où ?

| Réglage | Au déploiement (env) | Dans l'UI (settings) |
|---|:---:|:---:|
| Bind, chemins d'état, TTL session | ✅ | — |
| Secrets d'amorçage (token, hash viewer/opérateur) | ✅ | (comptes créés via UI/CLI ensuite) |
| Admin & comptes individuels | (amorçage) | ✅ (wizard + *Administration → Comptes*) |
| Source de détection (purple) | ✅ (legacy `PLUME_*`/`FORGE_DETECTION_SOURCE`) | ✅ **recommandé** (`detection_source`) |
| Politique opérateur (source-CIDR) | — | ✅ (`operator_policy`) |
| Politique de sauvegarde (schedule/offsite) | (2 knobs : tick, passphrase env) | ✅ (`backup_policy`) |
| Gouvernance des connecteurs | — | ✅ (`module`) |
| Chiffrement au repos | ✅ (image `encryption` + `FORGE_DB_KEY`) | (reflété : `capabilities.sqlcipher`) |
| Proxy de confiance (XFF) | — | ✅ (`trusted_proxy`) |

Le **provisioning headless** (sans navigateur) est possible : poser `FORGE_CONSOLE_PASS_HASH` /
`FORGE_CONSOLE_OPERATOR_HASH` / `FORGE_CONSOLE_TOKEN` — l'état de setup bascule alors `provisioned:true`
sans wizard. Voir [Premier déploiement](FIRST_DEPLOYMENT.md).

# Forge — Déploiement self-service (runbook) & empreinte

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Installation](INSTALLATION.md) ·
> [Premier déploiement (wizard)](FIRST_DEPLOYMENT.md) · [Configuration](CONFIGURATION.md) ·
> [**Upgrade / migration / backup (runbook)**](UPGRADE.md)

> **Usage AUTORISÉ uniquement.** Forge reste **INERTE par défaut** (`in_scope` vide = tout refusé).
> Rien de ce runbook n'arme quoi que ce soit : l'opérateur arme chaque couche consciemment (cf. la
> gate ROE à 4 couches dans le [README](../README.md)).

Ce document est le **runbook self-deploy bout-en-bout** pour un client frais : choisir une image,
la lancer, provisionner l'install **depuis le navigateur** (wizard — **rien de codé en dur**),
migrer d'éventuelles données existantes, et mettre en place des **sauvegardes chiffrées
programmées**. La deuxième moitié conserve l'**empreinte mesurée** et la matrice de déploiement.

**Table des matières**

1. [Options de build & run](#1-options-de-build--run) — mini/full, Docker, docker-compose, natif/systemd, image `encryption`
2. [Premier boot — le wizard web](#2-premier-boot--le-wizard-web) — admin, crypto, source de détection, politique opérateur
3. [Données — migration & sauvegardes chiffrées](#3-données--migration--sauvegardes-chiffrées)
4. [Contexte de build & dépendance `guatx-core`](#4-contexte-de-build--dépendance-guatx-core)
5. [Liveness `/health` & en-tête `Host`](#5-liveness-health--en-tête-host)
6. [Empreinte mesurée & matrice de déploiement](#6-empreinte-mesurée--matrice-de-déploiement) *(référence)*

---

## 1. Options de build & run

> ⚠️ **Contexte de build = le dossier PARENT `GUATX/`**, pas `forge/` (la console dépend du crate
> sibling `guatx-core` en `path`). Toutes les commandes `docker build`/`docker compose` ci-dessous
> se lancent **depuis `GUATX/`**. Détail + migration future en [§4](#4-contexte-de-build--dépendance-guatx-core).

### 1.0 Pré-étape OBLIGATOIRE — le fichier scope (fail-loud)

Le scope/ROE actif est **monté en volume**, jamais cuit dans l'image. Créer le **fichier** avant tout `up` :

```sh
cd GUATX/forge
cp scope.example.json scope.json          # in_scope vide = INERTE ; éditer AVEC AUTORISATION écrite
```

Si `scope.json` est absent, Docker crée un **répertoire** vide à sa place : l'entrypoint compose
**échoue bruyamment** (message explicite) plutôt que de démarrer sur un scope illisible. Absent/vide
sans répertoire ⇒ repli sur `scope.example.json` embarqué (INERTE). `scope.json` reste gitignoré.

### 1.1 Profils d'image : `mini` vs `full`

Un seul `--build-arg FORGE_TOOLS_PROFILE` bascule l'empreinte. Les modules **dégradent proprement**
(`available:false`) quand un outil manque — aucune erreur, c'est géré par l'engine.

| Profil | Contenu | Poids | `?format=pdf` | Modules PD (httpx/nuclei/subfinder) |
|---|---|---|---|---|
| `mini` | console + `python3` + `nmap` | **~150-250 MB** | `pdf_unavailable` (impression navigateur) | `available:false` |
| `full` *(défaut)* | + binaires ProjectDiscovery (vérifiés SHA256) + moteur PDF weasyprint | **~350-500 MB** | actif clé-en-main | disponibles |

### 1.2 Docker (image seule)

```sh
cd GUATX
# full (défaut)
docker build -f forge/Dockerfile -t forge:0.0.1 .
# mini
docker build --build-arg FORGE_TOOLS_PROFILE=mini -f forge/Dockerfile -t forge:0.0.1-mini .

docker run -d --name forge \
  -p 127.0.0.1:7100:7100 \
  -v forge-db:/data/db -v forge-ledger:/data/ledger \
  -v "$PWD/forge/scope.json:/data/scope/scope.json:ro" \
  --env-file forge/.env \
  forge:0.0.1
```

> Bind **loopback uniquement** (`127.0.0.1:7100`). N'exposer publiquement qu'à travers un
> reverse-proxy + auth + `FORGE_CONSOLE_HOST` (host-allowlist anti-DNS-rebinding) — cf. [§5](#5-liveness-health--en-tête-host).

### 1.3 docker-compose *(recommandé)*

Le compose fixe déjà le bon contexte, le fail-loud du scope, les volumes, le healthcheck `/health`
et le bind loopback. **Services optionnels derrière des profils** ⇒ un `up` nu démarre la **console seule**.

```sh
cd GUATX
docker compose -f forge/docker-compose.yml up -d --build          # console SEULE (profil full par défaut)
FORGE_TOOLS_PROFILE=mini docker compose -f forge/docker-compose.yml up -d --build   # console SEULE, image mini

# couches optionnelles, à la demande (aucune n'est requise au boot) :
docker compose -f forge/docker-compose.yml --profile browser up -d        # + accès/évasion (Camoufox :8080)
docker compose -f forge/docker-compose.yml --profile msf --profile burp up -d   # + connecteurs (BYO images)

docker compose -f forge/docker-compose.yml config      # valider la configuration résolue
```

Secrets & overrides (hashes argon2id, tokens, URLs des services pilotés, clés) → `forge/.env`
(gitignoré, `required:false`). Gabarit commenté : [`.env.example`](../.env.example). Les connecteurs
`browser`/`msf`/`burp` restent **inertes** tant que leur service n'est pas joignable (sonde à fire-time).

### 1.4 Natif / systemd (sans Docker)

Unité durcie fournie : [`deploy/forge.service`](../deploy/forge.service)
(`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`, seccomp `@system-service`…).
Le durcissement systemd **n'affaiblit aucun garde-fou applicatif**, il renforce l'isolation du process.

```sh
cd GUATX/forge/console && cargo build --release            # binaire offline depuis le cache cargo
sudo install -m0755 target/release/forge /usr/local/bin/
sudo mkdir -p /opt/forge && sudo cp -r ../forge /opt/forge/forge && sudo cp -r web /opt/forge/console/web
sudo useradd --system --home /opt/forge --shell /usr/sbin/nologin forge
sudo mkdir -p /var/lib/forge/{db,ledger,scope}                      # remplir scope/scope.json AVEC AUTORISATION
sudo install -m0600 -o root -g forge /dev/null /etc/forge/forge.env   # y mettre les hashes argon2id
sudo cp deploy/forge.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now forge
```

Le package Python est **pur-stdlib** (`deps=[]`) : il tient aussi en venv **sans aucune dépendance pip**.

### 1.5 Image `encryption` (chiffrement AU REPOS — SQLCipher, opt-in)

Le build **par défaut** stocke la base SQLite **en clair** (`capabilities.sqlcipher:false`). Pour un
chiffrement au repos, compiler la console avec la feature `encryption` puis fournir la clé au boot :

```sh
# 1) image chiffrée (feature Cargo -> backend crypto SQLCipher)
cd GUATX/forge/console && cargo build --release --features encryption
#    (Docker : construire une image taguée forge:0.0.1-encryption avec cette feature)

# 2) au boot, la console lit FORGE_DB_KEY et émet `PRAGMA key` AVANT toute requête (contrat SQLCipher)
#    extrait docker-compose.override.yml :
#      services:
#        forge:
#          image: forge:0.0.1-encryption
#          environment:
#            FORGE_DB_KEY: ${FORGE_DB_KEY}     # [SECRET] depuis .env/docker secret, JAMAIS commité
```

Sans `FORGE_DB_KEY` correcte, la base chiffrée est **illisible** (fail-closed). Convertir un install
existant en clair → chiffré = **Runbook B** de [`docs/MIGRATION.md`](MIGRATION.md). Le wizard expose
`capabilities.sqlcipher` (true seulement sur ce build) pour que l'UI le reflète honnêtement.

> **À part** la crypto AU REPOS (opt-in), le **ledger d'engagement** est signé **Ed25519** (asymétrique,
> vérifiable par un tiers avec la seule clé publique) **par défaut** — aucune action requise.

---

## 2. Premier boot — le wizard web

**Rien n'est codé en dur.** Une install fraîche n'a **aucun admin, aucun scope réel, aucune source de
détection** : tout se provisionne **depuis le navigateur** au premier accès.

1. Ouvrir **`http://127.0.0.1:7100`** (ou l'URL du reverse-proxy). Le SPA appelle `GET /api/setup/state` :
   - `needs_setup:true` ⇒ le **wizard** s'affiche ;
   - `capabilities.sqlcipher` ⇒ l'UI sait si le chiffrement au repos est disponible (image `encryption`).
2. **Le wizard `POST /api/setup`** (route **PUBLIQUE mais auto-désactivante** : `409` dès qu'un admin
   existe). Champs — seul l'admin est requis, **le reste n'est persisté que s'il est fourni** :
   - **Créer l'admin** (`admin_login` + `admin_password`) → hash **argon2id**, rôle `admin`. Le mot de
     passe/hash n'est **jamais** journalisé ni ledgerisé. Le navigateur **atterrit connecté** (cookie
     `forge_session`, HttpOnly/SameSite=Strict).
   - **Crypto** — le ledger est déjà signé **Ed25519** automatiquement ; le chiffrement **au repos**
     dépend de l'image (`encryption`, cf. [§1.5](#15-image-encryption-chiffrement-au-repos--sqlcipher-opt-in)),
     surfacé via `capabilities.sqlcipher`.
   - **Source de détection = LEUR infra** (`detection_source`, optionnel) — plugin **configurable, sans
     code** : FortiGate/pfSense/OPNsense/CrowdSec/Elastic/OpenSearch/fichier/exec… Modèle, préréglages
     et mapping MITRE : **[`docs/DETECTION.md`](DETECTION.md)**. Réglable aussi plus tard dans
     *Administration → Source de détection*. Le secret d'auth est **write-only** (jamais renvoyé/loggé).
   - **Politique opérateur** (`operator_policy`, optionnel) — gouverne le rôle **opérateur/C2** (RBAC) ;
     vide = C2 **fermé** (fail-closed). `session_ttl` optionnel.
3. La gate d'auth **s'engage** dès qu'un admin activé existe (l'état DB fait autorité). `/api/setup`
   se ferme définitivement.

**Provisioning headless** (sans navigateur) : poser `FORGE_CONSOLE_PASS_HASH` /
`FORGE_CONSOLE_OPERATOR_HASH` (hashes argon2id via `forge hashpw` / `hashpw-operator`) et
`FORGE_CONSOLE_TOKEN` dans `.env`/l'EnvironmentFile — l'`state` bascule alors `provisioned:true` sans wizard.

**RBAC/administration après boot** : gestion des comptes via `/api/users` (admin) ; **Basic** = viewer
(lecture), **Bearer token** = agent/admin (écriture d'ingestion), rôle **opérateur** pour le C2 gouverné.
Toutes les routes (sauf `/health`) sont derrière **host-guard** (anti-rebinding) + **auth-guard**.

---

## 3. Données — migration & sauvegardes chiffrées

### 3.1 Migrer un install existant

Reprendre un install **systemd/bare-metal** vers Docker (ou toute cible) **sans perdre l'audit**. Trois
artefacts **couplés** voyagent ensemble : la base SQLite, le ledger `engagement.jsonl`, **et sa clé de
signature `.ed25519`** (sinon la chaîne signée devient invérifiable). Runbook complet + garde-fous :
**[`docs/MIGRATION.md`](MIGRATION.md)**.

```sh
# UX primaire : conteneur one-shot au 1er déploiement (source ouverte READ-ONLY, jamais mutée)
docker run --rm \
  -v /ancien/forge:/import:ro -v forge-db:/data/db -v forge-ledger:/data/ledger \
  forge:0.0.1 \
  forge migrate --from /import --to /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl --verify
# chiffrer au passage (image `encryption`) : ... --encrypt --key-env FORGE_DB_KEY   (clé via ENV, jamais argv)
```

Le wizard propose aussi un **import pré-provision** (`POST /api/setup/migrate`), **opt-in** et réservé
au pré-déploiement (désactivé par défaut : `FORGE_ALLOW_API_MIGRATE` + `FORGE_CONSOLE_IMPORT_DIR`) ; la
voie CLI ci-dessus reste l'UX documentée.

**Mettre à jour une console DÉJÀ déployée** (bump de schéma après un `docker pull` d'une image plus
récente) → **une seule commande fail-closed** `forge upgrade` : snapshot pré-upgrade **chiffré** →
`migrate` additif → vérif schéma/ledger/santé → **rollback automatique** au moindre échec. Voir le runbook
dédié **[`docs/UPGRADE.md`](UPGRADE.md)** (SQLite solo, Postgres, HA rolling-upgrade, drill de restore).
La version de schéma est visible via `forge status` et le champ `schema_version` de `/health`.

### 3.2 Sauvegardes chiffrées + programmation + offsite

L'archive de sauvegarde est **TOUJOURS chiffrée** (argon2id + **XChaCha20-Poly1305**, pur Rust) — il
n'existe **aucun chemin en clair**, car elle embarque **la clé de signature ET la base**. Format,
restauration, garde-fous et expédition offsite : **[`docs/BACKUP.md`](BACKUP.md)**.

- **Politique** (activation / intervalle / rétention / offsite `rclone`|`exec`) : réglée dans
  *Administration → Sauvegarde* ou `POST /api/backup/policy` — **rien de codé en dur**. Le nom d'ENV
  portant la passphrase est référencé par `policy.passphrase_env` (jamais la passphrase en clair en DB).
- **Scheduler en-console** (fail-open : un échec est loggé + ledgerisé, ne crashe jamais la console),
  piloté par 2 knobs d'environnement :

| Variable | Rôle | Défaut |
|---|---|---|
| `FORGE_BACKUP_TICK_SECS` | période de réveil du scheduler | `60` s |
| `FORGE_BACKUP_PASSPHRASE` | **[SECRET]** passphrase (nom d'ENV référencé par `policy.passphrase_env`) | — |

Restauration : `POST /api/restore` (ou CLI), passphrase obligatoire (fail-closed), manifeste `sha256`
re-vérifié, clé `.ed25519` replacée en `0600`.

### 3.3 Object-store S3/MinIO pour artefacts (offsite `s3`) — feature Cargo `object-store` (OPT-IN)

Le stockage d'artefacts (archive de backup offsite, exports/évidence) passe par un **seam BlobStore**
backend-agnostique (`console/src/blob.rs`). Le build **PAR DÉFAUT (community)** ne compile que
`LocalFsBlobStore` (**système de fichiers**, aucune dépendance nouvelle) : le chemin par défaut (aucun
artefact S3 configuré) est **inchangé**. L'implémentation **S3/MinIO** (`S3BlobStore`) et sa dépendance
`rust-s3` vivent **derrière la feature Cargo `object-store`** (OFF par défaut). La feature est
**openssl-free** : `rust-s3` en `sync-rustls-tls` → TLS via **rustls** (provider `ring`) + `attohttpc`,
**jamais** native-tls/openssl. Le build community (feature OFF) ne pull **aucune** dép S3 et reste
byte-identique.

**Sélection runtime** : `S3BlobStore` est choisi **uniquement** si la feature est compilée **ET** l'ENV
S3 est configuré ; sinon `LocalFsBlobStore` (racine `FORGE_BLOB_DIR`, défaut `blobs/` sibling de la base).

| Variable | Rôle | Défaut |
|---|---|---|
| `FORGE_BLOB_DIR` | racine du store local (feature OFF **ou** S3 non configuré) | `blobs/` sibling de la base |
| `FORGE_BLOB_S3_ENDPOINT` | endpoint S3/MinIO (ex. `http://minio:9000`) — **requis** pour S3 | — |
| `FORGE_BLOB_S3_BUCKET` | bucket cible — **requis** pour S3 | — |
| `FORGE_BLOB_S3_ACCESS_KEY` | **[SECRET]** access key — **requis** pour S3 | — |
| `FORGE_BLOB_S3_SECRET_KEY` | **[SECRET]** secret key — **requis** pour S3 | — |
| `FORGE_BLOB_S3_REGION` | région SigV4 (MinIO l'ignore mais SigV4 l'exige) | `us-east-1` |

Adressage **path-style** forcé (compatible MinIO). Les credentials vivent **uniquement dans l'ENV** —
jamais en base, jamais dans la politique de backup, jamais journalisés/ledgerisés (les traces ne portent
que `backend`/`bucket`/`key`/`url`).

**Backup offsite `s3`** : sous la feature, la politique de backup accepte `offsite.kind = "s3"` (préfixe
de clé optionnel `key_prefix`). Le scheduler PUT l'archive **chiffrée** vers le bucket S3, référencée par
clé/URL — trace `console.backup.offsite` (kind + statut, aucun secret). Exemple de politique :

```jsonc
POST /api/backup/policy
{ "enabled": true, "interval_secs": 86400, "retention": 7,
  "passphrase_env": "FORGE_BACKUP_PASSPHRASE",
  "offsite": { "kind": "s3", "key_prefix": "offsite/backups" } }
```

**Build & validation (round-trip MinIO)** :

```bash
cd console && cargo build --release --features object-store   # (Docker : --build-arg FORGE_CARGO_FEATURES=object-store)

# MinIO de test + bucket
docker run -d --rm -e MINIO_ROOT_USER=forge -e MINIO_ROOT_PASSWORD=forgepw123 \
    -p 9000:9000 --name forge-minio minio/minio server /data
docker run --rm --network host --entrypoint sh minio/mc -c \
    'mc alias set l http://localhost:9000 forge forgepw123 && mc mb l/forge-artifacts'

export FORGE_BLOB_S3_ENDPOINT=http://localhost:9000 FORGE_BLOB_S3_BUCKET=forge-artifacts \
       FORGE_BLOB_S3_ACCESS_KEY=forge FORGE_BLOB_S3_SECRET_KEY=forgepw123
# round-trip PUT→GET→EXISTS→DELETE sur le store actif (S3 ici, sinon local)
forge blob-selftest --key evidence/proof.bin
# expédie un artefact RÉEL (archive de backup chiffrée) via le producteur offsite câblé, puis GET-vérifie
forge blob-selftest --file ./mon-archive.forge --key-prefix offsite/backups
```

Feature OFF (défaut), la sous-commande `blob-selftest` n'existe pas et seul le store local est disponible.

---

## 3bis. Backend Postgres (Stage 4 — HA / multi-instance)

Le backend PAR DÉFAUT est **SQLite** (fichier local, zéro dépendance) — **inchangé**. Un backend
**Postgres** OPT-IN existe derrière la feature Cargo `store-postgres` : plusieurs instances **console
stateless** peuvent partager **UNE** base Postgres. Le backend PG est **openssl-free** (TLS `rustls` +
provider `ring`, jamais native-tls/openssl) ; le build community (feature OFF) ne compile **aucune** dép
Postgres et reste byte-identique.

### 3bis.1 Build & run avec Postgres

Deux réglages runtime pilotent la sélection (gate **FAIL-CLOSED**) :

| Variable | Rôle |
|---|---|
| `FORGE_ENTERPRISE_STORE=postgres` | sélectionne le backend Postgres (sinon SQLite) |
| `FORGE_DB_URL` | DSN `postgres://user:pass@host:5432/db` — **requis** si `…=postgres` (sinon refus de démarrer) |

La feature doit être **compilée** dans le binaire (`FORGE_ENTERPRISE_STORE=postgres` sur un binaire
community échoue au boot avec un message clair « rebuild with `--features store-postgres` »).

```sh
# Natif : build feature (openssl-free) puis run
cd console && cargo build --release --features store-postgres
FORGE_ENTERPRISE_STORE=postgres \
FORGE_DB_URL='postgres://forge:forge@db.internal:5432/forge' \
  ./target/release/forge
```

**docker-compose** — un override ADDITIF (`docker-compose.postgres.yml`) recompile l'image avec la
feature (`--build-arg FORGE_CARGO_FEATURES=store-postgres`, qui installe aussi `pg_dump`/`pg_restore`
dans l'image) et démarre un service `postgres:16` (profil `postgres`). Le déploiement SQLite par défaut
(`docker-compose.yml` seul) reste **inchangé** :

```sh
# depuis GUATX/ (contexte de build = parent, cf. §4) — profil postgres + override
docker compose -f forge/docker-compose.yml -f forge/docker-compose.postgres.yml \
               --profile postgres up -d --build
```

Credentials par défaut d'ÉVAL (`forge/forge`) — **surcharger** en prod via `forge/.env`
(`FORGE_PG_USER`/`FORGE_PG_PASSWORD`/`FORGE_PG_DB`, repris à la fois par le service `postgres` et par
`FORGE_DB_URL`). Ne **jamais** publier le port Postgres publiquement (le service reste `expose:`-only sur
le réseau compose).

### 3bis.2 Migrer les données SQLite → Postgres (Stage 3, gouverné)

Si tu as déjà des données SQLite à conserver, migre-les **AVANT** le 1er run Postgres avec le migrateur
gouverné (copie table par table en ordre FK, recalage des séquences IDENTITY, **vérification des comptes
ligne à ligne** avec ROLLBACK sur écart, **checkpoint ledger signé**) :

```sh
# dry-run d'abord (n'écrit RIEN) — inspecte ce qui SERAIT copié
forge migrate-store --to 'postgres://forge:forge@postgres:5432/forge' \
  --from /data/db/forge.db --ledger /data/ledger/engagement.jsonl --dry-run
# puis la vraie migration (--force pour écraser une cible non vide)
forge migrate-store --to 'postgres://forge:forge@postgres:5432/forge' \
  --from /data/db/forge.db --ledger /data/ledger/engagement.jsonl
```

Codes de sortie : `0` OK · `1` refus de gouvernance (cible non vide sans `--force`) ou écart de comptes
(rollback) · `2` usage/connexion/schéma · **`3` migration committée mais checkpoint ledger non écrit**
(gouvernance : une migration sans son checkpoint tamper-evident ne rapporte **jamais** un succès — à
traiter comme un échec, ré-émettre le checkpoint). En Docker, lancer via un conteneur one-shot
`run --rm --entrypoint forge … migrate-store …` (cf. `docker-compose.postgres.yml`).

### 3bis.3 Sauvegarde & restauration Postgres (`pg_dump`)

Sous un backend Postgres actif, `forge backup` (CLI / `POST /api/backup` / scheduler) sauvegarde
**Postgres** — plus le fichier SQLite (qui serait **vide**). L'artefact `db` de l'archive chiffrée est un
dump **`pg_dump -Fc`** (format custom, compressé, **restaurable via `pg_restore`**), sous l'entrée
`db.pgdump` (le manifeste porte `db_format: "pgdump"`). `pg_dump` est invoqué en **argv fixe (no-shell)**
et les credentials du DSN sont **rédigés** dans les logs/le ledger. **Si `pg_dump` est absent** du PATH,
la sauvegarde **échoue avec un message clair** (jamais de repli silencieux sur un SQLite vide) — d'où
`postgresql-client` dans l'image PG.

Le reste de la chaîne est **inchangé** : archive **toujours chiffrée** (argon2id + XChaCha20-Poly1305),
ledger + clé `.ed25519` inclus, chaîne du ledger vérifiée avant/après.

**Restauration Postgres** (manuelle, hors console) — extraire `db.pgdump` de l'archive déchiffrée puis :

```sh
# 1) déchiffrer l'archive (POST /api/restore apply=false, ou l'outil de restore) et extraire db.pgdump
# 2) restaurer dans une base cible avec pg_restore (custom format)
createdb -h HOST -U forge forge_restored
pg_restore -h HOST -U forge -d forge_restored --no-owner db.pgdump
# vérifier : pg_restore --list db.pgdump  (liste les TABLE DATA — dump non trivial + restorable)
```

> Le **swap-en-place** de `POST /api/restore apply=true` reste SQLite-only (il remplace le fichier
> local). Sous Postgres, la restauration se fait via `pg_restore` ci-dessus (le dump est un artefact PG
> standard). Le `restore` CLI SQLite n'est **pas** le chemin PG.

### 3bis.4 Liveness `/health` sous PG

`/health` (§5) **ping le store ACTIF** : sous PG il fait un `SELECT 1` **à travers le backend** (donc via
le **reconnect+retry** HA — voir 3bis.5). Champ **additif `db`** : `"ok"` si le ping passe, `"degraded"`
si la base est injoignable. La sonde reste **rapide et non-fatale** : `/health` répond **toujours 200**
(liveness du routeur HTTP) même en `degraded`, donc le `HEALTHCHECK` (qui ne teste que le code 200)
n'oscille pas sur une coupure DB transitoire — mais un superviseur peut lire `db` pour alerter.

### 3bis.5 HA / multi-instance — ce qui est turnkey et ce qui NE l'est PAS

**Turnkey** : `N` instances console **stateless** contre **UNE** base Postgres partagée. Chaque instance
détient un **client session-pinné** ; sur une coupure (restart/failover Postgres) une opération du store
qui échoue avec une **erreur de connexion** **se RECONNECTE une fois puis REJOUE** l'opération
(reconnect au grain d'une opération — jamais au milieu d'une transaction ; une paire
`INSERT`+`last_insert_id` ne peut pas chevaucher un reconnect). Le seam PG partage la même **granularité
de verrou** que SQLite.

**PAS turnkey — contraintes réelles à connaître (soyons honnêtes) :**

- **Le ledger tamper-evident est un FICHIER (`engagement.jsonl`), pas dans Postgres.** Le multi-instance
  exige donc soit un **stockage partagé** pour ce fichier (volume RWX / NFS — attention aux appends
  concurrents : la console sérialise ses propres appends sous un verrou **par instance**, ce qui ne
  couvre **pas** deux instances écrivant le **même** fichier en parallèle), soit **un ledger par
  instance** (chaînes séparées, à agréger à la lecture). Il n'y a **pas** de ledger partagé
  transactionnel « clé en main ». Pour un vrai multi-writer, préférer **un ledger par instance** (chaque
  chaîne reste vérifiable indépendamment) plutôt qu'un fichier partagé exposé aux appends concourants.
- **Caches en mémoire par instance / éventuellement cohérents.** Plusieurs caches sont **locaux** à
  chaque process et **recalculés au boot / après une mutation faite PAR CETTE instance** :
  `detection_config` (source de détection), `auth_required` (gate d'auth engagée), le **head du ledger**
  (`prev`/`seq`). Une mutation faite via l'**instance A** (ex. changer la source de détection, créer un
  compte) n'invalide **pas** le cache de l'**instance B** tant que B ne re-boote pas / ne refait pas
  l'action → fenêtre d'**éventuelle cohérence**. La **donnée** (table `settings`/`users`…) est cohérente
  dans Postgres immédiatement ; c'est le **cache** qui traîne. Sûr pour la lecture (fail-open lisible),
  mais ne comptez pas sur une propagation inter-instances instantanée des réglages d'admin.
- **Sticky sessions recommandées** : les caches par instance + le head ledger par instance rendent un
  routage **collant** (une session admin → toujours la même instance) plus prévisible qu'un round-robin
  pur.

En résumé : **scale-out en lecture/exécution contre un Postgres partagé = OK** ; l'audit-ledger partagé
et la propagation instantanée des réglages d'admin **ne sont pas** automatiques — dimensionner en
conséquence (ledger par instance, ou stockage partagé assumé ; réglages d'admin propagés au reboot).

### 3bis.6 HA sur Kubernetes — manifests `k8s/` (readiness-dossier #13)

Les manifests HA vivent dans **`k8s/`** (à la racine du repo) et matérialisent la topologie Wave A/B/C
ci-dessus sur Kubernetes : **console à N réplicas** contre **un Postgres partagé**, MinIO/S3 pour les
artefacts, Ingress collant pour les flux SSE, et — le cœur du #13 — des **NetworkPolicies deny-by-default
est-ouest**. C'est le pendant k8s du harnais `docker-compose.ha.yml` + `Caddyfile`. Cette section
**REMPLACE** l'ancienne note « k3s / k8s single-replica » (voir §5 « Contrainte d'archi ») pour le cas HA.

**Appliquer.**

```sh
# 1) Construire l'image AVEC le backend Postgres (+ object-store si artefacts S3) — l'image community
#    SQLite par défaut FAIL-CLOSE sous FORGE_HA=1.
docker build -f Dockerfile \
  --build-arg FORGE_CARGO_FEATURES="store-postgres object-store" \
  -t <registry>/forge:0.0.1 ..        # contexte = parent GUATX/ (inclut core/ + forge/)
docker push <registry>/forge:0.0.1

# 2) Régler l'image dans k8s/40-console.yaml (et le host réel dans k8s/50-ingress.yaml +
#    FORGE_CONSOLE_HOST dans k8s/11-config.yaml).

# 3) PROD : NE PAS appliquer k8s/10-secrets.example.yaml (placeholders d'ÉVAL). Provisionner les 3
#    Secrets (forge-db, forge-auth, forge-objectstore) hors-bande (SealedSecrets/ExternalSecrets/
#    SOPS), retirer la ligne du kustomization.yaml, puis :
kubectl apply -k k8s/                          # namespace + config + PG + MinIO + console + ingress + netpol
# (lab : appliquer tel quel — les Secrets d'éval bootent le cluster de test.)
```

Validé par **`kubeconform -strict`** (20 ressources, 0 invalide) et `kubectl kustomize k8s/`.

**Contrat env de la console (= Wave A/B/C).** `k8s/40-console.yaml` reproduit exactement le contrat des
overrides compose :

| Variable | Source k8s | Rôle |
|---|---|---|
| `FORGE_HA=1` | ConfigMap | engage HA — boot FAIL-CLOSED si le store actif ≠ Postgres |
| `FORGE_ENTERPRISE_STORE=postgres` | ConfigMap | sélectionne le backend PG (exige `FORGE_DB_URL`) |
| `FORGE_DB_URL` | **Secret** `forge-db` | DSN Postgres partagé |
| `FORGE_INSTANCE_ID` | **`fieldRef: metadata.name`** | identité d'instance = **nom du pod** (unique par réplica → clé du bail leader). Une valeur statique collisionnerait — d'où le `fieldRef`, équivalent k8s du fallback HOSTNAME de compose |
| `FORGE_CONSOLE_ADDR=0.0.0.0:7100` | ConfigMap | bind interne au pod (jamais public — Service + Ingress + NetworkPolicy devant) |
| `FORGE_CONSOLE_HOST` | ConfigMap | allowlist Host anti-DNS-rebinding — DOIT inclure le host public de l'Ingress + les noms de Service |
| `FORGE_CONSOLE_TOKEN` / `_PASS_HASH` / `_OPERATOR_HASH` | **Secret** `forge-auth` | bearer d'ingestion + hashes argon2id (stables entre réplicas) |
| `FORGE_BLOB_S3_*` | ConfigMap (endpoint/bucket) + **Secret** `forge-objectstore` (clés) | object-store artefacts, actif seulement si l'image est buildée `--features object-store` |
| `FORGE_CONSOLE_DB` | ConfigMap → `emptyDir` | fallback SQLite **local au pod** (inutilisé sous PG) — jamais sur le volume partagé |

**Élection du leader — pas de worker séparé.** Les réplicas sont identiques. Ils **auto-élisent un unique
run-leader** via le bail single-row `leader_lease` (`scope='run-worker'`, TTL 45 s) dans le Postgres
partagé : le leader exécute les engagements (one-run-per-engagement, fencé en DB), les autres servent
UI/API et **reprennent le bail** à son expiration. `leader`/`instance_id` sont publiés sur `GET /health`.
**Aucun Deployment worker distinct n'est nécessaire** — scaler `replicas` suffit.

**Sondes.** `readinessProbe`/`livenessProbe` = `GET /health` sur 7100, avec **`Host: localhost`** en
en-tête (dans l'allowlist par défaut) — sinon kubelet enverrait `Host: <podIP>` → 421 → faux unhealthy.
`/health` répond **toujours 200** quand le routeur HTTP est vivant (`db:"degraded"` sur coupure DB
transitoire, sans faire flapper la sonde).

**Ledger partagé RWX — le choix à faire (RWX vs object-store vs ledger-par-instance).** Le ledger
tamper-evident est un **fichier** (`engagement.jsonl`), pas une table Postgres. `k8s/40-console.yaml` le
place sur un **PVC `ReadWriteMany`** monté par tous les réplicas — ce qui **exige une StorageClass RWX**
(NFS / CephFS / EFS / Azure Files / Filestore). Les volumes bloc classiques (**RWO** : EBS, GCE-PD, la
plupart des CSI par défaut) **ne satisfont pas** RWX et le 2ᵉ réplica ne schedulera pas. Trois options,
par ordre de robustesse d'audit :

1. **Ledger par instance** (recommandé pour un vrai multi-writer) — chaque réplica écrit **sa propre**
   chaîne (StatefulSet + PVC RWO par pod) ; chaque chaîne reste vérifiable indépendamment, agrégée à la
   lecture. Pas d'appends concourants sur un même fichier. *(Le manifeste fourni utilise un Deployment +
   PVC RWX partagé pour rester turnkey ; migrer vers un StatefulSet par-instance si l'audit strict
   l'impose.)*
2. **PVC RWX partagé** (fourni) — un seul `engagement.jsonl` pour tous. La console **sérialise ses propres
   appends par instance** ; ce verrou **ne couvre pas** deux instances écrivant le même fichier en
   parallèle → accepter la mise en garde « appends concourants » ou router de façon collante.
3. **Object-store pour les artefacts** — les **évidences/exports/backups** (pas le ledger lui-même) vont
   sur MinIO/S3 via le seam `object-store` (`FORGE_BLOB_S3_*`), déchargeant le volume partagé du gros
   binaire. Orthogonal au choix ledger : combinable avec (1) ou (2).

**Clé de signature du ledger — HORS du volume partagé (audit F1).** ⚠️ Le PVC RWX `forge-ledger` ne doit
porter que la **projection JSONL** du ledger (`engagement.jsonl` + high-water-mark), **jamais la clé de
signature**. Par défaut le signeur **local** écrit sa **clé privée** Ed25519 en `<ledger>.ed25519` (0600)
**à côté** du ledger — donc **sur ce volume partagé**, où le `0600` n'est **pas** une frontière
d'isolation : tout pod/sidecar montant le même PVC, ou un **snapshot** du PVC, lit la clé privée brute (→
forge d'entrées de ledger). Acceptable en mono-tenant lab ; **pas** en HA/multi-tenant. Deux patterns
supportés, opt-in (les deux préservent `runAsNonRoot`/`readOnlyRootFilesystem` + les NetworkPolicies
deny-by-default ; leurs Secrets ne sont **pas** dans le `kubectl apply -k k8s/` par défaut) :

1. **(préféré) Signeur off-host PKCS#11** (`FORGE_LEDGER_SIGNER=pkcs11`) — la clé vit sur un HSM/token et
   ne touche **aucun** volume de pod. Bloc env opt-in dans `k8s/40-console.yaml` ; module + PIN via le
   Secret `forge-ledger-pkcs11`.
2. **(repli) Clé en Secret monté read-only** — pré-générer la clé Ed25519 hors-bande, la fournir via le
   Secret dédié `forge-ledger-key` **monté en lecture seule**, et pointer **`FORGE_LEDGER_KEY`** dessus
   (bloc opt-in `k8s/40-console.yaml`). La clé est **lue, pas réécrite** → elle n'atterrit **jamais** sur
   le PVC `forge-ledger` partagé.

Détail complet, wiring k8s et rotation : **[`docs/KEY_CUSTODY.md` §HA key custody](KEY_CUSTODY.md#ha-key-custody-kubernetes--keep-the-private-key-off-the-shared-ledger-volume)**.

**Postgres — managé recommandé en prod.** `k8s/20-postgres.yaml` fournit un **StatefulSet single-replica +
Service headless + PVC RWO** pour le **test/dev**. En **prod, préférer un Postgres managé/opéré** (RDS,
Cloud SQL, CloudNativePG/Crunchy) : un Postgres mono-pod ne rend pas la stack HA (backups, failover, PITR
viennent du managé). Pour pointer la console dessus : ne pas appliquer `20-postgres.yaml`, mettre le DSN
managé dans le Secret `forge-db`, et remplacer la règle d'egress `console→postgres` par un `ipBlock` vers
l'endpoint managé (cf. notes de `60-networkpolicies.yaml`). Idem MinIO → **S3 externe** en prod.

**Sticky sessions pour SSE.** Les flux SSE (logs de run, présence live) doivent rester **épinglés à un
seul backend** pour la durée du stream, et les caches par-instance + le head de ledger par-instance
rendent le routage collant correct de toute façon. Deux niveaux, cumulés :

- **Ingress nginx** (`k8s/50-ingress.yaml`) : `affinity: cookie` (cookie `forge_lb`) — équivalent k8s du
  `lb_policy cookie` de Caddy ; plus `proxy-buffering: off` + `proxy-read-timeout: 3600` pour ne pas
  bufferiser/couper les streams.
- **Service** (`k8s/40-console.yaml`) : `sessionAffinity: ClientIP` (ceinture + bretelles). L'alternative
  sans ingress-controller est un `Service type: LoadBalancer` + `ClientIP` + `externalTrafficPolicy:
  Local` (fourni commenté).

**Modèle NetworkPolicy — deny-by-default est-ouest (cœur du #13).** `k8s/60-networkpolicies.yaml` pose
d'abord un **`default-deny-all`** (podSelector vide, `policyTypes: [Ingress, Egress]`, aucune règle → tout
refusé dans les deux sens pour **tous** les pods du namespace), puis **uniquement** les chemins
least-privilege, additifs :

| Flux autorisé | Egress (source) | Ingress (destination) |
|---|---|---|
| Ingress-controller → **console:7100** | — (hors namespace) | policy `forge` (from ns `ingress-nginx`) |
| **console → Postgres:5432** | policy `forge` | policy `forge-postgres` (from pods console) |
| **console → MinIO:9000** | policy `forge` | policy `forge-minio` (from pods console) |
| **\<tous pods\> → kube-dns:53** (UDP+TCP) | policy `allow-dns-egress` | (kube-system) |

**Tout le reste est refusé** : pas d'egress internet, pas de mouvement latéral, **pas de trafic
console↔console** (le bail leader, la présence et l'invalidation de cache inter-instances passent **par
Postgres**, pas pod-à-pod ; le ledger partagé est un volume fichier, pas un chemin réseau). Une connexion
ne passe que si elle est autorisée **des deux côtés** (egress source **et** ingress destination) — les deux
sont fournis. Deux mises en garde documentées dans le fichier : (a) les **sondes kubelet** viennent du
nœud, pas d'un pod — la plupart des CNI (Calico/Cilium) les exemptent ; sinon décommenter le stub
`ipBlock` vers le **CIDR du nœud** dans la policy console ; (b) pour un **backend externe** (PG managé / S3
externe), remplacer la règle pod-selector par un `ipBlock` vers son CIDR:port.

---

## 3ter. SSO entreprise — OIDC natif, SAML via pont OIDC (Stage entreprise, flag-gated)

Le SSO entreprise de Forge est **OIDC (OpenID Connect)** — et **rien d'autre** en natif. Comme le
backend Postgres ([§3bis](#3bis-backend-postgres-stage-4--ha--multi-instance)) et la multi-tenance, c'est
une feature **ENTREPRISE, séparable, runtime-gated** : le build **community (défaut)** se comporte
**exactement** comme aujourd'hui — comptes **LOCAUX** seulement (`users` + argon2id + cookie
`forge_session` + RBAC admin/opérateur/viewer). Tant que le flag n'est pas **engagé**, toutes les routes
`/api/sso/*` sont **absentes** (404) et le login local est **inchangé** (byte-identique). Le SSO n'affaiblit
jamais la surface de gouvernance/audit : il **AJOUTE** seulement un chemin de login Authorization-Code qui,
en cas de succès, émet **LE MÊME** cookie `forge_session` que `/api/login`.

### 3ter.1 Ce que Forge parle nativement : OIDC (et uniquement OIDC)

| Variable | Rôle |
|---|---|
| `FORGE_ENTERPRISE_SSO` (truthy) **ou** clé de config par-DB `enterprise.sso` | engage le SSO OIDC (sinon community, login local seul) |
| `FORGE_SSO_HTTP_TIMEOUT` | timeout des fetch discovery/JWKS/token (défaut `10` s) |

Le provider OIDC se configure **côté admin** (route admin-gated `POST /api/sso/config`, `client_secret`
**write-only** / rédigé, jamais renvoyé/loggé/ledgerisé) — **rien de codé en dur**, même substrat que la
source de détection. Champs : **`issuer`**, **`client_id`** / **`client_secret`**, **`redirect_uri`** (le
`/api/sso/callback` de cette console), **`allowed_redirect_uris`** (allowlist des cibles de retour
post-login — le navigateur n'est **jamais** redirigé ailleurs, même discipline que `redirect.open` /
`oauth.flow`, donc **pas d'open-redirect**), et le mapping identité (`provisioning` = `match`/`auto`,
`user_claim` = `email`/`sub`, `default_role`).

Flux **Authorization-Code + PKCE (S256)**, **fail-closed à chaque étape** : `GET /api/sso/login` construit
l'URL authorize (state + nonce + challenge persistés server-side) et 302 vers l'IdP ; `GET
/api/sso/callback` valide le state (one-time), échange le code contre les tokens, puis **VALIDE
cryptographiquement l'ID token** — signature **RS256 via la JWKS de l'IdP** (kid exact ; `none`/HS\*
rejetés → pas de downgrade d'algo), `iss`, `aud == client_id`, `exp`, et binding du `nonce`.

> #### ⚠️ Transport SSO — TLS d'egress OBLIGATOIRE (audit F3)
>
> **Le fetcher OIDC intégré du console est HTTP-only.** Discovery, JWKS **et** l'échange de token passent
> par le client HTTP interne de la console, qui **REJETTE `https://`** (`http_get_blocking` :
> « HTTPS non géré nativement par le fetcher intégré » ; `http_post_form_blocking` :
> « token endpoint must be http:// (TLS terminated upstream) »). **Un issuer `https://` exige donc
> aujourd'hui un proxy TLS d'egress** — la console ne parle pas TLS elle-même sur ce chemin.
>
> **Conséquence à connaître.** Au callback, la console POST vers le **token endpoint** de l'IdP le
> **`client_secret`** (`Authorization: Basic`, client_secret_basic) **et** le **`code`** d'autorisation.
> Ce POST partant en **HTTP clair**, ce hop **doit** être protégé au transport : soit l'IdP est joint via
> **TLS terminé par un proxy d'egress**, soit il vit sur un **segment interne de confiance**. Sans cela,
> `client_secret` + `code` transitent en clair et sont interceptables sur le réseau.
>
> **Ce qui protège déjà (défense en profondeur, indépendant du transport) :**
> - le **`client_secret` est write-only** — jamais renvoyé, **jamais loggé, jamais ledgerisé** (rédigé) ;
> - la **deny-list SSRF** console (`guard_integration_addr`) bloque loopback / link-local
>   (169.254.169.254) / RFC1918 / ULA / unspecified sur l'**IP résolue** de connexion (anti-DNS-rebinding),
>   pour discovery, JWKS **et** le POST token — sauf escape-hatch `FORGE_ALLOW_INTERNAL_INTEGRATIONS` ;
> - les endpoints discovery (`token`/`jwks`/`authorization`) sont **pinnés à l'origine de l'issuer**
>   (anti-SSRF, un document de discovery hostile ne peut pas rediriger ailleurs) ;
> - l'**ID token reste validé RS256/JWKS** quel que soit le transport de fetch — mais cela garantit
>   l'**intégrité** du token, **pas la confidentialité** du `client_secret`/`code` sur le fil. D'où
>   l'exigence de TLS d'egress ci-dessus.
>
> **Patterns recommandés (choisir un) :**
> - **proxy TLS-terminant d'egress** devant l'IdP — un Envoy/nginx/`ghostunnel`/`stunnel` (sidecar ou
>   service) qui écoute en `http://` côté console et **fait le TLS** vers l'IdP `https://`. Pointer alors
>   `issuer` sur l'endpoint `http://` local du proxy ;
> - **service-mesh mTLS** (Istio / Linkerd) — le sidecar chiffre le hop console→IdP de façon transparente ;
> - **oauth2-proxy** (déjà recommandé comme pont pour les IdP SAML, §3ter.2) placé devant, qui gère le TLS
>   amont vers l'IdP ;
> - à défaut, un **IdP sur segment interne de confiance** (réseau isolé, pas d'écoute possible).
>
> **Amélioration future (hors périmètre de ce durcissement).** Un client **rustls** natif dans le fetcher
> du console (`console/src`) supprimerait cette contrainte en parlant `https://` directement, tout en
> gardant la posture openssl-free (rustls/ring). Noté comme évolution possible ; **non implémenté**
> aujourd'hui — la recommandation reste le proxy TLS d'egress.

**Mapping groupes → rôles Forge.** Le claim OIDC `groups` de l'ID token est résolu vers un rôle/grants
Forge **via le seam RBAC « groups-from-claims »** (`rbac::groups_from_claims` → `rbac::resolve` →
`rbac::apply_to_user`) : les groupes de l'IdP pilotent le rôle (et les grants tenant) de l'identité, dès la
**première** connexion (y compris pour un compte auto-provisionné). **Fail-closed / moindre privilège** :
aucun groupe correspondant ⇒ le `default_role` configuré (jamais super-admin, non représentable dans le
mapping). L'IdP reste ainsi **la** source de vérité des rôles, sans double-administration des comptes.

### 3ter.2 IdP SAML-only : supportés via un **pont OIDC externe** (par conception)

Forge n'implémente **PAS** de SAML natif en-process — **choix délibéré**, pas une lacune :

- **Posture pure-Rust / openssl-free.** La pile SAML Rust (**`samael`**) tire **openssl + libxmlsec1 + une
  toolchain C**, ce qui casserait la posture openssl-free de Forge (auth 100 % Rust, `rustls`/`ring`, jamais
  native-tls/openssl — cf. la même discipline que le backend PG en [§3bis](#3bis-backend-postgres-stage-4--ha--multi-instance)).
- **Surface d'attaque.** Vérifier soi-même les signatures **XML-DSig** + le **C14N exclusif** est
  précisément la classe de foot-gun **XML-Signature-Wrapping (XSW)** — un contournement d'auth livré à
  répétition **même par des piles SAML matures**. Forge garde son **unique** surface d'auth pure-Rust et
  minimale plutôt que d'ajouter cette dette.

**Pattern supporté : mettre un pont OIDC DEVANT Forge.** Le pont termine le SAML contre l'IdP du client et
présente de l'**OIDC** à Forge. Forge ne parle **jamais** que l'OIDC qu'il valide déjà (RS256/JWKS,
groups→rôles) → openssl-free préservé, **zéro nouvelle dépendance, zéro nouvelle surface d'attaque**. Ponts
éprouvés : **Dex** (connecteur SAML), **Keycloak identity brokering** (broker l'IdP SAML du client, expose
de l'OIDC à Forge), ou **oauth2-proxy**.

```
   IdP SAML du client                Pont OIDC (hors Forge)              Forge console
 ┌──────────────────┐   SAML 2.0   ┌──────────────────────────┐  OIDC  ┌────────────────────┐
 │ ADFS / Azure AD  │ ───────────▶ │ Dex (connecteur SAML)    │ ─────▶ │ /api/sso/login     │
 │ Shibboleth / …   │ ◀─────────── │  — ou —                  │ ◀───── │ /api/sso/callback  │
 └──────────────────┘  assertion   │ Keycloak identity broker │ authz  │ RS256/JWKS + groups│
                                    │  — ou — oauth2-proxy     │  code  │      → rôles RBAC   │
                                    └──────────────────────────┘        └────────────────────┘
     libxmlsec1/XML-DSig CONFINÉ dans le pont ↑              Forge = OIDC pur, openssl-free ↑
```

Le pont porte **toute** la complexité XML/openssl ; Forge reçoit un ID token OIDC standard et applique son
mapping `groups → rôles` inchangé. C'est la voie recommandée pour tout IdP SAML-only.

### 3ter.3 Échappatoire — feature Cargo `saml` OPTIONNELLE (non construite par défaut)

Si un **contrat** exige un SAML **en-process** (pas de pont possible), une future feature Cargo **`saml`**
(backend `samael`) pourra être ajoutée — produisant une **variante de build openssl + libxmlsec1** distincte,
le build **community restant openssl-free par défaut** (même discipline opt-in que `store-postgres` /
`encryption`). **Non implémentée aujourd'hui** : documentée comme **disponible sur demande**, pas livrée. Le
défaut, et la recommandation, restent le **pont OIDC** ci-dessus.

---

## 4. Contexte de build & dépendance `guatx-core`

⚠️ Le contexte de build est le **PARENT `GUATX/`**, pas `forge/` : le crate `console` dépend du sibling
`guatx-core` via `guatx-core = { path = "../../core" }` (cf. `console/Cargo.toml`). `core/` est un repo
**partagé** appartenant à l'utilisateur — **non vendoré, non copié-committé** dans `forge/** : le stage
builder le consomme **depuis le contexte parent** (`COPY core/ ./core/`). Construire depuis `forge/`
seul **échouera** (core hors contexte) — c'est **voulu**.

- **Reproductibilité** : `console/Cargo.lock` est **committé** (retiré de `console/.gitignore`) — un
  binaire/produit verrouille ses deps pour des builds identiques client/CI. Le Dockerfile build
  d'ailleurs `cargo build --release --locked`, qui **exige** un `Cargo.lock` présent et à jour.
- **Ignore du contexte** : `forge/Dockerfile.dockerignore` (ignore-file **spécifique au Dockerfile** —
  BuildKit le préfère à un `.dockerignore` racine quand il jouxte le Dockerfile désigné par `-f`).
  Motifs relatifs à `GUATX/`. Exclut le cache Cargo `forge/console/target/` (~1.6 GB), les `*.db`/WAL,
  le ledger `*.jsonl`, `__pycache__`, `**/.git`, secrets (`*.env`/`*.key`/…) et les repos siblings
  inutiles (`plume/`, `guatx-infra/`, `guatx-k3s-manifests/`, `_archive/`). `forge/` et `core/` restent inclus.

**Migration future (clone forge-only)** : quand le repo public `guatx-core` existera, remplacer la dép
`path` par une dép **git épinglée** :

```toml
# console/Cargo.toml
guatx-core = { git = "https://github.com/guatx/core", tag = "vX.Y.Z" }
```

Le contexte pourra alors **redevenir `forge/` seul**, le `COPY core/ ./core/` du builder disparaîtra, et
un checkout **forge-only** (sans le sibling `core/`) buildera tel quel. Tant que c'est une dép `path`, le
contexte **DOIT** rester le parent `GUATX/`.

---

## 5. Liveness `/health` & en-tête `Host`

Le `HEALTHCHECK` (Dockerfile **et** compose) fait un vrai **`GET /health` attendant HTTP 200** — pas un
simple TCP port-open (qui passerait même si le routeur HTTP est mort).

- `/health` est **PUBLIC** (hors `auth_guard`) mais **sous `host_guard`** (anti-DNS-rebinding) : la sonde
  **doit** envoyer un `Host` autorisé. En visant `http://127.0.0.1:7100/health`, urllib pose
  `Host: 127.0.0.1:7100` → `host_guard` retire le port → `127.0.0.1`, présent dans l'allowlist **par
  défaut** (`localhost` / `127.0.0.1` / `::1`). Vérifié en exécutant le binaire : Host `127.0.0.1` → 200
  (healthy) ; Host étranger → **421** (unhealthy).
- Derrière un reverse-proxy avec `FORGE_CONSOLE_HOST` restreint, la sonde continue de viser `127.0.0.1`
  (toujours dans l'allowlist par défaut, indépendamment de `FORGE_CONSOLE_HOST`) — le healthcheck reste
  vert sans ouvrir le host-guard.
- **Corps `/health`** : `{"status":"ok","version":"X.Y.Z","db":"ok|degraded"}`. Le champ **`db`** est
  **additif** (Stage 4) : il **ping le store ACTIF** (SQLite : `SELECT 1` trivial ; Postgres : `SELECT 1`
  via le backend, donc à travers le reconnect+retry HA). `"degraded"` = base injoignable. La sonde est
  **non-fatale** : `/health` répond **toujours 200** même en `degraded` (le `HEALTHCHECK` ne teste que le
  code 200 → il n'oscille pas sur une coupure DB transitoire), mais un superviseur externe peut lire `db`
  pour alerter/évincer une instance dont la DB est down.

```sh
docker inspect --format '{{.State.Health.Status}}' forge      # -> healthy
curl -s http://127.0.0.1:7100/health   # -> {"db":"ok","status":"ok","version":"0.0.1"}
```

---

## 6. Empreinte mesurée & matrice de déploiement

*(chiffres mesurés)*

### Composition

Forge lui-même :

| Langage | Périmètre | LOC |
|---|---|---|
| Python | moteur, stdlib pur, `deps=[]` | ~5256 |
| Rust | console | ~4006 |
| Rust | guatx-core | ~1032 |
| JS / HTML / CSS | UI | ~3513 |

**ZÉRO** Java / C / C++ / Go / bash dans le code Forge.

Les outils **ORCHESTRÉS** (jamais embarqués, tous **OPTIONNELS**, auto-neutralisés si absents) :

| Outil | Langage |
|---|---|
| nmap | C |
| httpx / nuclei / subfinder | Go |
| MSF | Ruby |
| Burp | Java |
| browser / camoufox | Python + Firefox |

### Poids

- **Livrable cœur ≈ 5 MB** :
  - binaire Rust console **4.2 MB** (SQLite bundlé)
  - Python **196 KB**
  - web **432 KB**
- Le **1.6 GB** dans `forge/` = cache Cargo `console/target/` (**NON expédié**).
- **Image Docker** :
  - **minimale ~150-250 MB** (console + python + nmap)
  - **complète ~350-500 MB** (+ binaires Go PD)
- `browser-automation` = image **4 GB** séparée (sidecar optionnel derrière `profiles: ["browser"]`).

### Matrice de déploiement

#### Docker ✅

- `docker compose config` valide ; un `up` nu démarre la **console seule** (optionnels sous profils).
- Multi-stage (builder rust jeté → runtime debian-slim).
- Non-root uid 10001, tini PID1, volumes DB / ledger / scope.
- Contexte de build & dépendance `core/`, ignore du contexte, profils d'image, supply-chain SHA256,
  liveness : cf. [§1](#1-options-de-build--run), [§4](#4-contexte-de-build--dépendance-guatx-core),
  [§5](#5-liveness-health--en-tête-host).

**Supply-chain — pins SHA256.** Les archives ProjectDiscovery ne sont plus récupérées « par tag » non
vérifiées : chaque `.zip` est **épinglé par digest** (ARG `*_SHA256_amd64` / `*_SHA256_arm64`, issus des
`*_checksums.txt` officiels) et validé par `sha256sum -c` — toute non-correspondance **fait échouer le
build**. Bump de version = rafraîchir version **et** digest.

#### k3s / k8s ✅

- **Deux modes** : (a) **single-replica** SQLite (défaut community, ci-dessous) ; (b) **HA multi-réplicas**
  contre Postgres partagé → **manifests `k8s/` + NetworkPolicies deny-by-default**, cf.
  [§3bis.6](#3bis6-ha-sur-kubernetes--manifests-k8s-readiness-dossier-13).
- Mode (a) : Deployment **single-replica**.
- ⚠️① la console **SPAWN** `python3 -m forge.cli` (setsid) → python + package forge **DANS LE MÊME
  conteneur** (pas séparable).
- ⚠️② en mode (a) SQLite + ledger = **PVC ReadWriteOnce** → pas de scale horizontal. Le mode (b) lève ça
  via Postgres partagé + ledger sur PVC **RWX** (ou ledger-par-instance) — cf. §3bis.6.
- Outils externes (browser:8080, msfrpcd:55553, burp:1337) = Services / sidecars optionnels.

#### Host natif ✅

- `pip install -e .` + `cargo build --release` + outils sur PATH.
- Unité systemd durcie fournie (`deploy/forge.service`) — cf. [§1.4](#14-natif--systemd-sans-docker).

#### venv ✅

- `deps=[]` → la partie Python tient en venv **sans aucune dépendance pip**.

### Rapports & export PDF

Le rapport d'engagement est servi par la console : `GET /api/report/:id?format=md` (**défaut**,
rétro-compat) et `?format=html` (livrable client brandé, avec CSS `@media print` + couleurs forcées
`print-color-adjust`).

- **Voie PDF par défaut (aucune dépendance)** : ouvrir `?format=html` puis **« Imprimer » →
  « Enregistrer au format PDF »** dans le navigateur. La feuille de style d'impression est fournie, donc
  badges/posture restent lisibles. C'est le chemin recommandé — **zéro binaire externe**.
- **`?format=pdf` (OPTIONNEL)** : rendu PDF côté serveur, activé **seulement si** un moteur PDF est
  présent sur le PATH (`weasyprint` recommandé, pip pur-Python ; `wkhtmltopdf` supporté s'il est déjà là).
  Absent → JSON `pdf_unavailable` qui renvoie vers l'impression navigateur. Le profil `full` embarque
  `weasyprint` (venv isolé `/opt/pdfenv`, symlinké dans `/usr/local/bin`) → `?format=pdf` clé-en-main ;
  `mini` l'omet.

> Le moteur PDF est un outil **orchestré optionnel** (comme nmap/nuclei/Burp) : non embarqué,
> auto-neutralisé si absent. La claim « ZÉRO Go/Ruby/… dans le code Forge » n'est pas affectée
> (weasyprint est pur-Python ; ses libs C pango/cairo sont de la même catégorie que nmap).

### Contrainte d'archi

- **STATEFUL single-replica + PVC RWO** (pas scale-out).
- HA / multi-tenant futur = ledger hors-host + store partagé (à repenser).
- **Profil idéal actuel** : mono-opérateur / petit MSSP.
- **Atout** : noyau gouverné minuscule + moteurs lourds branchables en sidecars optionnels
  (livrable « mini » ~200 MB ou « full » selon le client).

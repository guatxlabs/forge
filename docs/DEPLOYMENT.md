# Forge — Déploiement self-service (runbook) & empreinte

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Installation](INSTALLATION.md) ·
> [Premier déploiement (wizard)](FIRST_DEPLOYMENT.md) · [Configuration](CONFIGURATION.md)

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
docker build -f forge/Dockerfile -t forge-console:0.0.1 .
# mini
docker build --build-arg FORGE_TOOLS_PROFILE=mini -f forge/Dockerfile -t forge-console:0.0.1-mini .

docker run -d --name forge-console \
  -p 127.0.0.1:7100:7100 \
  -v forge-db:/data/db -v forge-ledger:/data/ledger \
  -v "$PWD/forge/scope.json:/data/scope/scope.json:ro" \
  --env-file forge/.env \
  forge-console:0.0.1
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

Unité durcie fournie : [`deploy/forge-console.service`](../deploy/forge-console.service)
(`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`, seccomp `@system-service`…).
Le durcissement systemd **n'affaiblit aucun garde-fou applicatif**, il renforce l'isolation du process.

```sh
cd GUATX/forge/console && cargo build --release            # binaire offline depuis le cache cargo
sudo install -m0755 target/release/forge-console /usr/local/bin/
sudo mkdir -p /opt/forge && sudo cp -r ../forge /opt/forge/forge && sudo cp -r web /opt/forge/console/web
sudo useradd --system --home /opt/forge --shell /usr/sbin/nologin forge
sudo mkdir -p /var/lib/forge/{db,ledger,scope}                      # remplir scope/scope.json AVEC AUTORISATION
sudo install -m0600 -o root -g forge /dev/null /etc/forge/forge-console.env   # y mettre les hashes argon2id
sudo cp deploy/forge-console.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now forge-console
```

Le package Python est **pur-stdlib** (`deps=[]`) : il tient aussi en venv **sans aucune dépendance pip**.

### 1.5 Image `encryption` (chiffrement AU REPOS — SQLCipher, opt-in)

Le build **par défaut** stocke la base SQLite **en clair** (`capabilities.sqlcipher:false`). Pour un
chiffrement au repos, compiler la console avec la feature `encryption` puis fournir la clé au boot :

```sh
# 1) image chiffrée (feature Cargo -> backend crypto SQLCipher)
cd GUATX/forge/console && cargo build --release --features encryption
#    (Docker : construire une image taguée forge-console:0.0.1-encryption avec cette feature)

# 2) au boot, la console lit FORGE_DB_KEY et émet `PRAGMA key` AVANT toute requête (contrat SQLCipher)
#    extrait docker-compose.override.yml :
#      services:
#        forge-console:
#          image: forge-console:0.0.1-encryption
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
`FORGE_CONSOLE_OPERATOR_HASH` (hashes argon2id via `forge-console hashpw` / `hashpw-operator`) et
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
  forge-console:0.0.1 \
  forge-console migrate --from /import --to /data/db/forge-console.db \
    --ledger /data/ledger/engagement.jsonl --verify
# chiffrer au passage (image `encryption`) : ... --encrypt --key-env FORGE_DB_KEY   (clé via ENV, jamais argv)
```

Le wizard propose aussi un **import pré-provision** (`POST /api/setup/migrate`), **opt-in** et réservé
au pré-déploiement (désactivé par défaut : `FORGE_ALLOW_API_MIGRATE` + `FORGE_CONSOLE_IMPORT_DIR`) ; la
voie CLI ci-dessus reste l'UX documentée.

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

```sh
docker inspect --format '{{.State.Health.Status}}' forge-console      # -> healthy
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

- Deployment **single-replica**.
- ⚠️① la console **SPAWN** `python3 -m forge.cli` (setsid) → python + package forge **DANS LE MÊME
  conteneur** (pas séparable).
- ⚠️② SQLite + ledger = **PVC ReadWriteOnce** → pas de scale horizontal.
- Outils externes (browser:8080, msfrpcd:55553, burp:1337) = Services / sidecars optionnels.

#### Host natif ✅

- `pip install -e .` + `cargo build --release` + outils sur PATH.
- Unité systemd durcie fournie (`deploy/forge-console.service`) — cf. [§1.4](#14-natif--systemd-sans-docker).

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

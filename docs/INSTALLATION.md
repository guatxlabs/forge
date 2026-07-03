# Installation

> [Sommaire](README.md) · Suivant : [Premier déploiement (wizard)](FIRST_DEPLOYMENT.md) · Voir aussi :
> [Configuration](CONFIGURATION.md) · [Runbook self-deploy détaillé](DEPLOYMENT.md)

Cette page couvre **toutes les voies d'installation** avec les commandes exactes. Le runbook
self-deploy détaillé (empreinte mesurée, matrice Docker/k8s/host/venv, export PDF) est dans
[`DEPLOYMENT.md`](DEPLOYMENT.md).

> ⚠️ **Contexte de build = le dossier PARENT `GUATX/`** (pas `forge/`) : la console dépend du crate
> sibling `guatx-core` en dép `path`. Toutes les commandes `docker build`/`docker compose`
> ci-dessous se lancent **depuis `GUATX/`**. Détail + migration future (dép `git`, contexte
> forge-only) : [`DEPLOYMENT.md`](DEPLOYMENT.md) §4.

## Pré-étape OBLIGATOIRE — le fichier scope (fail-loud)

Le scope/ROE actif est **monté en volume**, jamais cuit dans l'image. Créer le **fichier** avant
tout `up` :

```sh
cd GUATX/forge
cp scope.example.json scope.json     # in_scope vide = INERTE ; éditer AVEC AUTORISATION écrite
```

Si `scope.json` est absent, Docker crée un **répertoire** vide à sa place ; l'entrypoint compose
**échoue bruyamment** plutôt que de démarrer sur un scope illisible, et bascule sur le
`scope.example.json` embarqué (INERTE) si le fichier manque/est vide. `scope.json`, `*.key`, `*.jsonl`
sont gitignorés.

---

## 1. Profils d'image : `mini` vs `full`

Un seul `--build-arg FORGE_TOOLS_PROFILE` bascule l'empreinte. Les modules **dégradent proprement**
(`available:false`) quand un outil manque.

| Profil | Contenu | Poids | `?format=pdf` | Modules PD (httpx/nuclei/subfinder) |
|---|---|---|---|---|
| `mini` | console + `python3` + `nmap` | ~150-250 MB | `pdf_unavailable` (impression navigateur) | `available:false` |
| `full` *(défaut)* | + binaires ProjectDiscovery (vérifiés SHA256) + moteur PDF weasyprint | ~350-500 MB | actif clé-en-main | disponibles |

---

## 2. Docker (image seule)

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

Bind **loopback uniquement**. N'exposer publiquement qu'à travers un reverse-proxy + auth +
`FORGE_CONSOLE_HOST` (host-allowlist anti-DNS-rebinding). L'image bind `0.0.0.0:7100` **dans** le
conteneur (réseau isolé) ; le mapping `127.0.0.1:7100:7100` restreint l'exposition hôte au loopback.

---

## 3. docker-compose *(recommandé)*

Le compose fixe déjà le bon contexte, le fail-loud du scope, les volumes, le healthcheck `/health`,
le bind loopback. **Services optionnels derrière des profils** ⇒ un `up` nu démarre la **console seule**
(aucun `depends_on` dur).

```sh
cd GUATX
docker compose -f forge/docker-compose.yml up -d --build          # console SEULE (profil full)
FORGE_TOOLS_PROFILE=mini docker compose -f forge/docker-compose.yml up -d --build   # image mini

# couches optionnelles, à la demande (aucune n'est requise au boot) :
docker compose -f forge/docker-compose.yml --profile browser up -d        # + accès/évasion (Camoufox :8080)
docker compose -f forge/docker-compose.yml --profile msf --profile burp up -d   # + connecteurs (BYO images)

docker compose -f forge/docker-compose.yml config      # valider la config résolue
```

Secrets & overrides (hashes argon2id, tokens, URLs des services pilotés, clés) → `forge/.env`
(gitignoré, `required:false`). Gabarit commenté : [`../.env.example`](../.env.example). Les connecteurs
`browser`/`msf`/`burp` restent **inertes** tant que leur service n'est pas joignable (sonde à
fire-time). Forge ne fournit **pas** d'image MSF/Burp (licence/outillage opérateur) — les stubs
compose documentent le câblage BYO (bring-your-own).

---

## 4. Natif / systemd (sans Docker)

Unité durcie fournie : [`../deploy/forge-console.service`](../deploy/forge-console.service)
(`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`, seccomp `@system-service`…). Le
durcissement systemd **n'affaiblit aucun garde-fou applicatif**.

```sh
cd GUATX/forge/console && cargo build --release            # binaire offline depuis le cache cargo
sudo install -m0755 target/release/forge-console /usr/local/bin/
sudo mkdir -p /opt/forge && sudo cp -r ../forge /opt/forge/forge && sudo cp -r web /opt/forge/console/web
sudo useradd --system --home /opt/forge --shell /usr/sbin/nologin forge
sudo mkdir -p /var/lib/forge/{db,ledger,scope}                      # remplir scope/scope.json AVEC AUTORISATION
sudo install -m0600 -o root -g forge /dev/null /etc/forge/forge-console.env   # hashes argon2id ici
sudo cp deploy/forge-console.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now forge-console
```

Le package Python est **pur-stdlib** (`deps=[]`) : il tient aussi en venv **sans aucune dépendance pip**.

---

## 5. venv / développement

```sh
cd GUATX/forge
# 1) moteur Python (met `forge` sur le PATH ; sinon `python3 -m forge.cli`)
pip install -e .
# 2) console Rust (compile offline depuis le cache cargo)
cd console && cargo build --release && cd ..
# 3) suite complète (Python unittest + cargo test de la console, zéro réseau)
make test
```

`pip install -e .` termine sans erreur, `forge --version` répond, `cargo build --release` produit
`console/target/release/forge-console`, et `make test` finit sur **`OK`**. Le package Python n'a
**aucune dépendance pip** — il tient en venv nu. Parcours opérateur 100 % hors-ligne (seed +
mock-Plume) : [`GETTING_STARTED.md`](GETTING_STARTED.md).

---

## 6. Image `encryption` (chiffrement AU REPOS — SQLCipher, opt-in)

Le build **par défaut** stocke la base SQLite **en clair** (`capabilities.sqlcipher:false`). Pour un
chiffrement au repos, compiler avec la feature `encryption` puis fournir la clé au boot :

```sh
# 1) image/binaire chiffré (feature Cargo -> backend SQLCipher)
cd GUATX/forge/console && cargo build --release --features encryption
#    (Docker : construire une image taguée forge-console:0.0.1-encryption avec cette feature)

# 2) au boot, la console lit FORGE_DB_KEY et émet `PRAGMA key` AVANT toute requête (contrat SQLCipher)
#    docker-compose.override.yml :
#      services:
#        forge-console:
#          image: forge-console:0.0.1-encryption
#          environment:
#            FORGE_DB_KEY: ${FORGE_DB_KEY}     # [SECRET] depuis .env/docker secret, JAMAIS commité
```

Sans `FORGE_DB_KEY` correcte, la base chiffrée est **illisible** (fail-closed). Convertir un install
existant en clair → chiffré = **Runbook B** de [`MIGRATION.md`](MIGRATION.md). Le wizard expose
`capabilities.sqlcipher` (true seulement sur ce build) pour que l'UI le reflète honnêtement.

> **À part** la crypto AU REPOS (opt-in), le **ledger d'engagement** est signé **Ed25519**
> (asymétrique, vérifiable par un tiers avec la seule clé publique) **par défaut** — aucune action
> requise.

---

## Vérifier l'installation

```sh
# liveness
curl -s http://127.0.0.1:7100/health          # -> {"status":"ok","version":"0.0.1"}
docker inspect --format '{{.State.Health.Status}}' forge-console   # -> healthy

# diagnostic des modules (quels outils sont présents)
python3 -m forge.cli doctor                    # ou: forge doctor
```

Le healthcheck fait un vrai **`GET /health` attendant HTTP 200** (pas un simple TCP port-open). Il
vise `127.0.0.1` (toujours dans l'allowlist host-guard par défaut), donc reste vert même derrière un
`FORGE_CONSOLE_HOST` restreint.

---

## Après l'installation

Ouvrir `http://127.0.0.1:7100` → le **wizard de 1er déploiement** provisionne l'admin, la crypto, la
source de détection et la politique opérateur. Voir **[Premier déploiement](FIRST_DEPLOYMENT.md)**.

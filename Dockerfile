# syntax=docker/dockerfile:1.7
#
# Forge — image de déploiement de la console red-team (usage AUTORISÉ uniquement).
# =============================================================================
#
# Multi-stage :
#   1) `builder`  — compile la console Rust (`cargo build --release`) ;
#   2) `runtime`  — image mince Debian : binaire console + python3 + le package `forge`
#                   (pur-stdlib) + les outils offensifs ProjectDiscovery (httpx/nuclei/
#                   subfinder) et nmap. La console SPAWN `python3 -m forge.cli` (cf.
#                   FORGE_PKG_DIR), donc l'image runtime a IMPÉRATIVEMENT besoin des deux.
#
# ⚠️ CONTEXTE DE BUILD = le dossier PARENT `GUATX/` (pas `forge/`), car le crate
#    `console/` dépend du crate sibling `../../core` (guatx-core). Construire ainsi :
#
#        docker build -f forge/Dockerfile -t forge-console:0.0.1 .      # depuis GUATX/
#    ou  (via docker-compose qui fixe déjà le bon context, voir forge/docker-compose.yml)
#
#    Construire depuis `forge/` directement ÉCHOUERA (core/ hors contexte) — c'est voulu.
#
# Services EXTERNES (jamais embarqués ici — montés/réseau, cf. docker-compose.yml & ENV) :
#   - browser-automation (Camoufox+Xvfb, :8080)  → FORGE_BROWSER_URL
#   - msfrpcd (Metasploit RPC, :55553)           → MSF_RPC_*
#   - Burp Suite REST API (:1337)                → BURP_API_*
#   Forge PILOTE ces outils, il n'en embarque pas la capacité offensive.
#
# Sûreté : l'image NE désactive AUCUN garde-fou. Forge reste INERTE par défaut
#   (in_scope vide = tout refusé). Le scope/ROE est monté en volume, jamais cuit dans l'image.

# -----------------------------------------------------------------------------
# Stage 1 — builder (Rust)
# -----------------------------------------------------------------------------
FROM rust:1.96-bookworm AS builder

WORKDIR /build

# Le crate console dépend du sibling guatx-core via `path = "../../core"`.
# On reproduit l'arborescence relative attendue : /build/forge/console -> ../../core = /build/core.
COPY core/ ./core/
COPY forge/console/ ./forge/console/

WORKDIR /build/forge/console

# Build release reproductible (profil release pinné dans Cargo.toml : opt-level=z, lto, strip).
# Le Cargo.lock du crate est committé → versions de deps verrouillées.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/forge/console/target \
    cargo build --release --locked \
    && mkdir -p /out \
    && cp target/release/forge-console /out/forge-console

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Versions pinnées des outils ProjectDiscovery (suite Go, binaires statiques).
ARG HTTPX_VERSION=1.6.9
ARG NUCLEI_VERSION=3.3.7
ARG SUBFINDER_VERSION=2.6.7
ARG TARGETARCH=amd64

LABEL org.opencontainers.image.title="forge-console" \
      org.opencontainers.image.description="Forge red-team console (ROE fail-closed + ledger tamper-evident) — usage autorisé uniquement." \
      org.opencontainers.image.vendor="GuatX" \
      org.opencontainers.image.source="https://guatx.com"

# Dépendances runtime :
#   - python3            : la console spawn `python3 -m forge.cli` (cœur pur-stdlib, zéro pip) ;
#   - ca-certificates    : TLS sortant (httpx/nuclei/connecteurs REST) ;
#   - nmap               : module recon.nmap_scan ;
#   - curl, unzip        : récupération des binaires PD ci-dessous ;
#   - tini               : init PID 1 (reaping des process enfants spawnés par la console).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        ca-certificates \
        nmap \
        curl \
        unzip \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Outils offensifs ProjectDiscovery (httpx / nuclei / subfinder), versions pinnées.
# Binaires Go statiques → simple téléchargement+install (pas de runtime Go embarqué).
# Si tu préfères les MONTER depuis l'hôte (toolkit existant) plutôt que les embarquer,
# commente ce bloc et bind-monte /usr/local/bin/{httpx,nuclei,subfinder} via compose.
RUN set -eux; \
    base="https://github.com/projectdiscovery"; \
    fetch() { \
        name="$1"; ver="$2"; \
        url="${base}/${name}/releases/download/v${ver}/${name}_${ver}_linux_${TARGETARCH}.zip"; \
        curl -fsSL "$url" -o "/tmp/${name}.zip"; \
        unzip -o "/tmp/${name}.zip" "${name}" -d /usr/local/bin/; \
        chmod +x "/usr/local/bin/${name}"; \
        rm -f "/tmp/${name}.zip"; \
    }; \
    fetch httpx "${HTTPX_VERSION}"; \
    fetch nuclei "${NUCLEI_VERSION}"; \
    fetch subfinder "${SUBFINDER_VERSION}"

# --- Application ---------------------------------------------------------------
# FORGE_PKG_DIR = racine où vit le package python `forge/` ET le scope.json par défaut.
WORKDIR /opt/forge

# Binaire console depuis le builder.
COPY --from=builder /out/forge-console /usr/local/bin/forge-console

# Package python `forge` + assets web de la console + modèle de scope.
# (On ne copie PAS les .db/.jsonl/secrets : ils vivent dans des volumes, cf. ENV ci-dessous.)
COPY forge/forge/            /opt/forge/forge/
COPY forge/console/web/      /opt/forge/console/web/
COPY forge/pyproject.toml    /opt/forge/pyproject.toml
COPY forge/scope.example.json /opt/forge/scope.example.json

# Répertoires de données persistés (déclarés en volumes) : DB console, ledger d'engagement,
# scope/ROE actif. Vides dans l'image — remplis par bind/named volumes au run.
RUN mkdir -p /data/db /data/ledger /data/scope

# Utilisateur non-root (least privilege) — la console bind un port haut (>1024), pas besoin de root.
RUN useradd --system --create-home --uid 10001 forge \
    && chown -R forge:forge /opt/forge /data
USER forge

# --- Configuration (ENV documentées) ------------------------------------------
# Console (Rust) :
ENV FORGE_CONSOLE_ADDR=0.0.0.0:7100 \
    FORGE_CONSOLE_DB=/data/db/forge-console.db \
    FORGE_CONSOLE_LEDGER=/data/ledger/engagement.jsonl \
    FORGE_CONSOLE_SCOPE=/data/scope/scope.json \
    FORGE_CONSOLE_WEB=/opt/forge/console/web \
    FORGE_PKG_DIR=/opt/forge \
    FORGE_PYTHON=python3 \
    FORGE_RUN_TIMEOUT=900 \
    PYTHONPATH=/opt/forge \
    PYTHONUNBUFFERED=1
# Secrets — NE PAS cuire dans l'image ; injecter au run (env_file / --env / secret) :
#   FORGE_CONSOLE_TOKEN           bearer d'ingestion (CSPRNG, sinon généré au boot)
#   FORGE_CONSOLE_PASS_HASH       hash argon2id du rôle viewer    (`forge-console hashpw <pw>`)
#   FORGE_CONSOLE_OPERATOR_HASH   hash argon2id du rôle opérateur (`forge-console hashpw-operator <pw>`)
#   FORGE_CONSOLE_HOST            allowlist Host anti-DNS-rebinding (CSV) si reverse-proxy
# Services externes pilotés (laisser vide = connecteur inerte/indisponible à fire-time) :
#   FORGE_BROWSER_URL=http://browser-automation:8080
#   MSF_RPC_HOST / MSF_RPC_PORT (55553) / MSF_RPC_USER / MSF_RPC_PASS / MSF_RPC_SSL / MSF_RPC_TOKEN
#   BURP_API_URL=http://burp:1337  /  BURP_API_KEY
# Boucle purple (mesure de couverture de détection Plume — laisser vide = OFF/fail-open lisible) :
# cf. docs/PURPLE_PREREQS.md
#   PLUME_URL=http://plume-internal:PORT     bascule ON la boucle purple (http:// interne uniquement)
#   PLUME_TOKEN=<base64 user:pass>           SECRET — Basic auth vers Plume

# bind 127.0.0.1 dans le binaire par défaut ; ici on bind 0.0.0.0 DANS le conteneur (réseau isolé).
# ⚠️ N'expose JAMAIS 7100 sur une interface publique sans reverse-proxy + auth + Host-allowlist.
EXPOSE 7100

# Persistance hors cycle de vie du conteneur.
VOLUME ["/data/db", "/data/ledger", "/data/scope"]

# tini = PID 1 (reaping propre des enfants `python3 -m forge.cli` spawnés par la console).
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["forge-console"]

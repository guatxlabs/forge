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
#        docker build -f forge/Dockerfile -t forge:0.0.1 .      # depuis GUATX/
#    ou  (via docker-compose qui fixe déjà le bon context, voir forge/docker-compose.yml)
#
#    Construire depuis `forge/` directement ÉCHOUERA (core/ hors contexte) — c'est voulu.
#
# ── Dépendance sibling `core/` (guatx-core) ──────────────────────────────────
#    console/Cargo.toml : `guatx-core = { path = "../../core" }`. `core/` est un repo
#    PARTAGÉ appartenant à l'utilisateur — NON vendoré, NON copié-committé ici : il est
#    consommé DEPUIS le contexte de build parent (COPY core/ dans le stage builder).
#    ➜ Migration future prévue quand le repo public existera : remplacer la dép `path`
#      par une dép git ÉPINGLÉE, ex.
#          guatx-core = { git = "https://github.com/guatx/core", tag = "vX.Y.Z" }
#      À ce moment-là le contexte de build pourra redevenir `forge/` seul et le
#      `COPY core/ ./core/` du builder disparaîtra. Tant que c'est une dép `path`,
#      le contexte DOIT rester le parent `GUATX/`.
#
# ── Ignore du contexte de build ──────────────────────────────────────────────
#    Le contexte réel = `GUATX/`, mais l'utilisateur ne modifie que `forge/`. On utilise
#    donc l'ignore-file SPÉCIFIQUE au Dockerfile (fonction BuildKit) : `forge/Dockerfile.dockerignore`.
#    BuildKit le préfère à un `.dockerignore` racine quand il existe à côté du Dockerfile
#    référencé par `-f`. Ses motifs sont relatifs à la RACINE du contexte (`GUATX/`). Il
#    exclut ~1.6 GB de `forge/console/target/`, les *.db/*.jsonl/ledger/secrets et les repos
#    siblings inutiles au build (plume/, guatx-infra/, …) — cf. ce fichier.
#
# ── Profils d'outils (FORGE_TOOLS_PROFILE=full|mini) ─────────────────────────
#    `full` (défaut) : embarque httpx/nuclei/subfinder (téléchargés + VÉRIFIÉS SHA256) et
#      un moteur PDF (weasyprint, pip, pur-Python) → `?format=pdf` clé-en-main.
#    `mini` : OMET ces outils ; les modules dégradent proprement (available:false, déjà géré)
#      et `?format=pdf` répond `pdf_unavailable` (l'impression navigateur reste dispo).
#      Build mini : `docker build --build-arg FORGE_TOOLS_PROFILE=mini -f forge/Dockerfile .`
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
# VERSION vit à la racine du crate (`forge/`) : la console la lit à la COMPILATION via
# `include_str!(CARGO_MANIFEST_DIR "/../VERSION")` = /build/forge/VERSION. Il faut donc la
# copier explicitement (elle n'est pas sous forge/console/ que COPY ci-dessus embarque).
COPY forge/VERSION ./forge/VERSION

WORKDIR /build/forge/console

# Cargo features OPTIONNELLES à activer au build (ADDITIF — VIDE PAR DÉFAUT => build community
# byte-identique, aucune dépendance supplémentaire). Ex. `store-postgres` (backend Postgres, TLS
# rustls/ring openssl-free) pour un déploiement HA/multi-instance :
#   docker compose ... build --build-arg FORGE_CARGO_FEATURES=store-postgres
# (l'override docker-compose.postgres.yml le pose automatiquement — cf. docs/DEPLOYMENT.md § Postgres).
ARG FORGE_CARGO_FEATURES=""

# Build release reproductible (profil release pinné dans Cargo.toml : opt-level=z, lto, strip).
# Le Cargo.lock du crate est committé → versions de deps verrouillées. `${FORGE_CARGO_FEATURES:+...}` :
# n'ajoute `--features <…>` QUE si l'ARG est non vide (sinon la ligne est IDENTIQUE au build par défaut).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/forge/console/target \
    cargo build --release --locked ${FORGE_CARGO_FEATURES:+--features "$FORGE_CARGO_FEATURES"} \
    && mkdir -p /out \
    && cp target/release/forge /out/forge

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Profil d'outils : `full` (défaut, embarque httpx/nuclei/subfinder + moteur PDF) ou `mini`
# (les omet ; les modules dégradent en available:false — déjà géré côté engine).
ARG FORGE_TOOLS_PROFILE=full

# Versions pinnées des outils ProjectDiscovery (suite Go, binaires statiques).
ARG HTTPX_VERSION=1.6.9
ARG NUCLEI_VERSION=3.3.7
ARG SUBFINDER_VERSION=2.6.7
ARG TARGETARCH=amd64

# Empreintes SHA256 des archives officielles (par arch), issues des `*_checksums.txt`
# signés de chaque release ProjectDiscovery. Elles ÉPINGLENT le binaire téléchargé : le
# build ÉCHOUE en cas de non-correspondance (plus de `curl`-par-tag non vérifié). Pour
# mettre à jour lors d'un bump de version :
#   curl -fsSL https://github.com/projectdiscovery/<tool>/releases/download/v<VER>/<tool>_<VER>_checksums.txt
ARG HTTPX_SHA256_amd64=c8d36461b5d736e88c3f9104fed15f2112eb7263dbda35fd08aa5a771bddfb5f
ARG HTTPX_SHA256_arm64=8cf124b4f62236ff3149b83a8bfc70203fcda3dfda6606013751b229b3e0aa95
ARG NUCLEI_SHA256_amd64=725ef892fcffd1b03ad4f0874942fc4b623c0419b6b6c6c91fe4a5a65671f77c
ARG NUCLEI_SHA256_arm64=a07744736613c73fa2c3aef63e176941e3de95fa76feb4870551a1c444ce7704
ARG SUBFINDER_SHA256_amd64=d988a481d3037c55e685afee023eb104a81a77dd2691fb902b59019a365f6103
ARG SUBFINDER_SHA256_arm64=07b7fa2c2cfe6770df9cdfc0ab761a33bbaaf7146add51ea44e806953edc2d88

LABEL org.opencontainers.image.title="forge" \
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

# POSTGRES BACKEND (feature `store-postgres`) — installe le CLIENT Postgres (`pg_dump`/`pg_restore`)
# UNIQUEMENT quand l'image est buildée avec la feature (`FORGE_CARGO_FEATURES` contient store-postgres).
# La console se CONNECTE via rustls (aucun libpq requis) ; `pg_dump` sert la SAUVEGARDE Postgres (Stage 4
# — cf. backup.rs). Build community (ARG vide) : le `grep` échoue -> aucun paquet installé -> image PAR
# DÉFAUT inchangée (aucun binaire Postgres). Ré-déclaré ici car un ARG ne traverse pas les stages FROM.
#
# ⚠️ VERSION du client : le postgresql-client de Debian bookworm est en v15, qui REFUSE de dumper un
# serveur v16 (« server version mismatch »). On installe donc le client depuis le dépôt PGDG officiel à la
# version `FORGE_PG_CLIENT_VERSION` (défaut 16, alignée sur le service `postgres:16` du compose) — un
# pg_dump vN dumpe un serveur <= vN. Le dépôt PGDG utilise une clé signée (signed-by .asc, sans gnupg).
ARG FORGE_CARGO_FEATURES=""
ARG FORGE_PG_CLIENT_VERSION=16
RUN set -eux; \
    if echo "${FORGE_CARGO_FEATURES}" | grep -q "store-postgres"; then \
        apt-get update; \
        apt-get install -y --no-install-recommends curl ca-certificates; \
        install -d /usr/share/postgresql-common/pgdg; \
        curl --fail -sSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
            https://www.postgresql.org/media/keys/ACCC4CF8.asc; \
        codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"; \
        echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main" \
            > /etc/apt/sources.list.d/pgdg.list; \
        apt-get update; \
        apt-get install -y --no-install-recommends "postgresql-client-${FORGE_PG_CLIENT_VERSION}"; \
        rm -rf /var/lib/apt/lists/*; \
        pg_dump --version; \
    else \
        echo "[build] store-postgres absent des features -> pg_dump non installé (image community inchangée)"; \
    fi

# Outils offensifs ProjectDiscovery (httpx / nuclei / subfinder), versions ET DIGESTS pinnés.
# Binaires Go statiques → simple téléchargement+install (pas de runtime Go embarqué).
# ── Profil : `full` uniquement. En `mini`, ce bloc s'auto-court-circuite (exit 0) et les
#    modules recon/web dégradent en available:false (déjà géré par l'engine, cf. runner.available).
# ── Supply-chain : chaque archive est VÉRIFIÉE par sha256sum contre le pin ARG de l'arch ;
#    toute non-correspondance (ou pin manquant) FAIT ÉCHOUER le build (set -e + exit 1).
# Si tu préfères les MONTER depuis l'hôte (toolkit existant) plutôt que les embarquer,
# construis en `mini` et bind-monte /usr/local/bin/{httpx,nuclei,subfinder} via compose.
RUN set -eux; \
    if [ "${FORGE_TOOLS_PROFILE}" != "full" ]; then \
        echo "[forge] FORGE_TOOLS_PROFILE=${FORGE_TOOLS_PROFILE} (mini) -> outils ProjectDiscovery OMIS ; modules recon/web -> available:false."; \
        exit 0; \
    fi; \
    case "${TARGETARCH}" in \
      amd64) HX_SHA="${HTTPX_SHA256_amd64}"; NU_SHA="${NUCLEI_SHA256_amd64}"; SF_SHA="${SUBFINDER_SHA256_amd64}";; \
      arm64) HX_SHA="${HTTPX_SHA256_arm64}"; NU_SHA="${NUCLEI_SHA256_arm64}"; SF_SHA="${SUBFINDER_SHA256_arm64}";; \
      *) echo "[forge] FATAL: TARGETARCH=${TARGETARCH} non supporté (amd64|arm64) pour les pins SHA256." >&2; exit 1;; \
    esac; \
    base="https://github.com/projectdiscovery"; \
    fetch() { \
        name="$1"; ver="$2"; sha="$3"; \
        if [ -z "${sha}" ]; then echo "[forge] FATAL: pin SHA256 absent pour ${name}/${TARGETARCH} — refus de télécharger non vérifié." >&2; exit 1; fi; \
        url="${base}/${name}/releases/download/v${ver}/${name}_${ver}_linux_${TARGETARCH}.zip"; \
        curl -fsSL --http1.1 --retry 5 --retry-delay 3 --retry-connrefused --retry-all-errors --connect-timeout 30 --max-time 300 "$url" -o "/tmp/${name}.zip"; \
        echo "${sha}  /tmp/${name}.zip" | sha256sum -c -; \
        unzip -o "/tmp/${name}.zip" "${name}" -d /usr/local/bin/; \
        chmod +x "/usr/local/bin/${name}"; \
        rm -f "/tmp/${name}.zip"; \
    }; \
    fetch httpx "${HTTPX_VERSION}" "${HX_SHA}"; \
    fetch nuclei "${NUCLEI_VERSION}" "${NU_SHA}"; \
    fetch subfinder "${SUBFINDER_VERSION}" "${SF_SHA}"

# Moteur PDF (weasyprint) — profil `full` uniquement, pour que `?format=pdf` marche clé-en-main.
# ── weasyprint est PUR-PYTHON (pip), il n'ajoute NI Go NI Ruby (la claim de composition tient).
#    Ses dépendances natives (pango/cairo/gdk-pixbuf/ffi) sont des libs C — même catégorie que
#    nmap, déjà présent — installées via apt. Isolé dans un venv pour respecter PEP 668 (Debian
#    externally-managed) ; `weasyprint` est symlinké dans /usr/local/bin pour que le lookup PATH
#    de la console (which_in_path("weasyprint")) le trouve.
# ── En `mini`, ce bloc s'auto-court-circuite : `?format=pdf` répond `pdf_unavailable` et pointe
#    vers l'impression navigateur (?format=html + « Enregistrer au format PDF »). Aucun moteur embarqué.
RUN set -eux; \
    if [ "${FORGE_TOOLS_PROFILE}" != "full" ]; then \
        echo "[forge] FORGE_TOOLS_PROFILE=${FORGE_TOOLS_PROFILE} (mini) -> pas de moteur PDF ; ?format=pdf -> pdf_unavailable (impression navigateur dispo)."; \
        exit 0; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        python3-pip python3-venv \
        libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi8 \
        fonts-dejavu-core; \
    python3 -m venv /opt/pdfenv; \
    /opt/pdfenv/bin/pip install --no-cache-dir --upgrade pip; \
    /opt/pdfenv/bin/pip install --no-cache-dir weasyprint; \
    ln -sf /opt/pdfenv/bin/weasyprint /usr/local/bin/weasyprint; \
    rm -rf /var/lib/apt/lists/*

# --- Application ---------------------------------------------------------------
# FORGE_PKG_DIR = racine où vit le package python `forge/` ET le scope.json par défaut.
WORKDIR /opt/forge

# Binaire console depuis le builder.
COPY --from=builder /out/forge /usr/local/bin/forge

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
    FORGE_CONSOLE_DB=/data/db/forge.db \
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
#   FORGE_CONSOLE_PASS_HASH       hash argon2id du rôle viewer    (`forge hashpw <pw>`)
#   FORGE_CONSOLE_OPERATOR_HASH   hash argon2id du rôle opérateur (`forge hashpw-operator <pw>`)
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

# Sonde de LIVENESS réelle (pas un simple TCP port-open) : GET /health -> attend HTTP 200.
# /health est PUBLIC (hors auth_guard) mais SOUS host_guard (anti-DNS-rebinding) : la sonde DOIT
# donc envoyer un Host autorisé. En visant http://127.0.0.1:7100/, urllib pose `Host: 127.0.0.1:7100`
# ; host_guard retire le port -> `127.0.0.1`, présent dans l'allowlist PAR DÉFAUT (localhost,
# 127.0.0.1, ::1). Vérifié en exécutant le binaire : Host 127.0.0.1 -> 200 (healthy) ; Host étranger
# -> 421 (unhealthy). python3 est déjà dans l'image (la console spawn `python3 -m forge.cli`).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python3", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7100/health', timeout=3).getcode()==200 else 1)"]

# Persistance hors cycle de vie du conteneur.
VOLUME ["/data/db", "/data/ledger", "/data/scope"]

# tini = PID 1 (reaping propre des enfants `python3 -m forge.cli` spawnés par la console).
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["forge"]

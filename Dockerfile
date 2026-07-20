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
# CONTEXTE DE BUILD = la RACINE DE CE DÉPÔT. Le crate `console/` résout `guatx-core` via une
#    git-dep publique ÉPINGLÉE (`git = "https://github.com/guatxlabs/core", tag = "v0.1.0"`,
#    cf. console/Cargo.toml) — core est récupéré depuis GitHub AU BUILD, aucun crate sibling
#    requis dans le contexte. Un clone STANDALONE de ce dépôt construit directement :
#
#        docker build -t forge:0.0.1 .        # depuis la racine du dépôt
#    ou  docker compose ... up -d --build     # (docker-compose.yml, context: .)
#
# ── Dépendance `core/` (guatx-core) : git-dep, plus de sibling ────────────────
#    console/Cargo.toml : `guatx-core = { git = "…/guatxlabs/core", tag = "v0.1.0" }`.
#    La migration path→git-dep est FAITE : le builder ne copie plus `core/`, le contexte est
#    le dépôt lui-même. En DEV monorepo, `console/.cargo/config.toml` (GITIGNORÉ) porte un
#    `[patch]` qui override la git-dep vers le core local — absent des clones publics.
#
# ── Ignore du contexte de build ──────────────────────────────────────────────
#    Le contexte = la racine du dépôt. On utilise l'ignore-file SPÉCIFIQUE au Dockerfile
#    (fonction BuildKit) : `Dockerfile.dockerignore`.
#    BuildKit le préfère à un `.dockerignore` racine quand il existe à côté du Dockerfile
#    référencé par `-f`. Ses motifs sont relatifs à la RACINE du contexte (le dépôt). Il
#    exclut ~1.6 GB de `console/target/`, les *.db/*.jsonl/ledger/secrets — cf. ce fichier.
#
# ── Profils d'outils (FORGE_TOOLS_PROFILE=full|mini) ─────────────────────────
#    `full` (défaut) : embarque httpx/nuclei/subfinder (téléchargés + VÉRIFIÉS SHA256) et
#      un moteur PDF (weasyprint, pip, pur-Python) → `?format=pdf` clé-en-main.
#    `mini` : OMET ces outils ; les modules dégradent proprement (available:false, déjà géré)
#      et `?format=pdf` répond `pdf_unavailable` (l'impression navigateur reste dispo).
#      Build mini : `docker build --build-arg FORGE_TOOLS_PROFILE=mini .`
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

# Le crate console résout guatx-core via git-dep (tag v0.1.0) — aucun sibling à copier.
COPY console/ ./console/
# VERSION vit à la racine du dépôt : la console la lit à la COMPILATION via
# `include_str!(CARGO_MANIFEST_DIR "/../VERSION")` = /build/VERSION. Il faut donc la
# copier explicitement (elle n'est pas sous console/ que COPY ci-dessus embarque).
COPY VERSION ./VERSION

WORKDIR /build/console

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
    --mount=type=cache,target=/build/console/target \
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

# Suite ÉTENDUE de scanners (profil `full` uniquement) — binaires Go/Rust téléchargés + VÉRIFIÉS SHA256.
# Versions pinnées (bump = re-télécharger l'asset + recalculer sha256sum). Pins amd64 UNIQUEMENT :
# le bloc d'installation ci-dessous se court-circuite proprement sur les autres arches (les modules
# correspondants dégradent alors en available:false — déjà géré par l'engine). Chaque digest a été
# calculé sur l'asset officiel EXACT et le binaire exécuté (--version) avant d'être épinglé ici.
ARG DNSX_VERSION=1.3.0
ARG DNSX_SHA256_amd64=1415020474886151a4820c62b9e68a315cc062f7f111a2fd13fda99047a809a6
ARG NAABU_VERSION=2.6.1
ARG NAABU_SHA256_amd64=018c4c9884dea971eda860435ede3021d1150732f34cfd245498c6726d8cab90
ARG KATANA_VERSION=1.6.1
ARG KATANA_SHA256_amd64=503754f1bd370c3ef287df6998e317baed2dd75bdd13ea64034f09b80ca393f3
ARG AMASS_VERSION=5.1.1
ARG AMASS_SHA256_amd64=5e22b5f0239e7eb79439d60d43d3cd20dca2478588bc2242e91ab0c4f8fa40dd
ARG GAU_VERSION=2.2.4
ARG GAU_SHA256_amd64=10e2e248c37cafb0be3f6d2931125296b95cd4186066d596d47fa417237529a9
ARG GOSPIDER_VERSION=1.1.6
ARG GOSPIDER_SHA256_amd64=41bdd76aff8d063655dc473f035ca7659f8549fbf264be5185f50d288666f93d
ARG DALFOX_VERSION=3.1.2
ARG DALFOX_SHA256_amd64=ef48d30c183cead88eb89da10bdc1a7fa58a484d175319096075b470f3652fd4
ARG FEROXBUSTER_VERSION=2.13.1
ARG FEROXBUSTER_SHA256_amd64=7985c00e6803b0f25d5e9139f7472279f3f4d891429627a5cedc629e53992d80
ARG FFUF_VERSION=2.2.1
ARG FFUF_SHA256_amd64=86307885810d3c36ba4a3e9ba5178c2d9027bba0dd7f4ea39e39e7c972b62396

LABEL org.opencontainers.image.title="forge" \
      org.opencontainers.image.description="Forge red-team console (ROE fail-closed + ledger tamper-evident) — usage autorisé uniquement." \
      org.opencontainers.image.vendor="GuatX" \
      org.opencontainers.image.source="https://guatx.com"

# Dépendances runtime :
#   - python3            : la console spawn `python3 -m forge.cli` (cœur pur-stdlib, zéro pip) ;
#   - ca-certificates    : TLS sortant (httpx/nuclei/connecteurs REST) ;
#   - nmap               : module recon.nmap_scan ;
#   - dnsutils           : fournit `dig` — ToolSpec `recon.dig` (lookup DNS gouverné) + repli natif de
#                          recon.dns / subdomain.takeover. Ajout MINIMAL (dig seul) ; le reste du catalogue
#                          d'outils se monte sans rebuild via /opt/tools (cf. docker-compose.yml), on n'embarque
#                          donc PAS toute la boîte à outils dans l'image.
#   - curl, unzip        : récupération des binaires PD ci-dessous ;
#   - tini               : init PID 1 (reaping des process enfants spawnés par la console).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        ca-certificates \
        nmap \
        dnsutils \
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

# =============================================================================
# Suite ÉTENDUE de scanners (profil `full` uniquement) — pour que les modules du catalogue
# (forge/modules/toolcatalog.py) qui restaient `available:false` faute de binaire deviennent
# disponibles et que la couverture Forge ÉGALE celle d'un scan manuel. Chaque outil est
# installé sous le NOM EXACT que le module sonde via `shutil.which(...)` (runner.available) :
#   apt        : whatweb, masscan, wafw00f, wfuzz, sqlmap, gobuster
#   git+wrap   : testssl.sh (drwetter/testssl.sh, sondé "testssl.sh"), nikto (sullo/nikto, "nikto")
#   release Go : dnsx, naabu, katana (ProjectDiscovery), amass (OWASP), gau, gospider, dalfox,
#                feroxbuster, ffuf  — binaires statiques, digests SHA256 pinnés (ARG ci-dessus)
# NON installés (par design) : zap-baseline (web.zap_baseline, prefer_docker → image zaproxy/zap-stable),
#   Burp (burp.py) et Metasploit (msf.py) restent des SERVICES EXTERNES pilotés via ENV/réseau, jamais
#   cuits dans l'image ; theHarvester (recon.theharvester) est OMIS ici (son PyPI est un placeholder v0.0.1
#   et la version amont exige Python>=3.12 alors que la base bookworm fournit 3.11) → reste joignable via
#   son docker_image `laramies/theharvester` si l'opérateur monte docker.
# En `mini`, CHAQUE bloc ci-dessous s'auto-court-circuite (exit 0) → les modules dégradent proprement
# en available:false (déjà géré par l'engine). Le profil `mini` reste donc BYTE-IDENTIQUE à avant.
# =============================================================================

# (1) Outils packagés apt + dépendances runtime des binaires/scripts installés plus bas :
#   - libpcap0.8                    : requis par naabu (release Go liée à libpcap) ;
#   - perl + libnet-ssleay/json/xml : requis par nikto (nikto.pl + modules Perl JSON/XML::Writer/SSL) ;
#   - procps (ps) + bsdmainutils (hexdump) + openssl : requis par testssl.sh au runtime ;
#   - git                           : clone de testssl.sh et nikto (bloc 2).
RUN set -eux; \
    if [ "${FORGE_TOOLS_PROFILE}" != "full" ]; then \
        echo "[forge] mini -> suite scanner étendue (apt) OMISE ; modules recon/web/sqli/xss -> available:false."; \
        exit 0; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        sqlmap whatweb wafw00f wfuzz masscan gobuster \
        git bsdmainutils procps openssl libpcap0.8 \
        perl libnet-ssleay-perl libjson-perl libxml-writer-perl; \
    rm -rf /var/lib/apt/lists/*

# (2) Outils clonés depuis git, ÉPINGLÉS à un commit de release PRÉCIS (reproductibilité + cohérence
#   avec la promesse « tous les outils vérifiés/immuables » : l'ancien `git clone --depth 1` suivait le
#   HEAD flottant de la branche par défaut → build non reproductible, upstream mutable). Les SHA
#   ci-dessous ont été relevés via `git ls-remote` au moment du pin et sont les SOMMETS des tags de
#   release indiqués (immuables). L'idéal serait un checksum de tarball signé ; le pin par SHA de commit
#   est la garantie git-native la plus forte à ce jour.
#     testssl.sh -> ae939a9faa19e2e603673eb954ca0b2900b0798a  (tag v3.2.4)
#     nikto      -> 150cb9ef535eda24964253728374beddeed42607  (tag 2.5.0)
#   Le NOM sur PATH DOIT matcher ce que le module sonde : web.testssl -> "testssl.sh" (binary="testssl.sh") ;
#   web.nikto -> "nikto". (Clone complet puis checkout du SHA — un `--depth 1` ne peut pas cibler un SHA
#   arbitraire ; le .git est supprimé ensuite, pas d'empreinte inutile dans la couche.)
RUN set -eux; \
    TESTSSL_SHA=ae939a9faa19e2e603673eb954ca0b2900b0798a; \
    NIKTO_SHA=150cb9ef535eda24964253728374beddeed42607; \
    if [ "${FORGE_TOOLS_PROFILE}" != "full" ]; then \
        echo "[forge] mini -> testssl.sh / nikto OMIS ; web.testssl & web.nikto -> available:false."; \
        exit 0; \
    fi; \
    git clone https://github.com/drwetter/testssl.sh /opt/testssl.sh; \
    git -C /opt/testssl.sh checkout -q "${TESTSSL_SHA}"; \
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh; \
    git clone https://github.com/sullo/nikto /opt/nikto; \
    git -C /opt/nikto checkout -q "${NIKTO_SHA}"; \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto; \
    rm -rf /opt/testssl.sh/.git /opt/nikto/.git

# (3) Binaires release (Go/Rust), digests SHA256 pinnés — amd64 uniquement (pins calculés+vérifiés).
#   Sur une arche non-amd64 le bloc se court-circuite : les modules dégradent en available:false (les
#   outils apt/git ci-dessus, eux, restent dispo sur toute arche). Toute non-correspondance SHA -> build
#   ÉCHOUE (sha256sum -c). Noms sur PATH = noms sondés : dnsx/naabu/katana/amass/gau/gospider/dalfox/
#   feroxbuster (recon.*, xss.dalfox) et ffuf (recon.content, binary="ffuf").
RUN set -eux; \
    if [ "${FORGE_TOOLS_PROFILE}" != "full" ]; then \
        echo "[forge] mini -> binaires Go étendus OMIS ; modules recon/xss/fuzz -> available:false."; \
        exit 0; \
    fi; \
    if [ "${TARGETARCH}" != "amd64" ]; then \
        echo "[forge] TARGETARCH=${TARGETARCH}: binaires Go étendus (dnsx/naabu/katana/amass/gau/gospider/dalfox/feroxbuster/ffuf) OMIS (pins amd64 uniquement) -> available:false sur cette arche ; outils apt/git restent dispo."; \
        exit 0; \
    fi; \
    cd /tmp; B=/usr/local/bin; \
    dl() { \
        curl -fsSL --http1.1 --retry 5 --retry-delay 3 --retry-connrefused --retry-all-errors \
            --connect-timeout 30 --max-time 300 "$1" -o "$3"; \
        echo "$2  $3" | sha256sum -c -; \
    }; \
    dl "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip" "${DNSX_SHA256_amd64}" dnsx.zip; \
    unzip -o dnsx.zip dnsx -d "$B/"; \
    dl "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" "${NAABU_SHA256_amd64}" naabu.zip; \
    unzip -o naabu.zip naabu -d "$B/"; \
    dl "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" "${KATANA_SHA256_amd64}" katana.zip; \
    unzip -o katana.zip katana -d "$B/"; \
    dl "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_linux_amd64.tar.gz" "${AMASS_SHA256_amd64}" amass.tgz; \
    tar -xzf amass.tgz --strip-components=1 -C "$B" "amass_linux_amd64/amass"; \
    dl "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_amd64.tar.gz" "${GAU_SHA256_amd64}" gau.tgz; \
    tar -xzf gau.tgz -C "$B" gau; \
    dl "https://github.com/jaeles-project/gospider/releases/download/v${GOSPIDER_VERSION}/gospider_v${GOSPIDER_VERSION}_linux_x86_64.zip" "${GOSPIDER_SHA256_amd64}" gospider.zip; \
    unzip -o -j gospider.zip "*/gospider" -d "$B/"; \
    dl "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-x86_64.tar.gz" "${DALFOX_SHA256_amd64}" dalfox.tgz; \
    tar -xzf dalfox.tgz --strip-components=1 -C "$B" "dalfox-v${DALFOX_VERSION}-linux-x86_64/dalfox"; \
    dl "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/x86_64-linux-feroxbuster.tar.gz" "${FEROXBUSTER_SHA256_amd64}" ferox.tgz; \
    tar -xzf ferox.tgz -C "$B" feroxbuster; \
    dl "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" "${FFUF_SHA256_amd64}" ffuf.tgz; \
    tar -xzf ffuf.tgz -C "$B" ffuf; \
    chmod +x "$B/dnsx" "$B/naabu" "$B/katana" "$B/amass" "$B/gau" "$B/gospider" "$B/dalfox" "$B/feroxbuster" "$B/ffuf"; \
    rm -f /tmp/*.zip /tmp/*.tgz

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
COPY forge/            /opt/forge/forge/
COPY console/web/      /opt/forge/console/web/
COPY pyproject.toml    /opt/forge/pyproject.toml
COPY scope.example.json /opt/forge/scope.example.json

# Répertoires de données persistés (déclarés en volumes) : DB console, ledger d'engagement,
# scope/ROE actif. Vides dans l'image — remplis par bind/named volumes au run.
#
# Points de montage OPT-IN pour l'outillage opérateur SANS rebuild (cf. docker-compose.yml, tous commentés
# par défaut) — créés VIDES ici pour que les binds `:ro` aient une cible existante ET lisible par le user
# non-root, et pour que /opt/tools existe sur le PATH même sans montage :
#   /opt/tools         → binaires & scripts AUTO-CONTENUS exécutables déposés par l'opérateur ; AJOUTÉ AU
#                        PATH (ENV ci-dessous) → résolus par `runner.tool`/`shutil.which` au run (un ToolSpec
#                        `binary: X` devient exécutable dès que /opt/tools/X existe). Ramassé sans redémarrage.
#   /opt/forge/plugins → modules Python `@register` utilisateur (via FORGE_PLUGINS) — CODE ARBITRAIRE, haute
#                        confiance opérateur ; chargés au boot / à la re-sonde du catalogue.
#   /opt/toolspecs     → ToolSpecs déclaratifs JSON/YAML (via FORGE_TOOLSPECS) — gouvernés, ZÉRO code ;
#                        fusionnés avec le dossier server-managed (les specs opérateur restent chargés).
RUN mkdir -p /data/db /data/ledger /data/scope /opt/tools /opt/forge/plugins /opt/toolspecs

# Utilisateur non-root (least privilege) — la console bind un port haut (>1024), pas besoin de root.
# Les dossiers de montage opt-in sont chownés au user pour rester LISIBLES même sous un bind `:ro`
# (le contenu monté est en lecture seule ; le user a seulement besoin de le LIRE/EXÉCUTER).
RUN useradd --system --create-home --uid 10001 forge \
    && chown -R forge:forge /opt/forge /data /opt/tools /opt/toolspecs
USER forge

# --- Configuration (ENV documentées) ------------------------------------------
# Console (Rust) :
# PATH : /opt/tools EN TÊTE → un binaire/script exécutable monté par l'opérateur (docker-compose.yml,
# bind `./tools:/opt/tools:ro`) est résolu par `runner.tool` (shutil.which) SANS rebuild. Dossier
# opérateur-contrôlé (vide dans l'image par défaut) : le préfixer est sûr et voulu (il n'ombre rien tant
# que l'opérateur n'y dépose pas délibérément un binaire homonyme). Le reste du PATH système est préservé.
# FORGE_CONSOLE_ADDR : bind LOOPBACK-STRICT par défaut (safe-by-default). Auparavant `0.0.0.0:7100` →
# un `docker run --network=host forge` SANS l'override de compose exposait la console sur tout le LAN.
# Défaut = 127.0.0.1:7100 ; exposer sur toutes les interfaces est un OPT-IN EXPLICITE (compose fixe déjà
# 127.0.0.1 explicitement ; k8s remet 0.0.0.0:7100 explicitement dans le Deployment console — sûr derrière
# ClusterIP + NetworkPolicy default-deny + PSA — pour que le Service atteigne le conteneur dans le pod).
ENV PATH="/opt/tools:${PATH}" \
    FORGE_CONSOLE_ADDR=127.0.0.1:7100 \
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

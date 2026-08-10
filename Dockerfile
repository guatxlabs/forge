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
#    git-dep publique ÉPINGLÉE (`git = "https://github.com/guatxlabs/core", tag = "v0.2.1"`,
#    cf. console/Cargo.toml) — core est récupéré depuis GitHub AU BUILD, aucun crate sibling
#    requis dans le contexte. Un clone STANDALONE de ce dépôt construit directement :
#
#        docker build -t forge:0.0.1 .        # depuis la racine du dépôt
#    ou  docker compose ... up -d --build     # (docker-compose.yml, context: .)
#
# ── Dépendance `core/` (guatx-core) : git-dep, plus de sibling ────────────────
#    console/Cargo.toml : `guatx-core = { git = "…/guatxlabs/core", tag = "v0.2.1" }`.
#    Le builder ne copie aucun crate voisin : le contexte est le dépôt lui-même, core est
#    résolu par cargo depuis GitHub. (Un `console/.cargo/config.toml` local, gitignoré, peut
#    rediriger la git-dep vers une copie locale du crate pour itérer — jamais dans un clone.)
#
# ── Ignore du contexte de build ──────────────────────────────────────────────
#    Le contexte = la racine du dépôt. On utilise l'ignore-file SPÉCIFIQUE au Dockerfile
#    (fonction BuildKit) : `Dockerfile.dockerignore`.
#    BuildKit le préfère à un `.dockerignore` racine quand il existe à côté du Dockerfile
#    référencé par `-f`. Ses motifs sont relatifs à la RACINE du contexte (le dépôt). Il
#    exclut ~1.6 GB de `console/target/`, les *.db/*.jsonl/ledger/secrets — cf. ce fichier.
#
# ── Profils d'outils (FORGE_TOOLS_PROFILE=full|mini) ─────────────────────────
#    `full` (défaut) : embarque les outils du MANIFESTE `forge/tools.json` (téléchargés +
#      VÉRIFIÉS SHA256) et un moteur PDF (weasyprint, pip, pur-Python) → `?format=pdf` clé-en-main.
#    `mini` : OMET ces outils ; les modules dégradent proprement (available:false, déjà géré)
#      et `?format=pdf` répond `pdf_unavailable` (l'impression navigateur reste dispo).
#      Build mini : `docker build --build-arg FORGE_TOOLS_PROFILE=mini .`
#    Le profil reste une décision de BUILD. Pour ajouter/mettre à jour un outil SANS rebuild,
#      cf. `forge tools install|update|remove` (volume outils persistant /data/tools, en tête du
#      PATH) — même manifeste, même vérification SHA256, journalisé au ledger.
#
# Services EXTERNES (jamais embarqués ici — montés/réseau, cf. docker-compose.yml & ENV) :
#   - automatisation navigateur (HTTP, :8080)    → FORGE_BROWSER_URL
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

# Le crate console résout guatx-core via git-dep (tag v0.2.1) — aucun sibling à copier.
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
ARG TARGETARCH=amd64

# ── MANIFESTE UNIQUE des outils téléchargés — `forge/tools.json` ─────────────────────────────
# Les versions et les empreintes SHA256 des binaires de sécurité (httpx, nuclei, subfinder, dnsx,
# naabu, katana, amass, gau, gospider, dalfox, feroxbuster, ffuf) NE SONT PLUS des ARG codés en dur
# ici (ni recopiés dans docker-compose.yml) : elles vivent dans `forge/tools.json`, LU par ce
# Dockerfile au build ET par l'installeur runtime (`forge tools install|update`). Une seule copie,
# donc plus de divergence Dockerfile↔compose possible (garde : tests/test_tools_manifest.py).
# Bump d'une version = éditer `forge/tools.json` (version + digests du `*_checksums.txt` amont).
# L'intégrité reste identique : chaque archive est vérifiée par `sha256sum -c` contre le pin de son
# architecture ; pas de pin -> l'outil est ÉCARTÉ du plan (jamais téléchargé non vérifié).

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

# Le MANIFESTE + son lecteur, copiés AVANT le bloc d'installation (le reste du package `forge/`
# arrive plus bas). `toolsmanifest.py` est un script AUTONOME (stdlib, zéro import relatif) : il
# tourne donc ici, avant que le package ne soit en place. Cette COPY précoce est aussi la bonne
# invalidation de cache : bumper un pin dans tools.json ré-exécute le téléchargement, et rien d'autre.
COPY forge/tools.json forge/toolsmanifest.py /opt/forge/forge/

# Outils offensifs téléchargés (binaires Go/Rust statiques) — LE PLAN VIENT DU MANIFESTE.
# Un SEUL bloc pour toute la suite (socle ProjectDiscovery httpx/nuclei/subfinder + suite étendue
# dnsx/naabu/katana/amass/gau/gospider/dalfox/feroxbuster/ffuf) : le manifeste porte, par outil,
# la version, l'URL, le membre d'archive et le digest PAR ARCHITECTURE — il n'y a plus de valeurs
# recopiées dans ce fichier, donc plus rien à garder synchronisé.
# ── Profil : `full` uniquement. En `mini`, le bloc s'auto-court-circuite (exit 0) et les modules
#    dégradent en available:false (déjà géré par l'engine, cf. runner.available).
# ── Supply-chain (INCHANGÉE) : chaque archive est VÉRIFIÉE par `sha256sum -c` contre le pin de son
#    architecture ; toute non-correspondance FAIT ÉCHOUER le build (set -e). Un outil sans pin pour
#    l'arch cible est ÉCARTÉ du plan (jamais téléchargé non vérifié) et signalé sur stderr — c'est
#    le cas de la suite étendue hors amd64, exactement comme avant. `--require-complete core`
#    garde le socle : un pin manquant sur httpx/nuclei/subfinder fait ÉCHOUER le build, jamais une
#    image silencieusement amputée.
# ── Les trois `${FORGE_BUILD_*:-…}` ne sont PAS des réglages opérateur : ce sont les seams qui
#    permettent au test `tests/test_tools_manifest.py` d'EXÉCUTER cette boucle hors Docker (curl/
#    sha256sum/unzip/tar stubés) et de prouver qu'elle consomme le manifeste correctement. Non
#    positionnés (le cas du build réel), les défauts s'appliquent → comportement inchangé.
# Si tu préfères MONTER les binaires depuis l'hôte plutôt que les embarquer, construis en `mini` et
# bind-monte /opt/tools via compose (déjà en tête du PATH).
RUN set -eux; \
    MANIFEST_PY="${FORGE_BUILD_MANIFEST_PY:-/opt/forge/forge/toolsmanifest.py}"; \
    BINDIR="${FORGE_BUILD_BINDIR:-/usr/local/bin}"; \
    STAGE="${FORGE_BUILD_STAGE:-/var/tmp/forge-tools}"; \
    if [ "${FORGE_TOOLS_PROFILE}" != "full" ]; then \
        echo "[forge] FORGE_TOOLS_PROFILE=${FORGE_TOOLS_PROFILE} (mini) -> outils téléchargés OMIS ; modules recon/web -> available:false."; \
        exit 0; \
    fi; \
    case "${TARGETARCH}" in \
      amd64|arm64) ;; \
      *) echo "[forge] FATAL: TARGETARCH=${TARGETARCH} non supporté (amd64|arm64) pour les pins SHA256." >&2; exit 1;; \
    esac; \
    rm -rf "$STAGE"; mkdir -p "$STAGE"; \
    python3 "$MANIFEST_PY" --arch "${TARGETARCH}" --profile full --require-complete core > "$STAGE/plan.tsv"; \
    while read -r name version archive sha strip member bin url; do \
        [ -n "$name" ] || continue; \
        echo "[forge] outil ${name} ${version} (${archive}, ${TARGETARCH})"; \
        rm -rf "$STAGE/x"; mkdir -p "$STAGE/x"; \
        curl -fsSL --http1.1 --retry 5 --retry-delay 3 --retry-connrefused --retry-all-errors \
             --connect-timeout 30 --max-time 300 "$url" -o "$STAGE/archive.bin"; \
        echo "${sha}  $STAGE/archive.bin" | sha256sum -c -; \
        case "$archive" in \
          zip)    unzip -o -j "$STAGE/archive.bin" "$member" -d "$STAGE/x" ;; \
          tar.gz) tar -xzf "$STAGE/archive.bin" --strip-components="$strip" -C "$STAGE/x" "$member" ;; \
          *) echo "[forge] FATAL: format d'archive inconnu '${archive}' pour ${name}" >&2; exit 1 ;; \
        esac; \
        install -m 0755 "$STAGE/x/${member##*/}" "$BINDIR/$bin"; \
        rm -f "$STAGE/archive.bin"; \
    done < "$STAGE/plan.tsv"; \
    rm -rf "$STAGE"

# =============================================================================
# Suite ÉTENDUE de scanners (profil `full` uniquement) — pour que les modules du catalogue
# (forge/modules/toolcatalog.py) qui restaient `available:false` faute de binaire deviennent
# disponibles et que la couverture Forge ÉGALE celle d'un scan manuel. Chaque outil est
# installé sous le NOM EXACT que le module sonde via `shutil.which(...)` (runner.available) :
#   apt        : whatweb, wafw00f, wfuzz, sqlmap, gobuster
#   git+wrap   : testssl.sh (drwetter/testssl.sh, sondé "testssl.sh"), nikto (sullo/nikto, "nikto")
#   release Go : dnsx, naabu, katana (ProjectDiscovery), amass (OWASP), gau, gospider, dalfox,
#                feroxbuster, ffuf — DÉJÀ installés PLUS HAUT par la boucle pilotée par le manifeste
#                (`forge/tools.json`, groupe `extended`) ; ils ne sont plus décrits ici.
# NON installés (par design) : zap-baseline (web.zap_baseline, prefer_docker → image zaproxy/zap-stable),
#   Burp (burp.py) et Metasploit (msf.py) restent des SERVICES EXTERNES pilotés via ENV/réseau, jamais
#   cuits dans l'image. theHarvester et masscan ont été RETIRÉS du catalogue (2026-08-09) : le premier
#   n'a aucune image utilisable (`laramies/theharvester` n'existe pas ; l'officielle ghcr.io lance un
#   SERVEUR REST, pas la CLI), le second se TAIT sans échouer sur une machine multi-homed (rc=0, stdout
#   vide) — donc son argv corrigé aurait produit un `tested` mensonger là où l'échec produisait un
#   `skipped` juste. `recon.naabu` couvre les ports ; `subfinder`/`amass`/crt.sh couvrent les sous-domaines.
#   gospider a été RETIRÉ à son tour (2026-08-10) : aucune image publiée en amont, et `katana` — même
#   fonction, image officielle — le couvre. Le binaire `gospider` n'est donc plus utile ici ; il reste
#   dans `tools.json` (groupe extended) tant que le manifeste n'est pas re-coupé, sans module qui le sonde.
# DEPUIS 2026-08-10 : les modules de ce catalogue déclarent des IMAGES DOCKER VÉRIFIÉES (feroxbuster,
#   gau, amass, nikto, testssl, wpscan, dalfox). Elles ne changent RIEN à cette image (pas de démon
#   docker dedans → la voie binaire reste la seule ici) : elles servent aux déploiements où Forge tourne
#   à côté d'un docker (standalone/dev), où ces outils étaient purement indisponibles.
# En `mini`, CHAQUE bloc ci-dessous s'auto-court-circuite (exit 0) → les modules dégradent proprement
# en available:false (déjà géré par l'engine). Le profil `mini` reste donc BYTE-IDENTIQUE à avant.
# =============================================================================

# (1) Outils packagés apt + dépendances runtime des binaires/scripts installés ailleurs :
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
        sqlmap whatweb wafw00f wfuzz gobuster \
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

# (3) WORDLIST PAR DÉFAUT DE feroxbuster — CE N'EST PAS UN CONFORT, C'EST LA FERMETURE D'UN SILENCE.
#   MESURÉ dans CETTE image, avant ce bloc : `feroxbuster --silent -u <cible>` sort **rc=0 avec un
#   stdout VIDE**, le motif n'apparaissant que sur stderr (« Could not open /usr/share/seclists/
#   Discovery/Web-Content/raft-medium-directories.txt »). Or `blindness.tool_did_not_run` borne son
#   rattrapage à `rc != 0` : le module concluait donc « recon.feroxbuster — aucun hit », c'est-à-dire
#   « j'ai vérifié, rien trouvé », sur une cible JAMAIS balayée. C'est le motif exact qui a fait
#   RETIRER masscan du catalogue — sauf qu'ici il frappait l'outil de découverte de contenu n°1, dans
#   l'image livrée, à chaque action. La voie docker (image `epi052/feroxbuster`, qui embarque sa liste)
#   ne sauve pas ce cas : DANS le conteneur Forge il n'y a pas de démon docker, donc le binaire local
#   est la SEULE voie possible.
#   POURQUOI LA VRAIE LISTE, ET PAS UN LIEN VERS CELLE DE wfuzz (déjà présente) : le chemin est le
#   défaut COMPILÉ de feroxbuster ; y poser un fichier qui n'est pas SecLists sous le nom
#   `raft-medium-directories.txt` mentirait à quiconque inspecte l'image. On télécharge donc le
#   fichier RÉEL (250 Ko), depuis un TAG immuable, ÉPINGLÉ PAR SHA256 — même discipline d'intégrité
#   que la boucle du manifeste plus haut. Aucun chemin machine-spécifique n'entre dans le catalogue :
#   le spec continue de n'avoir AUCUN défaut en dur (`params.wordlist` reste le seul réglage).
RUN set -eux; \
    SECLISTS_TAG=2024.3; \
    WL_SHA=862169ffa761ec93ef43b12ce43c5408f1f3d501b564b50d66bf3666a0cf50a2; \
    WL_DIR=/usr/share/seclists/Discovery/Web-Content; \
    if [ "${FORGE_TOOLS_PROFILE}" != "full" ]; then \
        echo "[forge] mini -> wordlist feroxbuster OMISE ; recon.feroxbuster -> available:false (binaire absent)."; \
        exit 0; \
    fi; \
    mkdir -p "$WL_DIR"; \
    curl -fsSL --http1.1 --retry 5 --retry-delay 3 --retry-connrefused --retry-all-errors \
         --connect-timeout 30 --max-time 300 \
         "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_TAG}/Discovery/Web-Content/raft-medium-directories.txt" \
         -o "$WL_DIR/raft-medium-directories.txt"; \
    echo "${WL_SHA}  $WL_DIR/raft-medium-directories.txt" | sha256sum -c -

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
# (On ne copie AUCUNE donnée d'engagement : .db, ledger et secrets vivent dans des volumes, cf. ENV
#  ci-dessous. Seul le jeu de démo SYNTHÉTIQUE ci-dessous est embarqué.)
COPY forge/            /opt/forge/forge/
COPY console/web/      /opt/forge/console/web/
COPY pyproject.toml    /opt/forge/pyproject.toml
COPY scope.example.json /opt/forge/scope.example.json
# Engagement de référence SYNTHÉTIQUE (hôtes `.example`, IP RFC 5737 — aucune cible réelle) :
# `forge seed-demo` le cherche sous $FORGE_PKG_DIR (= /opt/forge), donc `seed-demo` / `make demo`
# fonctionnent DANS le conteneur et pas seulement sur l'hôte. ~44 Kio.
COPY examples/         /opt/forge/examples/

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
#
# /data/tools → VOLUME OUTILS PERSISTANT (surcouche runtime, cf. `forge tools install|update|remove`).
#   Contrairement au /usr/local/bin baké — qui appartient à root et disparaît à chaque recreate du
#   conteneur — ce dossier appartient à l'utilisateur `forge` (uid 10001) et SURVIT au recreate (volume
#   nommé, cf. docker-compose.yml). `/data/tools/bin` est AJOUTÉ AU PATH (ENV plus bas), DEVANT le
#   /usr/local/bin baké : un outil installé/mis à jour au runtime prime sur la baseline SANS rebuild.
#   VIDE par défaut → aucun effet : le PATH y résout `None` et la baseline reste seule en vigueur.
RUN mkdir -p /data/db /data/ledger /data/scope /data/tools/bin /data/tools/state \
             /opt/tools /opt/forge/plugins /opt/toolspecs

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
# Puis /data/tools/bin (volume outils persistant, forge-owned) : ce que `forge tools install|update`
# y écrit PRIME sur le /usr/local/bin baké — un outil se met à jour sans rebuild. L'ORDRE est délibéré :
# le bind-mount opérateur (/opt/tools) reste le plus explicite et garde la priorité qu'il a toujours eue.
# Vides tous les deux par défaut → la résolution est IDENTIQUE à aujourd'hui tant que rien n'y est déposé.
# FORGE_CONSOLE_ADDR : bind LOOPBACK-STRICT par défaut (safe-by-default). Auparavant `0.0.0.0:7100` →
# un `docker run --network=host forge` SANS l'override de compose exposait la console sur tout le LAN.
# Défaut = 127.0.0.1:7100 ; exposer sur toutes les interfaces est un OPT-IN EXPLICITE (compose fixe déjà
# 127.0.0.1 explicitement ; k8s remet 0.0.0.0:7100 explicitement dans le Deployment console — sûr derrière
# ClusterIP + NetworkPolicy default-deny + PSA — pour que le Service atteigne le conteneur dans le pod).
ENV PATH="/opt/tools:/data/tools/bin:${PATH}" \
    FORGE_CONSOLE_ADDR=127.0.0.1:7100 \
    FORGE_CONSOLE_DB=/data/db/forge.db \
    FORGE_CONSOLE_LEDGER=/data/ledger/engagement.jsonl \
    FORGE_CONSOLE_SCOPE=/data/scope/scope.json \
    FORGE_CONSOLE_WEB=/opt/forge/console/web \
    FORGE_TOOLS_DIR=/data/tools \
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

# Persistance hors cycle de vie du conteneur. /data/tools = volume OUTILS (surcouche runtime) :
# ce que `forge tools install|update` y écrit survit à un recreate du conteneur, contrairement au
# /usr/local/bin baké. Vide par défaut → aucun changement de comportement.
VOLUME ["/data/db", "/data/ledger", "/data/scope", "/data/tools"]

# tini = PID 1 (reaping propre des enfants `python3 -m forge.cli` spawnés par la console).
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["forge"]

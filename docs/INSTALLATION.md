# Installation

[English](INSTALLATION.md) | [Français](INSTALLATION.fr.md)

> [Contents](README.md) · Next: [First deployment (wizard)](FIRST_DEPLOYMENT.md) · See also:
> [Configuration](CONFIGURATION.md) · [Detailed self-deploy runbook](DEPLOYMENT.md)

This page covers **every installation path** with the exact commands. The detailed self-deploy
runbook (measured footprint, Docker/k8s/host/venv matrix, PDF export) is in
[`DEPLOYMENT.md`](DEPLOYMENT.md).

> ℹ️ **Build context = the ROOT of this repository.** The console resolves `guatx-core` through a pinned
> public git-dep (`git = "https://github.com/guatxlabs/core", tag = "v0.2.2"`, see
> `console/Cargo.toml`) — the core is fetched from GitHub at build time, no sibling crate required. All
> the `docker build`/`docker compose` commands below are run **from the repository root** (a
> standalone clone is enough). Details: [`DEPLOYMENT.md`](DEPLOYMENT.md) §4.

## MANDATORY pre-step — the scope file (fail-loud)

The active scope/ROE is **mounted as a volume**, never baked into the image. Create the **file** before
any `up`:

```sh
# from the repository root
cp scope.example.json scope.json     # empty in_scope = INERT; edit WITH written AUTHORIZATION
```

If `scope.json` is missing, Docker creates an empty **directory** in its place; the compose entrypoint
**fails loudly** rather than starting on an unreadable scope, and falls back to the embedded
`scope.example.json` (INERT) if the file is missing/empty. `scope.json`, `*.key`, `*.jsonl`
are gitignored.

---

## 1. Image profiles: `mini` vs `full`

A single `--build-arg FORGE_TOOLS_PROFILE` switches the footprint. Modules **degrade cleanly**
(`available:false`) when a tool is missing.

| Profile | Contents | Size | `?format=pdf` | PD modules (httpx/nuclei/subfinder) |
|---|---|---|---|---|
| `mini` | console + `python3` + `nmap` | ~150-250 MB | `pdf_unavailable` (browser printing) | `available:false` |
| `full` *(default)* | + ProjectDiscovery binaries (SHA256-verified) + weasyprint PDF engine | ~350-500 MB | turnkey active | available |

---

## 2. Docker (image only)

```sh
# from the repository root
# full (default)
docker build -t forge:0.0.1 .
# mini
docker build --build-arg FORGE_TOOLS_PROFILE=mini -t forge:0.0.1-mini .

docker run -d --name forge \
  -p 127.0.0.1:7100:7100 \
  -v forge-db:/data/db -v forge-ledger:/data/ledger \
  -v "$PWD/scope.json:/data/scope/scope.json:ro" \
  --env-file .env \
  forge:0.0.1
```

Bind **loopback only**. Expose publicly only through a reverse-proxy + auth +
`FORGE_CONSOLE_HOST` (anti-DNS-rebinding host-allowlist). The image binds `0.0.0.0:7100` **inside** the
container (isolated network); the `127.0.0.1:7100:7100` mapping restricts host exposure to loopback.

---

## 3. docker-compose *(recommended)*

The compose file already sets the right context, the scope fail-loud, the volumes, the `/health` healthcheck,
the loopback bind. **Optional services behind profiles** ⇒ a bare `up` starts the **console alone**
(no hard `depends_on`).

```sh
# from the repository root
docker compose up -d --build          # console ALONE (full profile)
FORGE_TOOLS_PROFILE=mini docker compose up -d --build   # mini image

# optional layers, on demand (none is required at boot):
docker compose --profile browser up -d        # + access/evasion (Camoufox :8080)
docker compose --profile msf --profile burp up -d   # + connectors (BYO images)

docker compose config      # validate the resolved config
```

Secrets & overrides (argon2id hashes, tokens, URLs of the driven services, keys) → `.env`
(gitignored, `required:false`). Commented template: [`../.env.example`](../.env.example). The
`browser`/`msf`/`burp` connectors stay **inert** as long as their service is not reachable (probe at
fire-time). Forge does **not** provide an MSF/Burp image (operator licence/tooling) — the compose
stubs document the BYO (bring-your-own) wiring.

---

## 4. Native / systemd (without Docker)

Hardened unit provided: [`../deploy/forge.service`](../deploy/forge.service)
(`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`, seccomp `@system-service`…). The
systemd hardening **weakens no application guardrail**.

```sh
cd console && cargo build --release            # from the repository root; offline binary (cargo cache)
sudo install -m0755 target/release/forge /usr/local/bin/
sudo mkdir -p /opt/forge && sudo cp -r ../forge /opt/forge/forge && sudo cp -r web /opt/forge/console/web
sudo useradd --system --home /opt/forge --shell /usr/sbin/nologin forge
sudo mkdir -p /var/lib/forge/{db,ledger,scope}                      # fill scope/scope.json WITH AUTHORIZATION
sudo install -m0600 -o root -g forge /dev/null /etc/forge/forge.env   # argon2id hashes here
sudo cp deploy/forge.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now forge
```

The Python package is **pure-stdlib** (`deps=[]`): it also fits in a venv **with no pip dependency at all**.

---

## 5. venv / development

```sh
# from the repository root
# 1) Python engine (puts `forge` on the PATH; otherwise `python3 -m forge.cli`)
pip install -e .
# 2) Rust console (compiles offline from the cargo cache)
cd console && cargo build --release && cd ..
# 3) full suite (Python unittest + cargo test of the console, zero network)
make test
```

`pip install -e .` completes without error, `forge --version` answers, `cargo build --release` produces
`console/target/release/forge`, and `make test` ends on **`OK`**. The Python package has
**no pip dependency** — it fits in a bare venv. 100 % offline operator path (seed +
mock-Plume): [`GETTING_STARTED.md`](GETTING_STARTED.md).

---

## 6. `encryption` image (encryption AT REST — SQLCipher, opt-in)

The **default** build stores the SQLite database **in plaintext** (`capabilities.sqlcipher:false`). For
encryption at rest, compile with the `encryption` feature then provide the key at boot:

```sh
# 1) encrypted image/binary (Cargo feature -> SQLCipher backend)
cd console && cargo build --release --features encryption   # from the repository root
#    (Docker: build an image tagged forge:0.0.1-encryption with this feature)

# 2) at boot, the console reads FORGE_DB_KEY and issues `PRAGMA key` BEFORE any query (SQLCipher contract)
#    docker-compose.override.yml:
#      services:
#        forge:
#          image: forge:0.0.1-encryption
#          environment:
#            FORGE_DB_KEY: ${FORGE_DB_KEY}     # [SECRET] from .env/docker secret, NEVER committed
```

Without the correct `FORGE_DB_KEY`, the encrypted database is **unreadable** (fail-closed). Converting an existing
plaintext install → encrypted = **Runbook B** of [`MIGRATION.md`](MIGRATION.md). The wizard exposes
`capabilities.sqlcipher` (true only on this build) so that the UI reflects it honestly.

> **Apart from** crypto AT REST (opt-in), the **engagement ledger** is signed with **Ed25519**
> (asymmetric, verifiable by a third party with the public key alone) **by default** — no action
> required.

---

## Verifying the installation

```sh
# liveness
curl -s http://127.0.0.1:7100/health          # -> {"status":"ok","version":"0.0.1"}
docker inspect --format '{{.State.Health.Status}}' forge   # -> healthy

# module diagnostics (which tools are present)
python3 -m forge.cli doctor                    # or: forge doctor
```

The healthcheck performs a real **`GET /health` expecting HTTP 200** (not a mere TCP port-open). It
targets `127.0.0.1` (always in the host-guard allowlist by default), so it stays green even behind a
restricted `FORGE_CONSOLE_HOST`.

---

## After installation

Open `http://127.0.0.1:7100` → the **first-deployment wizard** provisions the admin, the crypto, the
detection source and the operator policy. See **[First deployment](FIRST_DEPLOYMENT.md)**.

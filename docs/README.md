# Forge documentation

[English](README.md) | [Français](README.fr.md)

**Forge** — a **governed** red-team assessment platform: every offensive action goes through a
*fail-closed* ROE gate and is sealed in a tamper-evident **engagement ledger**, while the
**purple** loop measures what the defense actually detected. Forge runs **standalone**
(integration with the Plume SOC is optional).

> ⚠️ **Authorized settings only** — in-scope bug bounty, contracted pentest, CTF, your own infra.
> The ROE gate + the scope-guard + the ledger are there to **enforce AND prove** authorization.
> Forge is **INERT by default**: nothing fires until the operator has armed every layer.

Documented version: **0.0.1**. This page is the table of contents. Each link points to a dedicated page.

---

## Where to start

| You are… | Start with |
|---|---|
| **A new operator** discovering the product | [Overview](OVERVIEW.md) → [Offline start](GETTING_STARTED.md) |
| **An admin/DevOps** deploying a console | [Installation](INSTALLATION.md) → [First deployment (wizard)](FIRST_DEPLOYMENT.md) |
| **An architect / CISO** evaluating | [Overview](OVERVIEW.md) → [Architecture](ARCHITECTURE.md) → [Security model](SECURITY_MODEL.md) |
| **An integrator** wiring a detection source | [Concepts: purple loop](CONCEPTS.md#5-the-purple-loop) → [Detection sources](DETECTION.md) |
| **A developer / scripter** | [CLI reference](CLI.md) → [HTTP API reference](HTTP_API.md) → [Configuration](CONFIGURATION.md) |

---

## Full table of contents

### 1. Understanding Forge

- **[Overview](OVERVIEW.md)** — what Forge is, the value proposition, standalone
  operation (Plume/purple is optional), what Forge is not.
- **[Architecture](ARCHITECTURE.md)** — how it is built: the Python engine (ROE scope-guard,
  coverage-safe planner, brain, evidence oracles, technique catalog, chaining,
  evasion-backed discovery, Ed25519 ledger, collectors), the Rust/axum console (RBAC, C2-light, DB,
  settings), the SPA, the module registry, the governance model. *(The historical rationale
  document remains [`../ARCHITECTURE.md`](../ARCHITECTURE.md).)*
- **[Concepts](CONCEPTS.md)** — ROE/scope-guard, tamper-evident ledger, evidence oracles
  (*tested-unless-proven*), module + technique catalog (ATT&CK mapping), purple loop,
  chaining, evasion-backed discovery.
- **[Module catalog](MODULES.md)** — 43 of the 88 modules of the registry are described there (MEASURED on 2026-11-24: `python3 -m forge.cli modules --json`): `kind`, capability (exploit/destructive),
  ATT&CK technique, description, dependency.
- **[Adding your own tool (from the UI)](TOOLS.md)** — declare a governed CLI tool (declarative
  ToolSpec: binary + no-shell argv + allowlist + params) without editing a file or recompiling.
- **[Tool lifecycle](TOOLS_LIFECYCLE.md)** — the **binary** (where `TOOLS.md` covers its
  declaration): single manifest `forge/tools.json` (versions + SHA256 pins per architecture), read by
  the build *and* by `forge tools install|update|remove` — install or update a tool without a
  rebuild, digest verified before anything is placed on the `PATH`, operation logged in the ledger.

### 2. Deploying & operating

- **[Installation](INSTALLATION.md)** — Docker (`mini`/`full` profiles), docker-compose (optional
  profiles), native/systemd, venv/dev, `encryption` image (SQLCipher at rest). Exact commands.
- **[First deployment](FIRST_DEPLOYMENT.md)** — the first-boot web wizard (admin, crypto, detection
  source, operator policy — nothing hard-coded).
- **[End-to-end offline start](GETTING_STARTED.md)** — 100 % offline operator walkthrough
  (seed + mock-Plume): install → scope → console → purple → report → integrity.
- **[Self-service deployment runbook](DEPLOYMENT.md)** — the detailed runbook (measured footprint,
  Docker/k8s/host/venv matrix, build context = repository root + `guatx-core` git-dep, `/health`
  liveness, PDF export).
- **[Using Forge standalone (without Plume)](STANDALONE.md)** — dedicated page: everything works
  without a SOC.

### 3. Administering

- **[Administration](ADMINISTRATION.md)** — accounts & roles (admin/operator/viewer), connector
  governance (enable/disable = "install/uninstall"), detection source
  configuration, operator policy + source-CIDR, backup/restore + scheduling/offsite,
  migration.
- **[Detection sources](DETECTION.md)** — plug in any BLUE infra **without code**
  (Plume/CrowdSec/FortiGate/pfSense/OPNsense/Elastic/OpenSearch/file/exec): `DetectionSource`
  model, presets, MITRE mapping.
- **[Plume prerequisites](PURPLE_PREREQS.md)** — the `kind=plume` preset of the purple loop.
- **[Data migration](MIGRATION.md)** — take over an existing install (DB + ledger + `.ed25519`
  key), SQLCipher encryption-at-rest option.
- **[Backup & restore](BACKUP.md)** — **always encrypted** archives (argon2id +
  XChaCha20-Poly1305), scheduling + offsite.
- **[In-UI console](CONSOLE.md)** — **governed** runner of `forge` subcommands from the UI (strict
  allowlist, **no shell**, admin-only, ledgered, streamed): removes the `docker compose exec forge forge …`
  for routine ops (`status`, `ledger verify`, `read`, `backup`, `upgrade`).

### 4. References

- **[Configuration](CONFIGURATION.md)** — COMPLETE table of **all** environment variables
  (`FORGE_CONSOLE_*`, `PLUME_URL`/`PLUME_TOKEN`, `FORGE_DB_KEY`, `FORGE_ALLOW_API_MIGRATE`,
  `FORGE_TOOLS_PROFILE`, operator/detection/backup knobs) **and** of all the keys of the
  `settings` table (name, meaning, default, example, configurable at deployment vs in the UI).
- **[CLI reference](CLI.md)** — all `forge` subcommands (`python -m forge.cli`) and
  `forge`, with their flags.
- **[HTTP API reference](HTTP_API.md)** — all console routes (method, required auth,
  purpose).

### 5. Security, troubleshooting, uninstall

- **[Security model](SECURITY_MODEL.md)** — authz, fail-closed gates, ledger integrity,
  encryption at rest, secret management, host-guard, exploit floor.
- **[Supported platforms](PLATFORMS.md)** — OS matrix (Linux primary, macOS fully
  supported, Windows best-effort): components that work everywhere vs the only Unix-only capability
  (`setsid`/`killpg` subtree kill of the governed C2 run), config/data/temp resolution per OS,
  and the `tests/test_portability_guard.py` anti-regression net.
- **[Troubleshooting & FAQ](TROUBLESHOOTING.md)** — common symptoms, diagnostics, frequently asked questions.
- **[Uninstall & data removal](UNINSTALL.md)** — stop, remove
  image/container/volumes, purge DB/ledger/keys, uninstall the tools.

### 6. Go-to-market & purple reference *(product context)*

- **[Positioning](POSITIONING.md)** — target segment, the three pillars, competitive teardown.
- **[Plan & roadmap](PLAN.md)** — blocker status, sequenced roadmap.
- **[MTTD — what the metric measures](MTTD.md)** — time-to-ALERT vs time-to-event, interpretation.
- **[Purple campaign runbook](PURPLE_CAMPAIGN.md)** — broad-recon campaign (to be launched on "go").
- **[Reference engagement template](REFERENCE_ENGAGEMENT_TEMPLATE.md)** — skeleton of the deliverable.
- **[Defects found upstream](UPSTREAM_REPORTS.md)** — minimal reproductions ready to send, for
  the third-party tool defects encountered here: they are not specific to forge, and working around them
  silently would leave other projects with the same blind spot.

---

## Concept map (in 30 seconds)

```
  cerveau (HeuristicBrain / orchestrateur Claude)
        │  propose des Actions (kind, target, exploit?, destructive?)
        ▼
  Engine ──► gate ROE ──► VETO | DRY_RUN | FIRE ──► Ledger (append-time, hash-chain + Ed25519)
        │                                  │
        │                                  ▼ (FIRE seulement)
        └──► module.fire() ──► Findings ──► report + console (findings / coverage / purple / runs)
                  ▲
        modules = OUTILS AUTONOMES orchestrés (recon, oracles à preuve, évasion, connecteurs MSF/Burp)
```

- **4-layer ROE gate** (`forge/roe.py`): *armed → in-scope → authorized capability → approved*.
  Out of scope ⇒ `VETO` (never simulated, never fired). See [Concepts](CONCEPTS.md#1-roe--scope-guard).
- **Tamper-evident ledger** (`forge/ledger.py`): SHA-256 chain + per-entry Ed25519 signature,
  verifiable by a third party with the public key alone. See [Concepts](CONCEPTS.md#2-the-engagement-ledger).
- **Purple loop**: every finding carries a `mitre` (ATT&CK) — join key with the SOC's
  detections. Detection source = **configurable plugin**. See [Concepts](CONCEPTS.md#5-the-purple-loop).

---

*Forge is a **[GuatX](https://guatx.com)** product — the governed offensive counterpart of the
blue-team SOC [Plume](https://github.com/guatxlabs/plume). Authorized / ethical use only
(see [`../LICENSE`](../LICENSE)).*

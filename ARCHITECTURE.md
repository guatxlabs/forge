# Forge — Architecture

[English](ARCHITECTURE.md) | [Français](ARCHITECTURE.fr.md)

Forge is the **offensive counterpart** of the blue-team SOC **Plume**
([`guatxlabs/plume`](https://github.com/guatxlabs/plume)). Design decision
(see reuse analysis): **shared core, separate products, autonomous modules** — above all
not an all-in-one that would merge the red arsenal into the blue binary (that would break the invariant
"the SOC must never be a security hole": exec-on-demand forbidden, read-only, localhost-only).

## The three layers

```
Ce dépôt — Forge (rouge, PUBLIC) : moteur Python (gate ROE, ledger, modules, évasion...) +
  console/        forge (bin Rust) : store rouge + API + dashboards — DÉPEND de guatx-core

Dépendances externes de la famille GUATX (repos séparés, PAS dans ce dépôt) :
  guatx-core      lib Rust — NEUTRE, PUBLIC : le ~70 % commun. v0 = moteur GXQL ; à étendre
                  (auth/host-guard, query-exec). RIEN d'offensif n'y descend. Consommée par la console
                  en git-dep publique épinglée (github.com/guatxlabs/core, tag v0.2.6).
  plume           Plume (bleu, PUBLIC) : event/metric, détection, collecteurs, BAS. PEUT adopter core.
```
**Repository boundary** (decided): **neutral public** `core` + **public** `plume` (blue) +
**public** `forge` (red, this repository). Since Plume must be able to depend on `core`, **`core` MUST be
public** — that is what forces the split. Discipline: no offensive element (module, CF/WAF evasion,
ROE logic) goes down into `core`; it stays in Forge, which depends on the public core.
The console consumes `core` via a **pinned public `git` dep** (`tag = "v0.2.6"`, fetched at
build time) — the migration from the old sibling `path` dep is **done**. The extraction is real (the
console uses it), not a plan.

v0 does not build `core/` (premature extraction = friction while the interfaces are moving). We
**build Forge first** (Python, like the original internal prototype), then we will move the common ~70 %
up into `core/` once Plume and Forge have converged.

## The engine (this repo)

```
roe.py      Scope (fail-closed) + Roe (gate 4 couches) + Action/Decision      ← LE cœur de sûreté
ledger.py   ledger append-time, hash-chain SHA256 + MAC HMAC par-entrée + verify()
schema.py   Finding (+ mitre, status) · Target · Campaign
engine.py   boucle : plan → roe.decide → (dry|fire|veto) → ledger → findings · coverage()
report.py   markdown + section « anti-masquage » (tiré/simulé/vétoé/jamais tenté)
modules/    registry.py (contrat dry/fire) + demo.py (no-op, illustre le contrat)
cli.py      forge scope-check | plan | run | campaign | ledger verify | modules | doctor | demo
```

**Central invariant**: a module is called with `fire()` **only** on a `FIRE` verdict. In
`DRY_RUN` only `dry()` (generates the PoC, no side effect). In `VETO`, nothing.

### Where what comes from (reuse, not rewrite)
- `Scope` ← the scope-guard of the original internal prototype (fail-closed membership +
  default-deny exploit/destructive),
  **enriched** with the arming model of `plume/collectors/respond.sh` (opt-in → default dry-run →
  global arming → per-action approval → allowlist). Inverted polarity: **in-scope** allowlist
  (fail-closed), not an IP deny-list.
- `ledger.py` ← Plume's hash-chain ledger + Ed25519 checkpoints, **fixed** on its two
  identified weaknesses: coverage (here ALL entries are chained) and between checkpoints
  (**per-entry** MAC, not only at the checkpoint).
- `Finding` ← the finding schema of the original internal prototype, + `mitre`/`status`.
- `report.py` ← the transparency section of the original internal prototype's report.

## The modules (P2) — orchestrated autonomous tools

The `Module` contract (`dry()`/`fire()`) wraps what already exists, which **remains runnable on its own**:
- a **collection of one-off web testers** (SSRF, IDOR, SQLi, XXE, JWT, GraphQL…) with a uniform CLI.
- the **original internal prototype** — recon (nmap/httpx), `access_control` (2-account IDOR),
  origin detection (PoC-verified CDN bypass); + its coverage-safe planner (FLOOR on the paying
  classes) and its graph.
- an **external browser automation service** — evasion: vision-assisted click (interactive
  Turnstile), capture/replay (WAF that blocks XHRs), intercept/modify (GraphQL
  persisted-query IDOR), OS drag.
- a **vector index of findings** — memory: dedup, knowledge base, dispatch per technique.

Discipline (inherited from the Plume collectors): OFF by default, self-neutralization if the underlying
tool is missing, zero side effect in dry-run.

## The purple loop (Plume ↔ Forge interface)

Plume's MITRE ATT&CK / BAS coverage specification is **already** in place on the blue side — Forge is
its **executing half**:

```
Forge exécute la technique T ─► run-record taggé {mitre: T} ─► Plume ingère
                                                                   │
                          Plume détecte ? alerte taggée {mitre: T} ┘
   corrélation = égalité de champ `mitre`  ─►  dashboard de couverture ATT&CK
   (Forge mesure le VRAI MTTD + le VRAI % de couverture de Plume)
```

No shared process: a POST/file contract. A thin "BAS-mode" adapter could live
in Plume (own-infra, sandbox, opt-in) and call Forge; **Forge-the-engine stays a separate
product** whose charter is authorized red-teaming in general, own-infra being only a *mode*.

## Roadmap

- **P0/P1 (done)** — engine + fail-closed ROE gate + tamper-evident ledger + CLI + tests.
- **P2 (done)** — coverage-safe planner, runner, brain (`Brain`/`HeuristicBrain`, Claude seam),
  **engagement graph** (`graph.py`: hosts→services→findings world-model), real handlers
  (`recon.httpx`/`recon.nmap`/`web.nuclei`/`access_control.idor`/`origin.find`), **browser-automation
  evasion** (`evasion.*` via `browser_client.py`, port 8080), **memory** (`memory.py`:
  JSONL store + dedup), ATT&CK run-records + `forge campaign`. The most mature building blocks of the
  original internal prototype (planner, runner, graph, access_control, origin) are **cleanly
  ported** into the Forge contract (no import of a neighboring project). Remaining under hardening: an
  embeddings backend behind the `Memory` interface.
- **P3 (v0 done)** — Rust console `console/` (axum + rusqlite, single binary, builds offline):
  red model store (`finding`/`runrecord`), `POST /api/ingest` (token) = purple junction
  point, `GET /api/findings|runrecords|coverage`, operator console (vanilla-JS PWA). Python↔Rust
  loop proven (`console_client.py` + `forge campaign --console`). **GXQL `event→finding`
  done** (`console/src/query.rs`: `search|stats|fields|sort|head` on `finding`/`runrecord`,
  compiled to read-only SQL, allowlisted fields, values as bound params, RO connection; `GET
  /api/query` + UI search bar). **Dashboards done**: saved GXQL panels
  (`panel` table, `/api/panels` CRUD, writes gated by token, `/:id/data` re-runs the query),
  table/bar/stat viz in the UI. **Auth/RBAC done**: `host_guard` (anti-DNS-rebinding, Host in
  allowlist) + `auth_guard` (argon2id Basic=operator/viewer · Bearer token=agent/admin/write ·
  `/health` open · no hash = localhost dev) + `hashpw` subcommand. P3 ESSENTIALLY
  COMPLETE. Remaining: extraction of the shared `core/` (the common ~70 % of Plume/Forge).
- **Hardening (done)** — **Ed25519** ledger (`signing.py`, `verify_external`); **off-host anchoring**
  (`anchor.py`: `Anchor` interface + co-signing `Witness` + `reconcile` that detects a rewrite
  re-signed locally); **semantic memory** (fuzzy stdlib `JaccardMemory` + optional `memory_faiss.py`
  embeddings, `make_memory` degrades); **`guatx-core`** (GXQL engine extracted, console on top of it).
  Remaining on demand: migration of Plume to `guatx-core`; remote witness over HTTP; embeddings
  backend enabled (requires the corresponding optional dependencies on the PYTHONPATH).

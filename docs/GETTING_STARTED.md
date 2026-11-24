# Forge — Getting started (end-to-end operator path, 100 % offline)

[English](GETTING_STARTED.md) | [Français](GETTING_STARTED.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Overview](OVERVIEW.md) ·
> [Installation](INSTALLATION.md) · [CLI reference](CLI.md)

> This guide runs **entirely offline**, with the provided **synthetic reference engagement**
> ([`examples/reference-engagement/`](../examples/reference-engagement/)) and the stdlib **mock-Plume
> stub** ([`tools/mock_plume.py`](../tools/mock_plume.py)). **No external service, no real
> target, no real SOC** is required. Each step has a **"What you should
> see"** checkpoint: if it does not match, stop there before going on.
>
> ⚠️ **Authorized settings only** (in-scope bug bounty, contracted pentest, CTF, your own infra).
> Getting past a WAF/Cloudflare ≠ a vulnerability: the ROE gate + the scope-guard + the ledger are there to
> **enforce AND prove** the authorization. See [`../README.md`](../README.md).

All commands are run from the repository root.

---

## (a) Install / build

The Python core is **pure-stdlib** (`deps=[]`); the console is a single Rust binary.

```bash
# 1) Python engine (puts the `forge` executable on the PATH)
pip install -e .            # without install: prefix commands with `python3 -m forge.cli`

# 2) Rust console (compiles offline from the cargo cache)
cd console && cargo build --release && cd ..

# 3) full test suite (stdlib on the Python side + cargo on the console side, zero network)
make test                  # = python3 -m unittest discover -s tests -t .  +  (cd console && cargo test)
python3 -m unittest discover -s tests -t .   # Python only (2949 tests, MEASURED on 2026-11-24)
```

> **What you should see**: `pip install -e .` completes without error and `forge --version` answers
> (version derived from the [`../VERSION`](../VERSION) file). `cargo build --release` produces
> `console/target/release/forge`. `make test` ends on **`OK`** (2949 green Python tests + 571 Rust tests, MEASURED on 2026-11-24,
> cargo test of the console). The footprint and the deployment matrix (Docker / k8s / host / venv)
> are detailed in [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## (b) Set up the scope (ROE)

Forge is **INERT by default**: empty `in_scope` ⇒ everything is refused (fail-closed). For a real
engagement, copy the example then fill in `in_scope` **with written authorization**:

```bash
cp scope.example.json scope.json     # scope.json is gitignored; scope.example.json (INERT) is committed
```

> ⚠️ **Compose guard** — in a Docker deployment, **create `scope.json` BEFORE `docker compose up`**.
> The bind-mount expects a **file**: if `./scope.json` is missing, Docker creates an empty
> **directory** in its place. The compose entrypoint **fails loudly** in that case, and **falls back to the
> embedded `scope.example.json` (INERT)** if `scope.json` is missing or empty (see
> [`../docker-compose.yml`](../docker-compose.yml)). Nothing fires as long as the scope does not authorize it.

For this offline guide, **nothing is edited**: we reuse the scope already provided with the reference
engagement — [`examples/reference-engagement/scope.json`](../examples/reference-engagement/scope.json)
(grey-box, `allow_exploit=false`, `allow_destructive=false`, reserved `.example` hosts).

```bash
forge scope-check api.lab.example --scope examples/reference-engagement/scope.json   # IN SCOPE ✅
forge scope-check evil.example    --scope examples/reference-engagement/scope.json   # OUT OF SCOPE ⛔ (printed as « HORS SCOPE ⛔ »)
```

> **What you should see**: the 1st command prints `IN SCOPE ✅`, the 2nd `HORS SCOPE ⛔` (out of scope)
> (exit code `1`). The scope-guard decides membership **before** any test.

---

## (c) Populate the console (gated campaign, or `make demo`)

Two paths, both offline:

**Fast path — `make demo`** ingests the reference engagement fixtures directly into
SQLite (idempotent, no network, touches only the demo campaign `acme-lab`, run `seed-demo-acme-lab`):

```bash
make demo          # seeds the demo database + starts the populated console -> http://127.0.0.1:7100
```

**CLI path — launch a gated campaign** against the seed (demonstrates plan → ROE → dry/fire → ledger →
report). The reference scope is INERT on the capability side (`allow_exploit=false`): without `--arm`, everything
stays in `DRY_RUN`/`VETO` (no effect), which is the intended behaviour — Forge never fires
blindly.

```bash
python3 -m forge.cli campaign \
    --scope   examples/reference-engagement/scope.json \
    --targets examples/reference-engagement/targets.json \
    --campaign getting-started --ledger engagements/gs.jsonl --report /tmp/gs_report.md
```

> **What you should see**: after `make demo`, the console listens on `http://127.0.0.1:7100` and its
> **Findings / Couverture ATT&CK / Runs** tabs (Findings / ATT&CK Coverage / Runs) are populated (6 findings, 8 run-records, campaign
> `acme-lab`). After the CLI campaign: a line `Tirées=… Simulées=… Refusées=…` (fired / simulated / refused) then
> `Rapport -> /tmp/gs_report.md`, and the list of **coverage gaps** (classes never attempted) —
> zero silent gaps.

---

## (d) See findings + evidence + ATT&CK coverage in the console

Console populated by `make demo`, at `http://127.0.0.1:7100`:

| Tab | URL | Contents |
|---|---|---|
| Findings | <http://127.0.0.1:7100/#findings> | 6 findings with severity, CWE, status, **evidence** and **PoC** |
| « Couverture ATT&CK » (*ATT&CK Coverage*) | <http://127.0.0.1:7100/#coverage> | per MITRE technique: number of runs attempted and how many **fired** |
| « Détection purple » (*Purple detection*) | <http://127.0.0.1:7100/#purple-coverage> | detected/missed matrix (populated in step (e)) |
| Ledger | <http://127.0.0.1:7100/#ledger> | integrity of the engagement chain |

Through the API (same data, read-only): `GET /api/findings`, `GET /api/coverage`, `GET /api/runrecords`.

> **What you should see**: the **Findings** tab lists the cross-tenant IDOR, the OOB SSRF, the credentialed
> CORS, the predictable reset token, the origin exposure and the missing headers —
> each with its **evidence** and its **PoC**. The **« Couverture ATT&CK »** (*ATT&CK Coverage*) tab shows the fired
> techniques (T1595, T1046, T1190, T1212, T1590.005, T1595.002, T1539).

---

## (e) Purple loop: detected / missed / MTTD matrix (mock-Plume stub)

```bash
make demo-purple   # starts tools/mock_plume.py (DEMO FIXTURE) + the console with PLUME_URL set
```

`make demo-purple` runs the **mock-Plume stub** on `127.0.0.1:8899`, which serves a **fixed,
synthetic** set of MITRE detections ([`examples/reference-engagement/detections.jsonl`](../examples/reference-engagement/detections.jsonl)),
then starts the console with `PLUME_URL` pointed at it. The console performs the **join**
red-fired ↔ blue-detected and displays the matrix.

> ⚠️ **This is a demonstration fixture, NOT a real SOC.** The stub labels every response
> `DEMO FIXTURE` (`_demo:true`, `_warning`, header `X-Demo-Fixture`). **Never** point a
> real engagement at it.

> **What you should see**: on <http://127.0.0.1:7100/#purple-coverage>, the matrix shows
> **7 techniques fired · 4 detected · 3 missed** (detection rate 57 %, average MTTD ≈ 3.9 min,
> max 6 min). The missed rows (T1590.005, T1595.002, T1539) are deliberately absent from the detection
> seed — that is what makes the matrix useful (detected **AND** missed).

---

## (f) Generate a report

**CLI** — the markdown engagement report, written by
[`forge/report.py`](../forge/report.py) `build_report` (already produced in step (c) via `--report`):

```bash
python3 -m forge.cli campaign --scope examples/reference-engagement/scope.json \
    --targets examples/reference-engagement/targets.json \
    --campaign gs --ledger engagements/gs.jsonl --report rapport.md
```

The CLI report carries: an **engagement header** (scope extent + ledger fingerprint: head +
Ed25519 public key when available), a summary by severity, detailed findings, an
**ATT&CK techniques exercised** section (the MITRE techniques actually fired), ROE transparency (anti-masking:
simulated / refused / deferred / never attempted), and a **pointer** to the console report.

**Console** — the **complete** deliverable is served by the console. Since the join with Plume
detections is **console-side**, it **alone** carries the **detected/missed matrix + MTTD** and
the **chain-of-custody appendix**:

```
GET http://127.0.0.1:7100/api/runs/seed-demo-acme-lab/report            # markdown (default)
GET http://127.0.0.1:7100/api/runs/seed-demo-acme-lab/report?format=html  # branded client deliverable
```

> **What you should see**: `rapport.md` opens on `## Engagement` (scope) then `## Synthèse` (summary),
> and ends with `## Techniques ATT&CK exercées` + an explicit pointer to
> `GET /api/runs/<id>/report`. The console link `?format=html` renders a self-contained printable document
> (Print → "Save as PDF"; see [`DEPLOYMENT.md`](DEPLOYMENT.md) § Reports & PDF export)
> with the purple matrix **and** the custody appendix.

---

## (g) Verify integrity (ledger) and the preflight (doctor)

The engagement ledger is **append-time, tamper-evident**: each act is chained (SHA-256) and
signed (Ed25519 by default; HMAC fallback if `cryptography` is absent).

```bash
# integrity: recomputes the chain + verifies each signature
forge ledger verify --ledger engagements/gs.jsonl

# Ed25519 public key (hex) — a third party verifies WITHOUT any secret
forge ledger pubkey --ledger engagements/gs.jsonl
forge ledger verify --ledger engagements/gs.jsonl --pubkey <hex_ci-dessus>   # external verification
```

**Purple loop preflight** (read-only — fires nothing, touches neither scope nor ledger):

```bash
forge doctor --purple      # module status + prerequisites of the purple join
```

> **What you should see**: `ledger verify` answers `{"ok": true, "entries": N, ...}`; `ledger
> pubkey` prints 64 hex characters (or a clear note if the ledger is HMAC-signed); the external
> `--pubkey` verification answers `ok: true` without any secret. `forge doctor --purple` lists the operational
> modules and flags what would be missing to plug in a real Plume — **without firing anything**.

---

## Going further

This whole guide runs **without a real Plume** (seed + mock-Plume stub). To plug in a **real Plume**,
see [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) (`PLUME_URL` / `PLUME_TOKEN`) — **not required here**.

- [`../README.md`](../README.md) — overview, 4-layer ROE gate, module catalogue.
- [`../examples/reference-engagement/README.md`](../examples/reference-engagement/README.md) — details of the synthetic seed + the expected purple matrix.
- [`ARCHITECTURE.md`](../ARCHITECTURE.md) — core (roe/ledger/engine/schema) + purple loop.
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — footprint, Docker/k8s/host/venv matrix, PDF export.
- [`PURPLE_CAMPAIGN.md`](PURPLE_CAMPAIGN.md) · [`MTTD.md`](MTTD.md) — the purple loop in depth.
- [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) — prerequisites to wire a real Plume (the moat).

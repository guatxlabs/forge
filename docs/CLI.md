# CLI reference

[English](CLI.md) | [Français](CLI.fr.md)

> [Contents](README.md) · See also: [Configuration](CONFIGURATION.md) ·
> [HTTP API reference](HTTP_API.md) · [Concepts](CONCEPTS.md)

Two executables:

- **`forge`** — the Python engine (`pip install -e .` puts `forge` on the PATH; otherwise `python3 -m
  forge.cli <commande>`). Handles scope, plan, run, campaign, ledger, diagnostics, collectors.
- **`forge`** — the Rust binary: launched **without arguments**, it starts the server (API + UI);
  with a sub-verb, it exposes utilities (hash, accounts, seed, migration, backup, ledger,
  local read).

> Safety: `forge` is **INERT** by default. `run`/`campaign` **simulate** (`DRY_RUN`) as long as
> `--arm` **and** the approval (or `--mode auto`) are not set. A `VETO` (out of scope / capability
> not authorised) is **never** fired. Usual exit codes: `0` OK, `1` failure/vuln found,
> `2` usage error.

### Exit codes of `run` / `campaign` — what flips them

| code | when |
|---|---|
| `1` | **at least one `status=vulnerable` finding** was produced by this run (a PROOF, not a severity: `Oracle.proof(proven=False)` returns `tested`, and a `vulnerable` without a proof token is refused by the schema). This is the signal a CI should gate on. A `[VULN] N finding(s) PROUVÉ(S) vulnerable -> exit 1` line is printed. |
| `0` | no proven finding — **including when the run was interrupted** (`--run-timeout` deadline, `SIGTERM`/`SIGINT`). This is **deliberate**: the honesty of a partial run is carried by the report ("RAPPORT PARTIEL — RUN INTERROMPU" (partial report — run interrupted) + "Couverture NON vérifiée" (coverage NOT verified) section), not by a failure code that would make a CI fail for a scheduling reason. A vuln found **before** the cut-off still exits with `1`. |
| ≠ 0 (traceback) | uncaught exception: the report is rendered first, then the exception propagates — a crash does not disguise itself as a successful run. |

> Before this fix, `run` and `campaign` returned `0` **unconditionally**: a run producing
> `HIGH`/`vulnerable` exited with `rc=0` and no CI could see a vulnerability.

---

## 1. `forge` (Python engine)

### `forge --version`
Prints the version (single source: the [`../VERSION`](../VERSION) file).

### `forge scope-check <target> --scope <S>`
Membership verdict for a target. Output `IN SCOPE ✅` / `HORS SCOPE ⛔` (+ `mode`,
`allow_exploit`, `allow_destructive`). Exit `0` if in scope, `1` otherwise.
```bash
forge scope-check api.lab.example --scope scope.json
```

### `forge plan --scope <S> [--actions <A>]`
Lists the actions and their **ROE verdict**, **without firing anything** (never armed). `--actions` = JSON
file `[{kind,target,exploit?,destructive?,desc?,params?}]`; absent ⇒ demo actions derived from the scope.
```bash
forge plan --scope scope.json --actions actions.json
```

### `forge run --scope <S> [options]`
Executes a **list of actions** through the ROE gate.

| Flag | Meaning |
|---|---|
| `--actions <A>` | JSON file of actions (otherwise demo). |
| `--arm` | Arms the engagement (layer 1). Without it, everything stays `DRY_RUN`. |
| `--approve <KIND:TARGET> …` | Approves actions (layer 4). |
| `--mode propose\|auto` | `propose` (default, approval required) or `auto` (approves everything). |
| `--ledger <L>` | Engagement ledger (JSONL) — every decision is sealed in it + checkpoint at the end. Also writes its **sidecars**: `<L>.ed25519` (signing key, `0600`), `<L>.hwm` (anti-truncation) and `<L>.durations` (shot durations aggregated **per module kind**, never per target — see `FORGE_DURATIONS` in [Configuration](CONFIGURATION.md)). |
| `--report <R>` | Writes the markdown report (otherwise stdout). |
| `--reason <txt>` | Reason logged at arming. |
| `--memory <M>` | Memory store (dedup of findings). |
| `--memory-mode exact\|jaccard\|embeddings` | Dedup backend of `--memory`. `exact` (default): normalised key target+category+title. `jaccard`: stdlib fuzzy dedup (same target + similar title). `embeddings`: semantic dedup — requires `sentence-transformers` **and** a model already in the local cache; degrades to `jaccard` if unavailable. |
| `--memory-allow-download` | Allows the network egress that downloads the embeddings model. Without this flag, the model is loaded **offline**: absent from the cache → `jaccard` fallback, no egress. |
```bash
forge run --scope scope.json --actions actions.json \
    --arm --approve demo.fingerprint:app.test --ledger engagements/e1.jsonl --report rapport.md
```

### `forge campaign --scope <S> --targets <T> [options]`
**Iterative** campaign (plan → observe → replan) driven by the brain + the coverage-safe planner.
`--targets` = JSON `[{host, kind?, attrs?}]`.

**What `host` accepts — an entity is a PIVOT, never a target.** All the safety is
anchored on a **pinnable IP**: the scope matches the host, then the ROE returns its verdict
(private / LAN / out-of-scope-by-IP) **against the resolved IPs**. A seed from which no IP can
be derived is not governable, and it is refused **at load time**, not later.

| seed | result |
|---|---|
| `example.com`, `sub.example.com:8443`, `https://example.com/a` | target as is |
| `1.2.3.4`, `[::1]:8081` | target as is (IP literal) |
| `alice@example.com` | **pivot** to `example.com`; the local part is discarded, the seed stays in `attrs.seed` |
| `Alice Martin`, `@alice_m`, `+33612345678` | **refused**, with the reason and the way forward |

**Forge tests an infrastructure, not a person.** A pseudonym or a phone number opens
no path here, and this is not a deferred feature: the target of an action is a
machine, and the verdict is returned against its IP. If the platform in question is within the authorised
scope, put **its domain** in the scope and target that domain.

| Flag | Meaning |
|---|---|
| `--arm`, `--approve`, `--mode`, `--ledger`, `--report`, `--reason`, `--memory` | as for `run`. |
| `--budget <f>` | Planner budget (bounds the **non-qualifying** work; qualifying classes are never starved). |
| `--exhaustive` | Disables scheduling → maximum coverage. |
| `--modules <k1,k2,…>` | **Restricts** the plan to the listed kinds (UI/console selection). Empty = the brain's full plan. |
| `--purple <F>` | Emits the ATT&CK run-records (JSONL) ingestible by the detection source. |
| `--campaign <name>` | Campaign name (console/purple correlation). Default `default`. |
| `--console <URL>` | Pushes findings + run-records + coverage to the console (`POST /api/ingest`). |
| `--console-token <tok>` | Ingestion bearer (prefer the `FORGE_CONSOLE_TOKEN` env — argv is visible to other users). |
| `--run-id <id>` | Correlates this shot with a specific console run. |

Output: `Tirées=… Simulées=… Refusées=… Erreurs=… Déférées(budget)=… Findings=… Dups=…
Run-records=…` (fired, simulated, refused, errors, deferred), the list of **coverage gaps** (classes never attempted), and the report.
```bash
export FORGE_CONSOLE_TOKEN='<token>'
python3 -m forge.cli campaign --scope scope.json --targets targets.json \
    --modules recon.httpx,recon.nmap,web.nuclei --mode auto --arm \
    --console http://127.0.0.1:7100 --campaign op1 \
    --purple runs/op1.jsonl --ledger runs/op1.ledger.jsonl --report runs/op1.md
```

### `forge ledger verify --ledger <L> [--pubkey <HEX>]`
Recomputes the chain + verifies each signature. `--pubkey <hex>` ⇒ **external verification** with
the Ed25519 public key alone (non-repudiation, no secret). Exit `0` intact / `1` broken.
```bash
forge ledger verify --ledger engagements/e1.jsonl
forge ledger verify --ledger engagements/e1.jsonl --pubkey $(forge ledger pubkey --ledger engagements/e1.jsonl | head -1)
```

### `forge ledger pubkey --ledger <L>`
Prints the raw Ed25519 public key (hex, line 1) + `# alg=ed25519` (line 2). In HMAC fallback:
plain message + `public_id` (no asymmetric non-repudiation). Reusable for external verification.

### `forge ledger keygen --ledger <L> [--force]`
**Deliberately** creates the Ed25519 pair (`<L>.ed25519`, `0600`) instead of the lazy auto-generation.
`--force` = **ROTATION** (invalidates the ed25519 signatures already written — `verify` would break). Refuses
to overwrite without `--force`. Prints the public key.

### `forge modules [--json]`
Lists the registered modules (`kind`, exploit, destructive, available). `--json` = full table
(kind, cls, exploit, destructive, web_allowed, available, mitre, description). See [MODULES.md](MODULES.md).

### `forge tools list [--json]`
State of the external tools of the **manifest** [`forge/tools.json`](../forge/tools.json): target version,
`PATH` resolution, provenance (`runtime` = persistent layer / `baseline` = binary baked into the image /
`absent`), and whether a SHA256 pin exists for the current architecture. **Read-only**: creates nothing,
downloads nothing and **executes no tool** (the installed version is read from the receipt dropped at
install time — listing must not be an execution).

### `forge tools install|update|remove <NAME> [--ledger <L>] [--actor <A>] [--json]`
Lifecycle of a tool **at runtime, without rebuild**. The binary is placed in the persistent tools
volume (`/data/tools/bin` in the image, `FORGE_TOOLS_DIR` otherwise), put **at the head of the `PATH`** ahead of
the baked `/usr/local/bin`.
- `install`: downloads the manifest's version, **verifies its pinned SHA256** (computed on the stream),
  extracts a single member, places it atomically at `0755`. Already installed ⇒ no-op.
- `update`: re-places the **manifest's** version (after a bump of `forge/tools.json`). There is no
  update "to the latest upstream version": that would be an unpinned download.
- `remove`: removes from the runtime layer; the baked baseline stays intact (the `PATH` falls back to it).

Fail-closed: name outside the manifest, pin absent for the architecture, mismatching digest, or **unresolvable
ledger** (`--ledger` / `FORGE_CONSOLE_LEDGER`) ⇒ **refusal**, nothing is placed on the `PATH`. There is
**neither `--url` nor `--sha256`**: the source comes from the manifest, that is the allowlist. Every act — including
an integrity refusal — is **logged** to the ledger (`tools.install`/`.update`/`.remove`/`.refused`).
Full details: [TOOLS_LIFECYCLE.md](TOOLS_LIFECYCLE.md).
```bash
forge tools list
forge tools install nuclei --ledger /data/ledger/engagement.jsonl --actor alice
forge ledger verify --ledger /data/ledger/engagement.jsonl
```

### `forge doctor [--json] [--purple] [--timeout <s>]`
**Read-only** diagnostics (fires nothing, touches neither scope nor ledger).
- Without `--purple`: for each module, says whether it is **OPERATIONAL** (`.available` probe) + the expected
  tool + the install hint, plus a health line for the configured **detection source**.
- `--purple`: **purple loop preflight** — console GET `/health` + probe of the detection
  source (legacy Plume **or** configured collector). Clear checklist; degrades gracefully.
```bash
forge doctor
forge doctor --purple --json
```

### `forge demo`
End-to-end demonstration, **no real target, no network I/O**: shows VETO (out of scope),
DRY_RUN (not armed), FIRE (armed + approved), the ledger integrity, then a tampering that **breaks**
`verify`.

### `forge detections --source <SPEC> [--since <N>]`
Detections collector (delegated by the console for "rich" sources). `--source` =
`env:NOM` (**preferred path** — no leak of the secret through argv), `@fichier`, or literal JSON.
Prints `{"detections":[{mitre,count,first_ts}]}`. Fail-open contract: reachable source (even 0
detections) ⇒ stdout + exit 0; unreachable/misconfigured ⇒ stderr **with the secret redacted** + non-zero
exit (the console switches to `source_reachable:false`). The auth secret is **never** printed.
```bash
FORGE_DETECTION_SOURCE='{"kind":"crowdsec","endpoint":"http://127.0.0.1:8080", …}' \
  forge detections --source env:FORGE_DETECTION_SOURCE --since 0
```

---

## 2. `forge` (Rust binary)

Launched **without arguments**, it starts the server (bind `FORGE_CONSOLE_ADDR`, cf.
[Configuration](CONFIGURATION.md)) **and creates/opens the database in the current directory**
(`FORGE_CONSOLE_DB`, default `./forge.db`). With a sub-verb:

### `forge --help` (or `-h`, `help`)
Prints the list of subcommands **and what launching without a subcommand does** (port opened,
database created in the CWD), then exits `0`. **Starts nothing.**

> **An unknown argv is REFUSED** (`exit 2`, help on stderr) — it **no longer** falls back to booting the
> server. Before this fix, `forge --help`, `forge doctor` or any typo
> silently started the server on `127.0.0.1:7100` and wrote `forge.db`, `forge.db-shm`,
> `forge.db-wal` and `toolspecs/` in the current directory. It is the most universal command
> a first-time contributor types; it trapped three reviews in a row. The same class of bug had
> already been closed ONE SUBCOMMAND AT A TIME (`forge ledger verify` booted the server and hung):
> the default is now fail-closed, so the class is closed in one go.

### `forge --version` (or `-V`)
Prints the version (`VERSION` file, `include_str!` at compile time).

### `forge hashpw <password>` · `hashpw-operator <password>`
Computes the **argon2id** hash (never in plaintext) of the password, for `FORGE_CONSOLE_PASS_HASH`
(viewer) / `FORGE_CONSOLE_OPERATOR_HASH` (C2 operator). Prints the hash.
```bash
HASH=$(forge hashpw 'mon-mot-de-passe')
```

### `forge useradd <login> <role> [--pass <pw>]`
Provisions an **individual account**. `role ∈ {viewer|operator|admin}`. The password is read from
**STDIN** by default (never in argv → no leak through `ps`); `--pass` tolerated for scripting.
argon2id hash stored in `users` (idempotent upsert by login). Creating the first admin this way engages
the auth gate.
```bash
forge useradd alice admin              # asks for the password on STDIN
```

### `forge findings | roe | coverage | query [args] [--json]`
**Local read parity**: reads the SAME SQLite database as the API, **READ-ONLY**, prints as a table
(default) or JSON (`--json`). No write, no spawn. `query` takes a GXQL query.
```bash
forge findings --json
forge query 'search severity=HIGH | fields target,title,mitre'
```

### `forge seed-demo [--dir <path>] [--campaign <name>]`
Seeds the database with the **synthetic reference engagement** ([`../examples/reference-engagement/`](../examples/reference-engagement/))
directly into SQLite (offline, without network, without `/api/ingest`). Idempotent (purges the demo
campaign). Used by `make demo`.

### `forge migrate --from <dir|db> --to <db> [--ledger <path>] [--verify] [--encrypt --key-env <ENVVAR>]`
Imports an existing (non-Docker) Forge install into a target database. Copies DB (`VACUUM INTO` /
SQLCipher), **ledger + `.ed25519` key** (`0600`), then `SCHEMA` + `migrate()` on the target. `--verify`
recomputes the source ledger chain and **aborts** on a break. `--encrypt` requires a
`--features encryption` binary. The key goes **through ENV** (`--key-env`), never in argv. Primary UX =
one-shot container. Details: [`MIGRATION.md`](MIGRATION.md).
```bash
forge migrate --from /var/lib/forge --to /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl --verify
```

### `forge backup --out <archive> --passphrase-env <ENVVAR> [--db <path>] [--ledger <path>]`
Creates an **ALWAYS encrypted** archive (argon2id + XChaCha20-Poly1305) bundling a DB snapshot
(`VACUUM INTO`) + ledger + `.ed25519` key + `manifest.json`. Passphrase read **only from
the ENV** (never argv). The ledger chain is verified beforehand; the backup is traced. Details:
[`BACKUP.md`](BACKUP.md).
```bash
export FORGE_BK_PASS='une-passphrase-forte'
forge backup --out /backups/forge-$(date +%s).forge --passphrase-env FORGE_BK_PASS
```

### `forge restore --in <archive> --passphrase-env <ENVVAR> [--to <db>] [--ledger <path>] [--force]`
Decrypts (wrong passphrase/tampering ⇒ **nothing written**), verifies the manifest `sha256`s + the
ledger chain, **refuses to overwrite** a non-empty install without `--force`, places db/ledger/key
(`.ed25519` at `0600`). An in-place swap **requires a restart** of the console.

### `forge ledger verify [--ledger <path>] [--json]`
**Fast, non-interactive** verification: recomputes the SHA-256 chain of the JSONL ledger and exits immediately
(`0` intact / `1` broken-absent / `2` usage). Does NOT start the server, does NOT open the database. The
**signature** verification (Ed25519) stays on the `forge ledger verify --pubkey` side (Python).

---

## 3. Make targets (shortcuts)

The [`../Makefile`](../Makefile) exposes: `make test` (Python + cargo), `make test-py`, `make
test-rust`, `make install`, `make console`, `make doctor`, `make check-version`, `make demo`,
`make demo-purple`, `make clean`. See [Getting started](GETTING_STARTED.md) and [Installation](INSTALLATION.md).

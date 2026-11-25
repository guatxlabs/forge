# Forge — Quickstart: deploy + test locally on a bug bounty program

[English](QUICKSTART.md) | [Français](QUICKSTART.fr.md)

> Goal: run Forge in **Docker** and test a **new bug bounty program**, **entirely through the web UI**.
> No file to create, no command before reaching the interface.
> Safety reminder: Forge is **fail-closed** — empty scope = everything refused. The scope IS your authorization (ROE).

## 0. Prerequisites
- Docker + Docker Compose. A standalone clone of this repository (the console fetches `guatx-core` through a public git-dep at build time — no parent context required).
- Nothing else. No scope.json, no account to pre-create.

## 1. Deploy — a single command
```bash
# from the repository root
docker compose up -d --build
```
- Service **`forge`**; web console at **http://127.0.0.1:7100** (loopback only).
- Data in the named volumes `forge-db` / `forge-ledger` (re-`up` is idempotent, nothing accumulates).
- `full` image by default (httpx/nuclei/subfinder SHA256-verified + PDF). `mini`: `FORGE_TOOLS_PROFILE=mini docker compose build`.

## 2. Open the UI → the wizard does everything
Open **http://127.0.0.1:7100**. On first launch, the **deployment wizard** (5 steps) creates EVERYTHING, in the browser:
1. **Admin** — your administrator account (argon2id). No `useradd` CLI.
2. **Encryption** — crypto at rest (SQLCipher optional depending on the image).
3. **Detection** — blue source (SIEM/IDS) for the purple loop, optional.
4. **Operator** — C2 policy (source-CIDR, fail-closed).
5. **Scope (ROE)** — **your program's scope, entered here**: `mode` (grey/white/black), **in-scope** hosts (globs/CIDR), **out-scope**. This is your authorization.

The wizard disables itself once provisioned. You are logged in, ready to test. **Zero files, zero commands.**

> ⚠️ **Provision BEFORE exposing the port.** The wizard is public until the admin exists — whoever reaches the host first can claim it. Keep the bind on **loopback `127.0.0.1`** (the default) and **do NOT switch to `0.0.0.0`** until you have claimed the admin (see `docs/DEPLOYMENT.md §2`).

> The scope you enter becomes **Engagement #1**. `allow_exploit`/`allow_destructive` stay `false` in bug bounty (destructive/DoS/brute-force techniques are banned and refused by the scope-guard anyway). Authenticated testing (IDOR/ATO: creds/session/idor_targets) is set in the engagement editor (secret, never logged).

## 3. A 2nd program = a new Engagement (in the UI)
Administration → **Engagements** → create an engagement with its own scope/ROE/ledger. Each program stays **isolated** (findings/runs/ledger/RBAC/report per engagement). Switch from one engagement to another in the UI. Nothing to edit on disk.

## 4. Test (launch a campaign) — **Launch** view
1. Pick the **modules** (or let the **planner** order them by value with coverage floors).
2. Enter/confirm the **in-scope targets** and launch. The **scope-guard** guarantees: nothing out of scope, never fired nor simulated.
3. **Live logs (SSE)**; **findings** appear with **evidence discipline** (`tested` as long as an oracle does not prove `vulnerable`).
4. **Triage** (`new → triaging → confirmed / false_positive / duplicate → resolved`) + **assign** (ownership), governed transitions + live event.
5. **Export** the report **per engagement** (HTML/PDF/CSV/JSON) + bulk-export.

Native techniques: IDOR, SSRF, XSS, SQLi, JWT/auth, CORS, XXE, race, CSRF, open-redirect, SSTI, cmdi,
proto-pollution, GraphQL, NoSQL, cache-poison, smuggling, takeover, secrets… (see `docs/TECHNIQUE_COVERAGE.md`).

## 5. Tools (driving nmap/nuclei/httpx/sqlmap/ffuf…) — EVERYTHING from the UI
Forge **drives** tools; it does not ship an offensive arsenal. The standard scanners are in the `full` image.
For Metasploit/Burp: point the `MSF_RPC_*` / `BURP_API_*` env vars at your services (profiles `--profile msf|burp`).
- **Configure a tool**: each tool (26 kinds — nmap, nuclei, ffuf, sqlmap, subfinder, naabu, feroxbuster, dalfox…) exposes its **arguments in the UI** (ports/scripts/timing/wordlist/threads/rate…), plus an allowlisted `extra_args` field. E.g. a fully custom nmap `-sV -p- --script http-* -T2`.
- **Rate-limit**: set the throughput (req/s) in the Launch view → propagated to each tool (`--max-rate`/`-rl`/`--rate`/`--delay`) + engine throttle + automatic back-off on 429/WAF.
- **Add YOUR tool**: Administration → **« ajouter un outil »** (*Add a tool*) → declare a governed ToolSpec (binary/docker, argv, params, allowlist) → it appears in Launch, configurable, scope-guarded. No file, no rebuild (see `docs/TOOLS.md`). *(The binary must be present in the image or provided by a script — otherwise the tool is `skipped`.)*
- **LIVE addition, no restart**: drop an executable into **`forge/tools/`** (usable on the next run, nothing to click) **or** add a ToolSpec through the UI / **`forge/toolspecs/`** → click **« Rafraîchir modules »** (*Refresh modules*). Both mounts are **ON by default** — never a `docker build`/`down`/`up` in the middle of a pentest.
- **Making the binary available — 3 ways** (details `docs/TOOLS.md §5`): (a) **already in the `full` image** (nmap/curl/dig/httpx/nuclei/subfinder); (b) **thin custom image** `FROM forge:0.0.1` + `apt install`/`COPY` (frozen set, prod); (c) **mount WITHOUT rebuilding** — host folders `:ro`: `./tools`→`/opt/tools` (executable binaries/scripts, **already on the PATH**) and `./toolspecs` (`FORGE_TOOLSPECS`, governed declarative ToolSpecs) are **ON by default**; `./plugins` (`FORGE_PLUGINS`, `@register` Python modules — code, high trust) stays **OPT-IN** (uncomment the bind + the env → a one-shot recreate `up`). E.g.: `cp myfuzzer forge/tools/ && chmod +x` → usable on the next run. ⚠️ `./tools`/`./plugins` = **trusted operator** (arbitrary); ToolSpec governance bounds the invocation, not the binary's internals.

## 6. Lifecycle (safe) — from the UI
Administration → **« Console Forge »** (*Forge console*): a panel that runs the governed commands (`status`, `ledger verify`,
`backup`, `upgrade`…) **without leaving the browser** (allowlist, no shell, `upgrade` asks for confirmation,
streamed output). In the CLI (optional, for regulars):
```bash
docker compose exec forge forge status
# safe upgrade: encrypted snapshot -> migrate -> verify -> automatic rollback on failure (no-op = 0 writes)
docker compose exec forge forge upgrade --passphrase-env FORGE_BACKUP_PASSPHRASE
```
Stop: `docker compose down` (volumes persist; `down -v` to wipe everything).

## Alternatives
- **Native host**: `cd console && cargo build --release && ./target/release/forge` (then the wizard in the browser).
- **Postgres (team)**: `--profile postgres` + `FORGE_ADVANCED_STORE=postgres` (see `docs/DEPLOYMENT.md §3bis`).
- **HA / k3s**: `kubectl apply -k k8s/` (see `docs/DEPLOYMENT.md §3bis.6`, `docs/UPGRADE.md`, `docs/KEY_CUSTODY.md`).

## Golden rule
The **scope is the authorization**. Put in it only what the program authorizes you to test; `allow_exploit`/`allow_destructive`
stay `false` unless there is a written ROE. Secrets do not lie around in plaintext: detection/SSO are set write-only in
the UI; env secrets (token, passphrase, connector creds) go through Docker/k8s secrets (`*_FILE`), not a
plaintext `.env` next to the app (see [`docs/SECRETS.md`](SECRETS.md)). Forge refuses everything out of scope; that is its reason for being.

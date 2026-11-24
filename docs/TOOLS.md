# Adding your own tool — from the UI (governed)

[English](TOOLS.md) | [Français](TOOLS.fr.md)

> [Contents](README.md) · See also: [Module catalog](MODULES.md) · [Administration](ADMINISTRATION.md) ·
> [Security model](SECURITY_MODEL.md) · [HTTP API](HTTP_API.md)

A red-teamer can declare **their own CLI tool** from the web console — **without editing a file in
the container, without an environment variable, without a restart**. The added tool is governed **exactly
like a native module**: fail-closed scope-guard, **fixed no-shell** argv, flag **allowlist**, status
**never** promoted to `vulnerable`, **exploit** floor (arm + reason). It is **declarative data** (a
`ToolSpec`), **never arbitrary code**.

---

## ⚡ Adding a tool DURING a pentest (without a restart)

**The two safe paths are mounted BY DEFAULT** (`docker-compose.yml`, `:ro` binds `./tools` + `./toolspecs`) —
nothing to enable, nothing to rebuild. **A running analysis is NEVER interrupted; the container keeps
running; you NEVER run `docker build` / `down` / `up` to add a tool.**

- **(a) An executable binary / script** → drop it into **`forge/tools/`** (`chmod +x`). `/opt/tools` is
  on the `PATH` and availability is checked **at fire-time** (`runner.available`→`shutil.which`) → the tool
  is **usable on the NEXT run**, **nothing to click**.

  ```bash
  cp ~/bin/myfuzzer forge/tools/ && chmod +x forge/tools/myfuzzer   # that's all
  ```

- **(b) A governed ToolSpec** (JSON/YAML, zero code) → drop it into **`forge/toolspecs/`** *(or add it
  through **Administration → Add a tool**)** → click **"Rafraîchir modules"** (Refresh modules; button `#mod-refresh`,
  operator; or `POST /api/modules/refresh`) → it **appears live**. The `./toolspecs` dir is **merged**
  with the server-managed dir of the tools added through the UI (`probe_toolspecs_env`) → the two **coexist**.

- **(c) A custom Python module** (`@register`) → **first enable** the `./plugins` mount (**OPT-IN** — arbitrary
  code): uncomment the `./plugins` bind + the `FORGE_PLUGINS` env in `docker-compose.yml`, drop the
  module, then **"Rafraîchir modules"**.

> **The ONLY exception to "never recreate"**: enabling the opt-in `./plugins` mount (or if you had
> removed the default mounts) requires **one** recreating `docker compose up` (a
> bind mount cannot be added to an already running container). This is precisely why `./tools` + `./toolspecs` stay **ON by
> default**: you are **never** faced with it in the middle of a pentest. Full details: [§5](#5-making-the-binary-available).

---

- [1. In short](#1-in-short)
- [2. The form (Administration → Add a tool)](#2-the-form)
- [3. Anatomy of a ToolSpec](#3-anatomy-of-a-toolspec)
- [4. Governance (what is guaranteed)](#4-governance)
- [5. Making the binary available in a container / k3s](#5-making-the-binary-available)
- [6. API](#6-api)
- [7. Python plugin upload (high trust — disabled by default)](#7-python-plugin-upload)

---

## 1. In short

1. Open **Administration → Add a tool** (**admin** session required).
2. Fill in: `kind` (in the **`custom.*`** namespace), `vuln_class`, `binary` (and/or `docker_image`),
   `argv_template` (list of tokens), optionally `params_schema`, `flag_allowlist`, `parser`, `mitre`/`cwe`,
   `phase`, `capability`, `severity`, `hit_status`, description.
3. **Add** → the tool is **validated fail-closed**, **persisted** (JSON `0600` in the server-managed folder),
   then the catalog is **hot-reloaded**: the tool appears **immediately** in **Capabilities** and in
   **Launch** (its `params_schema` is rendered **dynamically** as a configuration form).
4. **Delete**: the button next to the tool (in the "Added tools" list) removes it (file +
   catalog). A **native module can never be deleted**.

Every addition/deletion is **admin-only**, **attributed** to your account and **ledgered**
(`console.tool.add` / `console.tool.remove`).

## 2. The form

| Field | Role |
|-------|------|
| **kind** | Unique key **`custom.<nom>`** (impossible to override a native module; anti-traversal). |
| **vuln_class** | Category (`Recon`, `XSS`, `PortScan`, `TLS`…) — drives the grouping of the catalog. |
| **binary** | Binary resolved through `PATH` (or present in the image). |
| **docker_image** | **Optional** containerised fallback (requires the docker socket — cf. §5). |
| **argv_template** | **List of tokens** (never a shell string). Placeholders: `{target}`, `{target_host}`, `{target_url}`, `{param:NAME}`, `{args}`. |
| **flag_allowlist** | Flags allowed for `{args}` (e.g. `-t`, `--rate`). **Required if `{args}` is used.** |
| **params_schema** | Typed configuration fields (`text`/`number`/`select`/`list`/`flag`) → rendered in **Launch**. |
| **parser** | How to extract the hits: `lines`/`regex`/`json`/`jsonl`/`none`. |
| **phase / capability** | `recon`/`access`/`exploit` · `passive`/`active`/`exploit`. |
| **severity / hit_status** | Default severity of a hit · `tested` \| `reported_by_tool` (**never `vulnerable`**). |
| **exploit / destructive** | Governed capabilities (see §4 — an exploit tool stays **gated** by the armed opt-in). |

## 3. Anatomy of a ToolSpec

Minimal example (wraps `httpx` to fetch the `<title>`):

```json
{
  "kind": "custom.httptitle",
  "vuln_class": "Recon",
  "binary": "httpx",
  "docker_image": "projectdiscovery/httpx",
  "argv_template": ["-silent", "-title", "-u", "{target_url}", "{args}"],
  "flag_allowlist": ["-timeout", "-rate-limit"],
  "params_schema": [
    { "name": "note", "type": "text",   "label": "note libre" },
    { "name": "mode", "type": "select", "label": "mode", "allowed": ["fast", "deep"] }
  ],
  "parser": "lines",
  "phase": "recon",
  "capability": "passive",
  "hit_status": "tested",
  "severity": "INFO",
  "mitre": "T1595",
  "cwe": "CWE-200",
  "description": "httpx <title> (ToolSpec ajouté par l'UI)"
}
```

- A **placeholder** token is resolved into a **separate argv element** — a target containing shell
  metacharacters stays **a single argument** (anti-injection). A `{param:NAME}` reads the value entered in the
  Launch form; `{param:NAME:DEFAUT}` supplies a default.
- `{args}` expands into the **extra args** validated against the `flag_allowlist` (each flag **outside the list** is
  refused fail-closed — no process launched).

**Graded examples** (copy-paste-working — they load, register and pass the safety checks;
proven by `tests/test_contrib_graded_toolspecs.py`). **`custom.*` namespace mandatory**. Loaded through
`FORGE_TOOLSPECS=forge/modules/contrib`, `--toolspec <fichier>`, or the UI form (paste the JSON):

- [`forge/modules/contrib/simple.toolspec.json`](../forge/modules/contrib/simple.toolspec.json) — **SIMPLE**
  (`custom.whatweb`): the bare minimum — binary + target, **no** param, **no** `flag_allowlist`,
  no `{args}`. Just the target → run.
- [`forge/modules/contrib/medium.toolspec.json`](../forge/modules/contrib/medium.toolspec.json) — **MEDIUM**
  (`custom.dirfuzz`, ffuf): typed `params_schema` (wordlist/threads/rate/codes) rendered as a form,
  `flag_allowlist` governing `{args}`, and the positional keyword `FUZZ` injected into the URL.
- [`forge/modules/contrib/hard.toolspec.json`](../forge/modules/contrib/hard.toolspec.json) — **HARD**
  (`custom.nuclei_scan`): **exploit-class** (`exploit:true` → gated by the operator+arm floor), **docker**
  fallback (`projectdiscovery/nuclei`), **JSONL** parser + `parser_json_path` (field extraction), and
  rich `params_schema` (`severity` select + tags/templates/rate).

(The historical example [`forge/modules/contrib/example.toolspec.json`](../forge/modules/contrib/example.toolspec.json)
remains available — wraps `httpx` for the `<title>`.)

## 4. Governance

A tool added through the UI **inherits** all the guarantees of the external tools wrapper (proven by the
tests) — **nothing** is weakened by this endpoint, which only **declares** the tool:

- **Admin-only** (`check_admin`, fail-closed 403), **attributed**, **ledgered**.
- **Fail-closed validation** at submission: well-formed `kind` in `custom.*` (**no override of a native one**);
  `argv_template` = **list** (never a shell string); **only** the listed placeholders; `{args}` **requires**
  a `flag_allowlist`; **interpreter binaries** (`sh`/`bash`/`python`/…) **refused** (otherwise `bash -c` would
  reintroduce the shell); **exfiltration flags** (file write `-o`/`--output`, config read
  `--config`, **proxy** `--proxy`, `--file-read/-write`, `--os-shell`…) **refused** — same curation as the
  native allowlists; size caps + rejection of NUL bytes.
- **Anti-traversal**: the spec file is written into the **server-managed folder** under a name derived from the
  sanitised `kind` — **impossible to write outside the folder**.
- **At execution** (engine): **fail-closed ROE scope-guard** (target out of scope → `skipped`, **zero I/O**);
  **fixed no-shell argv**; status **CLAMPED** to `{tested, reported_by_tool}` (**never `vulnerable`**: a
  scanner *reports*, it does not *prove*); **exploit floor** — an `exploit=true` tool stays gated by
  `operator + arm + reason` (it is **not** launchable from the web without the governed opt-in).

## 5. Making the binary available

A tool whose `binary`/`docker_image` **is not present** in the runtime degrades cleanly to
`available:false` and is **skipped** at run time — **never** a false result, never an invented `vulnerable`.
**Three ways** to make a tool available:

### (a) It is already in the `full` image

The `full` profile (default) ships a **complete scanner suite** — these `binary:` are resolved automatically,
nothing to do:

- **Core / basic recon**: `nmap`, `curl`, `dig` (dnsutils), `httpx`, `nuclei`, `subfinder`.
- **Extended ProjectDiscovery suite**: `dnsx` (recon.dnsx), `naabu` (recon.naabu), `katana` (recon.katana).
- **Recon / enumeration**: `amass` (recon.amass), `gau` (recon.gau),
  `feroxbuster` (recon.feroxbuster), `ffuf` (recon.content),
  `gobuster` (recon.gobuster_dns), `whatweb` (recon.whatweb), `wafw00f` (recon.wafw00f), `wfuzz` (fuzz.wfuzz).
- **Web / TLS / XSS / SQLi scanning**: `nikto` (web.nikto), `testssl.sh` (web.testssl), `dalfox` (xss.dalfox),
  `sqlmap` (sqli.sqlmap, gated by the exploit floor).

*(In the `mini` profile, only `nmap`/`curl`/`dig` are present; **all** the tools above degrade to
`available:false` — the `mini` image stays minimal and byte-identical.)*

**Not shipped (by design)** — they remain reachable otherwise:
`wpscan` (web.wpscan) and `zap-baseline.py` (web.zap_baseline, `prefer_docker`) through their fallback `docker_image`;
**Burp** (burp.py) and **Metasploit** (msf.py) are **external services** driven through ENV/network (never baked
into the image); the **browser automation service** of the `evasion.*` modules (and of `xss.stored`) is
also an **external service** — see the box below.
On a **non-amd64** architecture, the Go/Rust binaries above (dnsx…ffuf) are omitted (amd64 pins only) — the
apt/git tools (sqlmap, nikto, testssl.sh, whatweb, wafw00f, wfuzz, gobuster) remain available.

> **Removed from the catalog (2026-08) — `recon.theharvester` and `recon.masscan`.** Neither of them
> had ever run: their argv was refused by the tool, or their image did not exist (52 findings
> each in the `gxrun2` ledger, all rendered as "I checked, nothing found").
> `theHarvester`: the declared image `laramies/theharvester` **does not exist** on Docker Hub; the author's
> official image (`ghcr.io/laramies/theharvester`) has `restfulHarvest` as its entrypoint — a
> **REST server**, not the CLI. *(That blocker has been **lifted** since 2026-08: `runner` now builds
> `--entrypoint` — see below. **The entry stays removed** for another reason, which
> is sufficient on its own: `-b all` requires API keys and, without them, theHarvester exits **rc=0 almost empty** —
> the exact silence that the `rc != 0` honesty guard cannot catch, the one that got
> `masscan` removed.)* Subdomains remain covered by `recon.subfinder`, `recon.amass` and
> `recon.subdomains` (crt.sh); what is lost are the **emails** (which were not scannable assets
> anyway).
> `masscan`: its argv was repairable (consume the IP pinned by the ROE), but a raw SYN scan does not
> see the response on a multi-homed host -> **rc=0, empty stdout** = a "no hit" that the honesty
> guard (`rc != 0`) does not catch. **`recon.naabu` covers the ports** (TCP connect, `params.ports
> = "1-65535"` for the full range) and it, for its part, runs.
>
> **`recon.gobuster_dns` and `recon.dnsx` now require `params.wordlist`.** Without it, the module
> returns a NAMED `skipped` without launching a process (inert, but honest): no wordlist is
> shipped — that would freeze an enumeration volume policy on the operator's behalf. `dnsx`
> accepts an **inline** comma-separated list (`-w www,mail,dev`), hence without a file;
> `gobuster` requires a **file path readable by the process** (beware: through the
> `docker_image` fallback, `runner` mounts no volume — a wordlist on the host is not visible there;
> install the local binary, or use `dnsx` with an inline list).

> **Seven images declared, one tool removed (2026-08-10) — the ABSENT tool, the other half of the problem.**
> A real campaign skipped **375 actions** as "module unavailable (underlying tool absent)"
> (15 tools × 25 targets), including **all** the discovery tools: the run reached only **9 URLs**.
> Eleven of these entries declared no image: outside an environment that installs the binary,
> they could do nothing other than declare themselves unavailable. Each image below was
> **pulled, executed against a disposable loopback target, and its output actually parsed** — argv AND
> `parser_regex` verified against the image's version, never deduced.
>
> | Module | Declared image | Provenance |
> |---|---|---|
> | `recon.feroxbuster` | `epi052/feroxbuster` (`prefer_docker`) | the author's Docker Hub; **ships its wordlist** |
> | `recon.gau` | `sxcurity/gau` | the image designated by the upstream README (`lc/gau`) |
> | `recon.amass` | `caffix/amass` | OCI label `source = github.com/owasp-amass/amass` |
> | `web.nikto` | `ghcr.io/sullo/nikto` | OCI label `source = github.com/sullo/nikto` |
> | `web.testssl` | `drwetter/testssl.sh` | the author's Docker Hub |
> | `web.wpscan` | `wpscanteam/wpscan` | OCI label `source = github.com/wpscanteam/wpscan` |
> | `xss.dalfox` | `hahwul/dalfox` + `--entrypoint /app/dalfox` | OCI label `source = github.com/hahwul/dalfox` |
>
> **Three entries stay BINARY-ONLY** — `recon.whatweb`, `recon.wafw00f`, `sqli.sqlmap`: no
> image is published under the project's name (verified), and the gap is not filled with a third-party
> rebuild (`secsi/…`, `googlesky/…`) — that is the rule that ruled out `secsi/theharvester`. They run
> in the Forge `full` image (apt) and degrade cleanly elsewhere.
>
> **`recon.gospider` is REMOVED.** Its argv and its parser were nevertheless CORRECT (measured: rc=0,
> 5 URLs parsed) — it is **availability** that decides: no image published upstream (the README
> only offers a `docker build` to do yourself). **`recon.katana` does the same work** (crawl →
> chainable endpoints → injection oracles) **with an official image**: coverage loses
> nothing functional.
>
> **What the measurement corrected along the way** — four entries returned false statements:
> `xss.dalfox` could produce no hit (image without entrypoint → rc=127; positional target
> refused in 3.x → `--url`; `--only-poc` became value-required); `recon.feroxbuster` exited
> **rc=0 empty stdout** without a wordlist — the silence that the `rc != 0` guard does not catch, and it was
> in effect **in the shipped image** (binary installed, SecLists not: the `Dockerfile` now installs
> the list, SHA256-pinned); `web.testssl` reduced its findings to the keyword "NOT ok" and counted
> "not vulnerable (OK)" as a vulnerability; `web.wpscan` captured ONLY the "No WPScan
> API Token" notice while its real, indented findings escaped it. `web.nikto` returned its
> report header as findings and `recon.whatweb` embedded ANSI sequences in the ledger.
> These real outputs are frozen in `tests/test_toolcatalog_measured_invocation.py`.

### The runner's `docker run` path — what it builds, and what it refuses

`runner` launches `docker run --rm --network host [--entrypoint E] <image> <args…>`.

**No `-v` / `--mount` — a deliberate refusal, not an oversight.** What it costs is named: `gobuster` requires
a wordlist **path** and is therefore usable only through its **local binary**; `web.nuclei` had to
give up `-list <fichier>` in favour of `-u a,b,c`. What was not adopted, and why:

| Property required of a mount | Verdict |
|---|---|
| **read-only** (`:ro`) | Insufficient **here**: `:ro` bounds writes, not **reads** — and `--network host` is already on every invocation, so a read is one `curl` away from exfiltration. |
| **bounded** (allowlist of roots) | Feasible, but the default would have to be **empty** (otherwise `/` or `~/.ssh` get through inadvertently) → capability **inert by default**, zero gain. |
| **explicit** (never guessed from an argv) | The path would come from `params.wordlist`, a **console form text** field: the engine's lowest-trust channel. The whole posture (`check_extra_args`, `safe_value`, `unsafe_positional_target`) consists in preventing a **param value** from becoming a **capability**; turning it into a **mounted** host path would do the opposite. |
| **visible** in the decision | Satisfiable (the displayed PoC is built by the same code as the launched command) — but does not redeem the three rows above. |

The two remaining paths are **measured and documented**: install the **local binary** (it reads the
host path with the engine's privileges, without a third-party image), or `dnsx -w www,mail,dev` (**inline**
list, no file). An operator who really wants to mount a file into a tool container
does it **outside the engine**; the engine, for its part, never manufactures access to the host's file system
for a third-party image.

**`--entrypoint` is shipped** (opt-in, `docker_entrypoint` field of a ToolSpec): it **exposes no
file** and unblocks the images whose entrypoint is not the expected CLI — measured case:
`ghcr.io/laramies/theharvester` starts `restfulHarvest`, a REST server. **Governed fail-closed**:
an **interpreter/shell** entrypoint (`sh`, `bash`, `/bin/busybox`, `python3.11`, `env`…) is **refused**
(`rc=126`, no process launched), and so is an entrypoint outside the bounded charset (`-…`, space, metacharacter,
relative path). Without this refusal, a **declarative** ToolSpec from the `./toolspecs` folder — mounted `:ro`
**by default** and presented as "governed, zero code" — could set `docker_entrypoint: "sh"` +
`argv_template: ["-c", …]` and **reintroduce the shell**. The refusal is placed in `runner`, at the single
chokepoint where the entrypoint reaches `docker run`: it covers **all** the declaration paths (code,
file, plugin). *(The console endpoint `/api/tools` does not accept this field: its list of fields is an
explicit allowlist — fail-closed by omission.)*

> ℹ️ **`evasion.*` modules: unavailable by design without a browser service.** The modules
> `evasion.xhr` / `evasion.turnstile` / `evasion.idor_intercept` / `evasion.discover` (and the
> `xss.stored` oracle, which requires DOM rendering) talk to a **browser automation HTTP service** that
> Forge **does not provide**: any implementation exposing the expected contract on `:8080`
> will do, addressed by `FORGE_BROWSER_URL` (default `http://localhost:8080`). Without this service, these
> modules stay `available:false` and their techniques (T1190 / T1556) appear as **not
> attempted** in the coverage matrix — this is **not** a detection gap, it is an
> absent sensor, and the report says so explicitly.

### (b) Thin custom image (`FROM forge:0.0.1`) — frozen tool set, production

Recommended when the tool set is **settled** (reproducible deployment, hardened container/k3s without mounts).
Derive the image and install/copy your binaries into the `PATH`:

```dockerfile
FROM forge:0.0.1
USER root
RUN apt-get update && apt-get install -y --no-install-recommends sqlmap ffuf \
    && rm -rf /var/lib/apt/lists/*
COPY ./bin/myfuzzer /usr/local/bin/myfuzzer        # self-contained binary or script (chmod +x)
USER forge
```

### (c) Mounting WITHOUT a rebuild — `./tools`, `./toolspecs` (default), `./plugins` (opt-in)

A red-teamer **iterates** over many tools: no need to rebuild the image on every addition. The image exposes
**three `:ro` mount folders** (binds in `docker-compose.yml`, section "OUTILLAGE OPÉRATEUR SANS
REBUILD") — **two ON by default, one opt-in**:

| Host folder | → container | Content | Wiring | Default | Taken into account |
|--------------|-------------|---------|---------|--------|-----------------|
| `./tools` | `/opt/tools` | binaries **or executable self-contained scripts** (shebang + `chmod +x`) | **already on the `PATH`** (no env) | **✅ ON** | resolved on PATH by `shutil.which` at **fire-time** — **without a restart, nothing to click** |
| `./toolspecs` | `/opt/toolspecs` | **declarative ToolSpecs** JSON/YAML (zero code) | env `FORGE_TOOLSPECS=/opt/toolspecs` (**ON**) | **✅ ON** | loaded at **re-probe** ("Rafraîchir modules" / `POST /api/modules/refresh`); **merged** with the server-managed dir |
| `./plugins` | `/opt/forge/plugins` | **Python `@register`** modules (code) | env `FORGE_PLUGINS=/opt/forge/plugins` | **⚠️ OPT-IN** | loaded at **boot / re-probe** — uncomment the bind **and** the env |

**Why `./tools` + `./toolspecs` are ON by default, and `./plugins` is not.** A bind mount can**not** be
added to an **already running** container — it must exist from the first `up`. So as to **never** block you in
the middle of a pentest, the two **safe** paths (a binary/script you choose; a **declarative
governed, zero-code** ToolSpec) are therefore mounted from the start. `./plugins` = **arbitrary Python code** in the engine
process → the operator enables it **explicitly**. The host folders already exist (tracked via `.gitkeep`), so
the default bind **does not create** a root-owned folder, and an **empty** mounted folder is harmless (no
tool loaded until something is dropped in — cf. §4/§5(a): absent binary → `skipped`).

### (d) Installing/updating a tool **from the Forge catalog** without a rebuild — `forge tools`

The three paths above are for bringing **your** tool. For the binaries Forge already knows
(httpx, nuclei, subfinder, dnsx, naabu, katana, amass, gau, dalfox, feroxbuster, ffuf), there
is a dedicated path: `forge tools install|update|remove <nom>`. It downloads the version from the
**manifest** [`forge/tools.json`](../forge/tools.json), **verifies its pinned SHA256**, and places the
binary into the persistent tools volume `/data/tools/bin` — at the head of the `PATH`, ahead of the
baked `/usr/local/bin`. Useful to (a) catch up on a tool omitted by a `mini` build, (b) update
without rebuilding the image. No arbitrary URL is accepted and every act is logged to the ledger.
See [TOOLS_LIFECYCLE.md](TOOLS_LIFECYCLE.md).

**Example — adding `myfuzzer` without a restart (mount already active):**

```bash
# drop the executable binary/script on the host side — that's all: usable on the NEXT run
cp ~/bin/myfuzzer forge/tools/ && chmod +x forge/tools/myfuzzer
```

Then declare a ToolSpec pointing to `"binary": "myfuzzer"` (through **Administration → Add a tool**, §2, or a
JSON file dropped into `./toolspecs` + **"Rafraîchir modules"**). `/opt/tools` being on the `PATH`,
`runner.tool` resolves it at run time. **No `docker build` / `down` / `up`.** *(The only exception: enabling the
opt-in `./plugins` mount requires a one-shot recreating `docker compose up` — see the table above.)*

> **Security posture — to be owned.** `./tools` and `./plugins` are **TRUSTED-OPERATOR**: you
> execute **arbitrary binaries / Python code that YOU choose to mount** (a `.py` plugin runs
> in the engine process). **ToolSpec governance** (fail-closed scope-guard, **no-shell** argv, flag
> **allowlist**, status never promoted to `vulnerable`, exploit floor) bounds **HOW** a tool is invoked — it
> does not sandbox what a binary/plugin does internally. `./toolspecs` is the **governed code-free** path
> (declarative only) — which is why it, like `./tools`, is **ON by default** while `./plugins`
> (code) stays **opt-in**. All mounts are **`:ro`**; the container runs as the **non-root** user `forge`
> (uid 10001) and reads a `0755` host folder without trouble. Nothing is loaded until you drop something in.

### `docker_image` (containerised fallback) — requires the docker socket

A ToolSpec can set a fallback `docker_image`. It **requires the docker socket** mounted into the Forge
container; **without** a socket (the hardened default), a `docker_image` tool **cannot** run → favour a
**present binary** (`full` image, custom image, or `./tools`) or a self-contained script.

### Custom Python scripts — two legitimate paths

A ToolSpec **CANNOT** invoke an interpreter (`python3 script.py`, `sh`, `bash`… are **refused
fail-closed** — otherwise `bash -c` would reintroduce the shell). For a tool written in Python:

- **either** a `@register` **plugin** dropped into `./plugins` (`FORGE_PLUGINS`) — the code path;
- **or** a **self-contained executable** (shebang `#!/usr/bin/env python3` + `chmod +x`) dropped into `./tools`,
  invoked by its **name** (`"binary": "monoutil"`), not through an interpreter.

In all cases: **binary absent at runtime → `skipped`** (offline-safe), never a false result.

### Supported languages

A tool can be written in **any language** — what matters is that the runtime can
launch it by its **name** (not through an interpreter, cf. the no-shell argv §4). The table below summarises
**how to supply** the tool depending on its language, and whether a **restart** is necessary.

| Tool language | How to supply it | Restart? |
|--------------------|--------------------|---------------|
| **Compiled binary** (C/C++/Rust/Go) | Drop the binary into **`forge/tools/`** (`chmod +x`). **Preferably static**: a **dynamically linked** binary requires its `.so` to be present in the image (otherwise `skipped` at run time). | **No** — resolved on the `PATH` at **fire-time**, without a restart. |
| **Python script** | `python3` is present (it is the engine). **Two paths**: (1) shebang `#!/usr/bin/env python3` + `chmod +x` in **`forge/tools/`**, invoked by its **name**; (2) **`@register`** module in **`forge/plugins/`** (**opt-in** mount, arbitrary code). ⚠️ Reminder: a ToolSpec `"binary": "python3", "argv_template": ["script.py"]` is **REJECTED** (python = banned interpreter, anti-shell §4) — hence the **executable with shebang** or the **plugin**. | **No** (`tools/`) — available on the next run. The `./plugins` plugin requires enabling the opt-in mount (one-shot recreation). |
| **Node/JS, PHP, etc.** | The interpreter is **NOT** in the `full` image → **supply it**: either a **static binary** (`node`/`php`) dropped into **`forge/tools/`**, or a **custom image** (`FROM forge:0.0.1` + `apt install nodejs php-cli`, cf. §5(b)). | **No** if static binary in `tools/`; **yes** (rebuild) for the custom image. |

> **What is really in the `full` image** (verified in the `Dockerfile`): the **engine's** interpreter
> is **`python3`** (the `full` profile also adds `python3-pip`/`python3-venv` for the weasyprint PDF engine,
> still Python); the extended scanner suite additionally pulls **`ruby`** (dependency of `whatweb`) and
> **`perl`** (+ modules, for `nikto`). The **binaries/scripts** shipped in `full`: `nmap`, `curl`, `dig`
> (dnsutils), `httpx`, `nuclei`, `subfinder`, `dnsx`, `naabu`, `katana`, `amass`, `gau`,
> `feroxbuster`, `ffuf`, `gobuster`, `whatweb`, `wafw00f`, `wfuzz`, `nikto`, `testssl.sh`,
> `dalfox`, `sqlmap` (list [§5(a)](#a-it-is-already-in-the-full-image)). **Neither `node` nor `php`** — for these languages, supply the interpreter
> yourself (column above).

### Adding a PACKAGED tool (e.g. `hydra`, an apt package) live

Some tools are not a simple self-contained binary but a **package** (system dependencies). Options,
**from fastest to most reproducible**:

1. **`docker compose exec -u root forge apt-get update && apt-get install -y <paquet>`** — installs the package
   into the **RUNNING container**, **without `build` / `down` / `up`**. Good to know: it is **ephemeral** (lost again as soon
   as the container is recreated), **non-reproducible**, and it **requires network access** (OK in local Docker;
   **blocked in k8s** if an `egress-deny` `NetworkPolicy` is in place). Then declare its **ToolSpec**
   (form **Administration → Add a tool**, §2) then **"Rafraîchir modules"**.
2. **Static / portable binary in `forge/tools/`** — no dependency trouble, **persistent** as long as the
   folder is mounted, **without a restart** (cf. §5(c)).
3. **Custom image `FROM forge:0.0.1` + `apt install <paquet>`** (§5(b)) — the **reproducible / permanent** path.
   It implies a **rebuild**, hence **NOT during a run** — to be **prepared before** the engagement.

**Governance — true for any packaged tool added:**

- It stays **scope-guarded**: the fail-closed ROE scope-guard applies (target out of scope → `skipped`, **zero
  I/O**) — **never** an out-of-scope action, whatever the tool.
- An **exploit / brute-force** tool must be **declared `exploit=true`** in its ToolSpec → it is
  **launchable** only with **operator + arm + reason** (the existing C2 gate, cf. §4).
- ⚠️ **Brute-force / cred-cracking** tools (`hydra`, `hashcat`, `john`) are **outside the catalog by
  default**: Forge is **proof-oriented** (and brute force is **banned** on the bug-bounty side). **BUT** the operator
  **can** add them for an **authorised pentest** — the mechanism **does not forbid it**: they stay
  **admin-gated**, **scope-guarded** and **armed** (exploit class). It is a **policy choice**, **not a
  technical block**.

## 6. API

All admin-only (admin session; fail-closed 401/403 otherwise), ledgered.

| Method & route | Effect |
|-----------------|-------|
| `POST /api/tools` | Validates + persists + **hot-reloads** a ToolSpec; returns the created tool (`registered`, `available`, `params_schema`). |
| `GET /api/tools` | Lists the tools added through the UI (`user_added`) + the managed folder. |
| `DELETE /api/tools/:kind` | Removes a UI tool (file + catalog). **Refuses** a native module (403). |

Server-managed folder: `FORGE_TOOLSPECS_DIR` if set, otherwise a `toolspecs/` **sibling of the database**
(folder of `FORGE_CONSOLE_DB`). It is injected into `FORGE_TOOLSPECS` on every re-probe of the catalog
(`forge modules --json`) — this is what makes the addition **immediate** without a restart, and **persistent** across reboots.

## 7. Python plugin upload

The addition endpoint accepts **ONLY** a declarative `ToolSpec` (binary + no-shell argv + allowlist) — the
**safe path by default**. It **never takes** arbitrary Python code.

Loading a **Python plugin** (`FORGE_PLUGINS`, arbitrary executable code) is a **separate high-trust
path**, **outside the UI**, reserved to the server operator (dropping a `.py` file + environment
variable). It **executes arbitrary code**: reserve it for a plugin whose source you control.
The **default** build **starts with zero user tools** (byte-identical behaviour).

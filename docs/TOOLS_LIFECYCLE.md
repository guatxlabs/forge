# Tool lifecycle — single manifest + runtime overlay

[English](TOOLS_LIFECYCLE.md) | [Français](TOOLS_LIFECYCLE.fr.md)

Forge downloads a dozen external security binaries (httpx, nuclei, subfinder, dnsx, naabu,
katana, amass, gau, dalfox, feroxbuster, ffuf; `nmap` and the `apt` suite are installed
differently). This page describes **where their versions live**, **how they are verified**, and **how
to install or update one without rebuilding the image**.

> Reading prerequisites: [Installation](INSTALLATION.md) (`mini`/`full` profiles) and
> [Adding your own tool](TOOLS.md) (ToolSpec — declaring a *governed* CLI tool, without code).
> This page deals with the **binary**; `TOOLS.md` deals with its **declaration** as a module.

---

## 1. The manifest — `forge/tools.json`

A single source of truth. It carries, **per tool**: the version, a URL template, the archive
format, the path of the binary *inside* the archive, the name placed on the `PATH`, and a **SHA256 per
architecture**.

```json
{
  "name": "httpx",
  "group": "core",
  "enabled": true,
  "profiles": ["full"],
  "version": "1.6.9",
  "archive": "zip",
  "url": "https://github.com/projectdiscovery/httpx/releases/download/v{version}/httpx_{version}_linux_{arch}.zip",
  "member": "httpx",
  "bin": "httpx",
  "sha256": { "amd64": "c8d3…fb5f", "arm64": "8cf1…aa95" }
}
```

Available templates: `{version}`, `{arch}` (Docker naming: `amd64`/`arm64`) and `{arch_uname}`
(`x86_64`/`aarch64` — some vendors name their assets that way). **Bring-your-own-tool** principle:
adding a tool = adding a JSON entry, **no code**.

**Why this file exists.** The versions and digests were hard-coded `ARG`s, **duplicated**
between `Dockerfile` and `docker-compose.yml`. Two copies of a pin are a silent divergence waiting
for its moment. They now exist only here — and a static guard
(`tests/test_tools_manifest.py`) fails if a tool version, digest or URL reappears in the
`Dockerfile` or the compose file.

**Bumping a version**: edit `version` + the digests (read from the `*_checksums.txt` of the upstream
release), then either rebuild the image, or — without a rebuild — `forge tools update <nom>` (§3).

### Who reads the manifest

| Consumer | When | Effect |
|---|---|---|
| `Dockerfile` (`python3 forge/toolsmanifest.py --arch … --profile full`) | at **build** | baseline baked into `/usr/local/bin`, according to `FORGE_TOOLS_PROFILE` |
| `forge tools list\|install\|update\|remove` | at **runtime** | persistent overlay in `/data/tools/bin` |
| console — `GET/POST /api/tools/runtime` + **Administration → tool lifecycle** panel | at **runtime** | drives the CLI above, admin-only + ledgered (§3.1) |

---

## 2. Build-time baseline — unchanged

`FORGE_TOOLS_PROFILE=full` (default) installs the manifest's tools; `mini` omits them and the modules
degrade cleanly (`available: false`). Verification is what it has always been: each
archive is validated by `sha256sum -c` against the pin for its architecture, **any mismatch
makes the build fail**.

Two guards are added, both fail-closed:

- a tool **without a pin** for the target architecture is **dropped from the plan** — never downloaded
  unverified — and listed on `stderr` (this is the case of the extended suite outside `amd64`, as before);
- the `core` base group (httpx/nuclei/subfinder) goes through `--require-complete core`: a missing pin
  **makes the build fail** rather than producing a silently truncated image.

---

## 3. Runtime overlay — installing / updating without a rebuild

```bash
forge tools list                              # state: target version, PATH resolution, provenance
forge tools install nuclei  --actor alice     # installs the manifest's version
forge tools update  nuclei  --actor alice     # re-places the manifest's version (after a bump)
forge tools remove  nuclei  --actor alice     # removes from the runtime layer; the baseline stays
```

The binary lands in **`/data/tools/bin`** — a persistent volume, owned by the `forge` user
(uid 10001), **at the head of the `PATH`** ahead of the baked `/usr/local/bin`. It therefore survives a container
*recreate*, and an update no longer requires rebuilding the image.

`PATH` resolution order: `/opt/tools` (operator bind mount, priority unchanged) →
`/data/tools/bin` (runtime layer) → `/usr/local/bin` (baked baseline) → rest of the system.

Outside a container, the default directory is `<data_dir>/tools`; `FORGE_TOOLS_DIR` overrides it.

> **On Kubernetes, the overlay is unavailable as is — and it says so.** The Deployment
> `k8s/40-console.yaml` sets `readOnlyRootFilesystem: true` and mounts only `/data/db`, `/data/ledger`
> and `/data/scope`. `/data/tools` is therefore read-only there: `forge tools install` **refuses
> cleanly** ("répertoire outils non inscriptible" — tools directory not writable), it degrades nothing silently. To
> enable it, mount a volume on `/data/tools` — a PVC if you want installs to survive a
> pod restart, an `emptyDir` if ephemeral per-pod installs are enough for you. Nothing else to
> change: `FORGE_TOOLS_DIR` and the `PATH` already come from the image.

### 3.1 From the console (API + panel)

The same thing, without a shell in the container. `Administration → cycle de vie des outils` (the tool lifecycle panel) lists the
manifest (target version, installed version read **from the receipt**, runtime/baseline/absent provenance,
resolved path, presence of the pin for the architecture) and attaches three actions to each row.

```
GET  /api/tools/runtime                              # state (executes no tool)
POST /api/tools/runtime  {"action":"install","name":"nuclei"}
```

**The body accepts ONLY `{action, name}`.** Any other field — `url`, `sha256`, `digest`, `version` —
makes the request **fail** with 400, before any subprocess. This is not silent
filtering: it is the same property as in the CLI, expressed at the HTTP level. The `name` must moreover
appear in the manifest **as the engine reports it** (`forge tools list --json`); if that
probe does not succeed, the mutation is **refused** rather than attempted blindly. The `argv` is fixed and
built server-side. A tool without a pin for the current architecture has **no button** in the
panel: there is no path, not even a cosmetic one, to an unverified download.

Governance: **admin-only** (`check_admin`, 403 otherwise — installing a binary is at least as
privileged as declaring a tool through `/api/tools`, and requires individual attribution), **bounded**
spawn (time budget, concurrency ceiling, byte cap, group kill), and **double
logging** — `console.tools.install|update|remove` (who asked for what, and the outcome) in addition to
the `tools.install` entry that the installer writes itself with **the verified digest**.

### What it does not do

- **No installation from an arbitrary URL.** There is neither `--url` nor `--sha256`. The source is
  computed from the manifest: that is the allowlist.
- **No "update to the latest upstream version".** That would be an unpinned download.
  Updating = bumping the manifest (reviewed and pinned change) then `forge tools update`.
- **No auto-update, no background task.** Explicit operator action, only.
- **No elevation.** The installed tool stays subject to exactly the same gates as the one from the
  baseline: fail-closed ROE scope-guard, exploit floor, fixed no-shell argv, availability probe.

---

## 4. The governance model, point by point

Installing a binary at runtime in an offensive tool is precisely the capability that cancels out
governance if it is badly set up. Each guarantee below is covered by a test
(`tests/test_tools_runtime_install.py`, `tests/test_tools_manifest.py`).

| Guarantee | Implementation | What happens on deviation |
|---|---|---|
| **Mandatory integrity** | SHA256 computed **on the stream** during the write, compared to the manifest's pin | refusal, temporary file destroyed, **nothing** on the `PATH`, refusal **logged** |
| **Pin required** | no digest for the architecture → refusal **before any network byte** | no request is issued |
| **Allowlisted source** | URL derived from the manifest; no URL parameter exists | name outside the manifest → refusal, nothing is downloaded |
| **Strict HTTPS** | `https://` template required at load time; redirection leaving HTTPS refused | `URLError`, download abandoned |
| **No shell** | `urllib` + `zipfile`/`tarfile` — neither `curl`, nor `unzip`, nor `tar`, no subprocess | (test: any process creation makes the suite fail) |
| **No path escape** | a single member extracted; the destination is **computed by us**, never read from the archive | a member named `../../evil` lands under the intended `bin` name, in the tools directory |
| **Logging** | `tools.install` / `tools.update` / `tools.remove` / `tools.refused` chained + signed | ledger unreachable → **action refused** (no untraced install) |
| **Atomic placement** | staging + `os.replace`, mode `0755` | never a half-written binary on the `PATH` |
| **No-op by default** | nothing is created or probed at import; no engine module imports the installer | without an operator action, behaviour identical to the baseline |

A ledger entry carries the name, the version, the architecture, **the verified digest**, the URL, the path
and the actor:

```json
{"kind": "tools.install", "detail": {
  "name": "httpx", "version": "1.6.9", "arch": "amd64", "actor": "alice",
  "sha256": "c8d36461…fb5f", "previous_version": "",
  "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip"}}
```

`forge ledger verify --ledger …` keeps validating the chain end to end.

---

## 5. What is not built (and why)

- **Versions outside the manifest.** Installing a version absent from the manifest would mean accepting a
  digest entered by the operator (or fetched then confirmed). That is an integrity UX in its own right,
  left to a dedicated iteration rather than rushed: as long as it does not exist, there is **no**
  path to an unpinned download.
- ~~**API and console panel.**~~ **Shipped** (§3.1): `GET/POST /api/tools/runtime` + the
  `Administration → cycle de vie des outils` panel. The constraint that made this work delicate is upheld —
  the route accepts only a **manifest name**, never a URL nor a fingerprint.
- **Version probe by execution.** `forge tools list` launches **nothing**: the installed version is
  read from the receipt dropped at install time. Listing must not be an execution.

# Roadmap — Tool lifecycle: install-or-not + update on demand (hybrid)

[English](roadmap-tools-lifecycle.md) | [Français](roadmap-tools-lifecycle.fr.md)

**Status: LARGELY BUILT** — design approved on 2026-07-04, building blocks 1/2/3 + CLI shipped.
User documentation: [`docs/TOOLS_LIFECYCLE.md`](TOOLS_LIFECYCLE.md). This document remains the record
of the DECISION; the progress status is summarised below.

| Building block | State | Where |
|---|---|---|
| 1. Single manifest (end of the Dockerfile↔compose duplication) | **done** | `forge/tools.json` + `forge/toolsmanifest.py`; guard `tests/test_tools_manifest.py` |
| 2. Persistent tools volume + PATH precedence | **done** | `/data/tools/bin` (Dockerfile `VOLUME`/`ENV PATH`/`FORGE_TOOLS_DIR`, compose `forge-tools`) |
| 3. Integrity of runtime installs (manifest versions) | **done** | `forge/toolsinstall.py` — SHA256 pin verified while streaming, fail-closed, mandatory ledger |
| 4. Console surface — **CLI** | **done** | `forge tools list\|install\|update\|remove` (`forge/cli/tools.py`) |
| 4. Console surface — **API + UI panel** | to do | `console/` (outside the batch's scope) |
| 5. Version probe | **partial** | installed version read from the receipt (`list` executes nothing); no `httpx -version` |
| 4bis. Off-manifest integrity UX | **not done, deliberately** | no path to an unpinned download as long as it does not exist |

## Problem
Today the external security tools (httpx, nuclei, subfinder; nmap is apt-installed separately) are installed only at **build** time through the Dockerfile toggle `FORGE_TOOLS_PROFILE=full|mini`. The versions are hard-coded ARGs, **duplicated** between `Dockerfile` and `docker-compose.yml`. There is **no** way to install an omitted tool, or to update a tool, without rebuilding the image. Maintainer's need: (a) choose whether each tool is installed or not, and (b) update the tools on demand.

## Chosen approach: HYBRID (build-time baseline + runtime overlay)
- **Build-time baseline unchanged**: the image keeps baking the tools according to `FORGE_TOOLS_PROFILE` (full/mini). Production stays reproducible and SHA-pinned. Default behaviour identical to today.
- **Runtime overlay**: the console gains an **admin-gated and audited** capability to install / update / remove a tool at runtime, in a **persistent tools volume, owned by the `forge` user**, which takes precedence on the PATH ahead of the baked `/usr/local/bin`. Installing/updating a tool at runtime **does not require a rebuild**.

## Building blocks (from the code reconnaissance, 2026-07-04)
1. **Centralise the tool metadata** (end of the Dockerfile↔compose duplication): a single manifest (versions + SHA256 pins per arch + URL template + enabled-by-default). The Dockerfile reads it; the runtime installer reads the same file. Candidate: `forge/tools.json`, or extend the catalog's `ToolSpec` (`forge/modules/toolspec.py`, currently only `binary` + `docker_image` — no version/checksum/url).
2. **Persistent tools volume**: new named volume mounted e.g. at `/data/tools/bin`, owned by uid 10001 (forge), prefixed to the PATH. Survives a container recreate (the baked `/usr/local/bin` does not). Touches compose + Dockerfile `VOLUME` + PATH variable.
3. **Integrity model for runtime installs** (preserve the "never an unverified download" posture, cf. `Dockerfile:151`):
   - Preferred: install only versions present in the manifest, which carry a pinned SHA256 → verify after download, as at build time.
   - For an arbitrary/newer version absent from the manifest: require the operator to supply the expected SHA256 (or fetch+display the checksum published by ProjectDiscovery for explicit admin confirmation). NEVER implicit trust.
4. **Console surface**:
   - API: extend the admin/module surface (natural hook: `POST /api/modules/:kind` `module_governance`, already `check_admin` at `main.rs:1675`) or a new `POST /api/tools/:name/{install|update|remove}`. Admin-only, audited through `append_console_ledger` (pattern at `main.rs:1614`).
   - CLI: `forge tools {list|install|update|remove}` subcommand (dispatch at `main.rs:9835`).
   - UI: tools panel showing installed version vs target version, install/update/remove buttons, mini/full baseline indicator.
5. **Version visibility**: today availability is a probed boolean (`shutil.which`, `runner.available`), without a version. Add a version probe (`httpx -version`, etc.) so that the UI shows installed vs target and offers the update when they differ.

## Constraints / pitfalls (to respect)
- Non-root container (uid 10001); `/usr/local/bin` is root-owned and baked → runtime installs must target the forge-owned tools volume, not `/usr/local/bin`.
- Unstable host egress (observed: HTTP/2 partial-file `curl (18)` + PyPI read-timeout) → the runtime installer must reuse the hardened curl flags (`--http1.1 --retry 5 --retry-delay 3 --retry-connrefused --retry-all-errors --connect-timeout 30 --max-time 300`).
- Keep the mini/full semantics of `FORGE_TOOLS_PROFILE` intact; the hybrid is additive.
- Vendor-agnostic principle: design the tools manifest generically (bring-your-own-tool), not hard-coded for the 3 PD tools.

## Non-goals (for now)
- No auto-update / background upgrade; explicit admin action only.
- No unpinned / unverified download.

## Sequencing when this gets built
1. Single-source tools manifest + Dockerfile/compose read it (removes the duplication) — safe, no behaviour change.
2. Persistent tools volume + PATH precedence + version probe.
3. Runtime install/update/remove: CLI first, then API (admin + audit), then UI panel.
4. Integrity UX for off-manifest versions.

## Related context
- Prior build fix: `COPY forge/VERSION` into the image (the compile-time `include_str!` was looking for a `VERSION` absent from the context).
- Hardening of the build-time tool download (curl `--http1.1` + retries) following the HTTP/2 network flake — same batch as this roadmap.
- Related out-of-scope residue: the runtime stage's `pip install weasyprint` has NO retry and flaked once (PyPI read-timeout); candidate for the same treatment later.

## Egress / network robustness residues (to watch)
The build host has an **unstable egress** (two flakes observed on 2026-07-04: HTTP/2 partial-file `curl (18)` on the download of the ProjectDiscovery tools, and a PyPI read-timeout on `pip install`). Two points recorded:

1. **`pip install weasyprint` without retry.** The runtime stage installs weasyprint (PDF) through `pip install` **without** a retry/timeout policy, unlike the tools' curl download, which is now hardened. It flaked once (read-timeout `files.pythonhosted.org`). **Not fixed yet — outside the scope of the current batch.** Candidate for the same treatment (retries + bounded timeouts, e.g. `pip --retries N --timeout T` or the `PIP_RETRIES`/`PIP_DEFAULT_TIMEOUT` variables) **if it happens again**.

2. **The curl fix is a workaround, not the root cause.** Forcing HTTP/1.1 + retries on the tools download is robust and sufficient in practice, but if the network flakes **persist**, the real cause is the **host's egress connectivity** (network/DNS/MTU/proxy), not the Dockerfile. In that case: diagnose the host connectivity rather than piling up retries in the image.

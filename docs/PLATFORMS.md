<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Platform support matrix

[English](PLATFORMS.md) | [Français](PLATFORMS.fr.md)

Forge is designed to be **OS-agnostic**: no absolute path or binary is hard-coded in the load-bearing
code. OS-specific decisions are **centralised** in two seams:

- **Python engine** — `forge/portability.py`: `config_dir()` / `data_dir()` (default directories PER
  OS, `FORGE_*` override takes precedence) and `restrict_file_permissions()` (0600 on POSIX,
  best-effort no-op elsewhere); binary resolution via `shutil.which` in the tool-wrapper
  (`forge/runner.py`) — handles the `.exe`/`.bat`/`.cmd` suffixes (PATHEXT) on Windows.
- **Rust console** — temporary paths via `std::env::temp_dir()` (honours `TMPDIR`/`TMP`/`TEMP`),
  database and data roots via environment variables (`FORGE_CONSOLE_DB`, `FORGE_PKG_DIR`,
  `FORGE_CONSOLE_WEB`, `FORGE_CONSOLE_SCOPE`, …), Python interpreter via `FORGE_PYTHON` resolved on
  the `PATH`, and the governed C2 spawn **guarded by `#[cfg(unix)]` / `#[cfg(not(unix))]`**.

> **Anti-regression net**: `tests/test_portability_guard.py` FAILS if a hard-coded `/tmp`, `/usr/bin` or
> `/home/` reappears in `forge/` or `console/src/`. It runs in the standard suite.

---

## Overview

| Platform | Status | Details |
|---|---|---|
| **Linux** (x86-64, arm64) | ✅ **Fully supported — primary** | Dev/CI/deployment target. All features, including the `setsid`/`killpg` subtree kill of the governed C2 run, and `0600` perms on keys/ledger. |
| **macOS** (Darwin, Intel/Apple Silicon) | ✅ **Fully supported** | POSIX: `setsid`/`killpg` and `chmod 0600` work exactly as on Linux. Default directories fall into the POSIX branch (`~/.config/forge`, `~/.local/share/forge`) — predictable. |
| **Windows** (10/11, Server) | 🟡 **Best-effort** | Console/DB/RBAC/wizard/detection/import + most tool-wrappers work. The **only** degradation: the governed C2 run lacks the POSIX subtree kill (see below). No crash: everything degrades cleanly. |

Common prerequisites: **Rust ≥ 1.70** (console) and **Python ≥ 3.9, stdlib only** for the engine
core (the network/tooling modules use `shutil.which` to discover optional binaries).

---

## Windows — what works vs what is Unix-only

| Component | Windows | Note |
|---|---|---|
| Rust/axum console (HTTP, SPA, `/health`) | ✅ | No POSIX call on the serving path. |
| SQLite database + migration + encrypted backup | ✅ | `rusqlite` is cross-platform; `FORGE_CONSOLE_DB` resolves the path. |
| RBAC (admin/operator/viewer), auth, host-guard | ✅ | Pure logic, no OS. |
| First-deployment wizard (`/api/setup`) | ✅ | Same. |
| Detection sources (Plume/CrowdSec/…/exec/file) | ✅ | `exec` resolves the program on the `PATH`. |
| Import (nmap/nuclei/burp/httpx/ffuf/generic) + `/api/import` | ✅ | Staging under `std::env::temp_dir()` → `%TEMP%`. |
| Tool-wrappers (binary resolution) | ✅ | `shutil.which` (Python) / `PATH` (Rust) — handle `.exe`/`.bat` via PATHEXT. Missing tools degrade to "unavailable", as on Linux. |
| Tamper-evident ledger (hash-chain + Ed25519/HMAC) | ✅ | Portable cryptography; **the key lands** even if the `chmod 0600` is skipped. |
| `0600` perms on keys/ledger | 🟡 degraded | `restrict_file_permissions()` is a **best-effort no-op** outside POSIX (Windows does not express `0600`) — secure through NTFS ACLs / the file location. |
| **Governed C2 run — subtree kill** (`setsid`/`killpg`) | 🟡 **degraded (Unix-only)** | The child process **spawns and runs**; cancel/watchdog terminate it via `kill_on_drop` and the reconciler marks the run terminal in the database. What is MISSING on Windows: cutting **the whole detached subtree** at once (POSIX session groups do not exist). Guarded by `#[cfg(not(unix))]`, documented, **never a crash**. |

**Invariants preserved on every platform**: ROE fail-closed / scope-guard, operator+exploit
floor, tamper-evident ledger, RBAC, host-guard, per-engagement isolation, shell-less spawn
(`shell=false`). None of these invariants depends on the OS.

---

## Resolution of config / data / temp directories

The environment override **always wins**; only the DEFAULTS are per-OS.

| Role | Override | Linux/macOS default (POSIX) | Windows default |
|---|---|---|---|
| **Config** (engine) | `FORGE_CONFIG_DIR` | `$XDG_CONFIG_HOME/forge` otherwise `~/.config/forge` | `%APPDATA%\forge` (fallback `~/AppData/Roaming/forge`) |
| **Data** (ledger, memory, index) | `FORGE_DATA_DIR` | `$XDG_DATA_HOME/forge` otherwise `~/.local/share/forge` | `%LOCALAPPDATA%\forge` (fallback `~/AppData/Local/forge`) |
| **Temp** (run plans, reports, import staging — console) | `TMPDIR`/`TMP`/`TEMP` (via `std::env::temp_dir()`) | `/tmp` (or `$TMPDIR`) | `%TEMP%` |
| **Console database** | `FORGE_CONSOLE_DB` | `forge.db` (relative to the cwd) | same |

`config_dir()` / `data_dir()` return a `pathlib.Path`; `create=True` does the `mkdir(parents,
exist_ok)`. See [`CONFIGURATION.md`](CONFIGURATION.md) for the exhaustive table of variables.

---

## Postgres backend (`store-postgres`) — host dependencies

The OPT-IN Postgres backend (Cargo feature `store-postgres`, see [`DEPLOYMENT.md`](DEPLOYMENT.md) §3bis)
stays **openssl-free** (TLS `rustls`/`ring`) and the **connection** requires **no** external binary
(no libpq — pure Rust client). The **Postgres BACKUP**, on the other hand, calls the external binary
**`pg_dump`** (and `pg_restore` on restore): it must be **on the PATH** of the host/container,
**in a version ≥ that of the server** (a v15 `pg_dump` refuses a v16 server). The Docker image built
with the feature installs `postgresql-client-16` from the PGDG repository (ARG `FORGE_PG_CLIENT_VERSION`);
natively, install the matching client package. Without `pg_dump`, the backup **fails clearly**
(never a silent fallback). Cross-platform: `pg_dump` exists on Linux/macOS/Windows.

---

## Documented Unix-only limitation (summary)

Only one capability is strictly Unix: **the process-group kill (`setsid` + `killpg`) of the
governed C2 run**, which makes it possible to cut in one go the whole subtree of a detached engine. Outside Unix,
the run remains controllable (spawn, cancel via `kill_on_drop`, reconciliation at boot, terminal status in
the database) but **without** the "cut the whole detached subtree" guarantee. This is an explicit choice,
guarded by `cfg`, non-crashing, and with no effect on the governance invariants. For this use,
prefer **Linux or macOS**.

One capability is moreover strictly **Linux**: the sweep of descendants that have LEFT the group
(`setsid`/double-fork) before releasing a slot of the engine bound. It relies on `/proc` (inherited
environment marker) and on `PR_SET_CHILD_SUBREAPER` (closed parent chain) — see
`docs/HTTP_API.md`. Without `/proc`, the sweep returns an **empty** list: no blind kill, and the
guard falls back to the group kill alone (so a detached descendant can survive). The rest of the
behaviour is identical.

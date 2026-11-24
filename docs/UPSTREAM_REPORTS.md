# Defects found upstream — reproductions ready to send

[English](UPSTREAM_REPORTS.md) | [Français](UPSTREAM_REPORTS.fr.md)

This file exists because a tool defect found here is **not** specific to this repository: any
project in the same configuration has it too, without knowing it. Reporting it upstream is better than
working around it silently — and a minimal reproduction costs the upstream maintainer less than a
prose report.

Each entry carries: the defect, **how it was isolated** (single factor), the reproduction, and what
the project did in the meantime.

---

## 1. cargo-deny / krates — an OPTIONAL dependency whose package name ≠ `[lib]` name disappears

**Status: to be reported.** Found on 2026-08-07, cargo-deny **0.18.2**.

### The defect

`cargo-deny` (via `krates`) **silently loses an entire dependency subtree** when an
**optional** dependency has a package name different from the name of its `[lib]` target.

The feature declares the **package** (`object-store = ["dep:rust-s3"]`), but the resolved edge returned by
`cargo metadata` carries the **lib** name (`"name": "s3"`). The matching fails, the feature is
considered disabled, and the whole subtree leaves the audited graph.

### Why it is serious — it is not a false negative, it is a false GREEN

The tool does not say "I did not look". It returns **`licenses ok`**. Measured on two copies of the same
repository differing **only** in the naming of this dependency:

| tree | verdict |
|---|---|
| `rust-s3 = { optional = true }` (lib name `s3`) | `licenses ok` — 239 crates seen |
| `s3 = { package = "rust-s3", optional = true }` | **`licenses FAILED`** — 287 crates seen |

The two crates that made the audit fail — `attohttpc` (MPL-2.0) and `tiny-keccak` (CC0-1.0) —
were invisible. Worse: this repository's policy had **removed `MPL-2.0`** from its allowed list
on the grounds that "cargo-deny reports it as not encountered". A licence decision taken **through**
the blind spot.

### Isolation — one factor changed at a time

| manifest | invocation | crates seen | subtree |
|---|---|---|---|
| `optional`, `dep:rust-s3` syntax | `--all-features` | 239 | absent |
| `optional`, implicit `["rust-s3"]` syntax | `--all-features` | 239 | absent |
| dependency made **non**-optional | *(no flag)* | 250 | **present** |
| **renamed** `s3 = { package = "rust-s3" }` | `--all-features` | 287 | **present** |

Ruled out by measurement: it is **not** `--all-features` (it does take effect: 201 → 239, the optional
dependencies of the other features come in), **not** the `dep:` syntax, **not** a restricted `targets` (there is
none), **not** an exclusion. `cargo metadata --all-features`, for its part, sees all 290 crates.

### Minimal reproduction

```toml
# Cargo.toml
[features]
object-store = ["dep:rust-s3"]

[dependencies]
rust-s3 = { version = "0.37", optional = true, default-features = false, features = ["sync-rustls-tls"] }
```

```bash
cargo-deny --all-features check licenses --config <chemin ABSOLU>/deny.toml
# -> the rust-s3 / attohttpc / aws-lc-sys subtree is ABSENT from the graph

# then, the only change:
#   s3 = { package = "rust-s3", version = "0.37", optional = true, ... }
#   object-store = ["dep:s3"]
# -> the subtree appears, +48 crates
```

`rust-s3` is a good public test case: package `rust-s3`, `[lib] name = "s3"`.

### Desired behaviour

Whatever fix is chosen upstream — what matters is that the tool **does not return `ok`** on a
graph it knows to be incomplete. A warning naming the lost dependency would be enough to turn a
false green into a question put to the human.

### What this project did in the meantime

1. **Renamed the dependency** (`s3 = { package = "rust-s3" }`) — one line, no code change
   (the extern was already called `s3`), `Cargo.lock` unchanged.
2. Added `scripts/check_dep_licenses.py`, which redoes the check on `cargo metadata --all-features`
   by reading the `allow` list of `deny.toml` — **a single policy truth, two engines**.
   Wired into CI with a red self-test, because a guard unable to fail is decoration.
3. Documented the actual scope of the audit in `docs/DEPLOYMENT.md` §3quater.2, including **what
   is still not covered** (`bans` / `sources` on these crates).

### Side note, same family

A **relative** `--config` is resolved from the manifest's folder and **silently falls back** to the
default configuration if the path does not resolve. Same class of defect: the tool carries on with a
policy that is not the one it was asked for, without saying so. Hence the **absolute** path everywhere
in this repository.

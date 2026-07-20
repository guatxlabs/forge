# Changelog

All notable changes to Forge are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Forge aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first tagged release.

> Forge is pre-1.0: the public API, module kinds, and config surface may still change between
> minor versions. Breaking changes will be called out here.

## [Unreleased]

### Notes for open-source builds
- The Rust console depends on `guatx-core` via a **pinned public git dependency**
  (`git = "https://github.com/guatxlabs/core", tag = "v0.1.0", features = ["forge"]`; see
  `console/Cargo.toml`). A standalone clone of this repo builds the console directly — the core is
  fetched from GitHub at build time, no sibling crate required. In a monorepo dev checkout,
  `console/.cargo/config.toml` (gitignored) carries a `[patch]` that overrides the git dep to a local
  `../../core` for speed; it is absent from public clones.

## [0.0.1] — initial release

First public cut of Forge — a governed, proof-oriented red-team engine.

### Core safety model
- **4-layer ROE gate** (`forge/roe.py`): armed → in-scope → capability → approved. Inert by
  default; any evaluation error is a hard `VETO`. Scope-guard is fail-closed (empty scope fires
  nothing).
- **Tamper-evident engagement ledger**: append-only, hash-chained, Ed25519-signed (HMAC fallback),
  with high-water-mark truncation detection and alg-aware verification.
- **Coverage-safe planner**: qualifying vuln classes are never silently starved; deferrals are
  reported.
- **Central secret redaction**: session credentials, API keys, and signing keys are redacted at
  the finding boundary — never reaching the ledger, reports, logs, or API responses.

### Engine & modules
- Recon arsenal (subfinder, amass, dnsx, httpx, nmap, masscan, katana, gau, gospider, whatweb,
  theHarvester, …) chained into proof-oriented oracles.
- Vuln oracles across the payable classes (IDOR/access-control, auth/ATO, SQLi, XSS, SSTI, SSRF,
  XXE, RFI, command injection, CSRF, CORS, JWT, GraphQL BOLA, request smuggling, cache poisoning,
  and more), each scope-guarded and requiring genuine proof to promote.
- Governed **ToolSpec** wrapper (wrap any CLI tool, no-shell, ROE-gated) + drop-in plugin loader.
- Importers for nmap/nuclei/burp/httpx/ffuf output.
- Per-engagement **authenticated context** for cross-account testing (IDOR/ATO), scope-guarded and
  credential-redacted.

### Operations
- **Unified resource profile** (`FORGE_RESOURCE_PROFILE=low|balanced|full`) — one knob sets sane
  resource defaults for constrained or beefy machines, with strict override > profile > default
  precedence and zero governance impact.
- **Governed console** (Rust/axum): findings, ATT&CK coverage, SoQL explore, dashboards, runs,
  ROE, ledger, admin — session-authenticated, RBAC, loopback-strict by default.
- **Optional LLM assist** (OpenAI-compatible, off by default, egress-gated, advisory-only).
- Postgres backend + HA topology, object-store artifacts, and Kubernetes manifests
  (deny-by-default NetworkPolicies) for enterprise deployments.

### Licensing
- **AGPL-3.0-or-later**, open-core. Enterprise features are documented in
  [`COMMUNITY_VS_ENTERPRISE.md`](COMMUNITY_VS_ENTERPRISE.md).

[Unreleased]: https://github.com/guatxlabs/forge/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/guatxlabs/forge/releases/tag/v0.0.1

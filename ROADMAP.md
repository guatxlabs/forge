<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Forge — Roadmap

[English](ROADMAP.md) | [Français](ROADMAP.fr.md)

> **Status: pre-1.0**, **100 % open source** under the AGPL-3.0-or-later license. The default build is
> **openssl-free** (rustls/ring); the shared core is consumed via the pinned public git-dep
> [`guatxlabs/core`](https://github.com/guatxlabs/core).
> Documentation: [`docs/README.md`](docs/README.md) — installation, deployment, CLI/API reference,
> security model.
>
> **Measured**: **88 modules** (`python3 -m forge.cli modules --json` → 88 entries, 13 `exploit`,
> 42 `bug_bounty_eligible`); suites green **offline** — **2949** Python tests
> (`Ran 2949 tests` / `OK (skipped=5)`, each skip naming the optional tool or corpus it lacks) and **571** Rust console tests (`cargo test`, default features),
> MEASURED on 2026-11-24.

This page describes **what is delivered**, **what remains open** and **how to contribute**. The
dated changes are in [`CHANGELOG.md`](CHANGELOG.md); the details of a fix are in the
message of the commit that carries it.

## Delivered

- **Verdict integrity** — an oracle does not return a negative verdict on a target it did not
  reach. A probe without a response produces `skipped` ("I could not verify"), never `tested`
  ("verified, nothing found"). The distinction covers the usual classes: IDOR, ATO, SSRF, SQLi,
  privilege escalation, path traversal.
- **Safety core** — fail-closed 4-layer ROE gate (armed → in-scope → capability → approved),
  scope-guard, opt-in exploit floor, tamper-evident engagement ledger (SHA-256 chain +
  per-entry Ed25519, verifiable by a third party with the public key alone).
- **Governed engagement seeds** — a target can be a host, a URL, an IP literal or
  an **e-mail** (pivot to its domain). A name, a pseudonym or a number is refused at
  load time, with its reason: safety is anchored on a pinnable IP, and an entity that
  produces none cannot receive any network verdict.
- **Per-port scope** — a scope pattern can restrict a host to a single port
  (`example.com:3000`); without a port it covers the whole host. Facing a target that reveals no
  port, `in_scope` refuses and `out_scope` blocks: each goes toward safety, there is no
  neutral answer.
- **Engine** — coverage-safe planner (no qualifying class silently starved), evidence
  oracles on the usual web classes, chaining recon → service discovery → content scan,
  arsenal of governed CLI tools (declarative ToolSpec, no-shell) + drop-in plugins, scan
  importers, zero-egress native triage, optional LLM assist (off by default, egress-gated, advisory).
- **Purple loop** — ATT&CK-tagged run-records, **configurable plugin** detection source
  (Plume, CrowdSec, FortiGate, pfSense/OPNsense, Elastic/OpenSearch, file, exec), exercised × detected × MTTD
  coverage matrix.
- **Console** — first-deployment wizard (no hard-coded default), admin/operator/viewer
  RBAC, read-only GXQL explorer, dashboards, run management, adding tools
  and per-tool parameters from the UI, governed subcommand runner, notifications,
  ownership + triage workflow, HTML/PDF/CSV/JSON exports per engagement.
- **Scaling (advanced modules, open, flag-gated)** — Postgres backend, multi-instance HA topology, Kubernetes
  manifests with deny-by-default NetworkPolicies, per-row multi-tenant isolation, per-engagement
  RBAC, OIDC SSO + SCIM 2.0 (SAML via OIDC bridge), retention/legal-hold/evidence export.
- **Lifecycle** — always-encrypted backups (argon2id + XChaCha20-Poly1305) with
  scheduling and offsite, one-command upgrade with automatic rollback, data migration,
  SQLCipher encryption at rest (opt-in image), off-host PKCS#11 / KMS key custody.
- **Resources tunable at launch** — unified `low|balanced|full` profile **plus** individual
  levers in the UI, generated from the engine's table rather than a copy that would drift.
  The allowlist is compiled server-side — the parser iterates over the known levers and fetches their
  key from the request, so an unknown key is unreachable by construction. Forge must be able to
  run on a constrained machine without saturating it, and no resource value is frozen
  in the code.

## Repository governance

Two rules apply to every contribution, human or automated. They are **checked by
the machine**: a commit that breaks them is refused. The operational details, written for a reader
without prior context, are in [`AGENTS.md`](AGENTS.md).

**1. A single public identity** — `guatxlabs <noreply@guatx.com>`, as author **and** as committer.
No personal or named address. A repository published under a collective must not expose the
personal account of whoever writes it.

**2. A commit message addresses a public reader** — someone who was not in the room,
who knows neither the session nor its author, and who must be able to act on what they read. A commit says
**what changes and why**. Excluded are first-person investigation narrative, direct
address to an interlocutor, and the session chronology as narrative thread. Still admitted: the voice
of the tool, a measurement date, and a long "why" — length was never the defect.

The first person is refused **as a block**, not verb by verb: an enumeration cannot be
complete, and the one that preceded it let `j'ai inséré` (*I inserted*) through where it refused `j'ai mesuré` (*I measured*).
The voice of the tool, which is written in the first person, passes by carrying a **quotation mark**
— quotation marks, code between backticks, or a `>` line. The operational details, written for a reader without
prior context, are in [`AGENTS.md`](AGENTS.md).

Two barriers enforce these rules from a **single** implementation
([`scripts/check_commit_register.py`](scripts/check_commit_register.py)): the `commit-msg` hook
(`make hooks`) and a CI job. The hook does not close — `git clone` does not carry it and editing
via the web interface never runs it. **The CI is what closes**; the hook only saves having
to fix things afterwards. Both identity slots are checked, author **and** committer, and a
range that git could not read is a refusal: a barrier fails closed.

## What a contribution must pass

Every gate is **required** by the CI aggregator — a job that is not listed there runs, fails and
blocks nothing.

| gate | what it refuses |
|---|---|
| registre public (*public register*) | identity other than `guatxlabs`, message addressed to an interlocutor |
| lint | dead import or variable, f-string without a field (`ruff` pinned to an exact version) |
| python floor | a syntax newer than the declared `requires-python` |
| tests | `unittest` on the core, `cargo test` on the console, end-to-end purple loop |
| licenses | a dependency or redistributed file without a compatible license |
| security | known vulnerability, banned license, secret in the tree or in the history |

## What remains open

These points are known and named because a technical reader needs to know where the edges are.
None of them is fixed by a simple patch.

- **GraphQL API coverage** — the injection classes live there behind a single
  entry point, and the injection point is an argument inside the query. The engine can
  now reach it — body template with escaping of both nested contexts (GraphQL string
  inside a JSON string), automatic chaining from schema introspection. Coverage
  remains lower than on classic REST surfaces.
- **The rate only bounds what Forge emits itself.** The ceiling applies to the engine's HTTP
  choke point. A third-party tool driven by Forge that hits the target through its own client — the
  scanner of an intercepting proxy, for example — emits traffic that this ceiling does not see.
  Conversely, control-plane traffic to the **operator's** services is
  deliberately not counted against the target's request budget.
- **Authenticated surfaces** — reaching an application's internal pages requires carrying a
  session through to the discovery tools. Tools that do not declare a header or
  cookie parameter explore anonymously and therefore only see the public surface.
- **Crawling and JavaScript rendering** — surface discovery relies on external tools whose
  capabilities vary. An application whose navigation only exists at runtime is less well
  covered than a server-side rendered application.

## Accepted and documented limits

- **Audit integrity vs host-root compromise** — by default the signing key is local and
  the anchor is null. Two opt-in controls close this case: off-host signer (PKCS#11 / KMS) and
  witness anchor. See [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md).
- **Detection collectors fail-open by design** — they feed reporting and coverage
  measurement, **never** a firing decision: scope, ROE and ledger stay fail-closed.
- **A secret MAY go out in plaintext to an explicitly authorized INTERNAL target.** It is the only
  surviving exception to "no plaintext", and it is narrow: it requires at once a
  **private** address, an **explicit** authorization (`FORGE_ALLOW_INTERNAL_INTEGRATIONS`), and none of
  this is the default. To a **public** target, a plaintext secret is refused before connection,
  with no variable to open it.
  *Why it stays open*: requiring `https` as soon as a secret exists breaks the reference
  on-prem deployment — an authenticated internal collector without a TLS listener. An enterprise CA
  changes nothing there: it provides an **anchor**, not a **listener**. Closing this door is a
  product trade-off, not technical debt; technically, it is a single condition in
  `net::reject_cleartext_secret`, at the price of a clean break for these installations.
- **Authentication material in backups** — an archive contains the whole database, hence
  all stored auth material. This is **inherent**: a backup must restore faithfully, and
  redacting the archive would lose the context on restore. The guarantee is therefore not "no
  secret in the archive" but **"no plaintext archive can exist"** — encryption is
  mandatory and fail-closed on all three paths (API, offline CLI, scheduler), the
  passphrase comes from the environment and never from argv, and two independent layers refuse it.

## Product decisions made

- **No in-process SAML.** The OIDC bridge (Dex / Keycloak / oauth2-proxy) is the supported path:
  native SAML would pull in openssl + libxmlsec1 — which breaks the openssl-free build — and a home-made
  XML-DSig is a trap. An optional `saml` Cargo feature remains deferred.
- **No dedicated cloud KMS driver.** The PKCS#11 signer covers HSM and CloudHSM, and the generic `exec`
  signer covers an Ed25519 KMS (recipe in [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md)).
  AWS-KMS does not sign Ed25519 and is therefore not usable for this ledger.
- **The rate (`rate`) is a governance datum** carried by the scope and the rules of
  engagement, not a resource-profile lever.

## Contributing

Fixes, modules and ToolSpecs are welcome. Read first
[`CONTRIBUTING.md`](CONTRIBUTING.md) (safety invariants not to break, build and tests),
[`AGENTS.md`](AGENTS.md) (commit rules, checked by the machine) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). For a vulnerability, follow
[`SECURITY.md`](SECURITY.md) — no public issue. The open points above really
are open: open an issue to discuss them before a large piece of work.

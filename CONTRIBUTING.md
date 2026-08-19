# Contributing to Forge

Thanks for your interest in Forge — the governed red-team engine. Contributions are welcome,
under a few rules that exist because Forge is a **safety-critical, authorization-enforcing**
tool.

By contributing you agree that your contribution is licensed under **AGPL-3.0-or-later** (the
project license), and you certify the [Developer Certificate of Origin](https://developercertificate.org/)
by signing off your commits (`git commit -s` → adds `Signed-off-by:`).

## Non-negotiable: the governance invariants

A pull request that weakens any of these will be **rejected**, no matter how useful the feature:

- **Scope-guard is fail-closed.** Every outbound request goes through the in-scope / `allow_private`
  check *before* any I/O. An empty scope means nothing fires.
- **The 4-layer ROE gate** (`forge/roe.py`) stays intact: armed → in-scope → capability
  (`allow_exploit`/`allow_destructive`) → approved. Any evaluation error is a `VETO`.
- **The exploit-floor holds.** No `exploit`/`destructive` action fires without explicit
  authorization. Capability flags are derived from module class attributes and only ever *raised*,
  never granted by config, a `module_param`, a plugin, or a resource profile.
- **The ledger is append-only and tamper-evident.** Do not add a code path that mutates,
  reorders, or downgrades a signed entry, or that lets `verify()` pass on a tampered chain.
- **Secrets are redacted at the boundary.** Session credentials, API keys, and signing keys must
  never reach a finding, the ledger, a report, a log, or an API response.
- **The planner is coverage-safe** — qualifying vuln classes are never silently starved; deferrals
  are reported, never dropped.
- **Findings are proof-oriented.** An oracle promotes to `vulnerable` only on genuine proof, never
  on a benign signal.

When in doubt, add a test that proves the invariant still holds.

## Building & testing

> **Note (open-source build):** the Rust console depends on `guatx-core` via a **pinned public git
> dependency** (`git = "https://github.com/guatxlabs/core", tag = "v0.2.1"`; see `console/Cargo.toml`).
> A standalone clone of *this* repo builds the console directly — the core is fetched from GitHub at
> build time. For a monorepo dev checkout, `console/.cargo/config.toml` (gitignored) `[patch]`es the
> git dep to a local `../../core`.

```sh
make test           # full suite: Python (unittest/pytest) + Rust (cargo test)
make test-py        # Python engine only (stdlib, zero network)
make test-rust      # Rust console only (offline)
make test-purple    # end-to-end purple loop (needs a built console binary — see below)
make doctor         # diagnose modules + expected tools/services
```

Everything must be **green** and **offline** — tests must not touch the network or a real target.

> **The purple loop is tested end to end, not just per side.** `make test-purple`
> (`scripts/purple_loop_e2e.py`, run by the `purple-e2e` CI job) drives the whole chain on one machine:
> the engine fires the synthetic `demo.fingerprint` module → the run-records are POSTed to a real
> console binary (`/api/ingest`) → the console queries the demo SOC stub `tools/mock_plume.py`
> (`GET /api/coverage/detections?since=…`) → `GET /api/purple/coverage` is checked against expectations
> *derived from the actual shots* (detected/missed sets, `detection_rate`, per-technique MTTD). It stays
> inside the "no offensive network I/O" rule: the stub only ever **answers** on 127.0.0.1, the targets are
> loopback IP literals (so the ROE pins them without any DNS lookup), and `demo.fingerprint` emits a
> synthetic finding without touching the network. It needs a console binary — pass
> `CONSOLE_BIN=console/target/debug/forge` if you have not built `--release`.

> **One optional tool: a JavaScript runtime (`node`).** The SPA governance guard
> (`tests/test_console_spa_governance.py`) proves *by execution* that the console's single network door
> attaches the operator proof: it imports the real API module under `node` with every network primitive
> instrumented. Text-based checks were tried and measurably fooled (an emptied helper, a look-alike name,
> even a dead string kept the suite green while every write left without proof). It also drives the door over a
> VARIATION plan — every route the server declares, plus generated URL shapes, crossed with the closed set of
> HTTP methods and a few invented extension methods — so that a proof decision which depends on the URL shows up
> as an inconsistency rather than having to be guessed. Without `node` those **six tests skip with an explicit
> message** — the rest of the guard is pure stdlib and still runs.
> CI sets `FORGE_REQUIRE_JS_RUNTIME=1`, which turns the absence into a **failure**, so the guard can never
> be silently off there. `FORGE_JS_RUNTIME=<path>` points at a runtime that is not on `PATH`.

## Code style

- **Python engine** — stdlib only (no runtime deps beyond what's already vendored). Class-based
  oracles over the `Oracle` base; scope-guard via `ScopeGuardMixin`; `argparse` with usage
  examples; `log(msg, level)` with `[*] [+] [!] [-] [VULN]` prefixes; **no shell** (fixed argv,
  never `sh -c`). New tool kinds register declaratively (`@register` + `forge/techniques.py`).
- **Rust console** — `openssl`-free (rustls/ring) **in the default and `store-postgres` builds, NOT
  under `--features object-store`** (transitive `aws-lc`, see `docs/DEPLOYMENT.md` §3quater.1); guard:
  `python3 scripts/check_openssl_freedom.py`. Errors via `ApiError`; the `Store` seam for
  DB access (no raw driver types at call sites); every SQL value bound as a `Param`.
- **Web SPA** — no `innerHTML` with untrusted data; render via `textContent` / the `safeHtml`
  tagged template / `esc()`. Writes go through the authenticated `write()` helper.

## Pull requests

1. Open an issue first for anything non-trivial, so we can agree on the approach.
2. One logical change per PR. Keep the diff focused.
3. Include tests. Preserve or improve coverage.
4. Run `make test` and (for Rust changes) `cargo clippy`. Both must pass.
5. Sign off your commits (`-s`), and enable the repository hooks once per clone:
   `git config core.hooksPath .githooks`. The `commit-msg` hook refuses a message that addresses an
   interlocutor, and an author identity other than `guatxlabs <…@guatx.com>`. It is a convenience,
   not the barrier: hooks are not carried by `git clone` and never run for GitHub's web editor —
   the CI job `registre public` checks every pushed commit and is what actually closes the door.
6. **Write for a public reader** — in commit messages, documentation *and* code comments alike.
   Every one of them addresses someone who wasn't in the room, doesn't know you, and has to act on
   what they read. Say what changes and *why*. Length is fine: a measured "why" is worth twenty
   lines, and a date that makes a claim traceable ("measured 2026-08-16") is traceability, not a
   diary. What does not belong: first-person narration of your own investigation ("I had dismissed
   this earlier…"), direct address ("as you asked"), and session chronology used as a storyline —
   that goes in `ROADMAP.md`. Stating what a status *means* ("a `skipped` says: I could not
   verify") is the tool's voice, and stays.
7. **Security issues do not go here** — see [`SECURITY.md`](SECURITY.md).

## A word on intent

Forge is for **authorized** use only (in-scope bug bounty, contracted pentest, CTF, your own
infrastructure). Contributions that make it easier to *evade authorization* or to attack targets
you don't own are out of scope for this project.

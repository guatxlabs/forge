# Contributing to Forge

Thanks for your interest in Forge — the governed red-team engine. Contributions are welcome,
under a few rules that exist because Forge is a **safety-critical, authorization-enforcing**
tool.

By contributing you agree that your contribution is licensed under **AGPL-3.0-only** (the
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

> **Note (open-source build):** the Rust console depends on `guatx-core` via a path dependency
> (`../../core`). Until that core is published as a crate / public git dependency, a standalone
> clone of *this* repo alone will not build the console. See `console/Cargo.toml`.

```sh
make test           # full suite: Python (unittest/pytest) + Rust (cargo test)
make test-py        # Python engine only (stdlib, zero network)
make test-rust      # Rust console only (offline)
make doctor         # diagnose modules + expected tools/services
```

Everything must be **green** and **offline** — tests must not touch the network or a real target.

## Code style

- **Python engine** — stdlib only (no runtime deps beyond what's already vendored). Class-based
  oracles over the `Oracle` base; scope-guard via `ScopeGuardMixin`; `argparse` with usage
  examples; `log(msg, level)` with `[*] [+] [!] [-] [VULN]` prefixes; **no shell** (fixed argv,
  never `sh -c`). New tool kinds register declaratively (`@register` + `forge/techniques.py`).
- **Rust console** — `openssl`-free (rustls/ring); errors via `ApiError`; the `Store` seam for
  DB access (no raw driver types at call sites); every SQL value bound as a `Param`.
- **Web SPA** — no `innerHTML` with untrusted data; render via `textContent` / the `safeHtml`
  tagged template / `esc()`. Writes go through the authenticated `write()` helper.

## Pull requests

1. Open an issue first for anything non-trivial, so we can agree on the approach.
2. One logical change per PR. Keep the diff focused.
3. Include tests. Preserve or improve coverage.
4. Run `make test` and (for Rust changes) `cargo clippy`. Both must pass.
5. Sign off your commits (`-s`).
6. **Security issues do not go here** — see [`SECURITY.md`](SECURITY.md).

## A word on intent

Forge is for **authorized** use only (in-scope bug bounty, contracted pentest, CTF, your own
infrastructure). Contributions that make it easier to *evade authorization* or to attack targets
you don't own are out of scope for this project.

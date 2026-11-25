# Changelog

[English](CHANGELOG.md) | [Français](CHANGELOG.fr.md)

All notable changes to Forge are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Forge aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first tagged release.

> Forge is pre-1.0: the public API, module kinds, and config surface may still change between
> minor versions. Breaking changes will be called out here.

## [Unreleased]

### Changed — the console builds against `guatx-core` v0.2.6 (was v0.2.2)

The query compiler shared with Plume now refuses forms it used to drop or misread without a word.
A query that compiled before and returned a result may now be refused with a message saying what to
write. Without any of these forms, the emitted SQL is unchanged.

- `stats`, `eventstats`, `timechart`, `sort`, `head`, `top`, `rare`, `join`, `append`… refuse any
  token they do not read (`sort ts desc` used to sort ascending; `stats count dc(user)` returned only
  the count); a `stats … by` key that names no field in scope is refused instead of becoming a label.
- `search` refuses a bare `OR`, `AND` or `NOT` and an unbalanced parenthesis (no boolean grammar
  exists; they used to become a free-text term). A `|` or `]` inside double quotes no longer splits
  the pipeline; an unclosed double quote is refused.
- Under a field mask, the JSON bag is never read raw: predicates and join keys on the bag are
  refused, group keys read the redacted projection.

### Added — coverage of the 2025 Top 10 web techniques: eleven evidence oracles

Eleven verification modules with benign evidence (exploit=False, destructive=False unless stated),
and the `DEFAULT_CHECKLIST` realigned on the measured acceptance rates (traversal and XSS first) —
the previous order left out these classes and made them invisible to `coverage_gaps()`.

- `upload.unrestricted` (CWE-434): dangerous file upload, inert marker served back.
- `cspt.redirect` + `recon.client_sinks`: Client-Side Path Traversal, path-depth differential
  observed in the browser; reading of source-to-sink pairs in same-origin JavaScript.
- `parserdiff.unicode` (CWE-176): Unicode normalization differential between WAF and backend.
- `ormleak.filter`: boolean oracle through an ORM filter, two probes per field, no sweeping.
- `ssrf.redirect_loop`: makes a blind SSRF visible through a redirect loop with incrementing codes.
- `massassign.params`: mass assignment proven by an inert canary, never a real privileged value.
- `business_logic.invariants`: invariants derived from the business object (negative, bound, sum).
- `llm.prompt_injection`: prompt injection, inert canaries, outside `DEFAULT_CHECKLIST` by default.
- `ssti.errors` (CWE-1336): blind SSTI through the error channel ("Successful Errors").
- `sidechannel.shape` (CWE-203): existence oracle through response shape (XS-Leak / length-leak).

Support: anti-reflection guard on `cmdi.probe` (a token contained in the payload does not prove
execution), static-asset filter in `recon.urls` (finding counted, never silent),
last-byte synchronization for `race`.

Registry: 88 modules, 42 bug_bounty_eligible.

### Fixed — the verdicts said more than what they had verified

This batch comes from a **real campaign** against an authorized production infra, entirely behind
a Cloudflare tunnel. None of these defects broke anything: they **reassured**.

- **`Oracle.skip()` emitted `status='tested'`.** The method LITERALLY NAMED `skip`, documented
  "not tested / missing config", therefore asserted "**I checked, found nothing**" — over
  **1,750 findings** measured, 25 kinds, **not a single byte sent for any of them**. A report listing
  "access_control.idor : tested" on a target for which no test account is configured
  reads as an **absence of vulnerability**; that is the failure mode that has already cost a campaign.
  Fixed to `skipped` — the vocabulary that already existed for "I could not verify", and that the
  report view promotes to a "Coverage NOT verified" section. **Breaking**: 8 tests froze the
  lie (including one named `test_no_session_jwt_is_skip` that asserted `"tested"`), and the equivalence
  snapshot had frozen it too — five entries fixed, the four `*_negative` ones left as
  `tested` because they really did fire.

- **A wall produced verdicts.** `Oracle._http` DISCARDS the body on `HTTPError` — yet the Cloudflare
  interstitial lives exactly there. The abstention guard was already wired into 6 modules and produced
  **zero** abstentions. The error body is now sampled (8 KiB, **for judging only**: the
  public contract of `_http` stays byte-identical) and `__init_subclass__` wraps the `fire()` of
  every oracle. **117 `tested` converted out of the 256 actually reachable, 0 legitimate verdict
  destroyed** (negative control on a healthy target: identical before/after). The boundary stays narrow and
  tested — a **BARE 403 remains an application verdict**, otherwise forge would become blind to access
  controls, its best-paying class.

- **Two FABRICATED verdicts.** (1) A `web.nuclei` batch killed at its wall returns a **partial** output,
  so the "tool failed" branch was never reached: every target never scanned came out as
  `tested` "no hit" — **15 out of 17** in reproduction. (2) The anti-gap accounting lived
  **after** the engine loop: a graceful stop skipped it, and the report announced "no
  gap, no unplanned module" when there were **78**.

- **The console silently lost 9.4 % of findings** — 499 out of 5,318, `UNIQUE(campaign, target,
  title) ON CONFLICT IGNORE` (neither `run_id`, nor `tool`, nor `severity`), including **8 `skipped`**, that is
  coverage holes that evaporated. The real symptom is worse than an overwrite: it is the **second**
  run that is refused, and since the report filters by `run_id`, **its report is EMPTY** — which reads
  "nothing found". Widening the key recovered only **8 findings out of 499** and broke the replay
  idempotence that `IncrementalIngest` documents: we **count and announce** (`findings_dropped`,
  `findings_write_errors`, tested conservation law), the storage does not change.

- **Secret leak in two deliverables.** The markdown appendix **and** the HTML client deliverable rendered
  an `Authorization: Bearer <jwt>` **in plaintext** — `html_escape` is not redaction. Found by
  the parity guard **on its very first run**.

### Added

- **In-process time budget** (`--run-timeout` / `FORGE_RUN_TIMEOUT`, existing `run_timeout_secs`
  lever that only had an EXTERNAL enforcement by SIGKILL) + graceful stop outside the console. **The
  report and the `.durations` sidecar are now guaranteed in all three stop cases** — deadline,
  SIGTERM, exception — where two real campaigns had lost their deliverable although all the
  work was done. A partial report **announces itself as partial**: cause, X/Y actions, untried ones
  listed. A gate also refuses to START a shot whose bound exceeds the remaining budget:
  overrun **+26 % → −0.8 %**, with more actions completed than before.
- **`web.nuclei` pooled per host** (`-u a,b,c` — `-list` is unusable, `docker run` is
  built without `-v`): **60 → 10 invocations**, per-URL coverage proven identical, scope-guard
  applied per target through four independent gates.
- **The console report leads with a verdict**, like the CLI: "Actionable",
  "Signal to qualify", "Coverage NOT verified" sections (the `skipped` PROMOTED), appendix behind an
  accounting. The parity guard that watches it compares **structures** — the old one
  only asserted five substrings and stayed green when parity broke.
- **`make check-supply-chain`** — the three guards (openssl-freedom, licenses, NUL bytes) ran
  in CI without any target exposing them: you could only discover them by breaking them in a PR.
- **`docs/UPSTREAM_REPORTS.md`** — minimal reproduction of the `cargo-deny`/`krates` defect (an
  OPTIONAL dependency whose package name differs from its `[lib]` name disappears from the graph, and
  the tool answers **`licenses ok`**). It is not specific to forge: keeping quiet about it would leave other
  projects with the same blind spot.
- **A private enterprise CA becomes verifiable — without reading the system store, and without relaxing a
  single check** (`FORGE_EXTRA_CA_PEM` / `FORGE_EXTRA_CA_PEM_FILE`). The TLS seam shipped just before
  verifies against the **compiled-in Mozilla** roots; the **system** CA store **is not read**, and
  that is exactly what avoids `schannel`, `security-framework` and `openssl`. This posture had a
  documented price: a deployment whose OIDC IdP or collector is signed by **its own CA**
  only had **bad** options — including **going back to plaintext**, precisely what "no plaintext"
  refuses.

  **The distinction is the whole point.** This knob **ADDS an anchor** that the operator **provides
  explicitly**; it **removes no check**. The chain is still validated up to an anchor, the
  **hostname** still verified, **expiry** still honored. `with_root_certificates` accepts
  additional anchors **without ever touching** the rustls `dangerous` API — the **source** guard
  that forbids the crate from opening it stays **green**, unchanged.

  **Proven by a PAIR, not by an assertion.** The existing rejection test (untrusted CA fixture +
  signed leaf) stays red-when-mutated, and **four** tests frame it: the **same** CA provided as PEM
  makes the handshake **SUCCEED** (the knob works); **ANOTHER** CA leaves it **FAILING** (it verifies, it
  does not swallow); a **hostname** outside the SAN is refused **with the anchor in place**; an **EXPIRED** leaf signed
  by the provided anchor is refused **with the anchor in place**, with as counter-example the **same** anchor + the
  **same** subject + the **same** SAN on a **non-expired** leaf, which succeeds — the only variable between
  the two halves being the validity window.

  **Fail-closed at boot**: a PEM that is configured but unreadable, empty or invalid **kills startup**
  (`[forge] FATAL`, code 2), it **never** degrades to "no anchor" — otherwise the operator would believe their
  CA installed and discover the opposite at the first handshake, under an "unknown issuer" that does not
  point to the cause. It is the **only** accepted difference from the in-house `secret_env` pattern, which is
  fail-**soft** by contract. Nothing configured ⇒ **no** line at boot. **Zero new dependencies**
  (the PEM parser is already in `rustls-pki-types`); openssl-freedom of the DEFAULT build verified by command (**0** hits).

- **The last three plaintext secrets at rest are sealed — but fallibility first.** The **detection
  source** token, the **notification channel** token and the **SSO `client_secret`** lived
  in plaintext in `settings`. They had been left out of the first field-encryption batch for a **real**
  technical reason, recorded: sealing them **requires** making `ds_secret`, `ch_secret` and
  `sso::load_config` fallible — and the latter returned an **`Option`**, where a failed decryption would have become
  "**SSO not configured**", i.e. the **silent degradation** that all this work forbids.

  The imposed order was followed. **(1) Fallibility, with a READABLE failure**: `sso::load_config` now returns
  `Result<Option<SsoConfig>, String>` — **three** distinct outcomes: `Ok(None)` = not configured
  (**403** `sso_unconfigured`), `Ok(Some)` = usable, `Err` = **configured but unreadable** (**503**
  `sso_secret_unreadable`). The two other secrets are opened at their **single point of use**
  (`collect_detections_with`, `deliver_blocking`): without a key, the integration **refuses to go out** with a
  named reason, instead of presenting itself **without authentication** — a 401 the admin would diagnose
  as a SIEM outage. **(2) Sealing**: `field_crypto` reused as is — **same** key
  (`FORGE_FIELD_KEY`), **same** `forge:fenc1:` envelope, **no** re-implementation of AEAD.

  **Unreadability proven ON THE DISK BYTES** (`.db` file + `-wal` + `-shm`), with its
  counter-example: the **same** probe, on the **same** database, **finds** the canaries when the same values
  are written without sealing — otherwise "absent" could be absent for the wrong reason. An existing
  database is **converted at boot**, in place and idempotently; without a key, nothing is converted but the
  remaining plaintext is **counted and announced** — never hidden. **Measured** scope: only the **value** of the
  secret is sealed; `kind`, `endpoint`, `auth.type`, `issuer`, `client_id` stay readable (the admin
  must be able to re-edit their config without the key, and these are not credentials).
- **Intra-wave preheating finally knows what a SLOW action is — it MEASURES it.** The scheduling
  of submissions (`engine._preheat_order`) estimated slowness with `action.cost`, because it was the
  only EXISTING carrier. Yet `cost` is a **governance** datum (the price one accepts to pay),
  not a **duration** measurement: the two often correlate, nothing guarantees it — and the brain only
  fills in an explicit cost for the kinds in its table, **everything else falls back to the 1.0 default**,
  including genuinely slow modules. The residue was recorded with its blocker: "neither the ledger nor
  the run-records timestamp better than to the second". That blocker is what is lifted.

  **Instrumentation**: `engine._decide_blocking` times the **shot** with the **monotonic** clock
  (`time.monotonic`, never wall-clock time). The **dry-run is NOT timed**, deliberately:
  `dry()` is side-effect free by contract, hence near-instant — measuring an unarmed campaign
  would teach that `web.testssl` takes 3 ms and **poison** the store. **Price measured, not
  asserted**: `1,23 µs` per observation in a tight loop, and a difference **below the noise** (`-0,1 ms` over
  24 shots) wall-to-wall — to be compared with **seconds** for a real tool.

  **Storage — the aggregate is PER KIND, NEVER PER TARGET** (`forge/durations.py`). This is not a
  constraint endured: a per-target duration store would be a **reconnaissance log persisting
  after the engagement** ("how long host X took to answer"), and preheating only
  needs the kind anyway. The guard is **structural** — `record()` refuses any key that is not a
  module identifier, on write as well as when re-reading a tampered file — and **proven on the
  written bytes**, not on the API. **Bounded** size: ≤ 256 kinds (deterministic eviction), aggregate of
  **fixed size** per kind (counter + ring of 8 durations) — 10,000 shots do not write one byte more
  than 10.

  **Confidence without a model**: under 3 observations, the kind has **no** estimate (n=1 is noise);
  beyond that, it is the **median** of the ring (a shot that fails in 3 ms does not make a slow kind look
  fast), **quantized** to one significant digit so that two kinds of comparable slowness
  stay in the **same level** — otherwise the "full level or nothing" rule would split the group
  of slow actions it exists to protect. No learning, no tunable threshold.

  **EXACT fallback**: without a store, or with a store holding no observation at all, `_preheat_key` returns
  `action.cost` for every action — **same levels, same order, previous behavior identical**.
  It is the first property tested, and its mutation (breaking the fallback) turns red.

  **Gain measured, and stated honestly** (`tests/bench_engine_parallel_order.py`, pool=4, 5 repetitions,
  two independent invocations, intra-series spread ≤ 1.3 %): on the shapes where `cost` **tells the
  truth**, the observed duration brings **NOTHING** — `straggler` 1.84 s → 1.83/1.84 s (within the noise),
  `queue-large` and `uniform` unchanged. It **only** pays off where
  `cost` **lies** — new `cost-lies` shape (a slow module left at the default cost, a fast module
  over-annotated): `index` 1.88 s, `cost` **1.92 s** (cost-based preheating is then **worse than
  doing nothing**), **observed 1.60 s** — i.e. **-16.8 %** versus cost and **1.05x** the
  work/pool floor instead of 1.26x. The real gain of this work is therefore not "it is faster", it is
  "scheduling no longer depends on a datum that never promised to be a duration".

  **Invariants intact**: the **APPLICATION** order does not move (ledger/findings/decisions identical
  to serial, chain verified on both sides), only the **SUBMISSION** order changes; scope, ROE and
  ledger stay fail-closed; **zero new dependencies**. The store is **frozen** for the duration of a
  run: two runs on the same store preheat identically (the accepted price: it is the **next**
  run that benefits from the measurements, not the following waves of the same run).
- **Encryption at rest of authentication material — in the DEFAULT build, without OpenSSL.** The
  network side had just been closed (TLS seam); rest remained. `docs/DEPLOYMENT.md` §1.5 conceded it:
  the default build stores the database **in plaintext**, and that database now carries the **per-engagement
  auth context** — bearers, cookies and header values of the operator's **test accounts**,
  that is **authenticated sessions on a client's estate**. Full encryption existed
  (`encryption` feature) but requires a **system/openssl crypto backend at compile time**: enabling it by
  default would have broken openssl-freedom.

  **FIELD encryption** (`console/src/field_crypto.rs`) with the **pure-Rust AEAD stack already shipped**
  (`chacha20poly1305` + `argon2`, non-optional deps — those of the backups): **ZERO new
  dependencies**, openssl-freedom of the DEFAULT build **verified at 0 occurrences** afterwards. The argon2id KDF and the AEAD core
  were **EXTRACTED** from `backup_crypto.rs` (`aead_seal`/`aead_open`) rather than rewritten — there is
  only **one** symmetric crypto implementation in the console, and it now has a contract test
  on the **AAD binding** (the mutation proof showed that no test depended on it).

  **A single write choke point**: `validate_engagement_scope` produces the persisted `scope_json` string,
  so sealing there makes it structurally impossible to write a credential in plaintext through a forgotten path.
  **A single opening point**: the run's **0600** `scope.json`. In between, the material stays
  encrypted — including in the `run_job.spawn_spec` blob of the HA *pending* path, which therefore becomes encrypted
  at rest too, in addition to being purged at claim time.

  **MEASURED scope**: sealed: `bearer` / `cookies` / header **values**. Left in plaintext, on purpose:
  the `label`, the header **names** and the `idor_targets` — the API **already** serves them back in plaintext to
  the editor, so sealing them would make the editor unreadable without the key **without protecting a single credential**.
  `users.pass_hash` (argon2id) and `session.token_sha` (SHA-256) are **not** encrypted: they are
  one-way digests, not replayable material.

  **FAIL-CLOSED, without silent degradation** — we had just fixed a bug where the auth context
  was silently erased, and it cost a campaign: (1) **no auth context ⇒ no key required**
  (strict no-op, payloads unchanged); (2) **writing material without a key ⇒ `503 field_key_missing`**
  naming the variable — never a credential persisted in plaintext "in the meantime"; (3) **unreadable sealed
  material ⇒ the run REFUSES to start** (`auth_context_sealed`) rather than going out with an empty `auth`
  that would disarm the access-control oracles without saying so.

  **Migration handled, not ignored**: existing databases are **sealed in place at boot**
  (idempotent, replayable, counted). Without a key, nothing is converted and the boot **shouts** it — giving
  the illusion of encryption would be worse than acknowledged plaintext. The state is also readable **in the product**
  (`auth.at_rest` ∈ `sealed|plaintext|mixed|none`).

  **Key**: `FORGE_FIELD_KEY`, via the in-house `<VAR>_FILE` pattern already supported. **Custody**: it is a
  secret to keep **together with** the backup passphrase — a database restored without it is intact but
  its material stays sealed (backup round-trip verified). Losing the key loses **no other data**:
  re-entering the material is enough. The two layers **compose** (`--features encryption` on top
  remains valid). Docs: `DEPLOYMENT.md` §1.6, `CONFIGURATION.md` §1.4, `KEY_CUSTODY.md`.
- **Outbound TLS seam — the console speaks `https://`, and verifies it.** The console had exactly three
  outbound TCP paths, all over a raw socket, hence **in plaintext**: the OIDC token exchange (`sso/mod.rs`), the
  notification webhook (`notify_channels.rs`) and the detection-source fetcher (`net.rs`). The most
  serious was the first: the POST to the token endpoint carries the **`client_secret`**
  (`Authorization: Basic`) **and** the authorization **`code`** — `docs/DEPLOYMENT.md` conceded it and
  prescribed an **egress TLS proxy** as a workaround.

  **A single exit point** (`console/src/tls.rs`), shared by all three: plaintext (**governed**) or TLS
  with **full certificate verification** — chain up to the Mozilla roots (`webpki-roots`) **and**
  hostname —, the **handshake completing before the first application byte**. Facing an unproven peer,
  the caller gets no stream, hence writes no secret. **No verification escape hatch** is
  shipped: no option, no ENV, no feature; a source guard forbids the crate from opening the dangerous API
  of rustls. The TLS-proxy workaround is **obsolete**; Slack / Teams / PagerDuty become reachable
  ; an `https` detection source is served **in Rust**, without a Python spawn on a read route.

  **The existing guards remain.** The SSRF deny-list applies to the **resolved** IP, over `http://` as well as
  `https://` (encrypting a fetch to `169.254.169.254` does not make it a legitimate target). The
  "secret + public plaintext target" refusal is **relaxed exactly**: allowed over `https://`, still refused
  over `http://`. Plaintext to an explicitly authorized **internal** collector is unchanged.

  **No SMTP** — refused independently of TLS: STARTTLS is a **negotiated** upgrade (class of
  plaintext command injection, CVE-2011-0411 and its descendants) and real-world SMTP is practiced with
  opportunistic TLS against self-signed relays. **No reading of the system CA store** — an enterprise
  CA is therefore not picked up AUTOMATICALLY; it is provided explicitly (see below,
  `FORGE_EXTRA_CA_PEM`). **mTLS**, announced as absent in an earlier version of this entry, is
  shipped further down in this same unpublished release.

  **Cost: 6 net crates** (`ring`, `rustls`, `rustls-pki-types`, `rustls-webpki`, `untrusted`,
  `webpki-roots`), ≈ +20 s CPU cold, **no new machine prerequisite** (`ring` compiles asm/C via
  `cc`, already required by `rusqlite/bundled`). **openssl-freedom preserved and verified by command**: no
  `openssl-sys` / `native-tls` / `aws-lc-rs` / `schannel` / `security-framework` in the closure, default
  build as well as under `store-postgres` (which shares the same stack, a single version of `rustls`).
- **Tool lifecycle — a single manifest, and a runtime overlay that opens no door.**
  The versions and SHA256 digests of the twelve downloaded security binaries (httpx, nuclei,
  subfinder, dnsx, naabu, katana, amass, gau, gospider, dalfox, feroxbuster, ffuf) were hard-coded
  `ARG`s **duplicated** between `Dockerfile` and `docker-compose.yml`. Two copies of a pin are
  a silent divergence waiting for its moment — and there was no way to install an omitted
  tool, or to update one, without rebuilding the image.

  **Single source: `forge/tools.json`.** Version, URL template, archive format, member to extract,
  name placed on the `PATH`, and a digest **per architecture**. The `Dockerfile` reads it at build time (via
  `forge/toolsmanifest.py`, a standalone stdlib script) and the runtime installer reads the same file.
  The compose file no longer propagates any pin. Bumping a version = editing this single file. A static guard
  fails if a tool version, digest or URL reappears in the `Dockerfile` or the compose file.

  **The build baseline does not change**: same binaries, same versions, same digests, same
  `sha256sum -c` that fails the build on any mismatch. Two guards are added: a tool without
  a pin for the target architecture is **dropped from the plan** (never downloaded unverified) and reported, and
  the base group goes through `--require-complete core` — a missing pin on httpx/nuclei/subfinder fails
  the build rather than producing a crippled image. Since a `docker build` cannot be run in
  CI, the install loop of the `Dockerfile` is **extracted and actually executed** by the test
  suite, with `curl`/`sha256sum`/`unzip`/`tar` stubbed: we check the downloaded URL, the digest
  presented, the extracted member, the `--strip-components` depth and the name of the placed binary — and
  that a mismatching digest makes everything fail without installing anything.

  **Runtime overlay: `forge tools list|install|update|remove`.** The binary lands in
  `/data/tools/bin` — persistent volume, owned by the `forge` user, at the head of the `PATH` in front of the
  baked `/usr/local/bin`: updating a tool no longer requires a rebuild, and the install survives a
  container *recreate*. Installing a binary at runtime in an offensive tool is precisely the
  capability that voids a governance if it is badly designed, so: pinned SHA256 **computed over the
  stream** and compared before anything reaches the `PATH` (mismatch ⇒ refusal, temporary file destroyed,
  refusal **logged**); source **allowlisted** by the manifest — there is neither `--url` nor
  `--sha256`, and a name outside the manifest triggers no request; strict HTTPS, a redirect leaving
  HTTPS refused; **no shell or subprocess** (`urllib` + `zipfile`/`tarfile`, a single member
  extracted to a destination that we compute — a member named `../../evil` does not escape the
  tools directory); **mandatory ledger** (`tools.install`/`.update`/`.remove`/`.refused`, chained
  and signed) — without a resolvable ledger, the action is refused: no capability change without a trace.

  No elevation: the installed tool remains subject to the fail-closed ROE scope-guard, to the exploit floor
  and to the same `Module` contract. And **the default is a no-op**: nothing is created or probed at import,
  no engine module imports the installer, the volume is empty as long as no operator action
  has taken place — `PATH` resolution is then identical to the baseline.

  Deliberately **not built**: installing a version *outside* the manifest (it would imply
  accepting a hand-typed digest — as long as it does not exist, there is no path to an
  unpinned download), the console admin API and UI panel, and the version probe by
  executing the binary. Documentation: `docs/TOOLS_LIFECYCLE.md`.

### Changed
- **A detection-source secret no longer goes out in plaintext to a PUBLIC target** (existing installs
  — **NAMED** breaking change). The source fetcher had **no** guard of this kind: a
  `plume`/`generic_http` source over **`http://`** to a **public** address, carrying an `auth.secret`, put
  its `Authorization:` header **on the wire**. The notification channel, for its part, already refused this case — the
  rule therefore existed, as an **inline copy** in only one of the two egress paths. It is now **shared**
  (`net::reject_cleartext_secret`, one implementation, verified once) and **applied to both**. The
  refusal falls **before the connection** and **no** environment variable opens it. Fixes:
  move the source to **`https://`** (a private CA is provided via `FORGE_EXTRA_CA_PEM`), or remove the
  secret.

  **What was NOT tightened, and why — measured, not assumed.** The option considered was to require
  `https` **as soon as a secret is configured**, the escape hatch then only covering the case *without* a secret.
  Measurement done: it breaks the **reference on-prem** deployment — an authenticated internal collector
  that exposes **no TLS listener** (`PLUME_URL`/`PLUME_TOKEN` on a private segment, encoded by two
  existing tests). The enterprise CA does not help here: it provides an **anchor**, not a **listener**.
  The tightening would therefore have **killed** the use case instead of moving it. `http://` + secret to an
  explicitly authorized **internal** target (`FORGE_ALLOW_INTERNAL_INTEGRATIONS=1`) therefore remains **served** — it is
  **governed** plaintext, and it is named as such.

- **Integration secrets are no longer persisted verbatim** (existing installs — **NAMED**
  breaking change). `settings.detection_source → auth.secret`, `settings.notify_channel → auth.secret` and
  `settings.sso.config → client_secret` were stored **in plaintext**; they are now **sealed**
  (`FORGE_FIELD_KEY`). Practical consequences: (a) without a field key, **setting** one of these secrets through
  the API returns **503** `field_key_missing` instead of writing it in plaintext; (b) an external tool that read
  these values directly from the database will find only an envelope there; (c) `FORGE_FIELD_KEY` becomes
  a secret to **keep** for these integrations too — losing it makes them unreadable, and the integration
  **refuses to go out** rather than presenting itself without authentication. The `keep_secret` path (editing
  the endpoint without retyping the token) works **without a key**: it copies the envelope as is.
- **A new file appears next to an engagement's ledger: `<ledger>.durations`** (existing
  installs — NAMED breaking change). A sidecar like `<ledger>.hwm` and `<ledger>.ed25519`, created at the
  first `forge run`/`forge campaign` that receives `--ledger` **and** fires at least one action. It carries
  **only** durations aggregated **per module kind** (no target, no host, no URL), weighs
  a few KiB at most, is **not** a secret, and is **not** in the auditability chain (losing
  it breaks nothing: preheating falls back on `action.cost`). Practical consequences: the
  purge scripts must include it (`docs/UNINSTALL.md` updated), and an operation that does not want it
  sets `FORGE_DURATIONS=0` (no file created, previous behavior identical). Without
  `--ledger`, nothing changes: no file has ever been written.
- **The purple join now has THREE states, not two — and the headline rate got stricter.** The join
  between fired techniques (red) and SOC detections (blue) was a plain **string equality** on the
  `mitre` tag, which produced two measured defects.

  **(a) Parent vs sub-technique.** Forge fires `T1110.001` (module `network.ssh`, SSH password
  guessing); a SOC that only has a `T1110` rule scored a flat `missed`. Naively normalising to the
  parent would have scored `detected` — and that would have been an **unmeasured** claim: the join sees
  an *identifier*, not a detection query, so it cannot prove the fired vector is covered. Read one by
  one, three of the shipped `T1110` rules are `ca-cred-mail-bruteforce` (`search source=mail
  action=failure …`, mail only), `ca-cred-web-login-bruteforce` (`search source=web status=401 …`, web
  only) and `ca-cred-distributed-bruteforce` (`search category=auth action=failure | stats
  dc(src_ip)`, needs IP spread) — none of those three catches a single-source SSH brute force. Other
  seeded `T1110` rules might, depending on which rules are enabled and which telemetry is wired. That
  ambiguity is the point: the join does not arbitrate it in the vendor's favour, it **names** it. So a
  parent match is now its own state,
  `detected-parent-approx`: it is **excluded from `detection_rate`** and **excluded from MTTD**
  sampling (a MTTD computed between an SSH fire and an unrelated alert is an invented number), and it
  is surfaced in its own `parent_approx` list with the parent named and an explicit reason — a *named
  blind spot*, which is the product, not waste.

  **(b) Multi-technique tags.** A `mitre` tag may carry several techniques separated by space, comma
  or semicolon — the norm at SigmaHQ (several `attack.` per rule). A tag `"T1595.002 T1046"` matched
  **neither** key, so a Sigma corpus manufactured false `missed`. Tags are now **split on both sides**
  of the join (fired records and detections), sub-technique preserved. A tag that parses to no
  technique at all is still joined verbatim — a fired technique must never silently vanish.

  New/renamed contract on `GET /api/detection/coverage` (alias `/api/purple/coverage`):
  `techniques_parent_approx` and `parent_approx[]` added; every row carries its `state`
  (`detected-exact` / `detected-parent-approx` / `missed`); `techniques_detected` and
  `detection_rate` now count **exact matches only**. Invariant: `detected + parent_approx + missed ==
  techniques_fired`. Report (markdown/HTML/JSON/`forge/report_engagement.py`), console UI and the
  bundled reference engagement all render the third state.
- **`GET /api/attack-matrix`: cell field `detected` renamed to `fired`, and the fire count `fired` to
  `fires`.** That boolean never measured detection — it was `runrecord.fired > 0`, i.e. *the red side
  actually shot*, as opposed to proposed/vetoed/dry-run. It sat next to the genuinely blue `detected`
  of the purple coverage under the same name, and the UI rendered it as « détectée ». Two distinct
  notions must not share one name in an API. The matrix stays a **red** view; MTTD and the
  parent-approx marker come from `/api/purple/coverage` as an enrichment, matched on the **exact**
  technique id (the previous « T1595.003 measured under its base T1595 » fallback is gone — it was
  precisely a parent-approx displayed as the sub-technique's MTTD). Read `missed` as the list it is: in **fail-open** (`purple_fail_open`) `techniques_fired` is `N` while all three counters are `0` — deriving `missed = fired - detected - parent_approx` there manufactures the very false "missed" that fail-open exists to prevent.

### Fixed
- **Detection-source fetch never completed its HTTP request.** The console's built-in fetcher
  (`console/src/net.rs::http_get_blocking`, used by `kind=plume` / `generic_http` over http) wrote its
  request headers without the terminating blank line, so an RFC-compliant server kept waiting for more
  headers, the console hit its read timeout, and `GET /api/detection/coverage` reported the source as
  unreachable (`source_reachable:false`, `error: "lecture réponse échouée: Resource temporarily
  unavailable (os error 11)"`) even though the SOC was up and answering. Measured byte for byte by
  replaying the emitted request against `tools/mock_plume.py`: without the blank line, no response in
  4 s; with it, `HTTP/1.1 200 OK` immediately. Now covered end to end by the `purple-e2e` CI job.

  **Blast radius — larger than the detection source.** `http_get_blocking` has three production
  callers, and all three were affected: `detection.rs:531` (detection source) **and `sso.rs:935`
  (OIDC discovery, `.well-known/openid-configuration`) and `sso.rs:1001` (JWKS)**. OIDC login over
  plain http therefore could not complete either. Only the token exchange was safe, because it goes
  through the *POST* helper (`sso.rs::http_post_form_blocking`), which did send the blank line — the
  omission was an oversight in the GET path, not a convention. An earlier wording of this entry
  mentioned only the detection source and cited the healthy POST sibling, which wrongly implied SSO
  was unaffected.

  **Why no test caught it, in either path.** The fetcher's tests only ever targeted
  `http://127.0.0.1:1/x` — an unreachable port — so they asserted that failure fails; a *successful*
  fetch was never exercised. And the 18 SSO tests still pass with the bug reintroduced, because their
  mock IdP does a single `read()` and answers immediately instead of waiting for the end of headers.
  A green suite proved nothing here; only an end-to-end exchange with an RFC-compliant server did.

### Added
- **End-to-end CI for the purple loop** (`purple-e2e` job + `scripts/purple_loop_e2e.py`,
  `make test-purple`): fires the engine, ingests the run-records into a real console binary, serves
  detections from the loopback demo stub `tools/mock_plume.py`, and asserts the computed coverage
  (`detected`/`parent_approx`/`missed`, `detection_rate`, per-technique MTTD, `since` windowing)
  against expectations derived from the actual shots — including the two guards of the three-state
  join: a fired sub-technique whose parent alone is covered must not move the rate, and its apparent
  MTTD must not be sampled; a multi-technique SOC tag must match every technique it carries. No offensive network I/O: loopback only, synthetic module, loopback IP
  literals (no DNS lookup).

### Notes for open-source builds
- The Rust console depends on `guatx-core` via a **pinned public git dependency**
  (`git = "https://github.com/guatxlabs/core", tag = "v0.2.6", features = ["forge"]`; see
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
- **Governed console** (Rust/axum): findings, ATT&CK coverage, GXQL explore, dashboards, runs,
  ROE, ledger, admin — session-authenticated, RBAC, loopback-strict by default.
- **Optional LLM assist** (OpenAI-compatible, off by default, egress-gated, advisory-only).
- Postgres backend + HA topology, object-store artifacts, and Kubernetes manifests
  (deny-by-default NetworkPolicies) for enterprise deployments.

### Licensing
- **AGPL-3.0-or-later** — the whole product is open source, with no paid edition. The advanced
  separable modules (multi-tenant, SSO/SCIM, compliance) are flag-gated and OFF by default; they are
  documented in [`ADVANCED_MODULES.md`](docs/ADVANCED_MODULES.md).

[Unreleased]: https://github.com/guatxlabs/forge/commits/main
[0.0.1]: https://github.com/guatxlabs/forge/commits/main

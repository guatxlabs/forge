# Bundled third-party components

[English](THIRD-PARTY-NOTICES.md) | [Français](THIRD-PARTY-NOTICES.fr.md)

Forge bundles the components below. They are distributed **under their own
license**, not under Forge's AGPL v3. The AGPL v3 applies to the project's own
code; nothing here substitutes it for theirs.

These components are deliberately **bundled** (`console/web/fonts/`) rather
than fetched at runtime: the console must display without outbound network access to
a font CDN. On an offensive tool the constraint is stronger still —
a console that calls a third-party CDN signals the ongoing engagement to that third party.

## Inter

- **Location**: `console/web/fonts/inter-latin.woff2`,
  `console/web/fonts/inter-latin-ext.woff2`
- **License**: SIL Open Font License 1.1 (`OFL-1.1`)
- **Text**: [`console/web/fonts/OFL-Inter.txt`](console/web/fonts/OFL-Inter.txt)
- **Upstream**: <https://github.com/rsms/inter>
- **Version**: 4.001 — the font's `name` table reads
  `Version 4.001;git-66647c0bb`
- **Copyright**: `Copyright 2016 The Inter Project Authors` — the upstream OFL text
  says the same with a `(c)` that the `name` table does not have

## JetBrains Mono

- **Location**: `console/web/fonts/jetbrains-mono-latin.woff2`,
  `console/web/fonts/jetbrains-mono-latin-ext.woff2`
- **License**: SIL Open Font License 1.1 (`OFL-1.1`)
- **Text**: [`console/web/fonts/OFL-JetBrainsMono.txt`](console/web/fonts/OFL-JetBrainsMono.txt)
- **Upstream**: <https://github.com/JetBrains/JetBrainsMono>
- **Version**: 2.211 — the font's `name` table reads `Version 2.211`
- **Copyright**: `Copyright 2020 The JetBrains Mono Project Authors`

The two copyright notices above are the ones **read from the font itself**
(`name` table, identifier 0), not inferred from the file name. Each license
text was fetched from upstream **as is**: Inter's at commit
`66647c0bb`, which the font declares, JetBrains Mono's at a revision where
it is identical from one version to the next around 2.211.

These files are `latin` / `latin-ext` subsets converted to WOFF2 —
hence **Modified Versions** in the OFL sense. That remains allowed: neither Inter
nor JetBrains Mono declares a **Reserved Font Name** after its copyright
notice, so clause 3 does not bite, and clause 5 (remaining under the OFL) is
respected since we redistribute them under no other license.

The OFL does not contaminate the rest of the project: its clause 5 states that
the obligation to remain under the OFL does not extend to documents produced with the
font, and its clause 2 explicitly allows redistribution **bundled with
any software** as long as each copy carries the copyright notice and
the license. That is the case here for the source **and for the image**: the `Dockerfile`
copies `console/web/` in full, so both license files travel with
the fonts they cover.

---

## What is NOT a bundled third party

To be reread before adding an entry above, so as not to swell the list with
what does not belong there:

- **The Rust dependencies are not vendored.** They are fetched by
  Cargo at build time (`console/Cargo.lock` pins them): this repository does not redistribute
  their code, and so does not have to redistribute their license text. That would change
  if a Cargo `vendor/` were committed.
- **The Python dependencies are not vendored** either: `pyproject.toml`
  declares them, pip installs them at build time.
- **`guatx-core` is a git-dep**, not a copy: it is pinned by tag,
  under `LGPL-3.0-or-later`, and lives in its own repository.
- **The screenshots in `docs/media/`, the SVGs in `console/web/` and the `.jsonl` files in
  `examples/reference-engagement/`** are productions of the project — the
  reference engagement fixtures are synthetic (`*.example` domains).

## Compliance note

The four `.woff2` files were redistributed **without any OFL text** in the
repository: the OFL 1.1 requires in its clause 2 that "each copy contains the above
copyright notice and this license", which was not satisfied. Both
texts were fetched from upstream and added before any publication.

The defect could not be seen by looking for *missing license files* — it
shows when you inventory what the repository **redistributes**, by content type and not
by extension. The inventory was redone that way: apart from the fonts, the only
tracked binaries are screenshots and SVGs produced by the project, and
no third-party JS/CSS is bundled (no minified bundle, no
`@license` header).

Any update of a font must **bring its license file along at the same
time as the binary**, and update the version stated above — the
version is read from the `name` table, not from the file name.

## Mozilla trust roots (`webpki-roots`) — bundled in the binary

The **outbound TLS seam** (`console/src/tls.rs`, see [`docs/DEPLOYMENT.md`
§3quater](docs/DEPLOYMENT.md)) verifies certificates against the roots
**compiled into the binary**, never against the system store — that is
what keeps the "zero system library" posture (no `schannel`, no
`security-framework`, no `openssl`). These roots are therefore also a
**redistributed** third-party component.

- **Location**: compiled into the binary from the cargo dependency
  `webpki-roots` (declared in `console/Cargo.toml`, pinned in
  `console/Cargo.lock`) — not a file tracked in this repository.
- **Content**: Mozilla's CA trust store (NSS), converted into
  trust anchors.
- **License**: `CDLA-Permissive-2.0` (allowed by name in `deny.toml`).
- **Upstream**: <https://github.com/rustls/webpki-roots>

An update of this dependency changes **the set of authorities the
console accepts**: it is not a routine bump, and it is reviewed as such.

## What the `object-store` feature adds to what you redistribute

This repository does not vendor its Rust dependencies (see above), but **a binary
redistributes their compiled code**. The **default** build calls for nothing
special here: its whole graph is permissive (MIT / Apache-2.0 / ISC / BSD /
Unicode-3.0), with no attribution obligation beyond what the AGPL already imposes.

The `--features object-store` build (S3/MinIO), however, adds **51 crates** — and two
of them carry an obligation that does not show in the `license` field:

- **`attohttpc` (MPL-2.0)** — the HTTP client of `rust-s3`. **Per-file**
  copyleft: anyone who distributes a binary built with this feature must
  keep the MPL notices and **make the source of those files available** (their
  unmodified upstream version is enough — we do not modify them). MPL-2.0 §3.3
  explicitly allows the "Larger Work" under the AGPL, and `attohttpc` **does not carry**
  the "Incompatible With Secondary Licenses" notice (checked file by
  file): so there is no conflict, only an obligation to honor.
- **`aws-lc-sys` (~69 MB of vendored C — BoringSSL/OpenSSL)** — its license is a
  conjunction of seven terms over five licenses (ISC, Apache-2.0, MIT, BSD-3-Clause, MIT-0). Its
  `LICENSE` file, which records the origin of each portion, **must travel with
  any binary redistribution**. Two points checked because they are the real
  risk and not the assumed risk: the code derived from OpenSSL is **relicensed
  Apache-2.0** there (no trace of the GPL-incompatible advertising clause), and the
  `jitterentropy` library, dual BSD-3-Clause **or** GPLv2, is
  **expressly distributed under BSD-3-Clause and not under GPLv2** by AWS.

These 51 crates are the ones that `cargo-deny` **does not read** (cause, figures and compensating
guard: [`docs/DEPLOYMENT.md`
§3quater.2](docs/DEPLOYMENT.md#perimetre-de-l-audit-de-licences)). Their licenses
are checked by `python3 scripts/check_dep_licenses.py`, wired into CI.

## What the `encryption` feature adds to what you redistribute

The `--features encryption` build (SQLCipher at rest) switches `rusqlite` to
`bundled-sqlcipher`. Chain: `encryption` → `rusqlite/bundled-sqlcipher` →
`libsqlite3-sys` 0.40.0 → `sqlcipher-src` 420.0.0, a **build** dependency whose
`license` field is `MIT AND BSD-3-Clause AND blessing AND WTFPL`. What actually ends up in
the binary is narrower than that expression:

- **SQLCipher 4.20.0 (BSD-3-Clause)** — the amalgamation `sqlcipher/sqlcipher.c` is compiled
  into the binary. The BSD-3-Clause requires that **binary redistributions reproduce the
  notice below** in the documentation or other materials: it travels with any binary built
  with `encryption`.
- **SQLite 3.54.1 (public domain, `blessing`)** — inside the same amalgamation. The author
  disclaims copyright and puts a blessing in place of a legal notice: no obligation.
- **libtomcrypt 1.18.2 (public domain or `WTFPL`)** — shipped in the crate for targets without
  a system crypto library. On a native build it is **not compiled**: `libsqlite3-sys` compiles
  the amalgamation alone and links the system `libcrypto` dynamically (its `build.rs`); checked
  on a Linux build, which produces `sqlcipher.o` and no libtomcrypt object. Compiled or not,
  neither of its two licenses imposes anything.
- **The crate's own glue (MIT)** — Rust code run by the build script only, not linked into the
  binary.
- **OpenSSL `libcrypto`** — linked dynamically from the host, not bundled: its license is that
  of the library installed on the machine.

None of these terms is reciprocal, so nothing conflicts with the AGPL. `blessing` and `WTFPL`
are allowed by name in `deny.toml`, with this justification. The notice to reproduce, copied
from `sqlcipher/LICENSE-sqlcipher` of the crate:

```text
Copyright (c) 2025, ZETETIC LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the ZETETIC LLC nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

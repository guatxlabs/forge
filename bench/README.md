<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# `bench/` — measuring Forge, not assuming

[English](README.md) | [Français](README.fr.md)

This folder contains **no** production code. These are **observers**: they drive Forge's
public CLI against targets with known ground truth and count what it finds, what
it misses, and — above all — what it wrongly asserts.

> Nothing here imports `forge/**` other than through the CLI and by reading the `--memory` store.
> A bench that called the internal API would not measure what an operator gets.

## `detection/` — multi-application detection bench

**Why.** The repository's only measurement of detection power covered **one** target (OWASP Juice
Shop). A sample of 1 does not say whether the engine generalizes or whether it was tuned to that target.

**How.** Four deliberately vulnerable applications, **different stacks**, each providing
its OWN ground truth:

| app | stack | ground truth (provided by the application) |
|---|---|---|
| Juice Shop | Node/Express/Angular | `GET /api/Challenges` — its challenge registry |
| DVWA | PHP/Apache/MariaDB | `/var/www/html/vulnerabilities/` — its module list |
| VAmPI | Python/Flask/OpenAPI3 | `README.md` § *List of Vulnerabilities* + the `if vuln:` branches |
| DVGA | Python/Flask/Graphene | `templates/partials/solutions/*.html` — its solution pages |

**Two tracks, measured separately** — because they do not say the same thing:

- **track A** — each oracle is **seeded by hand** on the known vuln (exact URL + parameter).
  Discovery is neutralized: only **judgment** is measured.
- **track B** — **autonomous campaign** (`--auto-pentest`). The **full chain** is measured
  (discovery + judgment) and it yields the volume in which **false positives** are counted.

**Three metrics, the third one first.** True positives per class; false negatives **with their
cause**; and **false positives** — every finding ≥ MEDIUM is replayed by hand against the application.

## Safety

- **Strict loopback.** Each container is published on `127.0.0.1` only;
  `provision.verify_loopback_only()` **refuses** to continue if a socket leaves the local loopback.
- **Port-bounded scope** (`in_scope: ["127.0.0.1:PORT"]`), checked by `forge scope-check`
  before any arming, with a counter-test on an out-of-scope target.
- **Modules that query a third party are excluded** (`provision.THIRD_PARTY_MODULES`: crt.sh, Wayback,
  public DNS resolvers, template repositories, callback collectors). The kept/excluded list is
  written to `modules_loopback_safe.json` on each run.
- These applications are **deliberately vulnerable**: never expose them. Teardown is
  **systematic** — it lives in a `finally`, covers **everything carrying the `forge-bench-` prefix**
  (discovered from docker, not read from a list), and **verifies its own effect**: `teardown()`
  rereads docker + the sockets after removing, and returns `(ok, restes)` (*ok, leftovers*).
  `--keep-up` leaves the bench up, but it is then an explicit operator choice.

  > Why this level of care: the replay of **2026-08-11** found `forge-bench-dvwa` still
  > listening **after** a `teardown()` deemed complete. The code had three leak paths —
  > opt-in teardown **after** the loop (no interruption survived it); teardown list
  > limited to the applications that had **answered**, leaving out of reach a container created but silent;
  > and above all the **scope refusal that exited without tearing down**, that is the guard which, by
  > refusing to arm because a vulnerable application was listening outside the local loopback,
  > left it listening precisely. Covered by `tests/test_bench_teardown_final.py`.

## Usage

```bash
# bring up the targets, seed, run both tracks, write the manifest
python3 -m bench.detection.run_bench --workdir /tmp/bench --track both --budget 900

# render the table (per app, per class, + the list of >= MEDIUM to verify by hand)
python3 -m bench.detection.report --workdir /tmp/bench --verdicts bench/detection/verdicts.json

# tear down by hand (the run already does it on its own, including if interrupted)
python3 -c "from bench.detection import provision; print(provision.teardown())"
```

**Campaigns run, raw outputs kept (never overwritten)** — `RESULTS_2026-08-10.md` (initial
measurement, 13 defects) and `RESULTS_2026-08-11.md` (bench replayed in full after remediation).
BEFORE/AFTER comparison and defects still open: `../../docs/BENCH_DETECTION.md`.

**Two known caveats about the bench itself** (recorded, not fixed):
`harness.run_forge` marks `partial=True` for ANY campaign given a `--run-timeout`, because
the engine's launch banner contains the word « PARTIEL » (*PARTIAL*) — read the banner of the engine's report
rather than this flag (defect **D15**); and `THIRD_PARTY_MODULES` excludes by declared intent, not
by observed egress — `recon.httpx` downloads a model from `huggingface.co` (defect **D17**).

## Files

| file | role |
|---|---|
| `groundtruth.py` | the ground truth, entry by entry, **with its source cited** |
| `provision.py` | brings up the targets on loopback, seeds them, writes `scope.json`/`targets.json` |
| `seeded.py` | track A: the actions seeded by hand, one per known vuln |
| `harness.py` | runs the Forge CLI, harvests the `--memory` store, reports whether the budget cut in |
| `score.py` | counts the three metrics; lists the ≥ MEDIUM ones to verify |
| `report.py` | renders the final table |

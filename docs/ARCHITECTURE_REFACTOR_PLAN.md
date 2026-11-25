# Architecture refactor plan — incremental, never a big-bang

[English](ARCHITECTURE_REFACTOR_PLAN.md) | [Français](ARCHITECTURE_REFACTOR_PLAN.fr.md)

> **Status: §1 (main.rs) DONE ✅; §2 (Python boilerplate) PLAN only.** This document
> modifies no code. It applies the principle "incremental architecture refactors, NEVER a
> big-bang" to the structural debt identified in the console.
>
> **UPDATE (post-split).** The decomposition of the `console/src/main.rs` god-file targeted by
> §1 is **DONE**: `main.rs` went from 6065 → **~460 lines**, with `router.rs` (build_router),
> `boot.rs` (serve/dispatch_cli/store-gate) and the **11 `tests_*.rs` files** extracted as planned
> (Steps 1→4 all applied). §1 below is **kept as a historical record** and marked
> ✅ DONE. The **largest remaining architecture debt** is now on the side of the **remaining large
> files** — `console/src/store.rs` (~2306 l), `console/src/sso.rs` (~2110 l),
> `console/src/scim.rs` (~1995 l) — to be decomposed with the **same** PURE MOVE/EXTRACT discipline
> when those areas are touched. §2 (`extra_args`/allowlist boilerplate in `forge/modules/*.py`)
> remains a valid PLAN, not started.
>
> **Guiding principle (non-negotiable):** each step is a **PURE MOVE / PURE EXTRACTION**
> with strictly preserved behaviour, self-contained (compiles + tests green on its own), and ordered from
> **smallest risk to largest**. We NEVER aim for a "clean" file in one go; we
> extract by coupling, opportunistically. The default build stays **byte-identical**.

---

## 0. Guardrails (to respect at EVERY step)

These invariants apply to every step of both workstreams. A step that violates a
single one must be reverted, not "fixed later".

1. **Green before / green after.** Before committing a step:
   - Rust: `cd console && cargo test` (the package is called `forge`, not `forge-console`)
     → **418 Rust tests** (MEASURED count: `test result: ok. 418 passed`) must stay green,
     **same number, same names**.
   - Python: `python3 -m unittest discover -s tests -t .` → **1513 Python tests** (MEASURED count:
     `Ran 1513 tests` / `OK (skipped=1)`) must stay green, same number.
   - `cargo build --release` (default build, default features) must produce a binary
     **byte-identical** to the previous HEAD: a PURE MOVE changes neither the generated code nor the
     `include_str!`/assets. (Check: `cargo build --release` then `sha256sum` of the binary
     before/after; or `cargo build && git stash` A/B if the environment is deterministic.)
2. **Zero behaviour change.** No public signature, no `.route()` order,
   no CLI exit code, no error message, no Finding field changes. The
   extractions introduce only moves + `pub(crate) use` / shared bases.
3. **A single seam per commit.** One commit = one cohesive extraction. Never two seams
   in the same diff (eases review and surgical `git revert`).
4. **The extraction pattern is already established in the repo — we EXTEND it, we invent nothing.**
   `main.rs` has already been split this way (findings.rs, runs.rs → runs_proc/runs_ha/runs_validate,
   engagements.rs, auth.rs, net.rs…), each time via `mod x; pub(crate) use crate::x::*;` with
   a "(PURE MOVE)" comment. Any new extraction copies this model **verbatim**.
5. **Opportunistic trigger.** These refactors happen when the area is already being touched OR as
   an explicitly budgeted debt breather — never as a "speculative rewrite" that
   would block a functional delivery.

---

## 1. `console/src/main.rs` (6065 lines) — god-file decomposition — ✅ DONE

> **✅ DONE.** This workstream is finished: `main.rs` is now **~460 lines**, `router.rs`
> and `boot.rs` are extracted, and the **11 `tests_*.rs` files** listed in §1.2 exist. The
> section below is left **for the record** (the "6065 lines" state describes the starting
> point before the split, not the current state). Next target: store.rs / sso.rs / scim.rs.

### 1.1 Actual state, verified (read, not assumed)

Structure of `main.rs` **before** the split (offsets read from the file, not assumed):

| Lines | Content | Nature |
|--------|---------|--------|
| 1–72 | `use` (axum, rusqlite, serde, std, tokio) | imports |
| 73–329 | ~30 × `mod x;` + `pub(crate) use crate::x::*;` + "PURE MOVE" comments | declarations of already extracted modules |
| 330–359 | `async fn health(State<App>) -> Json<Value>` | handler |
| 360–375 | `fn health_db_ping(&App) -> bool` | `health` helper |
| 376–387 | `fn catch_panic_response(err) -> Response` | responder of the `CatchPanic` layer |
| 388–607 | `fn build_router(app: App, web_dir: &str) -> Router` | **60 `.route()` + 8 `.merge(x::routes())`** |
| 608–621 | `#[tokio::main] async fn main()` | glue (dispatch_cli → serve) |
| 623–732 | `fn dispatch_cli(args: &[String]) -> Option<i32>` | CLI subcommands (hashpw, ledger verify…) |
| 733–1122 | `async fn serve()` | server boot (~390 l: DB open, PRAGMA, SCHEMA, migrate, store-gate, App, HA, bind) |
| 1123–1139 | `enum StoreSelection` | store-gate type |
| 1140–1164 | `fn advanced_store_gate(...) -> Result<StoreSelection, String>` | SQLite/Postgres decision |
| 1166–1167 | `#[cfg(test)] pub(crate) mod testutil;` | **already an external file** (`testutil.rs`, 83 l) |
| **1169–6065** | **`#[cfg(test)] mod tests { … }`** | **4897 lines, 133 `#[test]`/`#[tokio::test]` fns** |

**Key finding: ~80 % of the file (4897/6065) is the inline test module.** The non-test code
is only **~1168 lines**, whose only real internal "god-function" is `build_router`
(220 l, pure wiring of handlers already imported from the submodules). The plan therefore attacks
**the test module first** (massive size gain, near-zero risk), then the code seams.

> The handlers routed by `build_router` (`whoami`, `ingest`, `findings`, `coverage`,
> `attack_matrix`, `run_create`…) are **already** defined in the submodules and re-exported
> `pub(crate)` at the root (§73–329). `build_router` only wires them — extracting it is therefore
> mechanical. The inline tests access the root's private items via `use super::*` +
> `use crate::testutil::*`; a **child** test module (sibling file `mod tests;`) keeps
> this access (a child module sees the private items of its ancestors). This is what makes all
> the steps below safe.

### 1.2 Ordered sequence (small risk → large risk)

#### Step 1 — Move the test module out into a sibling file (`console/src/tests.rs`)
- **Move:** lines **1169–6065** (`mod tests { use super::*; use crate::testutil::*; … }`)
  → new file `console/src/tests.rs` (module body, without the `mod tests {}` braces).
  In `main.rs`, replace the block with `#[cfg(test)]\nmod tests;`.
- **Why it is safe:** `super::*` from `tests.rs` (child module of the root) resolves exactly
  the same private items of `main.rs` as inline; `crate::testutil::*` is already an unchanged absolute
  path. No `pub` to add, no test body touched.
- **Result:** `main.rs` goes from 6065 → **~1168 lines**. 80 % gain.
- **Risk: VERY LOW.** Pure move of text compiled only under `cfg(test)`.
- **Green check:** `cd console && cargo test` → **418 tests, same names** (MEASURED count); `cargo build
  --release` byte-identical (the non-test code is unchanged, tests excluded from the release build).

#### Step 2 — Split `tests.rs` by subsystem (mirroring the source modules)
Once `tests.rs` is isolated (4897 l, 133 tests), split it into sibling test files, **by
cohesive clusters already contiguous** in the file (offsets read in the current module):

| Proposed test file | Tests (theme) | Current range (in main.rs) |
|-------------------------|---------------|-------------------------------|
| `tests_http_boot.rs` | panic-responder, security-headers, store-gate contract, health, standalone-boot | 1177–1335, 5955–6065 |
| `tests_auth_session.rs` | create_session, login-lockout, tokens, sessions, cookie/bearer, attribution, auth-gate, https-detect | 1461–1846 |
| `tests_users_admin.rs` | panel-write, admin CRUD, users routes 403, settings round-trip | 1846–2083 |
| `tests_setup.rs` | wizard end-to-end, migrate/provision self-disabling, path-confinement | 2100–2407 |
| `tests_net_policy.rs` | ip-in-cidr, operator-source-cidr, trusted-proxy, ct_eq, host_guard, network-policy API | 2407–2610, 2909–3046 |
| `tests_ledger.rs` | ledger chain consistency, reload continuity, interleave-no-fork | 1394–1461, 2623–2713 |
| `tests_runs_engagement.rs` | run scope/ledger isolation, per-engagement slot, migrate-backfill, engagement CRUD | 2713–2909, 3046–3218, 3891–4033 |
| `tests_tenancy_rbac.rs` | tenancy isolation, per-engagement RBAC, superadmin, tenant CRUD | 3218–3891 |
| `tests_planning_techniques.rs` | technique selection/profiles, plan threading, workflows, techniques catalog | 4033–4189, 5429–5955 |
| `tests_reports_purple.rs` | run-report md/html, cvss, html-escape, purple coverage, detection source | 4189–4912 |
| `tests_modules_tools.rs` | high-impact gate, validate_modules, extra_args allowlist, toolspec, tools CRUD, module routes | 4912–5429 |

- **Mechanical move:** for each cluster, cut the relevant fns from `tests.rs` → sibling
  file; add `#[cfg(test)] mod tests_<x>;` in `main.rs` (or in a parent `mod tests;`
  that `pub(crate) mod`-declares the sub-files). Each file starts with
  `use super::*; use crate::testutil::*;` — the same preamble as the original module.
- **Risk: LOW.** Purely text; the only trap is a **shared** test helper defined
  in the module (e.g. `test_app`, `test_app_scoped`, `http_raw`, `get_req`, `post_req`,
  `parse_status`, `cookie_token`, `operator_headers`, `seed_two_tenants`…). **Prerequisite:**
  first move these shared helpers into `console/src/testutil.rs` (an already existing file,
  `pub(crate)`), in a dedicated **sub-step 2a**, before any splitting — otherwise a test file
  loses access to its helper. Single-use helpers stay with their test.
- **Incremental feasibility:** each file can be extracted **one by one**; in between, the
  build is green. There is NO obligation to do all 11 at once — one is done when the area
  is touched.
- **Green check:** after each file, `cargo test` → total unchanged.

#### Step 3 — Extract `build_router` into `console/src/router.rs`
- **Move:** lines **388–607** (`fn build_router`) → `console/src/router.rs` exposing
  `pub(crate) fn build_router(app: App, web_dir: &str) -> Router`. Take along
  `catch_panic_response` (376–387) and `health`/`health_db_ping` (330–375) **if** they are
  used only by the router/tests — otherwise leave them at the root and keep them `pub(crate)`.
- **Why it is safe:** `build_router` only wires handlers **already** re-exported
  `pub(crate)` at the root (§73–329); from `router.rs`, these symbols remain accessible via
  `use crate::*;` (or targeted imports). No handler is moved, no route order
  moves, no string changes → identical binary.
- **Risk: LOW.** The only point of attention is the list of `use` to copy; the compiler
  guarantees it is exhaustive.
- **Green check:** `cargo test` (the `*_routes_do_not_conflict`, `security_headers_*`,
  `standalone_boot_serves_health_*` tests already exercise the mounted router) + byte-identical release build.

#### Step 4 (optional, only if `main.rs` stays large) — Extract the boot into `console/src/boot.rs`
- **Move:** `serve` (733–1122), `dispatch_cli` (623–732), `advanced_store_gate` (1140–1164),
  `enum StoreSelection` (1123–1139) → `console/src/boot.rs` (`pub(crate)`). `main.rs` shrinks to
  `main()` + the root `mod`/`use` + the `mod tests`.
- **Why it is safe:** these are functions loosely coupled with the rest (they consume
  `App`, `advanced_store_gate`, `build_router`); the extraction is a move + `use`.
- **Risk: LOW-MEDIUM.** `serve` is the largest (~390 l) and touches `#[cfg(feature =
  "encryption")]` and the HA wiring — copy the `use`/`cfg` attributes **identically**. It is
  the only step with a little surface; it is **optional** and is only done if the
  readability gain justifies it after step 1.
- **Green check:** `cargo test` (the `advanced_store_gate_contract`,
  `standalone_boot_*`, `health_surfaces_stamped_schema_version` tests cover the area) + byte-identical
  release build.

### 1.3 Final target (indicative, NOT a goal to reach in one go)
```
console/src/main.rs        ~60 l   (main() + mod/use racine + mod tests;)
console/src/router.rs      ~230 l  (build_router + health + catch_panic_response)
console/src/boot.rs        ~430 l  (serve + dispatch_cli + store-gate)   [étape 4, optionnelle]
console/src/testutil.rs    ~250 l  (helpers de test partagés, étendu en 2a)
console/src/tests_*.rs      11 fichiers, ~4900 l au total (répartis)
```
Recommended execution order: **1 → (2a → 2 as you go) → 3 → 4 (if needed)**. After
step 1 alone, the "god-file" debt is already 80 % resolved for near-zero risk.

---

## 2. `forge/modules/*.py` — factoring out the `extra_args`/allowlist boilerplate

### 2.1 Actual state, verified

The codebase **already** has two factoring foundations in place:
- `forge/modules/oracle.py::Oracle` (+ `ScopeGuardedOracle`) — factors the 4 evidence-backed oracles
  (`proof`/`skip`/`_http`/`_curl`). **Well done, nothing to redo here.**
- `forge/modules/toolspec.py::ExternalToolModule` (382–…) — base of the wrappers **generated from a
  `ToolSpec`**: it ALREADY centralises, in a single `fire()`, the whole governed contract —
  fail-closed scope-guard, **positional-argument anti-injection** (`unsafe_positional_target`),
  **fail-closed `extra_args` allowlist** (`unsafe_extra_args`, 436–445), exploit floor,
  degradation when the binary is absent, no-shell execution.

**The debt is elsewhere:** the **hand-written** modules (not generated from a `ToolSpec`)
**each re-implement** what `ExternalToolModule` already centralises. Verified duplication:

| Module | Class(es) | `FLAG_ALLOWLIST` | local `_refuse()` | repeated `extra_args` param-spec | gate in `fire()` |
|--------|-----------|:---:|:---:|:---:|:---:|
| `recon.py` | `HttpxFingerprint`, `NmapServices` | 2× (l.53, 125) | 2× (l.81, 170) | 2× | 2× (`check_extra_args`) |
| `web.py` | `NucleiScan` | 1× (l.37) | 1× (l.77) | 1× | 1× |
| `origin.py` | `SubfinderEnum` | 1× (l.91) | (via check) | 1× | 2× (l.112, 130) |
| `recon_active.py` | `ContentDiscovery` (`PassiveSurface`) | 1× (l.96) | — | 1× | 6× refs |
| `injection.py` | `SqliProbe` (`InjectionOracle`) | 1× (l.286) | — | 1× | 1× (l.403) |

The duplicated pattern, **near-verbatim** from one module to the next:
```python
FLAG_ALLOWLIST = ("-x", "-y", ...)                       # (1) per-module constant
{"name": "extra_args", "type": "list", "label": "...", "flag": ""}   # (2) repeated params entry
# in preview:
_, extra = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)
# in fire():
bad_extra, _ = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)
if bad_extra is not None:
    return self._refuse(action, f"argument libre refusé ({bad_extra})")   # (3) duplicated fail-closed refusal
```
`_refuse` is copied **identically** in `recon.py` (×2), `web.py`, `origin.py`.

### 2.2 Factoring target

Introduce, **in `toolspec.py`** (next to the already shared `check_extra_args`/`safe_value`), a
**lightweight mixin** for the hand-written modules that do not descend from `ExternalToolModule`:

```python
class FlagAllowlistMixin:
    """Contrat extra_args gouverné pour les modules-wrappers ÉCRITS À LA MAIN.
    Factorise : la constante d'entrée de params, la porte fail-closed, et le finding de refus.
    Aucune capacité élargie — même allowlist, même comportement, une seule source."""

    FLAG_ALLOWLIST: tuple = ()          # declared by each concrete module (unchanged)

    # (2) the repeated params entry -> a classmethod that produces it
    @classmethod
    def extra_args_param(cls, label="extra args (allowlist de drapeaux)"):
        return {"name": "extra_args", "type": "list", "label": label, "flag": ""}

    # (3) the unified fail-closed refusal (replaces the copied _refuse)
    def _refuse(self, action, reason):
        return [self.finding(
            target=action.target, title=f"{self.kind} non exécuté — {reason}",
            severity="INFO", category="recon", status="skipped",
            tool=self._toolname(), evidence=f"{reason}. Aucun processus lancé (fail-closed).",
            poc=self.dry(action))]

    # (1+gate) the gate: None if OK, otherwise the already built refusal finding
    def gate_extra_args(self, action):
        bad_extra, _ = check_extra_args((action.params or {}).get("extra_args"), self.FLAG_ALLOWLIST)
        return self._refuse(action, f"argument libre refusé ({bad_extra})") if bad_extra is not None else None
```
> **Behavioural accuracy note:** the wording/`category`/`status` of the refusal finding must
> be aligned **verbatim** with what each module produces today (e.g. `status="skipped"`
> vs the exact message). If the modules diverge on wording, **keep the per-module
> wording** by passing it as an argument, OR first migrate the wordings to a common form in
> an isolated step BEFORE introducing the mixin — otherwise a finding regression test breaks.
> This is the only point of vigilance: the factoring must NOT standardise a message that the
> tests pin down.

### 2.3 Ordered sequence (smallest risk → largest)

| # | Migrated module | Why this order | Risk | Green check |
|---|--------------|--------------------|:------:|-------------|
| 0 | **Add `FlagAllowlistMixin` in `toolspec.py`** (without wiring it) + mixin unit tests | Introduces the foundation without touching any module → green build by construction | Very low | `python3 -m unittest`: +N new tests, the 1513 existing ones unchanged |
| 1 | **`web.py::NucleiScan`** (1 class, simplest local `_refuse`) | Most isolated case → validates the mixin on a real module | Low | `pytest -k nuclei` + full suite; byte-identical refusal finding |
| 2 | **`recon.py::HttpxFingerprint` then `NmapServices`** (2 classes, `_refuse` duplicated ×2) | Removes the most glaring duplication; two classes ⇒ two commits | Low | `recon`/`module_routes_do_not_conflict` tests |
| 3 | **`origin.py::SubfinderEnum`** (gate at 2 points: preview + fire) | Checks that the mixin covers the double `check_extra_args` call | Low | `origin`/exposure tests |
| 4 | **`recon_active.py::ContentDiscovery`** (`PassiveSurface`, 6 refs) | More contact points ⇒ after the mixin is broken in | Low-medium | `recon_active`/secret-scan tests |
| 5 | **`injection.py::SqliProbe`** (`InjectionOracle` → `ScopeGuardedOracle`) | Multiple inheritance (mixin + Oracle chain) ⇒ **last**, MRO to validate | Medium | `validate_extra_args_enforces_allowlist` test (Rust) + `pytest -k sqli` |

- **Each migration = 1 commit**: replace, in the module, the local `_refuse` + the
  literal `{"name":"extra_args",...}` + the `check_extra_args` call + guard with the mixin
  (`class X(FlagAllowlistMixin, ...)`, `params=[..., self.extra_args_param()]`,
  `if (r := self.gate_extra_args(action)): return r`). **The `FLAG_ALLOWLIST` constant stays
  declared by the module** (it is intrinsic to the wrapped tool — do NOT centralise it).
- **MRO trap (step 5):** `InjectionOracle` already descends from `ScopeGuardedOracle`
  (`ScopeGuardMixin, Oracle`). Add `FlagAllowlistMixin` at the **head** of the bases
  (`class SqliProbe(FlagAllowlistMixin, InjectionOracle)`) so that its methods take precedence without
  masking `finding`/`_in_scope` from the Oracle chain. Validate with `SqliProbe.__mro__` + the test.
- **Non-goal:** these modules are NOT merged into `ExternalToolModule` (they have their own
  parsing/judgement logic that cannot be generated from a `ToolSpec`). The mixin factors only the
  `extra_args` plumbing, not the business body.

### 2.4 Gain
- Removes ~4 copies of `_refuse`, ~6 `{"name":"extra_args",...}` literals, and unifies the
  `extra_args` gate into a single source — **without** changing an allowlist or a generated argv (the
  `validate_extra_args_enforces_allowlist` and `plan_threads_and_validates_module_params_extra_args` tests
  remain the safety net).
- Aligns the hand-written modules with the contract already carried by `ExternalToolModule`, reducing
  future divergence (the next wrapper module inherits the right behaviour by default).

---

## 3. What this plan is NOT

- **Not a big-bang.** No step depends on the next one to be green; you can stop
  after Step 1 of each workstream and have already banked most of the gain.
- **Not a rewrite.** Zero new logic: text moves + a shared base whose
  body is copied from the existing implementations.
- **No change to the default-build surface.** Byte-identical release binary; findings,
  routes, exit codes, allowlists — all unchanged.
- **Opportunistic.** Trigger: "I am already touching this area" or a budgeted debt window.
  Never "let's refactor for the sake of refactoring".

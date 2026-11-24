<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Multi-application detection bench — method and results

[English](BENCH_DETECTION.md) | [Français](BENCH_DETECTION.fr.md)

> [Contents](README.md) · Bench code: [`../bench/detection/`](../bench/README.md) ·
> Historical single-target measurement: kept outside the public repository; this document succeeds it and
> stands on its own.
>
> **TWO campaigns, kept side by side.** `2026-08-10` (initial measurement, 13 defects recorded) and
> `2026-08-11` (bench **replayed in full** after remediation, to measure the 13 fixes TOGETHER
> and no longer in isolation). The earlier figures are **kept visible** wherever they moved:
> a bench report that rewrites its errors is worthless as a reference. The replay closed
> 10 defects out of 13, left 3 partially open, and brought **6 new ones** to light (§6bis).

## 1. Why this bench exists

The repository's only measurement of detection power covered **one** application (OWASP Juice Shop):
2 confirmed vulnerabilities, ground truth supplied by the app itself. It is an honest measurement,
but a **sample of 1**: it does not say whether the engine GENERALISES or whether it was tuned to that
target. All the other confrontations had stalled on **access** (Cloudflare wall, UAT returning 404),
never on detection — except one real target where the engine produced **8 false HIGH**.

This bench answers one question and one only: **beyond Juice Shop, does forge find anything,
and does it assert false things?**

## 2. What is measured, and how

Four intentionally vulnerable applications, **deliberately different stacks**, each
supplying its OWN ground truth — never forge:

| app | stack | ground truth |
|---|---|---|
| Juice Shop (control) | Node/Express/Angular/SQLite | `GET /api/Challenges`: its challenge registry |
| DVWA | PHP 7/Apache/MariaDB | `/var/www/html/vulnerabilities/`: its list of modules |
| VAmPI | Python/Flask/connexion/OpenAPI3 | `README.md` § *List of Vulnerabilities* + `if vuln:` branches |
| DVGA | Python/Flask/Graphene | `templates/partials/solutions/*.html`: its solution pages |

Juice Shop is **replayed** to check that the bench REPRODUCES the repository's known measurement: without this
control, a deviation on the other three would be indistinguishable from a bench defect.

### Two tracks, never conflated

An autonomous campaign measures **two** capabilities at once — DISCOVERING the surface, and JUDGING once
on it. When it finds nothing, we do not know which one failed. The bench separates them:

- **track A — judgement.** Each oracle is seeded by hand on the EXACT URL and parameter of the known
  vuln. Discovery is neutralised; only the verdict remains.
- **track B — full chain.** `--auto-pentest` campaign on the app root. This is where the
  **false positives** are counted, because this is where the volume is.

### Three metrics, the third one first

True positives **per class** · false negatives **with their cause** (missing oracle? seeding?
browser? budget?) · and **false positives**: every finding ≥ MEDIUM is replayed by hand against
the application. A bench that only counted findings would prove nothing.

A class that **no** oracle in the repository claims is NOT counted as a false negative: it is a
coverage gap, counted separately. Classes banned from the scope (DoS, brute force, missing
rate-limit) are excluded from the denominator.

## 3. What was seeded — declared per application

"forge finds X with 2 supplied accounts" and "forge finds X with nothing" are two different
claims. The bench makes both readable; the exact seeding lives in `manifest.json`
(`apps.<app>.primed`) and is copied as is into the report.

| app | seeded |
|---|---|
| Juice Shop | 2 accounts of our own (self-signup) + the victim's basket as a marked IDOR target |
| DVWA | 1 authenticated session (native `admin` account), native `low` level, 1 **benign canary** in the web root |
| VAmPI | 2 accounts of our own + 1 resource owned by the victim, described by its marker |
| DVGA | **nothing** — the application is entirely anonymous |

DVWA's canary is not a shortcut: `path.traversal` REFUSES by design to target
`/etc/passwd` and requires a benign marker supplied by the operator. Without it, it can structurally
confirm nothing.

## 4. Bench safety

- **Strict loopback.** Each container is published on `127.0.0.1` only.
  `provision.verify_loopback_only()` reads `ss -ltn` and **refuses to arm** if a bench socket listens
  elsewhere. These applications are deliberately vulnerable: they must never be exposed.
- **Scope bounded to the port**: `in_scope: ["127.0.0.1:<port>"]`, plus `allow_private: true` (the ROE
  refuses private addresses by default). Checked by `forge scope-check` before each arming,
  with a **counter-test** on an out-of-scope target (expected: exit 1).
- **`allow_exploit: true`** — assumed and declared: the access-control oracles depend on it. These
  applications belong to us. `allow_destructive` stays `false`.
- **Modules querying a third party excluded** (`provision.THIRD_PARTY_MODULES`): crt.sh, Wayback,
  public DNS resolvers, upstream template repositories, off-host callback collectors. The
  kept/excluded list is written at each run to `modules_loopback_safe.json`.
  ⚠️ **THIS GUARANTEE IS INCOMPLETE, measured on 2026-08-11**: the exclusion covers a module's declared
  INTENT, not its observed egress. `recon.httpx` — kept as safe — downloaded
  92.6 MiB from `huggingface.co` on each of its 4 shots. Detail and evidence in **D17** (§6bis).
  The rest of the run stayed on local loopback; no request went out to a third-party target.
- **Accepted limit**: the governed browser service runs in its own network namespace; it
  cannot reach a host `127.0.0.1:<port>`. Browser-backed oracles
  (`xss.execution`, the DOM rendering of `xss.stored`) are therefore **not measurable** on this bench — they are
  counted `skipped`, never `manqués` (missed). Making them measurable would require binding the applications to
  the docker bridge address, which the "loopback only" rule forbids.

## 5. Results — BEFORE (2026-08-10) / AFTER (2026-08-11)

> **The two campaigns are kept side by side, column by column.** The 13 defects recorded
> in §6 were closed between the two, but **they had only been measured in ISOLATION**; the bench was
> replayed IN FULL to measure them TOGETHER. Raw outputs: [`RESULTS_2026-08-10.md`](../bench/detection/RESULTS_2026-08-10.md)
> and [`RESULTS_2026-08-11.md`](../bench/detection/RESULTS_2026-08-11.md).
>
> **IDENTICAL method** — same ground truth (supplied by the applications), same declared seeding,
> same budget `--budget 900`, same kept modules, same two tracks.
> **ONE SINGLE parameter changed, and it is declared**: DVWA's track-A `cmdi.probe`/`rce.probe` action
> now targets `/vulnerabilities/exec/?Submit=Submit` instead of `/vulnerabilities/exec/`
> (`bench/detection/seeded.py`). Reason: DVWA tests `isset($_POST['Submit'])` — without this co-parameter
> the RCE is **out of reach by construction**, whatever the payload. This is defect D6 seen
> from the seeding side: the action declared the co-parameter nowhere, so nothing could
> carry it. The D6 fix (preserving the other parameters) and this seeding correction are
> **inseparable**: neither one alone makes the RCE reachable.

### 5.1 Summary

| app | track | opposable | **true positives** | **false negatives** | **false positives** | findings emitted | ≥ MEDIUM claimed |
|---|---|---|---|---|---|---|---|
| | | | BEFORE → **AFTER** | BEFORE → **AFTER** | BEFORE → **AFTER** | BEFORE → **AFTER** | BEFORE → **AFTER** |
| Juice Shop | A | 3 | 2 → **2** | 1 → **1** | 0 → **0** | 6 → **6** | 2 → **2** |
| Juice Shop | B | 3 | 0 → **0** | 3 → **3** | 0 → **0** | 873 → **45** | 0 → **0** |
| DVWA | A | 9 | 3 → **5** | 6 → **4** | 0 → **0** | 15 → **15** | 3 → **5** |
| DVWA | B | 9 | 0 → **0** | 9 → **9** | **4 → 4** | 1806 → **1558** | 4 → **4** |
| VAmPI | A | 4 | 1 → **2** | 3 → **2** | 0 → **0** | 8 → **8** | 1 → **2** |
| VAmPI | B | 4 | 1 → **1** | 3 → **3** | 4 → **0** | 1175 → **319** | 5 → **1** |
| DVGA | A | 7 | 0 → **0** | 7 → **7** | 0 → **0** | 15 → **15** | 0 → **0** |
| DVGA | B | 7 | 0 → **0** | 7 → **7** | 0 → **0** | 1849 → **2940** | 0 → **0** |
| **TOTAL** | | | **6 → 9** ¹ | | **8 → 4** | **5747 → 4906** ² | **15 → 14** |

¹ true positives counted as distinct (app, class) pairs, without double counting across tracks.
² A+B combined. On the autonomous track alone: **5703 → 4862**.

- **What moved for the better**: DVWA gains `cmdi.probe` **HIGH** and `rce.probe` **CRITICAL** (the RCE,
  verified by hand: `uid=33(www-data)`); VAmPI gains `jwt.weakness` **HIGH**; VAmPI's 4 false positives
  are gone; track-B volume drops from 1806 to 1558 on DVWA and from 1175 to 319 on
  VAmPI.
- **What did NOT move**: DVWA's **4 `header_injection.probe` HIGH are still there** (§5.2);
  track B stays at **1 single true positive** across the 4 applications; DVGA stays at **0 out of 7** on both
  tracks, and its volume **INCREASES** (1849 → 2940).
- **"Partial run" column removed from the table**: it was wrong for 3 rows out of 4. See §6bis,
  defect **D15**.

### 5.2 False positives — every ≥ MEDIUM replayed by hand, in BOTH campaigns

**BEFORE — 15 claims ≥ MEDIUM: 7 true positives, 8 FALSE POSITIVES, 0 unverified.**
**AFTER — 14 claims ≥ MEDIUM: 10 true positives, 4 FALSE POSITIVES, 0 unverified.**

| verdict | BEFORE | AFTER | who | why (verified by hand against the application) |
|---|---|---|---|---|
| **TP** | 3 | **3** | `access_control.idor` (Juice Shop, VAmPI A+B) | victim's marker read from the attacker's session, absent when anonymous (401); Juice Shop **certified by the app** ("View Basket" `solved`) |
| **TP** | 3 | **3** | `sqli.probe` (DVWA ×2, Juice Shop) | MariaDB error / boolean differential / auth bypass `' OR 1=1--` → `admin@juice-sh.op` (witness without injection: 401) |
| **TP** | 1 | **1** | `path.traversal` (DVWA) | canary read; LFI proven **independently** of the canary (`?page=/etc/passwd` → `root:x:0:0`) |
| **TP** | 0 | **2** | `cmdi.probe` + `rce.probe` (DVWA) | **NEW (D6)** — POST `ip=127.0.0.1;id&Submit=Submit` → `uid=33(www-data)`, replayed outside forge |
| **TP** | 0 | **1** | `jwt.weakness` (VAmPI) | **NEW (D12)** — HS256 token forged outside forge with the secret `random` (`/vampi/config.py:13`) → `PUT /users/v1/attacker1/email` accepted (**204**) |
| **FP** | 5 | **4** | `header_injection.probe` | ~~directory redirect: `Location` built from `Host`~~ **that form is extinguished**; the 4 that remain go through **ANOTHER door** — see §5.2bis |
| **FP** | 3 | **0** | `ssrf.xspa` (VAmPI) | extinguished — but **not the way one would think**: see §5.2ter |

False-positive rate on actionable claims: ~~**8/15 ≈ 53 %**~~ → **4/14 ≈ 29 %**.
Unchanged, on the other hand: **all the false positives come from autonomous mode** (track B). Track A,
seeded by hand, produced **no** false positive on the 4 applications, in either campaign.

### 5.2bis DVWA's 4 `header_injection.probe` HIGH — the fix moved the door, it did not close the room

This was the explicit point of attention of the brief. Verdict: **they have NOT disappeared, and the D4
fix does not cover this form.** The count stayed strictly identical — only the targets
shifted by one character:

| | BEFORE (2026-08-10) | AFTER (2026-08-11) |
|---|---|---|
| targets | `/docs` · `/config` · `/external` · `/external/phpids/0.6` | `/docs/` · `/config/` · `/external/` · `/external/phpids/0.6/` |
| response | **301** with `Location: http://<marqueur>/docs/` | **200**, **no `Location`** |
| reflection path | `Location` header | **body** |
| forge verdict | HIGH `vulnerable` ×4 | HIGH `vulnerable` ×4 |

On the targets WITHOUT a trailing slash, the D4 fix works and says so — evidence returned:

> « canonicalisation d'URL ÉCARTÉE (en-tête Host) : la cible a répondu une REDIRECTION vers le MÊME
> chemin sur l'hôte injecté […] aucun reflet RÉSIDUEL hors l'écho du Location. »
> (URL canonicalisation RULED OUT (Host header): the target answered with a REDIRECT to the SAME path on
> the injected host […] no RESIDUAL reflection apart from the Location echo.)

But discovery ALSO proposes the variants WITH a trailing slash, where Apache no longer redirects: it serves
the directory index, and its footer copies the `Host` header. Reproduced by hand on all
four:

```
curl -H 'Host: evil.forge-hh.test' http://127.0.0.1:8081/docs/
  -> HTTP/1.1 200 OK      (aucun Location)
  -> <address>Apache/2.4.25 (Debian) Server at evil.forge-hh.test Port 80</address>
     occurrences de l'hôte injecté dans le corps : 1
     href portant l'hôte injecté                 : 0
```

This is `ServerSignature On`, **Debian's default setting**, and it appears on **every** page
auto-generated by Apache — directory index **and 404 page**. The reflection is **inert text**:
no link carries it, no cache serves it, no password reset uses it.
DVWA's ground truth (`/var/www/html/vulnerabilities/`) declares no "host header" class.
**Four false HIGH, again.**

Exact cause, read in the code: `_host_reflection` (`forge/modules/httpflow.py:520`) only discriminates
the `Location` path, by the destination path. As soon as the marker is in the BODY,
`_reflected_in` returns `"corps"` (body) without further examination, and the only remaining guard is
`control_reflects_host` — the guard that D4 itself described as structurally incapable:
the control request goes out **without** the injected header, so the marker can by construction
never appear in it, and it **always** returns `False`. The fix closed the `Location` door and
left the body door **exactly in the state the bench denounced**. Recorded as **D14** (§6bis).

### 5.2ter VAmPI's 3 `ssrf.xspa` — extinguished, but the campaign does not prove it

On track B, `ssrf.xspa` now returns `skipped — Requiert params.param` (requires params.param) on VAmPI's 9
targets: the parameterised URL `/console?__debugger__=yes&cmd=resource&f=console.png` **is no longer
discovered at all**. The 3 false positives have therefore disappeared **from the campaign** without the oracle
having to judge — it is the discovery fix (D8) that made them disappear, not the judgement
fix (D5).

The D5 fix was therefore verified **separately**, by replaying the oracle on the EXACT target of the 3 false
positives of 2026-08-10:

```
forge run --actions  {kind: ssrf.xspa,
                      target: http://127.0.0.1:5001/console?__debugger__=yes&cmd=resource&f=console.png,
                      params: {param: __debugger__}}

AVANT  -> MEDIUM · vulnerable · « XSPA CONFIRMÉ — joignabilité de ports internes »
          ports JOIGNABLES = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]   (9 sur 10 FERMÉS)
APRÈS  -> INFO   · skipped    · « XSPA non testé — la réponse ne VARIE PAS selon l'URL injectée »
          « les 12 réponses (2 baselines fermées + 10 port(s)) sont IDENTIQUES octet pour octet
            (HTTP 200, 1563 o) »
```

The 1,563 bytes are exactly those the bench had measured by hand in §D5. The fix holds
on its own measurement; **it is the disappearance in the campaign that proves nothing**, and distinguishing the two was
necessary.

### 5.3 False negatives — explained, one by one (BEFORE → AFTER)

| missed class | app | cause established BEFORE | AFTER (2026-08-11) |
|---|---|---|---|
| command injection / RCE | DVWA | **D6** — the POST probe carries ONLY the injected parameter; DVWA requires the `Submit` co-parameter | ✅ **FOUND** — `cmdi.probe` HIGH + `rce.probe` CRITICAL, verified by hand (`uid=33(www-data)`) |
| reflected XSS | DVWA | design: `xss.reflected` requires a JS-executable context; DVWA reflects into HTML content — the oracle SEES `réfléchi=True, non_échappé=True` and refuses to promote | unchanged — still `tested`, design abstention |
| stored XSS | DVWA, DVGA | **D7** — verdict fabricated from a browser service error | ✅ **honest abstention** — `skipped · « rendu navigateur indisponible (dégradation gracieuse) »` (browser rendering unavailable, graceful degradation). Still a false negative, but it no longer disguises itself as a verdict |
| DOM XSS | DVWA, Juice Shop | not measurable here (browser outside the network namespace) — `skipped`, correctly | unchanged |
| CSRF | DVWA | the anti-CSRF detector looks for `"csrf"` in **the whole body**; DVWA's "CSRF" page contains the word in its links and titles | unchanged — still `tested`, not promoted |
| SQLi | VAmPI | injection point = **path segment** (`/users/v1/{username}`); the oracles only write into a query parameter or a form body | **unchanged** — the D6 fix preserves the other parameters, it does not learn to write into a path segment |
| BFLA (someone else's password) | VAmPI | **correct** abstention (`PUT` mutates a third party's object, refused as long as `allow_destructive` is false) | ✅ abstention now **named**: « Privesc write PUT non tiré — capacité destructive non autorisée » (write PUT privesc not fired — destructive capability not authorised) (instead of « config manquante », missing config) |
| weak-key JWT | VAmPI | **D12** — the default HMAC list (16 entries) does not contain `random` | ✅ **FOUND** — HIGH `vulnerable`, secret cracked offline (candidate #16 of the extended list) |
| GraphQL introspection | DVGA | detected but rendered **INFO** by design; the path requires `b_marker` + `query` | unchanged |
| GraphQL cmdi / SQLi / traversal / XSS / SSRF | DVGA | injection points = **arguments in a GraphQL JSON body**; no oracle knows how to write into it | **unchanged — 0 out of 7** |
| all (track B, DVWA/DVGA) | — | discovery produced **no URL carrying a query parameter** | **unchanged**: 22 targets on DVWA, 25 on DVGA, **none with a query parameter** |
| all (track B, Juice Shop) | — | **D13** — the application died during the campaign | **the application died AGAIN** — but this time the cause is measured (§6bis, D13-bis) and the oracles no longer fire at the corpse |

### 5.4 The control did reproduce the reference measurement — twice

Juice Shop, track A, in BOTH campaigns: `access_control.idor` → **IDOR CONFIRMÉ** (IDOR confirmed),
`sqli.probe` → **SQLi CONFIRMÉ** (SQLi confirmed), 6 findings, 2 claims ≥ MEDIUM, **no deviation**. The app
attests it itself (`GET /api/Challenges`: `basketAccessChallenge` and `loginAdminChallenge` moved
to `solved`). The bench therefore introduces no bias, and the replay has not drifted: the deviations observed
on DVWA/VAmPI/DVGA are indeed the engine's.

*Recorded nuance*: on 2026-08-11 it was the **manual replay** (`' OR 1=1--` → `admin@juice-sh.op`) that
flipped `loginAdminChallenge`, whereas on 2026-08-10 forge's probe had done it itself.
Forge proved the SQLi by AUTHORISATION differential (`' OR '1'='1'-- -`, 401 → 200) without targeting the
administrator account. The claim remains a true positive — the vuln is where it was announced — but
the certification by the app comes from elsewhere.

### 5.5 Honest verdict on generalisation — the figure moved, the boundary did not

**Forge generalises a little more widely, still narrowly, and still only when it is
seeded.**

- **What holds across several stacks**: ~~`sqli.probe`, `access_control.idor` and `path.traversal` —
  **3 oracle classes out of 25 opposable**~~ → now **6 oracle classes out of the bench's 13 opposable**
  ones: `sqli.probe`, `access_control.idor`, `path.traversal`, **`cmdi.probe`**, **`rce.probe`**,
  **`jwt.weakness`**. In (app, class) pairs: **6 → 9 out of 23**.
- **The boundary, for its part, has moved by one notch only.** The old finding said "nothing outside a
  query parameter on a known URL". That is no longer accurate: the D6 fix brings in the
  **multi-field POST form** (DVWA `exec`, which requires the `Submit` co-parameter) — and that is the
  RCE, the heaviest finding of the bench. But the two other forms have **not** moved:
  **path segment** (VAmPI SQLi) and **GraphQL JSON body** (DVGA) remain at **0 detections**.
- **GraphQL: the figure has NOT moved — 0 out of 7**, on both tracks, in both campaigns.
  An entire stack remains out of reach, and its noise volume has even **increased** (1849 → 2940).
- **Autonomous mode still finds almost nothing, and is wrong even more often than it
  finds.** ~~5703 findings, 1 true positive, 8 false positives~~ → **4862 findings over the 4 campaigns,
  still 1 SINGLE true positive** (VAmPI's BOLA, and only because the operator had declared
  the IDOR target in the scope), against **4 false positives**. The false/true ratio improves from 8:1 to
  **4:1** — it remains **unfavourable**.
- **Answering the question asked**: *was forge tuned to Juice Shop?* No, and it is even
  clearer than before — the classes that work on Juice Shop work elsewhere, and DVWA now finds
  **more** than the reference target. *But* the sample of 1 still hid the same
  thing: outside the request forms the oracles know how to write, coverage drops to zero, and
  autonomous mode still produces more false HIGH than true ones.

**Publication recommendation — NOT REVERSED.** Publishing `--auto-pentest` mode as a scanner
would remain **indefensible**:

1. **More false than true**: 4 false HIGH against 1 true positive. An operator who followed this
   report would send 4 "host header poisoning" reports on a default Apache signature.
2. **The target still dies**, and this time the cause is established (§6bis, D13-bis): idle 34 minutes
   → stable memory; campaign launched → 4.9 GiB and `Exited(139)` in **90 seconds**.
3. **13 nmap out of 13 report "I checked" after scanning 0 hosts** (§6bis, D16). The count
   dropped (72 → 13), the blindness stayed at **100 %**.
4. Discovery **still produces no URL carrying a query parameter**: the oracles that
   pay have nothing to bite on in autonomous mode.

On the other hand, the **seeded oracles** (track A) are defensible, and **more so** than before:
**0 false positives** on the 4 applications in both campaigns, **9 true positives instead of 6**,
including a **proven CRITICAL RCE**, and named abstentions instead of fabricated verdicts.
The publication path remains "forge = an operator-seeded hypothesis verifier", not
"forge = an autonomous scanner" — now until **D14, D16 and the cause of D13** are
addressed.

## 6. The 13 defects of 2026-08-10 — **original text kept**, status measured in a full campaign

> The descriptions below are those of the day the bench found them, **unchanged**. All 13 have
> been closed since — each by a commit that carries its measurement —, but they had only been measured
> **in isolation**. The table that follows says what the FULL campaign of 2026-08-11 observed —
> and for three of them, the observation is not the one expected.

| # | what the fix promised | **observed in a full campaign** |
|---|---|---|
| D1 | the 2-account IDOR is no longer extinguished by `scope.session` | ✅ VAmPI evidence: `anon=401 · anon_refusé=True · « sonde anonyme tirée SANS matériel de session gouverné »` |
| D2 | the evidence of the marker path no longer lies | ✅ same — the old `anon=200 / anon_refusé=False` has disappeared |
| D3 | no more HIGH on a public resource | ✅ publicity veto visible in the evidence (`marqueur_lisible_anonymement=False`); no HIGH on a public resource in the 4 campaigns |
| D4 | the 5 false `header_injection` are extinguished | ⚠️ **PARTIAL — 1 out of 5 extinguished for good.** VAmPI `/ui`: yes, with the named abstention. DVWA: the 4 HIGH **come back** through another door → **D14** |
| D5 | `ssrf.xspa` no longer invents reachable ports | ✅ verified **separately** on the exact target (§5.2ter) — in the campaign, the target had already disappeared from discovery |
| D6 | DVWA's RCE becomes reachable | ✅ **HIGH + CRITICAL**, `uid=33(www-data)` verified by hand. The biggest finding of the replay |
| D7 | `xss.stored` no longer fabricates a negative verdict | ✅ `skipped — rendu navigateur indisponible (dégradation gracieuse)` on DVWA **and** DVGA |
| D8 | no more 404s ingested as endpoints | ✅ 22 targets on DVWA (all real), 9 on VAmPI; **no phantom URL** of the `/modern%20mom` kind |
| D9 | no more nmap on an endpoint | ⚠️ **PARTIAL** — 72 → 13, but **13 out of 13 scan 0 hosts and return `tested`** → **D16** |
| D10 | `forge run --actions` injects the auth context | ✅ (the bench still passes the values in the action; the injection is now idempotent) |
| D11 | `rc=1` on a proven vuln | ✅ **5 runs out of 8 return `rc=1`**, exactly those carrying a `vulnerable` (DVWA A/B, VAmPI A/B, Juice Shop A) |
| D12 | `jwt.weakness` cracks VAmPI's secret | ✅ **HIGH `vulnerable`**, confirmed outside forge (token forged with `random` → 204) |
| D13 | no more firing at a corpse | ✅ for the **symptom** (8 shots, **0 qualifying oracle verdicts** post-mortem) · ❌ for the **cause**, which is now established → **D13-bis** |

The original text of the 13 entries follows. Each entry carries its evidence: a command, an output, or
a code excerpt to the exact line. The order is that of severity for an operator **at the time
they were written**.

### D1 — A governed session DISABLES the 2-account IDOR oracle (silent false negative)

`access_control.idor` judges by `vuln = same and anon_denied` (`access_control.py:390`), where
`anon_denied` comes from `ru = self._fetch(url, {})` (`access_control.py:363`). But `Oracle._http`
**merges the governed session** (`scope.session`) on any in-scope URL: the so-called "anonymous" probe
therefore goes out AUTHENTICATED as soon as a `scope.session` is configured — which `scope.example.json`
explicitly recommends for attaching auth material.

Measured on VAmPI's real BOLA (`GET /books/v1/victimbook`, ground truth: the app's README),
same accounts, same target, only `scope.session` differs:

| scope | evidence returned by the oracle | verdict |
|---|---|---|
| **with** `session` | `A=200 B=200 anon=200 même_objet=True anon_refusé=False` | `IDOR non confirmé` — **INFO** |
| **without** `session` | `A=200 B=200 anon=401 même_objet=True anon_refusé=True` | `IDOR CONFIRMÉ` — **HIGH** |

Independent check: `curl http://127.0.0.1:5001/books/v1/victimbook` (no header) → **401**.
And directly on the chokepoint:

```
Oracle._http(url, headers={})                       -> 401     (vraiment anonyme)
with session.using(store): Oracle._http(url, {})    -> 200 + corps du panier
```

**Consequence**: the #1 bug bounty class is extinguished by a legitimate configuration — and without
any signal, since the finding returned is a normal-looking "not confirmed".

### D2 — The same probe falsifies the evidence of the marker path

On the `_fire_auth_targets` path, `anon_denied` does not promote, but it is **printed**:
on Juice Shop, `GET /rest/basket/1` answers **401** to a real anonymous user, and the finding's evidence says
`anon=200 ; anon_refusé=False`. A reviewer reads "public resource" there and discards a true positive.

### D3 — `access_control.idor` promotes a HIGH on a PUBLIC resource

`proven = marker_hit` alone (`access_control.py:227`). A marker present in a public
resource proves no ownership, and the anonymous probe — broken by D1 — cannot veto.

Counter-test run: VAmPI's `GET /users/v1` is **public by design** (anon → 200, lists
all users), declared `idor_target {owner: victim, marker: "victim1"}`. Verdict returned:

> **HIGH · vulnerable · « IDOR CONFIRMÉ — l'attaquant lit la ressource de la victime (accès
> cross-compte) »** (IDOR CONFIRMED — the attacker reads the victim's resource, cross-account access), evidence `anon=200 … anon_refusé=False`.

Yet a test bears that name — `tests/test_auth_context.py::test_no_false_positive_on_public_200`.
It passes, and it cannot fail: its `idor_target` has **no `marker`**
(`{"url": …, "owner": "victim"}`), and `marker_hit = bool(marker) and …`. The test therefore covers the
NON-promoting branch and leaves intact the one that promotes — the one `scope.example.json` describes
as "the PREFERRED path".

### D4 — `header_injection.probe`: one HIGH per directory, on default server behaviour

A `Host:` reflected in `Location:` promotes `HIGH / vulnerable / CWE-644 (host header poisoning)`
(`httpflow.py:515`). But **every** directory redirect builds its `Location` from the
request's `Host`. Reproduced on TWO stacks:

```
curl -H 'Host: evil.example' http://127.0.0.1:8081/docs   -> 301  Location: http://evil.example/docs/   (Apache 2.4)
curl -H 'Host: evil.example' http://127.0.0.1:5001/ui     -> 308  Location: http://evil.example/ui/     (Werkzeug 2.2)
```

Neither DVWA nor VAmPI declares this class in their ground truth. Harvest: **4 HIGH on DVWA**
(one per discovered directory) + **1 HIGH on VAmPI**. The internal control cannot catch it: it
compares with the **real** `Host`, where the marker cannot by construction appear.

### D5 — `ssrf.xspa` declares REACHABLE ports that listen nowhere

On VAmPI (Flask `debug=True`, hence the Werkzeug console exposed), the autonomous campaign promoted **3
MEDIUM `vulnerable` findings**:

> « XSPA CONFIRMÉ — joignabilité de ports internes via SSRF » (XSPA CONFIRMED — internal port reachability via SSRF) ·
> `ports JOIGNABLES (différentiel)=[22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]`

Check by direct TCP connection on the same host: **9 of these 10 ports are CLOSED**
(only `8080` listens). And the target — `/console?__debugger__=yes&cmd=resource&f=console.png`, the
debugger's static resource server — is not SSRF-able at all:

```
__debugger__=yes                        -> 200,  507 o
__debugger__=http://127.0.0.1:1/        -> 200, 1563 o     <- « baseline port fermé »
__debugger__=http://127.0.0.1:3306/     -> 200, 1563 o     <- corps IDENTIQUE
```

⚠️ **THIS CAUSE WAS WRONG, corrected on 2026-08-11** — it is left here because a bench report
that rewrites its errors is worthless as a reference. Initial version: "the
differential relies on timing gaps of the order of 20 ms (`0.036s` vs `0.056s`)". **The
timing is measured and printed but enters NO verdict** — only `sig != closed_sig` promotes.

**The real cause**: the reflection neutralisation was applied **ASYMMETRICALLY**. The
baseline was port **1**, and the body was scrubbed of the port number of the current request:

    re.sub(r"(?<!\d)1(?!\d)",    "<PORT>", body)   # baseline: eats ALL isolated "1"s
    re.sub(r"(?<!\d)3306(?!\d)", "<PORT>", body)   # port: no-op

On any HTML body (`HTTP/1.1`, `version 1.0.1`), the baseline is mutilated and the port
bodies are not. Reproduced: IDENTICAL bodies in input -> different signatures -> all 10
ports declared "diff", 10 out of 10. **The mechanism meant to suppress the false signal was manufacturing it**,
unconditionally — and the module emitted `status=vulnerable` as MEDIUM on that basis.

The lesson goes beyond D5: the "obvious" cause (the timing, visible in the evidence) was not
the cause. It is the ninth diagnosis of this series to fall before measurement.

### D6 — The injection oracles lose the request's other parameters

Four independent implementations (`injection.py::_send`, `clientflow.py::_send_h`, `rce.py`,
`ssrf.py`) build the request like this:

```python
sep = "&" if "?" in action.target else "?"
url = f"{action.target}{sep}{urllib.parse.urlencode({param: payload})}"   # GET: APPENDS
...
data=urllib.parse.urlencode({param: payload})                             # POST: REPLACES the whole body
```

- **POST** — the body contains ONLY the injected parameter. DVWA's command injection requires the
  `Submit` co-parameter: `ip=127.0.0.1;echo FORGEMARK123` alone → **0 occurrences**; the same payload
  with `&Submit=Submit` → **1 occurrence** (command executed). Hence `cmdi.probe` and `rce.probe` as
  "not confirmed" on a very much alive RCE (`uid=33(www-data)` verified by hand).
- **GET** — the parameter is APPENDED, not substituted: `?id=1&Submit=Submit&id=<payload>`. In PHP the
  last one wins (measured: `ID: 2`) so it works; in **Flask/Werkzeug the first one wins**
  (`MultiDict(parse_qsl("id=1&Submit=Submit&id=INJECTION")).get("id")` → **`1`**). On any
  first-wins parser, the payload never reaches the sink and the oracle still returns "not confirmed".

This defect is **invisible on a single target**: it depends on the stack's parser.

### D7 — `xss.stored` returns a NEGATIVE verdict from a browser error page

Guard at `clientflow.py:620`: `if rst is None or not dom:` — navigation **success** is never
checked. A 500 from the browser service returns `(500, "Internal Server Error")`: `dom` is non-empty,
the guard passes, and the oracle concludes. Deterministic reproduction (stubbed seams):

```
xss.stored     -> tested  · « XSS stored non confirmé — pas de reflet exécutable non échappé
                            dans le DOM rendu » ; evidence : « réfléchi=False … module NAVIGATEUR
                            utilisé pour le rendu DOM »
xss.execution  -> skipped · « sonde navigateur non aboutie (dégradation gracieuse) »   <- correct
```

The sibling oracle makes the right choice (`if not _ok(gst): return False`). It is a fabricated verdict.

### D8 — Discovery ingests 404s as endpoints, without a confirmation probe

The `recon.feroxbuster` spec (`toolcatalog.py:366`) invokes `--silent` and parses `https?://\S+`.
`--silent` **suppresses the status column**: forge cannot see it. Measured:

```
docker run --rm --network host epi052/feroxbuster -u http://127.0.0.1:8081 --no-recursion
  404  ... 285c http://127.0.0.1:8081/modern%20mom
  404  ... 287c http://127.0.0.1:8081/Reports%20List
```

(feroxbuster's auto-filter misses these 404s: their size varies with the path length.)
These URLs become **graph nodes** and receive the full oracle sweep. Yet `_discovery.py`
applies exactly this discipline to PORTS ("a real GET obtains an HTTP STATUS") —
it is not applied to URLs. This is the origin of most of the volume: 1806 findings on DVWA.

### D9 — `--auto-pentest` bypasses the host/endpoint discrimination

`brain.py:175` says explicitly that an endpoint must not receive "recon/nmap/origin on a
URL", and `_base_actions` applies it. But `AutoPentestBrain.propose` sweeps **every technique over
every touched target**, endpoints included, without this guard. Result measured in the ledger:

```
poc      : docker run --rm --network host instrumentisto/nmap -sV -Pn --top-ports 1000 \
           http://127.0.0.1:8081/Planned%20Giving
evidence : Nmap done: 0 IP addresses (0 hosts up) scanned in 0.35 seconds
status   : tested        title : « Services exposés (nmap -sV) »
```

**22 `recon.nmap` findings out of 22** are in this situation. nmap exits with `rc=0` ("Unable to split netmask
from target expression"), so the `rc != 0` bound of `blindness.tool_did_not_run` cannot
see it: a tool that scanned nothing is rendered as "I checked".

### D10 — `forge run --actions` does not inject the per-engagement auth context

The injection of `accounts`/`idor_targets` from `scope.auth` lives in `Engine._prepare`
(`engine.py:1184-1209`), called ONLY by `campaign()`. `Engine.run()` (`engine.py:839`) does not
call it. Consequence: with a complete `scope.auth`, `forge run --actions` returns "IDOR not
tested — missing config". The bench works around it by passing the values in the action; the CLI, for its part,
documents this nowhere.

### D11 — The documented exit code "1 = vuln found" is never produced

`docs/CLI.md:16` announces "`0` OK, `1` failure/vuln found". `cmd_run` (`cli/engine.py:277`) and
`cmd_campaign` (`cli/engine.py:466`) do `return 0` unconditionally. Measured: all the bench runs
that produced `HIGH/vulnerable` findings exit with **`rc=0`**. A CI that gates on the
exit code would never see a vulnerability.

### D12 — `jwt.weakness`'s default HMAC list is very short

16 secrets (`tokenapi.py:108`). VAmPI's secret is `'random'` (`config.py`) and is not in it →
false negative. With `hmac_wordlist=["secret","password","random","changeme"]`, the same oracle returns
**HIGH · vulnerable · « secret HMAC faible craqué hors-ligne »** (weak HMAC secret cracked offline). The mechanism is sound, the list is
the limiting factor.

### D13 — Autonomous mode KILLS the target, and the qualifying oracles fire at a corpse

Two `--auto-pentest` campaigns on OWASP Juice Shop, two **application crashes**:

```
docker ps -a  ->  forge-bench-juice     Exited (139)
                  forge-bench-juiceshop Exited (139)
docker logs   ->  FATAL ERROR: Ineffective mark-compacts near heap limit
                  Allocation failed - JavaScript heap out of memory
```

Measurable consequence: `access_control.idor` — the #1 class — returned, on BOTH runs,
« IDOR non testé — cible injoignable (aucune réponse) … attaquant=None, anonyme=None » (IDOR not tested — target unreachable, no response). The oracle
abstains correctly (that is the right discipline), but the net result is **zero measurement**: the
content-discovery storm runs BEFORE the qualifying oracles and takes the target down. The
planner's anti-starvation floor protects their *selection*, not their *execution order*.

It is also a policy problem: the workspace bans DoS techniques, and autonomous mode
produces one by accident.

## 6bis. Defects brought to light by the REPLAY (2026-08-11) — RECORDED, NOT FIXED

No file under `forge/**` was modified by this replay. As in the first round, each entry carries
its evidence: a command, an output, or a code excerpt to the exact line.

### D13-bis — The cause of Juice Shop's death is established, and it is NOT the one that was retained

The D13 fix (liveness gate) was delivered with an explicit conclusion: *"the campaign was
not the CAUSE of the death"*, backed by a measurement from an agent (container alone, zero packets, 121 MiB →
4.79 GiB, death at 222 s). That measurement came from a single source, **not reproduced** by an
independent cross-check, and the question remained open. **The replay settles it.**

The bench starts Juice Shop **at the same time as the three other applications** then tests it
**last**. It therefore stayed alive, untargeted, for 34 minutes — a free negative
control. `docker stats --no-stream` sampling, one measurement per minute:

```
12:38:47  102.6 MiB      <- conteneur levé à 12:34:39, AUCUNE campagne ne le vise
12:45:55   57.1 MiB
12:55:05   48.1 MiB
13:05:16   63.8 MiB
13:11:22   24.4 MiB
13:12:23   21.2 MiB      <- 34 minutes plus tard : mémoire STABLE, tendance à la BAISSE

13:12:42                 <- la phase juiceshop commence (piste A, puis `--auto-pentest`)
13:13:24    3.782 GiB    <- ~40 s après
13:14:25    4.905 GiB
13:14:47                 <- Exited (139) · FATAL ERROR: Ineffective mark-compacts near heap limit
```

`docker inspect`: `StartedAt 10:34:39Z → FinishedAt 11:14:47Z`, `ExitCode 139`, `OOMKilled false`
(it is the V8 heap that saturates, not the cgroup). **34 minutes at rest: nothing. 90 seconds under
campaign: 0.02 → 4.9 GiB, then death.** The premise "it self-destructs on its own" is therefore
**contradicted by the measurement**, and the bench's original finding — *autonomous mode kills the target* — is
**restored**. The product decision "no throttle is justified" rests on a false premise.

What does hold, on the other hand, is the fix itself: `Tirées=8` (fired) on the corpse (against 1107
before), each abstention named (« la cible a répondu pendant ce run puis a CESSÉ de répondre », the target answered during this run then STOPPED answering), and
**no qualifying oracle emitted a post-mortem verdict** — the 22 findings after the death
are all `feroxbuster` records from the tool that was in flight at the time of the crash.

### D14 — `header_injection.probe`: the D4 guard covers ONLY the `Location` path; the BODY path is intact

Described in detail in §5.2bis. In short: **4 false HIGH on DVWA, exactly as many as before**, on the
same directories, to within one character.

```
curl -H 'Host: evil.forge-hh.test' http://127.0.0.1:8081/docs/      -> 200, AUCUN Location
  corps : <address>Apache/2.4.25 (Debian) Server at evil.forge-hh.test Port 80</address>
  occurrences de l'hôte injecté dans le corps : 1        href porteur : 0
  (identique sur /config/, /external/, /external/phpids/0.6/ — et sur toute page 404)
```

`ServerSignature On` is Apache's Debian default: **every** auto-generated page copies the
`Host` header. The reflection is inert text inside an `<address>` — no link, no cache, no
reset link. None of the four applications declares this class in its ground truth.

Mechanics, to the line: `_host_reflection` (`httpflow.py:520`) only calls `_is_canonical_redirect`
to discriminate the `Location`. As soon as the marker is in the body, `_reflected_in`
(`httpflow.py:286`) returns `"corps"` (body) without further examination, and the only remaining guard is
`control_reflects_host` — **the guard that D4 itself showed to be incapable**: the control request
goes out without the injected header, so the marker can by construction never appear in it, and it
always returns `False`. The D4 fix therefore addressed **the observed symptom** (the directory
redirect), not **the mechanism** (a control guard that can guard nothing).

### D15 — The BENCH's `partial` flag is true for every campaign, interrupted or not

A defect **of the bench**, not of the engine, and it affects a published column: `harness.py:108` decides
`partial = hard_kill or ("PARTIEL" in text.upper()) or ("interrompu" in text.lower())`, where `text` is
forge's standard output **plus** the report. But `forge/cli/engine.py:177` emits, **at the launch**
of any campaign given a `--run-timeout`:

> `# Budget de temps : 900s — à l'échéance le run S'ARRÊTE proprement (frontière d'action) et rend un
> rapport annoncé PARTIEL.`
> (Time budget: 900s — at the deadline the run STOPS cleanly, at an action boundary, and returns a report announced as PARTIAL.)

Counter-test run — a campaign of **a single action**, finished in a few seconds,
`Déférées(budget)=0` (deferred), `rc=0`, report **without** an interruption banner:

```
banniere de LANCEMENT contient « PARTIEL »  -> OUI (ligne 1)
rapport annonce « RAPPORT PARTIEL »          -> NON (0 occurrence)
ce que le harnais en déduit                  -> partial = True
```

Consequence: the four `OUI (budget)` (YES) rows of the "partial run" column of the §5.1 table **of
2026-08-10 carried no information**. The true count, read in the engine's report (which, for its part,
tells the truth): **only one** campaign out of four was actually interrupted by the budget — VAmPI B
(909.3 s for 900 s requested, « RAPPORT PARTIEL » banner present). DVWA B (617 s) and DVGA B
(718 s) ran to completion, with actions **not started** by the budget gate and named as
such (`web.testssl`, `web.zap_baseline`, `xss.dalfox`: « borne d'exécution déclarée 600s > budget
de temps restant 299s », declared execution bound 600s > remaining time budget 299s). Juice Shop B stopped on the target's death, not on the budget.
The column was removed from the table and replaced by this paragraph.

### D16 — 13 nmap out of 13 return "I checked" after scanning **0 hosts**

The D9 fix did bring down the **number** of nmap shots (72 → 13) by applying to the autonomous
sweep the rule that `brain.py:175` already stated. But the defect D9 named — *"a tool that
scanned nothing is rendered as 'I checked'"* — is **intact**, and its frequency went from 22/72
to **13/13**.

```
poc      : docker run --rm --network host instrumentisto/nmap -sV -Pn --top-ports 1000 127.0.0.1:8081
evidence : Nmap done: 0 IP addresses (0 hosts up) scanned in 1.10 seconds
statut   : tested      titre : « Services exposés (nmap -sV) »
```

The 13 shots (DVWA ×5, DVGA ×4, VAmPI ×3, Juice Shop ×1) all scan **0 hosts** and all return
`tested`. Two distinct causes, neither covered:

- **URL form** — `http://127.0.0.1:8081`, `http://127.0.0.1:8081/`, `https://127.0.0.1:8081` are
  still proposed to nmap. The D9 guard discriminates "endpoint" and "host"; a ROOT URL
  passes for a host;
- **`host:port` form** — `127.0.0.1:8081` is treated by nmap as a **host name** to resolve, which
  does not exist → `0 IP addresses`. Even the "correct" form is therefore unscannable as is.

nmap exits with `rc=0` in both cases, so the `rc != 0` bound of `blindness.tool_did_not_run` still cannot
see it. An operator reads "Exposed services — checked" where nothing was looked at.

### D17 — The bench emitted traffic towards a THIRD PARTY, and its exclusion list could not see it

A defect **of the bench**, and it affects its strongest safety guarantee (§4: "no traffic towards a
third party"). `provision.THIRD_PARTY_MODULES` excludes the modules whose **declared intent** is
to query a third party (crt.sh, Wayback, public DNS resolvers, template repositories, callback
collectors). `recon.httpx` is not one of them — it only talks to the target… except on first
start:

```
finding « Fingerprint HTTP (httpx) », evidence :
  2026/08/11 10:43:40 INFO Model not found, downloading
      url=https://huggingface.co/datasets/happyhackingspace/dit/resolve/main/model.json
      dest=/root/.dit/model.json
  2026/08/11 10:43:42 INFO Model downloaded size=92.6MB
```

Observed **4 times** (DVWA ×2, DVGA, Juice Shop; the container runs with `--rm`, so nothing is
cached from one shot to the next): that is ≈ **370 MiB downloaded from huggingface.co** during a run whose
announced property is strict loopback. No request went out **towards the targets**, and
`verify_loopback_only()` did its job — but it checks **listening** sockets, not
**egress**. Sweep of the 4,906 findings: this is the **only** proven egress; all the other
occurrences of third-party hosts are page content quoted as evidence (`github.com` in DVGA's
HTML), tool banners (`nmap.org`), or synthetic markers never resolved
(`attacker.example`, `forge-redirect.example`).

**The lesson is the same as D5's**: a guard formulated on a module's INTENT cannot
catch a behaviour of its underlying tool. Egress would have to be measured (tool container
network cut off, or observation) rather than declared.

### D18 — The bench's seeding mutates the target, and the bench does not say so

Minor, but it skews any manual follow-up. The track-A `csrf.state_change` action targets
`/vulnerabilities/csrf/?password_new=a&password_conf=a&Change=Change`: it **actually changes the
password** of DVWA's `admin` account to `a`. Observed afterwards — manual reconnection with
`admin/password` fails, `admin/a` succeeds. A new bench run does not suffer from it
(`provision.prime_dvwa` resets the database via `setup.php` before connecting), but any
manual check made AFTER a run must know it. DVWA's `AuthMaterial.declared` does not
mention this side effect.

## 7. What held up well (not to be lost)

- **Anti-masking is real.** ~~The DVWA run was cut off by the budget and the report announces it at the
  top: « RAPPORT PARTIEL — RUN INTERROMPU », « 1751 action(s) exécutée(s) sur 2700 planifiée(s),
  949 jamais tentée(s) »~~ — **example corrected on 2026-08-11, it was not the right one**: the flag that
  had designated it came from the bench, not from the engine (defect **D15**). The mechanism itself holds and can be
  verified on the campaign that was REALLY interrupted, **VAmPI B** (909.3 s for 900 s requested):
  its report does carry the « RAPPORT PARTIEL — RUN INTERROMPU » (PARTIAL REPORT — RUN INTERRUPTED) banner at the top, and forge repeats it
  even in the output summary — « 1 finding(s) PROUVÉ(S) vulnerable (run INTERROMPU : ce total ne
  couvre que la partie exécutée) » (1 PROVEN vulnerable finding; run INTERRUPTED: this total only covers the executed part). On the NON-interrupted campaigns, the same discipline applies
  to the actions not started by the budget gate, named one by one: « borne d'exécution déclarée
  600s > budget de temps restant 299s — la démarrer dépasserait l'échéance ; AUCUN verdict n'est émis
  pour cette action (non testée, pas “rien trouvé”) » (starting it would exceed the deadline; NO verdict is emitted for this action — not tested, not "nothing found").
- **Evidence discipline holds on negatives**, and it held twice: ~~1770 of the 1806
  DVWA findings~~ → **1476 of the 1558** are explicit `INFO` `tested`/`skipped` (the rest: 78 LOW
  and the 4 false HIGH); no blind verdict, each abstention is named. Better than before: the abstentions that were previously
  fabricated verdicts (`xss.stored`) or silent (`privesc`) are now explained in plain words.
- **The liveness gate holds on its own measurement.** Juice Shop died during the campaign, as
  the first time — but **`Tirées=8`** on the corpse, each `SKIP` named (« la cible a répondu
  pendant ce run puis a CESSÉ de répondre »), and **no qualifying oracle emitted a post-mortem
  verdict** (against 221 "I checked, nothing found" before).
- **A third-party tool claim stays contained.** `dalfox` reported a reflected XSS on
  `/docs?any=…`; manual check: the payload comes back **URL-encoded** in the `href`, hence
  inert. Forge classified it `reported_by_tool` / LOW, under « Signal à qualifier (exploitabilité NON
  démontrée) » (signal to qualify, exploitability NOT demonstrated) — never promoted. This is the right behaviour, and it has not regressed: the 70
  `reported_by_tool` of the replay are all LOW, none promoted.
- **The scope-guard does what it says.** `scope-check` in scope → `rc=0`, out of scope
  (`http://example.com`) → `rc=1`, on the **four** engagements of **both** campaigns; no
  request left local loopback **towards a target**. Named reservation: a tool, for its part, did
  go out — see **D17**.
- **The exit-code contract is now honoured** (D11): 5 of the 8 runs return `rc=1`, and they
  are exactly the 5 that carry a `vulnerable` finding.

## 8. Reproduce

```bash
python3 -m bench.detection.run_bench --workdir /tmp/bench --track both --budget 900
python3 -m bench.detection.report   --workdir /tmp/bench --verdicts bench/detection/verdicts.json
python3 -c "from bench.detection import provision; provision.teardown()"
```

`run_bench` writes `manifest.json` (seeding, redacted scope, durations, `partial` flag per track —
**caution: this flag is wrong, cf. D15; read the banner of the engine's report**), a JSONL
`--memory` store per track and per application (the raw findings), the engine's markdown report and
its signed ledger.

Raw outputs kept, one per campaign — **never overwritten**:
[`RESULTS_2026-08-10.md`](../bench/detection/RESULTS_2026-08-10.md) ·
[`RESULTS_2026-08-11.md`](../bench/detection/RESULTS_2026-08-11.md).
The manual verdicts of both campaigns coexist in
[`verdicts.json`](../bench/detection/verdicts.json): the targets changed shape between the two
runs (D6 fix), so the keys do not overlap, and `report.py` only matches those of the run
it is given.

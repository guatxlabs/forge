# Module catalog

[English](MODULES.md) | [Français](MODULES.fr.md)

> [Contents](README.md) · See also: [Concepts §4](CONCEPTS.md#4-module--technique-catalogue) ·
> [CLI reference](CLI.md) (`forge modules`, `forge doctor`)

A **module** is a self-contained attack tool orchestrated by the engine behind the ROE gate. It
never fires without a `FIRE` verdict, neutralises itself if its underlying tool is absent
(`available:false`), and produces no side effect in `dry-run`. The contract and the governance
model are described in [Architecture §2.3](ARCHITECTURE.md#23-the-module-registry-forgemodules).

> The source of truth is the **registry**, not this page: `python3 -m forge.cli modules --json`. To
> know availability **on your machine** (tool present or not): `python3 -m forge.cli doctor`.
>
> ⚠️ **This table is an EXTRACT, not the complete catalog.** Measured on this tree
> (`python3 -m forge.cli modules --json | python3 -c "import json,sys;print(len(json.load(sys.stdin)))"`):
> the registry counts **88 modules**, of which **43 are described below** — the other 45 exist and can be
> fired, but do not have their row here yet. No module listed below is absent from the registry
> (verified: 0 phantom entries). When in doubt, trust the command, not the page.

> **Tools shipped in the `full` image (default).** Since the scanner suite was added to the
> `Dockerfile`, the `full` profile ships — in addition to `nmap`/`curl`/`dig`/`httpx`/`nuclei`/`subfinder` —
> the binaries `dnsx`, `naabu`, `katana`, `amass`, `gau`, `feroxbuster`, `ffuf`,
> `gobuster`, `whatweb`, `wafw00f`, `wfuzz`, `nikto`, `testssl.sh`, `dalfox`, `sqlmap`. The modules of the
> **OSS catalog** (`recon.dnsx`, `recon.amass`, `web.nikto`, `web.testssl`, `xss.dalfox`, `sqli.sqlmap`…)
> as well as the native modules with an **optional tool** (`recon.content` → ffuf, `recon.waf` → wafw00f,
> `sqli.probe` → sqlmap) are therefore `available:true` **out of the box** in `full`. In `mini` they degrade to
> `available:false`. Not shipped (by design): `wpscan`/`zap-baseline` (`docker_image` fallback), **Burp** &
> **Metasploit** (external ENV services) — cf.
> [TOOLS.md §5(a)](TOOLS.md#a-it-is-already-in-the-full-image).

## Columns

- **exploit** — the module exploits (⇒ requires `allow_exploit` in the scope, otherwise `VETO`).
- **destructive** — the module is destructive (⇒ requires `allow_destructive`).
- **ATT&CK** — MITRE technique (console badge + purple join key).
- **dependency** — expected tool/service (`stdlib` = always available, pure Python; otherwise
  auto-neutralised if absent).

## 43 of the 88 modules in the registry

| kind | exploit | destructive | ATT&CK | dependency | description |
|---|:---:|:---:|---|---|---|
| `access_control.idor` | yes | — | T1190 | stdlib (params.accounts+urls) | IDOR/BOLA differential oracle with PROOF on 2 accounts: A owns the object, does B obtain the SAME normalised body (anon refused)? Also enumerates IDs. CWE-639. |
| `auth.takeover` | yes | yes | T1212 | stdlib | ATO/auth-bypass oracle with PROOF: after the bypass flow, does whoami return the VICTIM's identity? Otherwise tested. CWE-287/640. |
| `burp.scan` | — | — | T1595.002 | Burp REST API | Drives the Burp Suite REST API: active scan (authenticated through the governed session, scope-locked), probes the state, brings back the issues → Finding(s). |
| `business_logic.invariants` | — | — | T1190 | stdlib | DERIVES the arithmetic invariants of a business object (negatives, bounds between fields, sums, off-grid values) then tries to violate them with values the server MUST reject. Complements `business_logic.scan`, whose three e-commerce checks, written in free text, could not test anything by themselves and described only a single business. |
| `cors.credentials` | yes | — | T1539 | stdlib | CORS-credentials oracle with PROOF: ACAO reflects the attacker origin (not `*`) AND ACAC=true on an authenticated endpoint. Otherwise tested. CWE-942. |
| `cspt.redirect` | yes | — | T1190 | stdlib | PROVES a Client-Side Path Traversal by DEPTH DIFFERENTIAL: the same canary is sent with and without `../`, and the paths ACTUALLY emitted by the browser are compared. Proof = the path of the traversal probe carries strictly fewer segments — normalisation did take place and the authenticated request went elsewhere. |
| `csrf.state_change` | — | — | T1204 | stdlib | CSRF oracle with TARGETED PROOF (non-destructive): `vulnerable` ONLY for a CRITICAL action without anti-CSRF AND SameSite confirmed absent. Detection only. CWE-352. |
| `demo.fingerprint` | — | — | T1595 | none | Demonstration module — illustrates the pipeline (plan→ROE→dry/fire→finding→ledger) without any network I/O. |
| `evasion.discover` | — | — | T1594 | browser-automation:8080 | Discovery of endpoints behind a WAF through browser-automation: passes the managed challenge then extracts in-scope DOM/JS/XHR, emitted with the discovery marker. |
| `evasion.idor_intercept` | yes | — | T1190 | browser-automation:8080 | Arms in-flight IDOR interception through browser intercept-modify (identifier substitution) — proof through `/intercept-dump`. CWE-639. |
| `evasion.turnstile` | — | — | T1556 | browser-automation:8080 | Passes the interactive Cloudflare Turnstile through vision-click-os (template detection + X11 OS click) — access enabler. |
| `evasion.xhr` | — | — | T1190 | browser-automation:8080 | Observation of XHR requests through the browser-automation session (capture-start/dump) — WAF/DataDome bypass. |
| `graphql.access` | — | — | T1190 | stdlib | GraphQL oracle with TWO-OPERATOR-ACCOUNTS PROOF: introspection (informational) + object/field BOLA (A reads B's object, both owned by the operator; anon refused). Otherwise tested. CWE-639. |
| `jwt.weakness` | — | — | T1606 | stdlib | JWT oracle with OPERATOR-ACCOUNT PROOF: alg=none, RS256→HS256 confusion, weak HMAC secret (bounded list), kid injection. PROOF = forged token accepted FOR THE OPERATOR ACCOUNT. Otherwise tested. CWE-347. |
| `llm.prompt_injection` | — | — | T1059 | stdlib | Tests the trust boundary between the system instructions of a language-model application and user input. Four families: unsanitised output (an XSS whose payload transits through the model), direct injection, delimiter confusion, instruction leak. The canaries are INERT — this is not a jailbreak tool and it never asks for harmful content. |
| `massassign.params` | — | — | T1078 | stdlib | PROVES that an API mass-deserialises by accepting a privileged field that the form does not expose. Three points: reference state read BEFORE, injection of an inert CANARY, persistence verified on re-read. The injected value has no power — proving that `role` is assignable does not require writing `admin`. |
| `msf.module` | yes | — | T1210 | msfrpcd | Drives msfrpcd (msgpack RPC): launches the MSF module chosen by the operator, PROVES success (session opened / CheckCode confirmed), promotes to `vulnerable` ONLY WITH proof — otherwise reported_by_tool. Scope-guard + exploit floor. |
| `origin.find` | — | — | T1590.005 | subfinder+httpx | Finds the origin IP behind a CDN/WAF (subfinder + passive prefixes → DNS → drop-CF → Host-header check) — WAF bypass if the origin is reachable. Shot **bounded to 600 s** (`origin.MAX_RUNTIME`, announced to the engine through `max_runtime`, trimmed to the remaining budget): what the bound cuts comes out as a counted `skipped`, never as "nothing found". |
| `ormleak.filter` | — | — | T1190 | stdlib | PROVES that a search API allows filtering on a field it does not expose, which makes it a boolean oracle on its content. Three points: the discriminant exists on a known field, a sensitive field is ACCEPTED as a criterion, and it discriminates too. Stops there — proving that one can read does not require reading. |
| `parserdiff.unicode` | — | — | T1027 | stdlib | PROVES a Unicode normalisation gap between the upstream filter (WAF) and the application. Three-point differential: the bare marker passes, its sensitive ASCII variant is refused, its CONFUSABLE variant passes AND comes back normalised to ASCII. It is the conjunction of the three that proves — the gap BETWEEN the two readings is the vulnerability, not either result taken alone. |
| `path.traversal` | — | — | T1190 | stdlib | Path-traversal oracle with BENIGN PROOF: reads a non-sensitive CANARY through traversal (never a system file). PROOF = the benign marker comes back. Otherwise tested. CWE-22. |
| `recon.client_sinks` | — | — | T1595 | stdlib | Reads SAME-ORIGIN JavaScript and extracts source -> sink pairs from it (DOM XSS) and API paths with a constructed segment (Client-Side Path Traversal). No oracle READ the client code: the two best-paying classes are precisely those found by reading, not by spraying guessed parameters. |
| `recon.content` | — | — | T1595.003 | ffuf (local) | ACTIVE discovery of web content/routes through ffuf — scope-locked, rate-limited, read-only. **Surface producer**: in-scope routes carry `DISCOVERY_ENDPOINT_MARKER` and are chained to the oracles (shared selection: queryable ones first, non-target infrastructure set aside, `crawl_max_endpoints` cap). ffuf absent → skipped. |
| `recon.dns` | — | — | T1590.002 | stdlib socket (dnspython/dig opt.) | DNS resolution (A/AAAA/CNAME/MX/TXT/NS) of the in-scope hosts. Backend dnspython > dig > socket; impossible → skipped. |
| `recon.httpx` | — | — | T1595 | httpx (bin/docker) | HTTP fingerprint (httpx): status, title, detected technologies. |
| `recon.js_endpoints` | — | — | T1594 | stdlib | Fetches the in-scope pages and extracts the API routes/URLs referenced in their JavaScript. Endpoints never called. |
| `recon.nmap` | — | — | T1046 | nmap (bin/docker) | Discovery of exposed services (`nmap -sV`) on the top 1000 ports by default. Opt-in param `full_ports` → `-p-` (full scan 1-65535, takes precedence over `ports`/`top_ports`). |
| `recon.secrets` | — | — | T1552.001 | trufflehog/gitleaks | Detects EXPOSED SECRETS in reachable in-scope assets (JS bundles, config) through trufflehog OR gitleaks. Secret redacted. Absent/KO → skipped. |
| `recon.subdomains` | — | — | T1590 | stdlib (crt.sh) | PASSIVE subdomain enumeration (crt.sh CT + optional passive DNS), locked to the in-scope roots. |
| `recon.tech` | — | — | T1592.002 | stdlib (httpx opt.) | Technology fingerprint from the HTTP responses (Server/X-Powered-By/cookies/meta); enriched by httpx if available. Passive, in-scope. |
| `recon.urls` | — | — | T1596 | stdlib (Wayback) | PASSIVE discovery of historical URLs (Wayback CDX / CommonCrawl), filtered to the declared roots. No URL requested. |
| `recon.waf` | — | — | T1590 | stdlib (wafw00f opt.) | Identifies the WAF/CDN in front of an in-scope host (passive heuristic + wafw00f if present). INFORMATIONAL fingerprint. |
| `redirect.open` | — | — | T1204.001 | stdlib | Open-redirect oracle with IMPACTFUL PROOF: `vulnerable` ONLY if attacker-controlled target AND chainable to a sensitive sink (OAuth/token/email). Redirections not followed. Otherwise tested. CWE-601. |
| `sidechannel.shape` | — | — | T1592 | stdlib | SIDE-CHANNEL oracle by response shape (XS-Leak / length-leak): PROOF = the shape (status/ETag/length) of the PRESENT is stable AND differs from the ABSENT, revealing an existence oracle on a third party's state. Read-only, benign. Otherwise tested. CWE-203. |
| `sqli.probe` | — | — | T1190 | stdlib | SQLi oracle with PROOF: reliable BOOLEAN differential and/or error-based DBMS version ONLY (never a dump). Optional sqlmap. Otherwise tested. CWE-89. |
| `ssrf.callback` | yes | — | T1190 | stdlib + callback collector | SSRF oracle with PROOF: injects a unique callback URL and confirms reception on the collector side. No callback → tested (never blind vuln). CWE-918. |
| `ssrf.redirect_loop` | — | — | T1190 | stdlib | Makes a blind SSRF VISIBLE through a redirection loop with incremental codes (302, 303, … 311), which pushes the target's HTTP client outside the codes it knows how to handle: it errors out and discloses the chain, internal response included. Three-point proof — reach, blindness of the direct probe, visibility through the loop — and MASKED evidence. |
| `ssti.errors` | — | — | T1190 | stdlib | BLIND SSTI oracle through the error channel ("Successful Errors"): proof by conjunction — an ARITHMETIC error appears on N*M/0 (test) but not on the inert marker (control) nor the witness. HIGH if the product leaks into the error, otherwise MEDIUM. No code execution. Otherwise tested. CWE-1336. |
| `ssti.eval` | — | — | T1190 | stdlib | SSTI oracle with BENIGN PROOF: injects a unique arithmetic product; PROOF = the EVALUATED product is reflected. No code execution. Otherwise tested. CWE-1336. |
| `upload.unrestricted` | — | — | T1190 | stdlib | FILE UPLOAD oracle with BENIGN PROOF: uploads an INERT file (text marker, no code) under names that bypass the extension/MIME filters; PROOF = the marker is SERVED BACK, with a dangerous extension preserved or a rendering Content-Type. No webshell is ever built. Otherwise tested. CWE-434. |
| `web.nuclei` | — | — | T1595.002 | nuclei (bin/docker) | Vulnerability scan through nuclei templates (medium/high/critical). |
| `web.security_headers` | — | — | T1595.002 | stdlib | Audit of the HTTP security headers (CSP/X-Frame-Options/nosniff/Referrer-Policy/HSTS on https/Permissions-Policy) + insecure cookies (Secure/HttpOnly/SameSite). One INFO/LOW finding per gap, status=tested (never vulnerable). CWE-693. |
| `xss.reflected` | — | — | T1059 | stdlib | Reflected XSS oracle with BENIGN PROOF: unique marker reflected UNESCAPED in a JS-executable context. Real execution + chainability require the browser/evasion module. Otherwise tested. CWE-79. |

## Connector governance

An administrator can **disable** ("uninstall") a connector from the console — it is
then SKIPPED at firing **even if its binary/service is present**, including when it is the planner (and
not `--modules`) that chose it. See [Administration → Connector governance](ADMINISTRATION.md#3-connector-governance-installuninstall)
and `POST /api/modules/:kind` in the [API reference](HTTP_API.md).

## Operator connectors (driven standard tools)

Forge adds no offensive capability of its own: two connectors **drive** tools that the
operator already runs, and **map** their results into Findings behind the same ROE gate. Both
probe their service **at fire-time** (never at catalog time) and neutralise themselves if the service
is unreachable.

| Module | Driven tool | Env variables (defaults) |
|---|---|---|
| `msf.module` | **msfrpcd** (msgpack RPC) — launches the MSF module chosen by the operator; no payload generated by Forge | `MSF_RPC_HOST` (127.0.0.1) · `MSF_RPC_PORT` (55553) · `MSF_RPC_USER` (msf) · `MSF_RPC_PASS` · `MSF_RPC_SSL` (true) · `MSF_RPC_TOKEN` |
| `burp.scan` | **Burp Suite REST API** Pro/Enterprise — launches an in-scope scan, brings back the issues | `BURP_API_URL` (http://127.0.0.1:1337) · `BURP_API_KEY` |

Governance: `msf.module` declares `exploit=True` (fail-safe → the engine requires `allow_exploit`);
`burp.scan` stays `exploit=False` but emits `reported_by_tool` (never `vulnerable` without proof
of exploitability — like nuclei). `forge doctor` shows which ones are reachable. Configuration:
[Configuration §1.9](CONFIGURATION.md#19-operator-connectors-optional).

# Changelog

All notable changes to Forge are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Forge aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first tagged release.

> Forge is pre-1.0: the public API, module kinds, and config surface may still change between
> minor versions. Breaking changes will be called out here.

## [Unreleased]

### Added
- **Seam TLS sortant — la console parle `https://`, et le vérifie.** La console avait exactement trois
  sorties TCP, toutes en socket brut, donc **en clair** : l'échange de jeton OIDC (`sso/mod.rs`), le
  webhook de notification (`notify_channels.rs`) et le fetcher de source de détection (`net.rs`). La plus
  grave était la première : le POST au token endpoint porte le **`client_secret`**
  (`Authorization: Basic`) **et** le **`code`** d'autorisation — `docs/DEPLOYMENT.md` le concédait et
  prescrivait un **proxy TLS d'egress** en contournement.

  **Un seul point de sortie** (`console/src/tls.rs`), partagé par les trois : clair (**gouverné**) ou TLS
  avec **vérification complète du certificat** — chaîne jusqu'aux racines Mozilla (`webpki-roots`) **et**
  nom d'hôte —, le **handshake aboutissant avant le premier octet applicatif**. Face à un pair non prouvé,
  l'appelant n'obtient aucun flux, donc n'écrit aucun secret. **Aucune échappatoire de vérification** n'est
  livrée : ni option, ni ENV, ni feature ; une garde de source interdit au crate d'ouvrir l'API dangereuse
  de rustls. Le contournement par proxy TLS est **caduc** ; Slack / Teams / PagerDuty deviennent joignables
  ; une source de détection `https` est servie **en Rust**, sans spawn Python sur une route de lecture.

  **Les gardes existantes restent.** La deny-list SSRF s'applique à l'IP **résolue**, en `http://` comme en
  `https://` (chiffrer un fetch vers `169.254.169.254` n'en fait pas une cible légitime). Le refus
  « secret + cible publique en clair » s'**assouplit exactement** : autorisé en `https://`, toujours refusé
  en `http://`. Le clair vers un collecteur **interne** explicitement autorisé est inchangé.

  **Pas de SMTP** — refusé indépendamment du TLS : STARTTLS est une élévation **négociée** (classe
  d'injection de commandes en clair, CVE-2011-0411 et sa descendance) et le SMTP réel se pratique en TLS
  opportuniste contre des relais auto-signés. **Pas de mTLS** (aucun certificat client) ni de lecture du
  magasin d'AC système — une AC d'entreprise n'est donc pas reprise automatiquement (cf. DEPLOYMENT §3quater).

  **Coût : 6 crates nets** (`ring`, `rustls`, `rustls-pki-types`, `rustls-webpki`, `untrusted`,
  `webpki-roots`), ≈ +20 s CPU à froid, **aucun nouveau prérequis machine** (`ring` compile de l'asm/C via
  `cc`, déjà exigé par `rusqlite/bundled`). **openssl-freedom préservée et vérifiée par commande** : aucun
  `openssl-sys` / `native-tls` / `aws-lc-rs` / `schannel` / `security-framework` dans la fermeture, build
  par défaut comme sous `store-postgres` (qui partage la même pile, une seule version de `rustls`).
- **Cycle de vie des outils — un manifeste unique, et une surcouche runtime qui n'ouvre aucune porte.**
  Les versions et les empreintes SHA256 des douze binaires de sécurité téléchargés (httpx, nuclei,
  subfinder, dnsx, naabu, katana, amass, gau, gospider, dalfox, feroxbuster, ffuf) étaient des `ARG`
  codés en dur **dupliqués** entre `Dockerfile` et `docker-compose.yml`. Deux copies d'un pin, c'est
  une divergence silencieuse qui attend son heure — et il n'existait aucun moyen d'installer un outil
  omis, ni d'en mettre un à jour, sans reconstruire l'image.

  **Source unique : `forge/tools.json`.** Version, gabarit d'URL, format d'archive, membre à extraire,
  nom posé sur le `PATH`, et un digest **par architecture**. Le `Dockerfile` le lit au build (via
  `forge/toolsmanifest.py`, script autonome stdlib) et l'installeur runtime lit le même fichier.
  Le compose ne propage plus aucun pin. Bumper une version = éditer ce seul fichier. Une garde statique
  échoue si une version, un digest ou une URL d'outil réapparaît dans le `Dockerfile` ou le compose.

  **La baseline du build ne change pas** : mêmes binaires, mêmes versions, mêmes digests, même
  `sha256sum -c` qui fait échouer le build en cas d'écart. Deux garde-fous s'ajoutent : un outil sans
  pin pour l'architecture cible est **écarté du plan** (jamais téléchargé non vérifié) et signalé, et
  le groupe socle passe par `--require-complete core` — un pin manquant sur httpx/nuclei/subfinder fait
  échouer le build plutôt que produire une image amputée. Comme un `docker build` n'est pas jouable en
  CI, la boucle d'installation du `Dockerfile` est **extraite et réellement exécutée** par la suite de
  tests, avec `curl`/`sha256sum`/`unzip`/`tar` doublés : on vérifie l'URL téléchargée, le digest
  présenté, le membre extrait, la profondeur de `--strip-components` et le nom du binaire posé — et
  qu'un digest non concordant fait tout échouer sans rien installer.

  **Surcouche runtime : `forge tools list|install|update|remove`.** Le binaire atterrit dans
  `/data/tools/bin` — volume persistant, propriété de l'utilisateur `forge`, en tête du `PATH` devant le
  `/usr/local/bin` baké : mettre à jour un outil ne demande plus de rebuild, et l'install survit à un
  *recreate* du conteneur. Installer un binaire au runtime dans un outil offensif est précisément la
  capacité qui annule une gouvernance si elle est mal posée, donc : SHA256 épinglé **calculé sur le
  flux** et comparé avant que quoi que ce soit n'atteigne le `PATH` (écart ⇒ refus, temporaire détruit,
  refus **journalisé**) ; source **allowlistée** par le manifeste — il n'existe ni `--url` ni
  `--sha256`, et un nom hors manifeste ne déclenche aucune requête ; HTTPS strict, redirection quittant
  HTTPS refusée ; **aucun shell ni sous-processus** (`urllib` + `zipfile`/`tarfile`, un seul membre
  extrait vers une destination que nous calculons — un membre nommé `../../evil` ne sort pas du
  répertoire outils) ; **ledger obligatoire** (`tools.install`/`.update`/`.remove`/`.refused`, chaînés
  et signés) — sans ledger résoluble, l'action est refusée : pas de changement de capacité sans trace.

  Aucune élévation : l'outil installé reste soumis au scope-guard ROE fail-closed, au plancher exploit
  et au même contrat `Module`. Et **le défaut est un no-op** : rien n'est créé ni sondé à l'import,
  aucun module du moteur n'importe l'installeur, le volume est vide tant qu'aucune action opérateur
  n'a eu lieu — la résolution `PATH` est alors identique à la baseline.

  Volontairement **non construit** : l'installation d'une version *hors* manifeste (elle supposerait
  d'accepter un digest saisi à la main — tant qu'elle n'existe pas, il n'y a aucun chemin vers un
  téléchargement non épinglé), l'API admin et le panneau UI de la console, et la sonde de version par
  exécution du binaire. Documentation : `docs/TOOLS_LIFECYCLE.md`.

### Changed
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
  (`git = "https://github.com/guatxlabs/core", tag = "v0.2.1", features = ["forge"]`; see
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
- **AGPL-3.0-or-later**, open-core. Enterprise features are documented in
  [`COMMUNITY_VS_ENTERPRISE.md`](COMMUNITY_VS_ENTERPRISE.md).

[Unreleased]: https://github.com/guatxlabs/forge/commits/main
[0.0.1]: https://github.com/guatxlabs/forge/commits/main

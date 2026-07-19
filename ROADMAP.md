# Forge — Roadmap

> État : `vps/main` — build par défaut **communautaire byte-identical + openssl-free** (rustls/ring), `../core`/`../soc` (Plume) jamais touchés.
> Validation à jour : `cargo test` défaut + `--features store-postgres` verts, `pytest` vert, `kubeconform` OK.
> Docs détail : [`docs/AUDIT.md`](docs/AUDIT.md) · [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md) · [`docs/READINESS_MATRIX.md`](docs/READINESS_MATRIX.md) · [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) · [`docs/QUICKSTART.md`](docs/QUICKSTART.md) · [`docs/UPGRADE.md`](docs/UPGRADE.md) · [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md) · [`docs/TECHNIQUE_COVERAGE.md`](docs/TECHNIQUE_COVERAGE.md) · [`docs/TOOLS.md`](docs/TOOLS.md)

## 🐞 Bugs & UX d'un test live (2026-07-13) — ✅ TOUS CORRIGÉS

Un test réel de la webUI (wizard → engagement → run C2 → rapport → console) a remonté 13 défauts. **Tous corrigés + validés** :
`adc7b29` (B1 ledger fork + B2 ingest 421 + B3 token) · `d3b2595` (B4 scope persist + B5 switch + B6 profils techniques) · `ecd74d0` (B7 export + B8 format ×2 + B9 logo) · `11f7ba1` (B10 drilldowns + B11 boutons import + B12 filtre statut C2) · `532ec76` (B13 favicon transparent/centré). Causes détaillées ci-dessous.

### 🔴 CRITIQUE — intégrité / correctness
- **B1 — Ledger CASSÉ (fork de chaîne).** `forge ledger verify` → INVALIDE « chaînage rompu (prev), entrée seq=8 après 23 valides » ; `forge status` → `ledger ok=false`. Cause probable : la **console Rust** ET le **moteur Python** appendent au MÊME `engagement.jsonl` sans **verrou advisory partagé** (le flock Python ne couvre pas l'append Rust) → collision de seq. Fix : partager le flock cross-process (Rust `with_ledger_lock` doit prendre le même `fcntl.flock` que `forge/ledger.py`), ou sérialiser les deux écrivains.
- **B2 — Ingest 421 Misdirected Request.** Le moteur n'arrive pas à réinjecter les findings dans la console (`HTTPError 421`) → host_guard rejette le `Host`. Findings/panneaux non persistés.
- **B3 — Ingest token non affiché.** « Colle l'ingest token affiché au démarrage » mais il n'apparaît **ni au wizard ni dans l'UI** → impossible d'écrire panneaux/dashboards. Le surfacer (UI, write-only) ou l'auto-gérer.

### 🟠 FONCTIONNEL
- **B4 — Scope non enregistré.** Éditeur d'engagement : saisir `example.com` en in-scope **ne persiste pas** ; incohérence mode/scope (report=black/example.com vs éditeur=black/app.example.com) ; du coup C2 → « HORS SCOPE ».
- **B5 — « Basculer » d'engagement ne fait rien / pas clair.**
- **B6 — Sélection de techniques (profils) confuse.** Choisir un profil (bug bounty) puis changer d'onglet/​recharger → revient à **custom** ; « Enregistrer » ne demande **pas de nom** de profil (bug_bounty/pentest) ; pas de suppression de profil ; « Enregistrer » **ne demande pas le token** mais ledgerise quand même. Clarifier : sélection = drilldown auto ; Enregistrer = créer/nommer un profil (+ token si gouverné).
- **B7 — Export rapport blanc.** DOCX/PDF/JSON → page blanche (PDF attendu en `mini` sans weasyprint, mais **DOCX/JSON doivent marcher** même sans finding).
- **B8 — Format en double.** Le sélecteur de format apparaît **2 fois** (drilldown + prévisualisation) → incohérent.
- **B9 — Placeholder logo client** dans le rapport d'engagement (carré vide) : le rendre optionnel/clair (branding client BB).

### 🟡 STYLE / COHÉRENCE UI
- **B10 — Drilldowns non stylisés** (pas le design de la page) : Findings, Importer un scan, Campagnes, ROE/Garde-fou.
- **B11 — Boutons « Importer un scan » pas tous stylisés.**
- **B12 — Lancement C2 : filtre « Tous statut » non stylisé.**
- **B13 — Favicon** : pas centré ; enlever le carré noir (fond transparent), **juste la plume**.

## 🐞 Round 2 — 2e test live (2026-07-13) : ✅ TOUS CORRIGÉS

Fixes : **C1/C6** `cd4739c` · **C2** `9653ac1` · **C5/C8/C9** `48a4c51` · **C3/C4/C7** `a93b6a3`.
⚠️ Le round 1 « TOUS CORRIGÉS » était **prématuré** (validé curl/markup, pas le vrai navigateur → cookie Secure & popups natives ratés). **Leçon appliquée au round 2 : validé en pilotant un vrai navigateur (harness Camoufox MCP).** Plusieurs « bugs » (C3 indicateur, C7 format-double) étaient déjà réglés au HEAD — l'user testait un **build antérieur** ; d'où le rebuild systématique du conteneur après chaque vague.

- **C1 — 🔴 LOGIN CASSÉ sur http (cookie `Secure`).** Bons cred → session non stockée (navigateur jette le cookie Secure sur http). **✅ CORRIGÉ `cd4739c`** : `Secure` uniquement si https (`X-Forwarded-Proto: https` / `FORGE_FORCE_SECURE_COOKIE`), sinon http local marche ; HttpOnly+SameSite gardés. Prouvé curl (http=no-Secure+session OK, xfp-https=Secure).
- **C6 — 🔴 Token exigé pour écrire (panneaux/dashboards).** Un admin loggé devait coller un token machine qu'il n'a pas (→ mettait le mdp admin). **✅ CORRIGÉ `cd4739c`** : écritures UI via **session admin/operator** (`check_writer`) ; token ingest = machine only ; token **surfacé au wizard** + carte admin.
- **C2 — Popups Chrome natives → modals stylisés** (`modalPrompt`/`modalConfirm`, drive Camoufox). **✅ CORRIGÉ `9653ac1`**
- **C5 — Profils nommés** (save-as/rename/delete ; cause = comparaison résolue-vs-brute → « custom »). **✅ CORRIGÉ `48a4c51`**
- **C9 — Personnaliser un outil (args) découvrable dans Launch** — panneau « Personnaliser \<outil\> » + roue + `extra_args` universel. **PER-RUN** (`module_params` → payload du run, JAMAIS écrit dans la table `module`) → **ne modifie pas l'outil global**. **✅ CORRIGÉ `48a4c51`**
- **C3 — Indicateur « actif : \<nom\> · \<mode\> »** (+ CSS anti-wrap). **✅ CORRIGÉ `a93b6a3`**
- **C4 — Bouton « Vérifier »** stylé (2 thèmes). **✅ CORRIGÉ `a93b6a3`**
- **C7 — Rapport** : un seul sélecteur de format + drilldown stylé. **✅ CORRIGÉ `a93b6a3`**
- **C8 — Bouton GLOBAL tout sélectionner/désélectionner** (techniques). **✅ CORRIGÉ `48a4c51`**

## 🐞 Round 3 — 3e test live (2026-07-13)
- **C10 — Doublon « actif : … »** : l'indicateur `#eng-active` répète le sélecteur (qui affiche déjà « Engagement par défaut · white »). **Supprimé** l'indicateur redondant (`9583467`) — actif affiché une seule fois (le sélecteur).
- **C11 — Label « C2 » trompeur** : « Lancement C2 » / « opérateur C2 » / « C2-light gouverné » → C2 = Command&Control **post-exploitation** (implants), or Forge lance des campagnes recon/scan/oracle **pré-exploitation** orientées-preuve. **Renommé** l'UI en « Lancement / Campagne / Opérateur » (`9583467`) — 43 occurrences « C2 » user-facing → 0 (IDs internes intacts).
- **C12 — Popup Chrome native au chargement** (au lieu du wizard/login stylé) : root cause `GET /` gated → `401` + `WWW-Authenticate: Basic realm="forge"` → le navigateur ouvre son **dialog Basic natif** sur la navigation top-level, le SPA ne se rend jamais. **Corrigé** : `/` servi **public** (shell SPA statique, sans secret, identique à `/index.html`) hors auth_guard ; en-tête `WWW-Authenticate` **retiré** du 401 du guard (le guard reste **fail-closed** + accepte toujours `Authorization: Basic` proactif — rétro-compat Plume/curl). Plus aucun popup natif ; le SPA gère l'auth via le portail de login stylé sur 401. **✅ corrigé — `03b3444`**
- **C13 — Flash de l'app derrière le login au reload** : au `Ctrl+R`, l'ossature app (header/layout/footer) se **peint visiblement** un instant AVANT que le login la recouvre. Root cause : `<body>` **non-gaté** au 1er paint (le shell se peint) + `.login-view` **transparente** (seule la carte est opaque) → pendant l'aller-retour réseau de la sonde `whoami`, l'app est à l'écran (pire au Ctrl+R, l'ossature en cache repeint instantanément tandis que la sonde traîne). **Corrigé** : `<body class="gated">` par défaut → l'ossature est `display:none` dès le 1er paint (rien ne se peint avant que l'auth soit connue ; seul le fond aurora neutre est visible pendant la sonde), puis le boot bascule vers l'état correct après la sonde `setup/state`+`whoami` (`showApp` retire `gated` si session valide, sinon login/wizard restent gatés) ; **défense en profondeur** : `.login-view` rendue **opaque plein écran** (`background:var(--bg)`) avec l'aurora conservée via `.login-view::before` (miroir de `body::before`) → le portail occulte totalement l'ossature dans TOUT état transitoire. **✅ corrigé — `64bc134`**
- **C14 — Échec 401 à la création d'engagement (écriture opérateur)** : un admin connecté reçoit **401** sur `POST /api/engagements` (les GET passent). Root cause : `operatorHeaders()` (front) attachait un `Authorization: Bearer <forge_token>` **viewer périmé** — un `forge_token` en localStorage résidu d'un ANCIEN build (jamais réécrit par le build courant : lu seulement, aucun `setItem`) — et côté serveur `resolve_session_identity` **priorisait ce Bearer** sur le cookie `forge_session` : le Bearer périmé ne résolvait vers AUCUNE session → identité `None` → `check_operator`/`auth_guard` refusent → **401**. Le cookie de session VALIDE n'était jamais consulté (masqué par le Bearer). **Corrigé** : `resolve_session_identity` essaie désormais les DEUX candidats dans l'ordre — `Authorization: Bearer` PUIS cookie `forge_session` — et renvoie l'identité du **PREMIER** token qui résout vers une session valide (non expirée, compte activé). Une session cookie valide authentifie donc MÊME avec un Bearer périmé/étranger. **Aucune élévation** : chaque candidat est validé INDÉPENDAMMENT contre la table `session` (join user réel, disabled→refus, expiry→purge best-effort) → un Bearer bidon + cookie valide authentifie comme le user DU COOKIE ; un Bearer bidon sans cookie → `None` (fail-closed). Refactor : helper privé `lookup_session_token(app, token)` (logique de lookup+purge INCHANGÉE) + extracteurs `bearer_session_token`/`cookie_session_token` ; `session_token_from_headers` conservé Bearer-prioritaire pour son autre appelant (`tenancy::caller_user_id`). **Hygiène front** : `operatorHeaders()` n'attache PLUS le `Bearer <forge_token>` legacy (mort, il ne faisait que masquer le cookie) — le secret opérateur voyage via `X-Forge-Operator`, l'AUTHN via le cookie de session. Prouvé e2e (db temp) : cookie+Bearer-bidon → **200** (était 401), cookie seul → **200**, Bearer-bidon seul → **401**. Test de non-régression `valid_cookie_authenticates_despite_stale_bearer`. **✅ corrigé — `2c939b1`**

- **C15 — « Erreur réseau : Failed to fetch » au lancement de campagne** : `POST /api/run` (front `launch/submit.js`) voyait son `fetch()` **THROW** (« Failed to fetch » = connexion coupée, aucune réponse lue), alors que le serveur **ne crashait pas** (0 restart). Cause : **blip réseau transitoire**, PAS un panic du handler. Repro authentifié end-to-end (admin session, db temp, `RUST_BACKTRACE=1`) sur `run_create`→`claim_and_spawn` en conditions live (scope serveur absent, scope per-engagement) : TOUTES les variantes (modules vides / module réel / hors-scope / scope vide / engagement absent-ou-inconnu / opt-in haut-impact / FIFO concurrent) renvoient un **JSON propre** (202 / 4xx gouverné / 409) — **aucun `panicked`**, aucune connexion resetée, `stderr` vierge. Le handler est robuste (toute entrée invalide → 4xx typé ; échecs I/O → `mkdir_failed`/`write_failed`/`spawn_failed`/`ownership_write_failed` 500 gouvernés, process reap + slot libéré). **Filet anti-panic ajouté** (défense en profondeur, utile quelle que soit la cause) : `tower_http::catch_panic::CatchPanicLayer` câblé comme couche **la plus externe** de `build_router` (enveloppe host_guard/auth_guard/Extension + tous les handlers) → une panique IMPRÉVUE de n'importe quel task devient un **`500 {"error":"internal","why":"une erreur interne est survenue"}` JSON** (content-type `application/json`, corps STABLE et NON-FUYANT — ni message ni backtrace), **plus jamais une connexion coupée** que le navigateur ne peut pas lire. Feature `catch-panic` d'un crate **déjà présent** (tower-http) — **zéro nouvelle dépendance**, build community **openssl-free** préservé (`cargo tree` vide), `Cargo.lock` inchangé. Tests : `catch_panic_response_is_stable_and_non_leaking` (500 + JSON + non-fuite) + `catch_panic_layer_converts_handler_panic_into_clean_500` (**end-to-end** : route qui panique servie sur port éphémère + client TCP brut → reçoit bien `HTTP/1.1 500` + corps JSON, jamais un RST). 335 tests verts ; repro re-jouée sur le binaire final → `202` propre, `NO PANIC`. **✅ corrigé — `3359d06`**

- **C16 — « Failed to fetch » au lancement (chemin fort-impact honoré + auto/arm) + badge « état inattendu (400) »** : suite de C15, ciblage du chemin que l'investigation précédente n'avait PAS exercé — l'opt-in fort-impact **PLEINEMENT honoré** (`allow_high_impact:true` HONORÉ car operator armé + `arm:true` + `reason` non vide → `high_impact=true`) combiné à `mode:"auto"` + `modules:[]` (planner). **Root cause du panic : AUCUN — non reproductible.** Repro end-to-end sur le corps EXACT de l'UI live (engagement white, `127.0.0.1` in-scope, db temp, `RUST_BACKTRACE=1`, stderr capturé), via **session admin** ET via **hash env opérateur + `X-Forge-Operator`**, plus les variantes (`exhaustive`, `budget=0`/`1e308`/string, `rate`, `auto_pentest`, modules exploit réels `access_control.idor`+`auth.takeover`, `technique_selection`, `module_params`) : TOUTES renvoient un **`202` propre** — le moteur démarre réellement et FIRE les modules exploit (`[FIRE] access_control.idor/ssrf.callback/auth.takeover…`) — **aucun `panicked` en stderr**, aucune connexion coupée, le serveur reste vivant. Le chemin fort-impact honoré (scope écrit `allow_exploit/destructive=true`, ledger `console.run.high_impact_authorized`, `high_impact_modules`) est robuste ; les `.unwrap()` de `claim_and_spawn` portent sur `serde_json::to_vec(&Value)` (**infaillible**). Le filet `CatchPanicLayer` (C15/`3359d06`) couvre déjà toute panique résiduelle imprévue → `500` JSON gouverné, jamais un reset. **Aucun code de run modifié** (pas de fix inventé, aucun garde-fou touché). **Test de non-régression ajouté** `honored_high_impact_auto_arm_run_is_clean_202_not_panic` (corps EXACT honoré → `202 high_impact:true`, ledger `high_impact_authorized` présent). **Badge « état inattendu (400) » — VRAI bug corrigé** : la sonde `probeC2State()` (`launch/live.js`) POST `/api/run` (targets vides, `X-Forge-Operator` vide) pour détecter l'état opérateur. Un **operator/admin CONNECTÉ** (session) franchit le contrôle opérateur (la session prime sur le header vide) et échoue seulement sur la **validation** → `400 no_targets`. L'ancien mapping traitait ce 400 en « **état inattendu (400)** » alors qu'il **PROUVE que le gate opérateur est OUVERT**. **Corrigé** : `400` (validation, gate franchi) → badge **« opérateur prêt »** (`badge ok`, icône `lock`) ; seul un `403 operator_required` signifie le gate fermé (« opérateur armé »/« opérateur fermé » selon le `why`). Prouvé : sonde en session admin → `400 no_targets` → « opérateur prêt » ; sonde anonyme (gate fermé) → `403` → « opérateur armé ». **openssl-free** préservé (`cargo tree -e no-dev` vide), **zéro nouvelle dépendance**, `node --check` OK, 336 tests verts, repro re-jouée sur le binaire final → `202` propre, `NO PANIC`. **✅ corrigé — `5624ea9`**

## 🔒 Round 3 — durcissements issus de l'auto-scan (F1/F2)
- **C17 / F1 — Console sans en-têtes de sécurité HTTP** : l'auto-scan (nmap/httpx + revue manuelle) a montré que la console ne renvoyait AUCUN en-tête de sécurité HTTP (une CSP existait en `<meta>` mais pas en header, et `X-Frame-Options`/`nosniff`/`Referrer-Policy`/HSTS absents → clickjacking + MIME-sniffing possibles). **Corrigé** : middleware `security_headers` (outermost) → `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, CSP HTTP (réplique de la meta + `frame-ancestors 'none'`, `frame-src/child-src 'self' blob:` pour l'aperçu rapport, `connect-src 'self'` pour SSE), HSTS **scheme-aware** (via `request_is_https`, jamais sur http loopback). Test ajouté, CSP prouvée non-cassante (SPA/SSE/rapport OK), openssl-free. **✅ `5779723`**
- **C18 / F2 — Rapport de couverture sous-rapporté** : un run select-all laissait 35+ modules « outil présent mais jamais planifié » **absents** des `coverage_gaps` (contredisait « zéro lacune silencieuse »). **Corrigé** : nouveau bucket `not_planned` (moteur `engine.py`) = `selected − planned`, avec raison véridique dérivée des données (`exploit non autorisé` / `outil absent` / `désactivé` / `technique désélectionnée` / `hors périmètre du plan`). Exposé en Markdown ET JSON (`not_planned` additif, unknown-field-safe côté Rust). Test `TestCoverageAccounting` prouve la clôture `planned ∪ not_planned == selected` (disjoints). 1175 tests OK. **✅ `76a247c`**

## 🧩 Round 3 — nouveau module (F3)
- **C19 / F3 — Module oracle `web.security_headers`** : Forge n'avait aucun module dédié à l'audit d'en-têtes de sécurité (nuclei medium+ les filtre, nuclei all-sev ne les template pas ici) → il ratait la classe « missing headers » que la revue manuelle voyait. **Ajouté** : oracle `web.security_headers` (`ScopeGuardedOracle`, stdlib urllib, non-exploit/non-destructif, web_allowed, `T1595.002`/`CWE-693`) — flague en INFO/LOW chaque en-tête manquant/faible (CSP, X-Frame-Options/clickjacking, nosniff, Referrer-Policy, HSTS **https-only**, Permissions-Policy, `Set-Cookie` sans Secure/HttpOnly/SameSite, fuite de version), tout en `status=tested` (orienté-preuve, jamais `vulnerable`). Param `host` pour l'anti-rebinding. Prouvé : 6 findings vs serveur nu, 1 vs console durcie F1. 17 tests dédiés, suite 1199 verte. **✅ `69ad961`**

## 🛡️ Round 3 — feature sécurité réseau (F4)
- **C20 / F4 — Politique réseau deux-portes (scan réseau client sans devenir une faille)** : pour qu'un pentester puisse scanner du privé/LAN/loopback sans que Forge soit une surface d'attaque sur le réseau client. **Modèle 3 portes cumulatives** : (1) interrupteur **global** `network.allow_private` (OFF par défaut, admin, ledgerisé — kill-switch instantané sans down/up) ; (2) opt-in **par-engagement** (isolation) ; (3) scope fail-closed. `effective = global && engagement`, écrit dans `scope.json`. **Enforcement 2 couches** : Rust `run_create` (IP littérale → `400 private_target_blocked`) + moteur `roe.py` (résout hostnames via getaddrinfo → VETO ceux pointant vers du privé = anti-rebinding/SSRF). **Compose durci** : `network_mode: host` + `FORGE_CONSOLE_ADDR=127.0.0.1:7100` (loopback strict, jamais 0.0.0.0 — prouvé : console inaccessible depuis l'IP LAN 192.168.1.38:7100 → 000). **F1 complété** : `Permissions-Policy` ajouté. UI : toggle global danger-styled + case par-engagement. E2E prouvé bloqué(400)→débloqué(202), fail-closed prouvé, 349 tests Rust + 1208 Python. **✅ `38aa635`**

## 📋 Suite / reste ouvert (consigné, non engagé) + principe ressources

### Chantiers restants
- **Oracles auth-based (idor/ato/takeover)** : encore « config manquante » — ils ont besoin de **comptes/creds**, pas de query params. Feature séparée « **contexte authentifié** » : gérer creds/session/idor_targets par-engagement (déjà un champ éditeur) → seeder les oracles auth pour tester cross-account. C'est le pendant auth du crawl→param déjà fait (G1).
- **LLM Tier-2 payload hook** : générer des payloads d'injection via le LLM (deephat sans-refus / OpenAI-compat) branché sur la chaîne G1. **Différé** — le cœur déterministe suffit ; IA-2 (`forge/llm.py`) est déjà le seam d'accroche (off par défaut, egress-gaté, advisory, fail-open).
- **Wall-clock gros run** : parallélisme (G3, pool=4) aide mais 58 modules × N services reste long. Suite = parallélisme plus agressif **+ voir principe ressources ci-dessous**.

### ⚙️ Principe TRANSVERSE — paramétrabilité ressources (machine cliente faible)
**Exigence** : tout ce qui consomme des ressources DOIT être réglable ; un client sur machine faible doit pouvoir tourner Forge sans le saturer. **Aucune valeur ressource ne doit être codée en dur.**

**Déjà réglable (acquis de la session)** : `FORGE_PARALLELISM` (pool exécution, G3) · `FORGE_RUN_TIMEOUT` (watchdog run, D1) · timeouts par-action/par-outil (E3) · `FORGE_TOOLS_PROFILE=mini|full` (arsenal, D3) · sévérité nuclei (G2) · `module_params` par-module (débit req/s, threads, wordlist, ports…) · caps de fan-out (crawl ≤25, services ≤32, params ≤3) · triage (seuils, on/off, IA-1) · LLM (off/endpoint/model/timeout/max_tokens, IA-2) · politique réseau.

**Gap / à faire** :
1. **Profil ressources unifié** `FORGE_RESOURCE_PROFILE=low|balanced|full` : pose d'un coup des défauts sains machine-faible (pool bas, timeouts courts, jeu d'outils léger, caps crawl réduits, nuclei templates restreints, LLM off, arsenal mini). `low` = safe par défaut sur petite machine.
2. **Audit anti-hard-code** : passer en revue moteur+modules pour qu'AUCUNE valeur ressource-impactante (pool, timeout, cap, threads, rate, num_ctx, batch) ne soit figée — toutes overridables (env/settings/param).
3. **Exposer dans l'UI** : les knobs ressources visibles/éditables au lancement (pas seulement via env).
4. **Garde-fou mémoire** : borne mémoire/process concurrents optionnelle (un client faible ne doit pas OOM — cf. les OOM de build qu'on a eus).

**✅ Livré — R1 (`9f9da8d`) + R2** :
- **R1 (`9f9da8d`)** — `forge/resource_profile.py` : profil unifié + résolveur `resolve(knob, override>profil>défaut)` + snapshot auditable (ledger `engine.resource_profile`). Leviers primaires câblés : pool (`parallelism`), timeout par-action, caps crawl (`crawl_max_endpoints`/`crawl_max_params`), fan-out contenu (`content_fanout_max`), sévérité nuclei. `balanced` == défauts-code (profil non défini = NO-OP byte-identique).
- **R2** — balayage anti-hard-code exhaustif du RESTE. **Désormais résolveur-driven** : profondeur traversal `injection.MAX_DEPTH` (`crawl_max_depth`, balanced=8) · LLM `llm_max_tokens` (512) + `llm_num_ctx` (0=non envoyé → no-op ; low=2048 borne le contexte, loopback-only comme keep_alive) · caps de synthèse triage `triage_max_items` (10) / `triage_max_clusters` (20) — **coverage-safe préservé** (res.ranked garde TOUT, seul le digest est borné) · fan-out découverte ports `discovery_max_fanout` (25) + endpoints crawlés via `crawl_max_endpoints` · helper `max_concurrent_procs()` exposé (résolvable). Overrides explicites (env/scope/param) priment toujours ; `low` allège réellement LLM/triage/profondeur/fan-out. Preuves : balanced == littéraux d'aujourd'hui (no-op) + low réduit, dans `tests/test_resource_profile.py`.
- **Intentionnellement LAISSÉ** (documenté) : `rate_per_sec` = **DOCUMENTATION-ONLY** (débit porté par le scope/ROE — gouvernance, jamais câblé au profil) · watchdog Rust (`FORGE_RUN_TIMEOUT`, env, couche Rust) · build-arg Docker outils (`FORGE_TOOLS_PROFILE`) · **enforcement** de `max_concurrent_procs` (sémaphore runner) → **R4** · exposition UI des knobs → **R3**. Gouvernance INTOUCHÉE : scope-guard, allow_private, plancher exploit, planner coverage-safe, allowlist sévérité nuclei — le profil ne règle QUE des défauts de ressources, n'élargit aucune capacité, ne relâche aucun gate.

## 🤖 IA en 2 tiers (gouvernée, réutilise deephat-search)
- **IA-1 (`06ca557`) — Triage NATIF** : `forge/triage.py` stdlib-only, **zéro egress** (sûr entreprise). Dédup (Jaccard shingle) + cluster du bruit + noise-score (MEDIUM+ jamais flaggé) + rank actionnable-first. **Coverage-safe** (count in==out prouvé, brut+ledger intacts), **transparent** (section `## Triage` + annotation par finding), **configurable** (défaut sûr : auto-hide OFF). Résultat : 216 findings → 4 actionnables / 212 bruit / 3 clusters. 49ms/2004 findings.
- **IA-2 (`d4c069a`) — Assist LLM opt-in** : `forge/llm.py` client **OpenAI-compatible** (Ollama/OpenAI/tout compat, repris du `ollama()` de deephat-search). **OFF par défaut**, endpoint externe **gaté** (`allow_external` fail-closed), **egress ledgerisé** (`llm.egress`, jamais le secret), api_key redacted. Advisory-only (enrichit le triage, 1 appel/run, ne touche pas les findings/ledger), fail-open. 16 tests.

## 🔭 Chantiers G1-G4 — ✅ TOUS LIVRÉS (issus des tirs comparatifs A→E4)
Après la chaîne A→E4 (Forge à parité de couverture largeur avec le manuel), 4 leviers restants — l'IA (cerveau LLM via Ollama local :11434) intégrée **si efficient, fail-open sinon** :
- **G1 (`7b60fdd`+`8d91826`+`e3889e1`) — Exploitation autonome** : crawl→param→inject ; le résiduel live (params à valeur vide `?QUERY=` droppés par `parse_qsl` défaut → « config manquante ») corrigé (`_query_params` keep_blank_values, une action par param, borné 3) — 11 oracles param-only tirent sur chaque param crawlé, test avec le VRAI module katana. Reste : les oracles rce/sqli/idor/xss sortent « config manquante » faute de surface injectable. Chaîne **crawl (katana/gospider) → param-discovery (host:port/path?param=val nœuds chaînables) → oracles d'injection** qui testent le param découvert. + hook **cerveau LLM Ollama** optionnel (priorise params/payloads), fail-open/mockable/off par défaut. Cœur déterministe d'abord. *(gros levier)*
- **G2 (`70da52e`) — Plancher nuclei** : `-severity medium+` masque les expos INFO/LOW (Swagger/openapi, LLM panels, exposed-files). Élargir/rendre configurable, sévérité réelle du finding préservée (pas d'inflation).
- **G3 (`fdb777b`) — Parallélisme intra-vague** : executor série → gros run >25 min. Paralléliser l'exécution (borné) en **sérialisant les écritures ledger/ingest** (ordre déterministe — raison du report par E3). Gouvernance intacte, composé D1/E2/E3/E4. *(le plus risqué)*
- **G4 (`27f841d`) — Flake pytest** : race timing ROE-arming/durability (`test_roe`/`test_connector_governance`/`test_engine_durability`, ~1/5-8, corrélé charge — hostnames `.test` qui VETO par intermittence en résolution DNS). Rendre déterministe (mock résolution / éliminer dépendance temps).

Livré : G1 crawl→param→inject (11 oracles chaînés ; IA Ollama skippée honnêtement) · G2 nuclei info/low sans inflation · G3 parallélisme pool=4 **ledger déterministe prouvé** (~6× speedup) · G4 flake tué (mock getaddrinfo, 15/15 verts). Suite **1319 tests verts**.

## 🛑 Cancel effectif (E4, révélé par T29)
- **E4 (`63c8428`)** — `POST /api/runs/:id/cancel` marquait la DB mais ne tuait PAS le moteur détaché (continuait à spawner nuclei ; hard-kill manuel nécessaire). Cause : cancel n'envoyait qu'**un** SIGTERM (le handler D1 ne fait que poser un flag lu aux checkpoints), et les outils E3 sont en sessions séparées → jamais atteints. Fix : SIGTERM (grâce flush D1) → **escalade SIGKILL détachée** (`escalate_kill_group`, `runs_proc.rs`) + **registre de pgid d'outils vivants** (`runner._LIVE_TOOL_PGIDS`) reapé par le handler SIGTERM → moteur ET outils morts, zéro orphelin. Idempotent, fail-safe (pgid inconnu), auth inchangée. Composé avec D1/E2/E3 sans double-kill. Tests Rust escalade + Python tool-reap verts. Note : flake pré-existant de la suite (race ROE timing) non lié.

## 🚦 Scheduler — priorité + anti-hang (E3, révélé par T27)
T27 : E1 routait bien vers les ports découverts mais **0/8 verdicts profonds** car (1) scanners de contenu EV≈0.2 derrière ~40 oracles → nuclei jamais planifié ; (2) nikto a hangé et gelé le pipeline 4+ min. Corrigé :
- **E3 (`c93f3da`+`eeca89a`)** — (a) **priorité** : table EV des scanners de contenu (httpx 0.81 / security_headers 0.765 / nuclei 0.72 / tech 0.60) > sweep 0.25 > lents (nikto 0.07, testssl 0.04) → `nuclei` passe de l'index ~75 à **2/77**. Pur ré-ordonnancement, floor de couverture intact (lents déférés, pas supprimés). (b) **anti-hang** : `Popen(start_new_session)` + kill du process group sur timeout par-action (rc=124) → un outil qui pend est tué (petit-fils prouvé mort, borné <20s) et le run continue. Composé avec D1 (watchdog run) + E2 (daemon reap), sans double-kill. Pas de parallélisme (différé, honnête). 1295 tests verts.

## 🔌 Pipeline recon→scan & hygiène (E1/E2 — révélés par le re-tir T24)
Le re-tir (post D1/D2/D3) a montré que Forge **découvrait les ports mais ne scannait aucun service** (scanners de contenu tapaient `:80` fermé → couverture ≈0 % vs manuel malgré l'arsenal). Corrigé :
- **E1 (`52394cc`+`cf38b40`, décisif)** — double root cause : (1) le brain ne semait que `httpx`+`nuclei` en AUTO (8 autres scanners jamais proposés sur nœud découvert) ; (2) `naabu`/`masscan` (spec-driven) n'émettaient aucun marqueur de découverte. Fix : helpers `_discovery.py` ; naabu/masscan émettent inventaire + `DISCOVERY_SERVICE_MARKER` HTTP-confirmé ; **edge (g) chaîne les 10 scanners de contenu** sur tout `host:port` découvert (AUTO + explicite). Preuve E2E : naabu `:8000` → `web.security_headers` FIRE dessus. + quick-wins (gau skip IP, inventaire ports, httpx par-port). Borné ≤32×10, gouvernance intacte.
- **E2 (`59158d6`)** — `recon.amass` fuitait un **démon `amass engine`** (v4 double-fork détaché, échappe au reap pgid ; pprof exposé `:6060` via host-net). Fix : reaper ciblé par **token uuid par-run** (`_daemon_reap.py`) → SIGTERM/SIGKILL uniquement les survivants portant le token, sur success/timeout/cancel (composé avec D1). Pas de pkill large. Prouvé no-leak.

## 🧰 Robustesse & arsenal — issus du tir comparatif COMPLET (T20, tous modules non-exploit vs manuel)
Le tir complet a révélé que Forge **ne persistait RIEN** sur un gros run (534 actions → watchdog 900s → kill → 0 finding malgré 487 FIRE) + 2 crashes + des gaps d'outils. Corrigé :
- **D1 (`d0b9b26`, CRITIQUE)** — persistance **incrémentale** : flush par batch (25) + frontière de vague ; **handler SIGTERM** flush le travail en vol ; ingest `partial` (statut `running`→`timeout`, compteurs non-nuls) ; offsets = pas de double-comptage ; watchdog 900→**3600s** (safety gardée, non-destructive). Un run tué ne perd plus le travail fait. 5 tests durability + suite verte.
- **D2 (`70aa85b`)** — crash `ValueError('unknown url type')` sur host nu corrigé (`cache_poisoning`/`header_injection`/`request_smuggling` normalisent via `web_url_candidates`) + **garde défense-en-profondeur** dans `oracle._http` + **audit de TOUS les modules web** → aucun ne crashe sur host/host:port.
- **D3 (`3d88e0e`)** — **arsenal** : 17 outils installés dans l'image `full` (sqlmap, nikto, dalfox, feroxbuster, wafw00f, whatweb, testssl, naabu, dnsx, katana, gau, gospider, amass, masscan, gobuster, wfuzz, ffuf), SHA256-pinnés, vérifiés en conteneur jetable → les modules « indispo » deviennent disponibles. `mini` inchangé.
- **Consigné (hôte, pas Forge)** : `HOST_EXPOSURE_NOTES.md` — `:8099` expose le `/tmp` de l'hôte sur `10.100.0.0` (réel), noVNC/VNC/Ocular potentiels, Ollama/Swagger bénins.

## 🎯 Couverture de scan — chaîne A→C3 (issue du tir comparatif Forge vs manuel, validée en live)
Le tir comparatif T14 (post-remédiation) a montré 2 écarts Forge vs scan manuel → corrigés et **confirmés en live sur la propre console** :
- **A (`de3571e`)** — `recon.nmap` param `full_ports` → `-p-` (range complet) ; défaut top-1000 inchangé. Live : 11-13 ports = identique au manuel `-p-`.
- **B (`58e67ea`)** — planner : les modules **explicitement sélectionnés** ne sont plus déférés en silence (root cause : le brain ne les proposait jamais → intersection vide). `_directive_actions` les tire contre la surface. Auto-mode inchangé, gouvernance intacte.
- **C1 (`4e27d41`)** — `web.security_headers` (+ recon.tech/waf) ne crash plus sur host nu : normalisation URL (`host`→`http://host`, `host:port`, fallback https) via `web_url_candidates`.
- **C2 (`98a957b`)** — `recon.nmap/httpx` émettent une découverte par service web (`host:port`) → devient nœud du graphe → les modules web explicites chaînent dessus (vague ultérieure). Endpoint hors-scope découvert → VETO.
- **C3 (`031d0fd`)** — pivot élargi : httpx **confirme HTTP** les ports ouverts que nmap mal-classe (ex: `:7100` fingerprinté `font-service?` à cause du 421 anti-rebinding) → les modules web les couvrent. VNC/non-HTTP filtrés (probe→None). Borné ≤25.
- **Validation live** : `web.security_headers` FIRE sur `127.0.0.1:7100` découvert → **verdict PROPRE véridique** (curl confirme les en-têtes F1). Forge couvre désormais les services web même quand nmap ne les reconnaît pas.

## 🔍 Audit holistique multi-agents (2026-07) → remédiation
Rapport complet : [`docs/HOLISTIC_AUDIT.md`](docs/HOLISTIC_AUDIT.md). 54 agents (find → vérif adverse → synthèse), **31 findings confirmés** (42 bruts) : **0 critique · 1 HIGH · 7 MEDIUM · 20 LOW · 3 INFO**. Posture globalement saine (garde-fous cœur cohérents) ; défauts = écarts d'uniformité concentrés sur 3 thèmes.

**Remédiation — ✅ LIVRÉE & DÉPLOYÉE (rebuild host-net, ledger verify OK, console loopback-strict prouvée) :**
- ✅ **T1** ledger WORM (H1 purge sous verrou cross-process + test de course zéro-perte, M1 canon parité, M2 verify tolérant) — `563611a`
- ✅ **T2** auth/tenancy (M3 dual-candidate propagé, M4 SSO no-auto-adopt, L6 role borné, L7 SCIM tx) — `7fe3b70`
- ✅ **T3** ROE/anti-rebinding (L1-L4 TOCTOU de décision fermé + IP épinglée, L5, L16 ; connexion-pin bout-en-bout → suivi T8) — `53407a6`
- ✅ **T4** moteur/modules (M5 SSE scopé, M6 FIRE→ERROR, M7 origin corrélé, L11/L12 caps net.rs, L14) — `b4014d5`
- ✅ **T5** data/runs (L8 delete-then-attest, L9 import gaté tenancy/scope, L10 async) — `da658db`
- ✅ **T6** front quick-wins (L17/L18/I2/I3) — `77155b9`
- ✅ **T7** plan archi (`docs/ARCHITECTURE_REFACTOR_PLAN.md` — main.rs = ~80% tests ; découpe incrémentale) — `64f48dc`
- ✅ **T8** anti-rebinding bout-en-bout : modules connectent sur l'IP épinglée (urllib `Oracle._http` + socket `httpflow`), SNI/cert préservés (aucun bypass), 14 tests socket-level — `a8ebd87`. Résiduel documenté : redirects cross-host + `recon_surface._http_get` re-résolvent (hors des 2 chokepoints).
- ✅ **T9** refactor archi exécuté : `main.rs` **6069 → 956 lignes** (tests → `tests.rs` `c683d18`, `build_router` → `router.rs` `d9af574`), 361 tests inchangés. Fix guard portabilité (exclut les modules de test extraits) — `d3b7362`.

**Plan initial (tranches — historique) :**
- **T1 — Intégrité ledger (WORM)** : `H1` purge hors verrou cross-process (`compliance.rs:377`) → perte d'écriture silencieuse + **test de course** · `M1` parité `canon_json` Rust/Python (`\b`/`\f`, `ledger_api.rs:78`) · `M2` `verify()` tolère ligne torn + flock (`ledger.py:292`).
- **T2 — Auth / tenancy** : `M3` Bearer périmé masque le cookie dans `tenancy.rs:70` (**même classe que C14, non propagée**) · `M4` SSO auto-lie un compte local par collision (`sso.rs:371`) · `L6` borne role SSO · `L7` SCIM membership transactionnel.
- **T3 — ROE / anti-rebinding SSRF** : `L1-L4` épinglage d'IP (résout au FIRE, connexion par-IP) `roe.py` · `L5` `_log` fail-safe · `L16` clamp `severity`.
- **T4 — Moteur / modules** : `M5` `finding_events` scopé · `M6` wrapper `ExecResult(ERROR)` FIRE · `M7` corrélation contenu origin · `L11/L12` caps parsing `net.rs` · `L14` race.py.
- **T5 — Data / runs** : `L8` delete-then-attest · `L9` `import_scan` RBAC/scope · `L10` 4 handlers async blocants.
- **T6 — Front quick-wins** : `L17` toasts good/warn · `L18` double-esc title · `I2` dead import · `I3` doc `write()`.
- **T7 — Architecture (plan incrémental)** : découpe `main.rs` (5911 l) + factorisation modules Python — opportuniste, JAMAIS big-bang.

## ✅ Résiduels traités (continuation)
- **T10** anti-rebinding — 2 chemins restants fermés : redirects cross-host (pinné sous règles ROE, ou 3xx non suivi si refusé) + `recon_surface._http_get` pinné, via helper partagé `pin.build_pinned_opener` (TLS/SNI préservés). `327bff4`. Résiduel LOW documenté : redirect cross-host d'une cible recon déjà pinnée re-résout (GET passif).
- **T11** archi étapes 2 & 4 — `tests.rs` → **11 fichiers `tests_*.rs`** (+ helpers → `testutil.rs`), `boot.rs` extrait. **`main.rs` 981 → 450 lignes**, 361 tests inchangés (default + postgres). `6859511`, `1c3a1a2` (contenu split dans `d59eeef` suite à une course worktree — code correct, commit mal étiqueté, pas de force-push).
- **T12** factorisation Python `FlagAllowlistMixin` — 5 modules migrés (web/recon/origin/recon_active/injection), byte-identical vérifié champ-par-champ, suite 1245 constante. `d69e487`→`05ad800`. SqliProbe garde son refus sqlmap bespoke.
- **M4 élargi (`ef80249`)** : login SSO accepte désormais les comptes **SCIM-managed** (déploiement SCIM+SSO combiné) ; comptes locaux non-marqués **toujours refusés** (propriété de sécurité M4 intacte), rôle SCIM préservé. 362 tests verts.
- **Résiduel LOW T10 — FERMÉ (T13, `e1b8093`)** : `recon_surface` gate désormais les redirects cross-host en fail-closed (re-résolution ROE via `safe_pinned_ip` + pin, ou 3xx non suivi). **Plus aucune re-résolution non-pinnée sur un chemin de cible.** crt.sh/Wayback byte-identical. 4 tests socket-level (teeth-verified). Suite 1249 verte.

### ✅ Session de remédiation TERMINÉE — audit holistique (31 findings) intégralement traité (T1→T12 + M4), aucun item de remédiation ouvert. Résiduels : **0 sécu ouvert** (T10 fermé par T13) ; cosmétique git (`d59eeef` — annoté via `git notes`, non corrigeable sans force-push interdit).

## Reste (hors bugs live)
- **2 items planifiés** (P5/P6 — LIVRÉS, voir §D) + choix **accepted-as-is**. Aucun item readiness / audit / sécurité non résolu.

---

# ✅ FAIT — par thème

## A. Readiness équipe / entreprise (dossier `fc2a18ca` — cf. `docs/READINESS_MATRIX.md`)
Les 11 écarts §03 + les 7 contrôles §07 sont **tous livrés et vérifiés sur le code**.
- **Postgres 0→4** — seam Store backend-neutre, dialect normalisé, backend PG feature-gated (`store-postgres`, OFF par défaut), boot/seed routés backend-actif, **pool de connexions + `RETURNING`** (writers concurrents), migrator gouverné `forge migrate-store` (FK-order, dry-run, verify, checkpoint ledger signé). `9e10c67 d48ab4b 1118f3b e188e2b`
- **HA / multi-instance** — `FORGE_HA` opt-in, leader-lease, run-leader (exécution leader-only, one-run-per-engagement **fencé DB**), ledger single-writer (verrou advisory unique, jamais de fork), cache-invalidation cross-instance, présence partagée, object-store S3/MinIO, manifests **k8s** + NetworkPolicies deny-by-default, HWM anti-troncature. `7ce53f7 c07231e 5a1fb4f b85ce1e 0c6fb99 3b74963 0ff4591 0abff20 0d127ee`
- **Multi-tenant** — `tenant_id` row-level, filtre grant fail-closed (sentinelle `NO_ENGAGEMENT`).
- **RBAC par-engagement** — grants `(user,tenant,engagement,role)`, most-specific-wins, intersecté fail-closed.
- **SSO / SCIM** — OIDC générique (PKCE/RS256/JWKS/discovery, **agnostique IdP** : Keycloak/Okta/Azure/Authentik/…), SCIM 2.0 ; SAML via bridge OIDC.
- **Matrice ATT&CK par-engagement** (exercé×détecté×MTTD) — `/api/attack-matrix` + vue grille. `613cd8d`
- **Vues sauvegardées + bulk-ops** + **pagination keyset/curseur**. `05a64ef`
- **Ownership + triage findings** — `assignee` grant-scopé + bulk-assign (`6723dab`) ; **workflow de triage gouverné** `new→triaging→{confirmed|false_positive|duplicate}→resolved` + `reopened`, transitions fail-closed, ledgerisé, **SSE live**. `b5257ba`
- **Export par-engagement** (HTML/PDF/CSV/JSON) + bulk-export.

## B. Qualité de code (cf. `docs/AUDIT.md`)
- **God-files scindés** behavior-neutral : `launch.js`/`admin.js`→packages `92759d1`, `runs.rs`→proc/ha/validate `ac568bd`, `cli.rs`→`cli/` + `compliance.rs`→policy/evidence `73eaea6`, `state.rs`→schema/detection `66ae602`, `backup.rs`→crypto/sched `bcfbf39`, `main()`→dispatch/serve `bc0244b`, `msf.py`→`_msgpack` `ab06a3a`.
- **Typage mypy** du cœur Python (`roe/ledger/planner/engine`) `41c44b4` · **dedup** `rand_hex`/`err`→`common.rs` `a52e117`.
- Grades : Rust *strong/production-leaning*, Python *A−*, Web *A−*.

## C. Sécurité (audit pentest / purple / DevSecOps — cf. `docs/SECURITY_AUDIT.md`)
Tous les findings **HIGH/MEDIUM/LOW exploitables corrigés** :
- **HIGH** : bypass scope-guard via redirect + exfil secrets session `a9678d3` ; IDOR cross-tenant run-endpoints `5504f5d` ; ATO SSO email-collision `40ff5dd`.
- **MEDIUM** : oracles non scope-gardés + discipline de preuve schéma-contrainte `a9678d3` ; SSO state/discovery/downgrade + SCIM `40ff5dd` ; k8s securityContext/PSA/MinIO-pin `855c3d1`.
- **LOW** : SSRF deny-list intégrations + reap process + drops audit observables + login lockout `e1b649e` ; canonical secret-redaction (fuite token fermée) `adbf6de` ; enterprise swallowed-writes + SQL value-binding `6216c70`.
- **Hygiène des clés** : création atomique `O_EXCL 0600` fail-closed `6f587b8` ; clé ledger hors volume RWX partagé (`FORGE_LEDGER_KEY` + signeur off-host) `3418d31`.
- **Portabilité vérifiée** : **0 couplage Authentik, 0 dépendance Vault** — secrets par env/fichier/k8s-Secret/PKCS#11.
- **KMS/HSM** : signeur **PKCS#11** Ed25519 opt-in (`docs/KEY_CUSTODY.md`) `d7fb893`.

## D. Expérience opérateur / UI-first
- **Onboarding zéro-étape** `55b5d03` — `docker compose up` sans aucun fichier → **wizard 5 étapes** (admin + **scope/ROE dans l'UI** + détection + opérateur). Plus de scope.json, plus de `useradd`.
- **Rename `forge-console` → `forge`** `cb55511` — l'app EST la console/UI (binaire+service+image+k8s+docs, DB `forge.db`).
- **Args custom par-outil dans l'UI** `0d19512 5c15dfd` — **26 kinds** avec `params_schema` typé + `flag_allowlist` conservatrice (nmap custom + nuclei + 20 ToolSpec + ffuf/sqlmap/httpx/subfinder), rendu dynamique, `extra_args` allowlisté no-shell.
- **Rate-limit** `3034616` — throttle moteur (token-bucket `Oracle._http`) + flags rate par outil + back-off 429/`Retry-After`/WAF + signal « throttled ». Défaut byte-identical.
- **Ajout d'outils par l'UI** `b6b8ee8` — `POST /api/tools` admin+ledgered, **ToolSpec gouverné** `custom.*` (no-shell, allowlist, traversal-safe, jamais built-in/`vulnerable`), hot-reload, form `admin/addtool.js`, `docs/TOOLS.md`.
- **CLI `--param KIND.KEY=VALUE` + curl/dig gouvernés** `f6a5281` — args par-run en CLL (précédence sur scope.json/workflow) ; `recon.curl` (fetch benin, pas d'exfil) + `recon.dig` (DNS) configurables UI+CLI.
- **Outils sans rebuild** `a237e11` — `dnsutils`(dig) dans l'image + `/opt/tools` sur `PATH` + **3 montages opt-in** (`./tools` binaires/scripts, `./plugins` FORGE_PLUGINS, `./toolspecs` FORGE_TOOLSPECS). « 3 façons » dans `docs/TOOLS.md` : image full / image custom `FROM forge` / **mount sans rebuild**. Binaire absent → `skipped` (jamais de faux résultat).
- **Secrets sans `.env` en clair** `83d47cc` — indirection **`*_FILE`** (Docker/k8s secrets) sur TOUS les secrets (token, passphrase backup, `FORGE_DB_KEY`, creds connecteurs MSF/Burp/Plume, PIN PKCS#11) : l'env porte un **chemin**, le secret vit dans un fichier monté root-owned. Détection & SSO déjà write-only UI. `docs/SECRETS.md`. Défaut byte-identical.
- **Console `forge` gouvernée DANS l'UI** `b4096bd` — panneau admin « Console Forge » : runner à **allowlist** (`status`/`ledger verify`/`read`/`backup`/`upgrade`), **argv fixe, jamais de shell**, args schéma-validés, `upgrade` exige `confirm`, destructifs (`restore`/`migrate-store`) exclus, secrets jamais échoués, ledgerisé, sortie **streamée SSE**. Supprime `docker compose exec` pour les ops courantes. `docs/CONSOLE.md`.
- **Notifications in-app** `6b6d518` — l'assigné est notifié sur assign/triage (cloche+badge+panneau, **grant-scopé**, own-only, live SSE). Complète ownership+triage.
- **Revue sécu de la nouvelle surface** `50c458a` — audit adverse post-features (console-exec/add-tools/args-custom/rate/secrets/wizard) : **0 Critical/High**, contrôles tiennent ; 3 notes Info (frontière admin) fermées : `dangerous_flag` élargi (exfil `-T`/`-K`/`-F`/`--upload-file`), **parité de validation** du loader Python (spec `FORGE_TOOLSPECS` = mêmes checks que l'API), note port-avant-provision.

## E. Déploiement & cycle de vie
- **Upgrade sûr une-commande** `131ee7d` — snapshot chiffré pré-upgrade → migrate → verify → **rollback auto** si échec ; `schema_version` + `forge status` ; `docs/UPGRADE.md`.
- **Re-déploiement idempotent** `fcc0be1` — seeding/`migrate()` idempotents, `upgrade` no-op = 0 écriture, pruning des snapshots ; aucun résidu ne ship (gitignore/dockerignore).
- **Backup chiffré + migrate vérifié** (argon2id + XChaCha20, chaîne vérifiée, offsite S3/MinIO).
- **Quickstart UI-first** `docs/QUICKSTART.md`.

## F. Couverture technique (cf. `docs/TECHNIQUE_COVERAGE.md`)
- **100 % des techniques web** des 439 findings FAISS → oracle natif Forge ; scanners → ToolSpec ; long tail → drop-in plugin. Hors-couverture = exclusions **par design** (DoS/cred-cracking/memory-safety native/LAN-spoofing/forensics), pas des lacunes.

---

# 🔜 RESTE À FAIRE

## Planifié — expérience opérateur
- **Rien de planifié — les items UX sont livrés** (onboarding zéro-étape, rename `forge`, args custom tous outils, rate-limit, ajout d'outils UI, secrets `*_FILE`, console `forge` dans l'UI). Voir §D.

## Décisions produit (actées)
- **Triage enrichi** → **notifications in-app LIVRÉES** (`6b6d518`). SLA / email / webhook **différés** : nécessitent une config de canaux (SMTP/webhook) — à construire sur demande, pas une dette.
- **Native in-process SAML** → **DÉCISION : ne pas construire.** Garder le **bridge OIDC** (Dex/Keycloak/oauth2-proxy) — SAML natif tirerait openssl+libxmlsec1 (casse openssl-free) et XML-DSig maison = foot-gun XSW. Feature `saml` optionnelle reste différée, uniquement si un contrat l'exige. (`docs/DEPLOYMENT.md §3ter`.)
- **KMS cloud** → **DÉCISION : pas de driver bespoke.** L'**exec-signer générique couvre déjà GCP-KMS Ed25519** — recette concrète dans `docs/KEY_CUSTODY.md` (`50c458a`). PKCS#11 couvre HSM/CloudHSM. AWS-KMS **impossible** (pas d'Ed25519).

## Résiduels sécurité — ASSUMÉS et documentés (cf. `docs/SECURITY_AUDIT.md §4`)
- **F4** — intégrité d'audit vs compromission **host-root** : **fermable en opt-in** (signeur off-host PKCS#11 + `WitnessAnchor`). Par défaut local + `NullAnchor` (byte-identique).
- **F6** — collecteurs de détection **fail-open by design** : alimentent le reporting/couverture, **jamais** une décision de FIRE (scope/ROE/ledger restent fail-closed).

## Accepted as-is (délibéré, pas du backlog caché)
- **~25 tests d'intégration router dans `main.rs`** — de vrais tests `build_router` end-to-end via un réseau de helpers partagés (pas des unit-tests mal rangés).
- **Sites `let _ = store.execute(...)` best-effort** (présence/GC/heartbeat/membership SCIM/cancel background) — fail-soft intentionnel sans attestation d'audit ; les swallowed-writes **porteurs d'audit** ont tous été corrigés.
- **Duplication chemins SQLite/PG** (quelques variants `_pg`/`_store`) — collapse sans gain de correctness, basse priorité.

---

# Annexes (détail conservé)

## Postgres — programme étagé (DONE)
- **Stage 0** seam DB-access + conversion modules · **Stage 1** normalisation dialecte (`?`/`$N`, `ON CONFLICT`, `->>`) · **Stage 2** backend PG feature-gated · **Stage 2b** (`9e10c67`) tout `db()` + seeding routés backend-actif, pool + `RETURNING` (`e188e2b`) · **Stage 3** (`d48ab4b`) migrator gouverné `forge migrate-store` · **Stage 4** (`1118f3b`) HA/ops (pool+timeouts, `/health` DB ping, `pg_dump`, docker-compose profile).
> Le ledger tamper-evident est un fichier (`jsonl`), pas en DB — Postgres n'affecte pas l'intégrité d'audit ; sous HA sérialisé par un verrou advisory unique (`0abff20`).

## SSO
- **OIDC** natif (`FORGE_ENTERPRISE_SSO` : Auth-Code+PKCE, RS256/JWKS, redirect-allowlist, groups→role) ; SAML-only via bridge externe (Dex/Keycloak/oauth2-proxy). SAML in-process **différé** derrière feature `saml` optionnelle (défaut openssl-free préservé). Détail `docs/DEPLOYMENT.md §3ter`.

## Deferred engineering — RÉSOLU
- `significant_drop_tightening` clippy **activé** (`3c7a5c4`) · `last_insert_id()` session-scoping **résolu** via `Store::execute_returning_id` (`e188e2b`).

## 🚀 Publication open-source (org `guatxlabs`) — plan & décisions (2026-07-19)

**Org GitHub** : `guatxlabs` (UNE org, repos séparés : `guatxlabs/forge` · `/core` · `/plume` · `/ocular`).
X : `@guatxlabs` (display « GuatX »). Reddit : poster dans r/netsec/r/redteamsec/r/rust (pas de subreddit dédié au lancement). URLs forge (README/CHANGELOG/DEPLOYMENT/Cargo.toml) réalignées sur `guatxlabs`.

**Licences — split lib/app :**
- `core` (guatx-core, la **lib partagée** liée par forge+plume) → **LGPL-3.0**.
- `forge` / `plume` / `ocular` (**applications**) → **AGPL-3.0** (garde le moat « pas de SaaS-fermé concurrent »). **Forge = AGPL inchangé** (97 headers SPDX intacts, aucune réécriture). Ocular est indépendant (ne lie PAS core). LGPL core + AGPL forge/plume = **compatible** (LGPL liable dans (A)GPL).

**B1 — build standalone (dép core) : git-dep maintenant → crates.io plus tard.**
- `console/Cargo.toml` **committé** = `guatx-core = { git = "https://github.com/guatxlabs/core", tag = "v0.1.0", features=["forge"] }`.
- **Override dev** : `console/.cargo/config.toml` **GITIGNORÉ** = `[patch."…/guatxlabs/core"] guatx-core = { path = "../../core" }` → garde la vitesse du path en monorepo sans dépendre du core publié. **Prouvé** : `cargo metadata --offline` résout vers le path local (git absent non touché) ; `cargo build --release` vert (1m01s) ; **Cargo.lock inchangé**.
- ⚠️ **Alignement tag** : `v0.1.0` DOIT être identique sur core/forge/plume (sinon un clone public ne résout pas la dép).
- ⚠️ **Chicken-egg** : publier `guatxlabs/core` + tag `v0.1.0` **EN PREMIER** (forge/plume en dépendent). Rebuild Docker forge **après** core publié (la git-dep résoudra pour de vrai ; d'ici là l'image déployée tourne sur le build path-dep antérieur, intacte).

**Prêt côté forge (public-ready)** : code (3 rounds d'audit + delta-audit, isolation tenant prouvée non-contournable, 0 CRITICAL/HIGH) · tests+couverture (1493 py / 385 rust / 106 core · **88%/84%**) · E2E UI complet (22 vues, 0 erreur JS ; contraintes loopback-strict+anti-rebinding contournées explicitement le temps du test puis restaurées) · fichiers communauté (README/SECURITY/CONTRIBUTING/CODE_OF_CONDUCT/CHANGELOG) · **historique clean** (271 commits, 0 vrai secret — uniquement des fixtures de redaction) · remote `vps` local-only (pas dans un clone public).

**Enforcement (famille GUATX)** : `GUATX/AGENTS.md` (convention partagée : mapping repo↔remote, discipline git, anti-clobber, hand-off cross-repo, actions gatées, §7 pre-receive) **existe déjà**. Hook `pre-receive` écrit+**testé à froid** (secret-scan **fixture-aware** HARD, trailer SOFT, gate tests optionnelle ; 4 cas verts) — **installer APRÈS le publish** (ne pas risquer un faux-positif bloquant la publication cette nuit).

**Stratégie de lancement** : publier le repo forge **bientôt** (soft — feedback/stars, polir les aspérités) ; réserver le **gros splash Reddit/X** pour le moment **purple-team Forge+Plume** ensemble (récit « red+blue open & souverain », plus fort avec les deux).

**Actions forge EN ATTENTE (feu vert humain)** : créer `guatxlabs/forge`+`/core` → `git remote add public …` + `git push public main` (je câble le remote local sur go ; le `push` tu le déclenches). **Périmètre** : core/plume/ocular (relicence, purge historique filter-repo, publication) = domaine user ; **forge = moi** ; coordination des actions par l'user (core d'abord).

**Historique forge : scrubé + signé (avant publication).** Identité réécrite → `GuatX <noreply@guatx.com>` (0 gmail perso, 0 xGuatx) ; **271/271 commits signés SSH** (ed25519, « Good signature ») ; config forge locale auto-signe les futurs commits ; 0 merge commit (historique linéaire). Force-pushé sur vps.

**Durcissement GitHub — ORDRE : pousser d'abord, verrouiller ensuite** (une règle « require PR » rejette le push initial ; « signed »/« linéaire » sont déjà satisfaites côté forge).
- *Fait côté repo forge (mon domaine)* : CI `permissions: contents: read` + toutes actions **SHA-pinnées** + gitleaks-action ; `.github/dependabot.yml` (cargo+github-actions, PR-only) ; `SECURITY.md` → GitHub advisories ; historique signé/linéaire.
- *À faire côté GitHub (domaine user, settings — pas d'accès d'ici)* : **ruleset sur `main` ET les tags** (bloquer force-push+suppression, exiger CI verte + commits signés + historique linéaire, **inclure les admins** sinon ça ne protège rien) ; **secret scanning + push protection** (équivalent natif du hook gitleaks, gratuit public — le hook VPS reste pour les remotes privés) ; **Private Vulnerability Reporting** (sinon le canal de SECURITY.md n'existe pas) ; **CodeQL** en UI « default setup » (python+javascript ; Rust non couvert → cargo-audit CI) ; **Dependabot** alertes+MàJ (piloté par le `.github/dependabot.yml`) ; **réglages Actions** (GITHUB_TOKEN read-only, interdire aux Actions de créer/approuver des PR, approbation requise pour workflows de contributeurs externes, actions tierces pinnées SHA) ; **désactiver wiki+projects** si inutilisés ; **ajouter la clé ed25519 comme _Signing Key_** + **vérifier `noreply@guatx.com`** (sinon commits signés = « Unverified »), activer le **mode vigilant APRÈS**.

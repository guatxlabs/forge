<!-- Audit holistique multi-agents (54 agents, findings verifies adversarialement) — 2026-07 -->

# Rapport d'audit holistique — Forge

## 1. Synthèse exécutive

La posture de sécurité de Forge est **globalement saine**. Sur 31 findings confirmés adversarialement, **aucun n'est critique et un seul est HIGH** ; l'immense majorité (20 LOW + 3 INFO) relève du durcissement défense-en-profondeur, de la robustesse ou de la dette d'architecture — pas de vulnérabilité exploitable par un attaquant anonyme ou un utilisateur à privilège moindre. Les garde-fous cœur du moteur gouverné (scope-guard fail-closed, ROE « jamais FIRE sans armement », ledger WORM tamper-evident, RBAC/tenancy multi-locataire) sont présents et cohérents ; les défauts trouvés sont surtout des **écarts d'uniformité** — un chemin qui n'a pas reçu le durcissement appliqué à ses voisins.

Trois risques dominent et méritent une action ciblée : **(1) le HIGH `compliance.rs:377`** — le purge du ledger réécrit le fichier hors du verrou cross-process, rouvrant la perte-d'écriture silencieuse que le WORM est censé interdire ; **(2) un cluster d'intégrité ledger↔DB** (parité canon_json Rust/Python, verify() trop strict, attestations écrites avant/sans le commit DB) qui peut faire lire un ledger honnête comme « CASSÉ » ou attester une mutation qui n'a jamais eu lieu ; **(3) un cluster ROE/SSRF anti-rebinding** dont la garantie annoncée (« point ANTI-REBINDING ») n'est pas réellement appliquée faute d'épinglage d'IP. Ces trois thèmes sont concentrés, bien délimités, et corrigeables sans réécriture.

---

## 2. Tableau de bord

### Par sévérité

| Sévérité | Nombre |
|----------|:------:|
| CRITICAL | 0 |
| **HIGH** | **1** |
| MEDIUM | 7 |
| LOW | 20 |
| INFO | 3 |
| **Total** | **31** |

### Par dimension

| Dimension | HIGH | MEDIUM | LOW | INFO | Total |
|-----------|:----:|:------:|:---:|:----:|:-----:|
| security | 1 | 2 | 7 | 1 | 11 |
| correctness | 0 | 5 | 6 | 0 | 15 |
| architecture | 0 | 0 | 3 | 2 | 5 |

### Par cluster (thème)

| Cluster | Findings | Thème dominant |
|---------|:--------:|----------------|
| rust-ledger | 2 | Intégrité WORM (purge, canon parité) |
| py-io | 2 | Intégrité ledger / validation schema |
| rust-auth | 4 | SSO/tenancy/SCIM auth |
| py-roe | 5 | ROE / SSRF / anti-rebinding |
| py-engine | 3 | Robustesse campagne / budget / dup |
| py-modules | 3 | Proof discipline / crash module |
| rust-runs | 3 | Tenancy import / blocage async / IPv6 |
| rust-data | 2 | SSE cross-tenant / delete attest |
| rust-core | 2 | net.rs (buffering / overflow) |
| js-core / js-views | 5 | Cosmétique / duplication front |

---

## 3. Findings prioritaires (regroupés par sévérité et thème)

### 🔴 HIGH (1)

#### H1 — Le purge du ledger contourne le verrou cross-process → perte d'écriture silencieuse, WORM défait
- **Dimension** : security · `console/src/compliance.rs:377`
- **Impact concret** : `purge()` ne prend QUE le mutex Rust in-process (`app.ledger_lock`), pas le `FlockExclusive` ni le `ha::with_ledger_lock` (advisory lock PG) que prennent tous les appends. Il snapshotte le fichier, construit/chiffre l'archive (I/O DB de plusieurs ms à s), puis **remplace l'inode entier** via `backup_write_atomic` (write tmp + rename). Un append du moteur Python (`forge/ledger.py`, flock) ou d'un pair HA qui tombe dans la fenêtre snapshot→rename écrit sur l'ancien inode que le rename délie → **l'entrée d'audit signée ed25519 est détruite définitivement**, sans déclencher `signed_survivor` (elle n'était pas dans le snapshot), et `/api/ledger/verify` continue de répondre `ok`. C'est exactement la perte-d'écriture cross-process que le flock existait pour empêcher. Gated admin + flag, déclenchement dépend du timing — mais la perte est **silencieuse et indétectable**, ce qui annule la finalité tamper-evidence du module.
- **Correctif** : exécuter le snapshot→réancrage→rename dans le MÊME section critique cross-process que les appends — prendre `FlockExclusive` sur tout le read+rewrite (+ `ha::with_ledger_lock` sous HA), relire la queue sous le verrou juste avant d'écrire et abort si le fichier a changé. Comme le rename remplace l'inode, les appenders doivent honorer un verrou path-keyed (pas seulement flock sur le fd) — ou réécrire in-place sous flock plutôt que via rename. Ajouter un test de course (appender style-moteur martelant le fichier pendant un purge) prouvant zéro entrée perdue.

---

### 🟠 MEDIUM (7)

**Thème A — Intégrité du ledger (3 findings, à traiter avec H1)**

#### M1 — `canon_json` diverge de Python pour 0x08/0x0c → fausses alarmes « entrée altérée »
- **Dimension** : correctness · `console/src/ledger_api.rs:78`
- **Impact** : `canon_str` émet `\u0008`/`\u000c` là où `json.dumps` Python émet les escapes courts `\b`/`\f`. Toute entrée moteur (Python) contenant ces octets dans un champ `detail` (titre de finding, kind ROE — donc **injectable par ingestion**) produit un préimage différent côté Rust → `verify_ledger_chain` renvoie `ok:false why="entrée altérée"` sur une entrée légitime, faisant basculer `/api/ledger/verify` et l'attestation `chain_ok` du bundle de preuve.
- **Correctif** : ajouter dans `canon_str` `'\u{0008}' => "\\b"` et `'\u{000c}' => "\\f"` AVANT l'arm générique `< 0x20`. Test de parité : `canon_json` de chaque octet de contrôle 0x00..0x1f == `json.dumps(..., ensure_ascii=False)`.

#### M2 — `verify()` traite toute ligne malformée comme falsification (contredit la tolérance crash de `append`/`_disk_tail`)
- **Dimension** : correctness · `forge/ledger.py:292`
- **Impact** : un crash mid-write laisse une ligne tronquée `T` ; le prochain `append` l'isole (`\n`) et chaîne après → `T` devient une ligne intérieure. `verify()` rejette la première ligne non-parsable → **ledger honnête lu comme « CASSÉ ❌ » de façon permanente**. En prime, `verify()` lit sans flock (LOCK_SH) → faux positif transitoire sur append concurrent (cas multi-process visé par le module).
- **Correctif** : aligner `verify()` sur `_disk_tail` — ignorer la DERNIÈRE ligne non-vide si elle échoue au parse (ne déclarer tamper que pour une ligne intérieure), et prendre le flock partagé autour de la lecture. Le HWM couvre déjà la vraie troncature.

**Thème B — Authentification / isolation multi-locataire (2 findings)**

#### M3 — Tenancy refuse un utilisateur valablement authentifié (cookie) si un Bearer périmé est présent
- **Dimension** : correctness · `console/src/tenancy.rs:70`
- **Impact** : `auth_guard` utilise le résolveur dual-candidat (`resolve_session_identity` : Bearer OU cookie), mais `caller_user_id` utilise `session_token_from_headers` (Bearer prioritaire, single-candidat). Un user avec cookie valide + Bearer périmé/étranger (résidu fréquent d'ancien build front) est **admis puis traité sans grant** → voit zéro engagement/finding/run et ne peut pas opérer, en mode entreprise. Fail-closed (pas d'escalade) mais déni d'accès légitime. Le code lui-même documente que le fix n'a pas été propagé au chemin tenancy (`auth.rs:345-346`).
- **Correctif** : résoudre `caller_user_id` via la MÊME logique dual-candidat ; idéalement exposer le `user_id` résolu depuis `resolve_session_identity` et le réutiliser, pour qu'auth et tenancy ne puissent plus diverger.

#### M4 — SSO auto-lie et re-rôle un compte LOCAL préexistant par collision de login
- **Dimension** : security · `console/src/sso.rs:371`
- **Impact** : `map_user` retourne tout compte `users` préexistant dont le login égale le claim OIDC sanitisé, sans marqueur SSO/consentement, puis `apply_to_user` **écrase `users.role`** selon le claim `groups` de l'IdP. En mode `user_claim=sub`, la garde `require_email_verified` est contournée : un `sub` attaquant qui sanitise vers un login privilégié existant s'authentifie AS ce compte. Un admin local qui clique « Sign in with SSO » peut aussi être silencieusement rétrogradé. Gated flag entreprise + SSO configuré ; exploitabilité réelle dépend de l'IdP (opaque-sub mainstream = impraticable ; réaliste surtout en sub-mode username/self-asserted).
- **Correctif** : ne pas auto-adopter un compte sans marqueur `sso_managed`/`external_subject` — exiger un lien admin explicite avant qu'une identité SSO puisse s'authentifier comme, ou re-rôler, un login local existant. Appliquer `require_email_verified` aussi au mapping `sub`-keyed ; jamais re-rôler au PREMIER login SSO sauf compte créé par SSO/SCIM.

**Thème C — Fuite de métadonnées cross-tenant (1 finding)**

#### M5 — Le SSE `finding_events` diffuse les transitions de triage cross-tenant (aucun scoping)
- **Dimension** : security · `console/src/findings.rs:732`
- **Impact** : `finding_events(State(app))` n'a ni `HeaderMap` ni `ConnectInfo` — il ne peut structurellement pas résoudre l'identité/les grants. Il forwarde tout event `run_id==FINDINGS_TOPIC` à tout abonné authentifié. Le payload porte `finding_id`, from/to state, `engagement`, et `by` (login de l'acteur). Sous tenancy ON, un viewer grant-é uniquement sur le tenant A **reçoit en direct qui triage quoi sur le tenant B**. Tous les autres chemins de lecture sont scoped via `resolve_view_engagement_id` ; ce SSE est l'exception (le sibling `presence_events` scope correctement). Fuite de métadonnées + logins, pas de contenu.
- **Correctif** : donner un `HeaderMap` à `finding_events` et dropper chaque event sauf si `tenancy::engagement_visible(...)` (no-op en community). Alternative : réduire le payload à un signal contentless « re-fetch » et laisser `/api/findings` (déjà scopé) faire le re-fetch.

**Thème D — Robustesse moteur / discipline de preuve (2 findings)**

#### M6 — Exception non capturée dans `module.fire()` → toute la campagne avorte, rapport anti-masquage perdu
- **Dimension** : correctness · `forge/engine.py:248`
- **Impact** : `raw = module.fire(action) or []` n'est enveloppé dans aucun try/except (ni `run()` ni la boucle `campaign()`). Une exception d'un module (ex : `msf.py` fait `int()`/`float()` sur des params opérateur hors de son propre try/except) remonte jusqu'à `cmd_campaign` et **crashe tout l'engagement** : vagues/cibles restantes jamais tentées, `coverage()`/`skipped_budget`/rapport/checkpoint ledger jamais produits — violation directe du contrat « zéro lacune silencieuse ». Les 4 autres chemins de `execute()` produisent un `ExecResult(SKIP/ERROR)` traçable ; le chemin FIRE est l'exception.
- **Correctif** : envelopper le corps FIRE dans un try/except produisant `ExecResult(Verdict.ERROR, reasons=[repr(e)])`, l'append à `results` + ledger, puis continuer la vague suivante — comme le chemin no-module. Le finding manquant devient un ERROR visible, pas un crash.

#### M7 — Origin-behind-CDN promu `vulnerable`/HIGH sur le code de statut seul (403 inclus)
- **Dimension** : correctness · `forge/modules/origin.py:195`
- **Impact** : `verified` est vrai si httpx contre `http://IP` avec `Host:` spoofé renvoie 200/301/302/**403**. Un statut — surtout 403 — ne prouve pas que l'IP sert le site : shared-hosting, vhost par défaut, WAF deny-by-default renvoient couramment 200/403 à un Host arbitraire. Cela **fabrique un finding HIGH `vulnerable` sans corrélation de contenu** (pas de comparaison body/title/hash), en contradiction avec le docstring du module lui-même. Casse la proof discipline qui réserve `vulnerable` à la preuve cross-vérifiée.
- **Correctif** : exiger une corrélation de contenu positive avant promotion (hash normalisé / title / `origin_marker` contre la baseline CDN) ; retirer 403 du set `verified` (ou le traiter comme `tested` inconclusif).

---

### 🟡 LOW (20) — regroupés par thème

**Cluster ROE / SSRF / anti-rebinding (`forge/roe.py`) — 5 findings, à traiter ensemble**
Plusieurs pointent la même racine (`getaddrinfo` à `roe.py:257`, résolution unique au decide-time) :

| # | Titre | file:line | Correctif convergent |
|---|-------|-----------|----------------------|
| L1 | Anti-rebinding non appliqué — DNS résolu une fois, jamais épinglé à la connexion (TOCTOU) | roe.py:257 | **Épingler l'IP validée** et forcer le module à se connecter à CETTE IP (Host header conservé), ou re-valider l'IP effective au connect. |
| L2 | `getaddrinfo` sans timeout + sans cache à chaque `decide()` (stall/DoS liveness) | roe.py:257 | Timeout borné (thread + join, ou `setdefaulttimeout` scopé) + cache par host pour la durée du run ; fail-closed (VETO) sur timeout. |
| L3 | DNS résolu même en `forge plan`/dry (I/O réseau en chemin « inerte », fuite d'intention opsec) + TOCTOU | roe.py:257 | Ne résoudre qu'au point FIRE (pas en simulation) ; combiner avec l'épinglage L1. |
| L4 | `out_scope` CIDR ignore un hostname qui résout dans la plage (matching littéral only, asymétrie avec le veto privé) | roe.py:238 | Pour un pattern CIDR/IP en `out_scope`, tester aussi les IP résolues de la cible (réutiliser la résolution de `is_private_target`). |
| L5 | Échec d'écriture ledger dans `_finish()` échappe à `decide()` → viole « toute erreur ⇒ VETO » | roe.py:365 | Try/except autour de `ledger.append` dans `_log` : construire la Decision puis logger ; le log ne doit jamais changer/abort un verdict fail-closed. |

> **Note** : L1/L3 sont deux facettes du même défaut anti-rebinding ; un seul chantier (épinglage d'IP + résolution FIRE-only + timeout/cache) ferme L1, L2, L3 et adoucit L4. Recommandation : traiter comme **un mini-chantier `roe.py` unifié**.

**Cluster auth Rust (`sso.rs`/`scim.rs`) — 2 findings**

| # | Titre | file:line | Correctif |
|---|-------|-----------|-----------|
| L6 | SSO auto-provisioning `default_role` accepte `admin` (parité manquante avec SCIM qui l'interdit) | sso.rs:503 | Borner `default_role` à `viewer\|operator` (rejeter `admin`), exiger un mapping group→admin explicite. Foot-gun admin, pas escalade. |
| L7 | SCIM group remove/replace avalent les erreurs DB mais loggent le succès (divergence ledger↔DB) | scim.rs:836 | Matcher le `Result` de chaque DELETE membership, envelopper PUT/PATCH dans un `with_tx`, 500 avant le ledger sur échec. |

**Cluster intégrité ledger↔DB (attestations) — 1 finding (à rapprocher de M2/M1/L7)**

| # | Titre | file:line | Correctif |
|---|-------|-----------|-----------|
| L8 | `engagement_do_delete` écrit l'entrée ledger « delete » AVANT la transaction → atteste un rollback | engagements.rs:526 | Exécuter le cascade-delete d'abord ; n'appender l'entrée ledger dédiée que sur `Ok(())`. Ordre delete-then-attest, comme tous les handlers voisins. |

**Cluster tenancy / async runs (`console/src/`) — 2 findings**

| # | Titre | file:line | Correctif |
|---|-------|-----------|-----------|
| L9 | `import_scan` saute la RBAC per-engagement + filtre contre le scope GLOBAL (findings landent en engagement #1) | runs.rs:373 | Résoudre l'engagement cible, enforcer `can_operate_engagement`, construire `scope.json` depuis le scope de l'engagement — comme `run_create`. |
| L10 | `std::process::Command::output()` bloquant dans 4 handlers async → stalle les workers Tokio | planning.rs:236 (+398, 634, runs.rs:435) | Remplacer par `tokio::process::Command(...).output().await` ou `spawn_blocking`, comme `runs_proc.rs:257`/`exec.rs:384`. |

**Cluster net.rs (parsing HTTP intégré) — 2 findings**

| # | Titre | file:line | Correctif |
|---|-------|-----------|-----------|
| L11 | Buffering de réponse non borné (`read_to_end`, timeout par-read) → épuisement mémoire | net.rs:187 | `stream.take(MAX_RESPONSE_BYTES).read_to_end(...)` + deadline wall-clock. Source admin-configurée (trust boundary), donc défense-en-profondeur. |
| L12 | Overflow entier dans `dechunk` (`start + size`) → panic sur chunk-size malicieux (contenu par `spawn_blocking`) | net.rs:232 | `checked_add` + borne de taille de chunk cohérente avec le cap de L11. |

**Cluster robustesse modules Python — 3 findings**

| # | Titre | file:line | Correctif |
|---|-------|-----------|-----------|
| L13 | Budget planner remis à zéro à chaque vague → plafond global non implémenté + critère d'arrêt #3 inexistant | engine.py:447 | Porter un budget résiduel (`self._budget_left`) décrémenté inter-vagues, OU corriger le docstring pour documenter `--budget` comme par-vague. |
| L14 | `race.condition` crashe sur `success_codes` malformé (`int(c)` non gardé) | race.py:93 | Try/except autour de la conversion `int()`, skip des entrées invalides, `skip` finding sur vide/invalide (contrat « ne lève jamais »). |
| L15 | Option-smuggling : le garde ignore les positionnels `{param:NAME}` dans l'argv ToolSpec | toolspec.py:213 | Appliquer `safe_value`/`_dangerous_flag` aux valeurs de param positionnelles résolues commençant par `-`/`--`. Seul cas embarqué réel = `dig record_type` (impact faible). |

**Cluster validation schema — 1 finding**

| # | Titre | file:line | Correctif |
|---|-------|-----------|-----------|
| L16 | `severity` non validée contre `SEVERITIES` → findings à sévérité invalide absents de la synthèse | schema.py:135 | Dans `__post_init__` : `self.severity` normalisé/validé fail-closed vers `INFO` si hors-liste, cohérent avec le traitement de `status`. |

**Cluster front cosmétique (js) — 2 findings**

| # | Titre | file:line | Correctif |
|---|-------|-----------|-----------|
| L17 | Double-échappement de `login`/`role` dans la propriété DOM `.title` (entités littérales affichées) | presence.js:58 | Retirer `esc()` sur les assignations `.title` (propriété texte, pas d'innerHTML — pas de XSS). |
| L18 | Toasts utilisent des kinds indéfinis `'good'`/`'warn'` → styling neutre au lieu de succès/warning | identity.js:60 (+admin/addtool.js:197) | Remplacer `'good'`→`'ok'`, `'warn'`→`'info'` (ou ajouter `.toast.warn` en CSS) ; normaliser les kinds inconnus vers `'info'`. |

**Cluster duplication / architecture — 2 findings LOW**

| # | Titre | file:line | Correctif |
|---|-------|-----------|-----------|
| L19 | Logique du panneau grants dupliquée quasi-verbatim entre `engagements.js` et `tenancy.js` (~80 lignes) | engagements.js:257 | Extraire `components/grants-panel.js` (`mountGrantsPanel({row, colSpan, listUrl, addUrl, roles, extraTables})`) + `loginError` partagé. |
| L20 | `cmd_doctor_purple` (legacy Plume) duplique `_doctor_source_preflight` (~40 lignes) | purple.py:173 | Extraire `_render_purple_preflight(...)` + `_console_health_line(...)`, faire converger les deux préflights. |

---

### ⚪ INFO (3)

| # | Titre | file:line | Note |
|---|-------|-----------|------|
| I1 | Classifier IPv6 privé rate les adresses IPv4-compatible (`::a.b.c.d`) embarquées | runs.rs:60 | Trou de complétude dans un garde annoncé « miroir exact » de `roe.py::_ip_is_private`. Non routé par les stacks modernes → pas de SSRF réel. Ajouter le fold-through + tests `::127.0.0.1`/`::10.0.0.5`, garder Rust/Python en lock-step. |
| I2 | Contrat `write()` périmé : la doc annonce des modes auth (`'token'`=Bearer) que le code n'implémente plus | api.js:36 | 0 appelant utilise `'token'`. Aligner la doc sur l'implémentation OU rejeter explicitement un `auth` inconnu. |
| I3 | Import module-level `editing` mort, shadowé par un `const` local | workflows.js:2 | Supprimer l'import de `dashboards.js` (dead code + hazard de shadowing). |

---

## 4. Plan de remédiation (incrémental, priorisé — surtout PAS « tout réécrire »)

### (a) Quick wins — < 1 jour, corrections ciblées, faible risque

| Item | Findings | Effort | Risque |
|------|----------|:------:|:------:|
| Parité `canon_json` (2 escapes `\b`/`\f`) + test | M1 | ~1h | **Très faible** — 2 lignes + test, comportement rendu conforme à Python. |
| `verify()` tolère la dernière ligne torn + flock LOCK_SH | M2 | ~2h | Faible — direction fail-safe, HWM couvre la vraie troncature. |
| `severity` validée fail-closed dans `__post_init__` | L16 | ~30min | Très faible — miroir du clamp `status` existant. |
| `race.py` try/except sur `success_codes` | L14 | ~30min | Très faible. |
| `roe.py` `_log` try/except (log ne casse pas le verdict) | L5 | ~1h | Faible — durcit le fail-closed. |
| Toasts `good`/`warn` + `.title` double-esc + dead import + doc `write()` | L17, L18, I2, I3 | ~1h total | Nul — cosmétique/mort. |
| SSO `default_role` borné à viewer/operator (parité SCIM) | L6 | ~30min | Faible — rejette une valeur dangereuse en config. |
| `checked_add` + cap dans `dechunk` ; cap `read_to_end` | L11, L12 | ~1h | Faible — durcit du parsing d'input non fiable. |

### (b) Chantiers moyens — 1 à 3 jours, correction structurée + tests

| Item | Findings | Effort | Risque |
|------|----------|:------:|:------:|
| **Purge sous verrou cross-process** (flock + `with_ledger_lock` sur snapshot→rewrite, re-read sous verrou, appenders honorent un lock path-keyed) + **test de course** | **H1** | 2-3j | **Moyen** — touche le cœur WORM ; exige le test de course pour prouver la non-régression. **Priorité #1.** |
| Épinglage d'IP anti-rebinding unifié (`is_private_target` retourne l'IP, module se connecte par-IP, résolution FIRE-only, timeout + cache, out_scope CIDR résout) | L1, L2, L3, L4 | 2j | Moyen — modifie l'interface Decision→module ; bien cadré, tous dans `roe.py` + couche connexion. |
| `caller_user_id` dual-candidat + exposer le `user_id` résolu depuis `resolve_session_identity` | M3 | 1j | Faible-moyen — unifie auth/tenancy, réduit la divergence future. |
| Wrapper `ExecResult(ERROR)` autour de FIRE dans `engine.py` | M6 | ~4h | Faible — aligne le chemin FIRE sur les 4 autres. |
| `finding_events` scopé (HeaderMap + `engagement_visible`) ou payload contentless | M5 | 1j | Faible — no-op en community. |
| SSO no-auto-adopt d'un compte non-marqué SSO (binding explicite) | M4 | 1-2j | Moyen — touche le flow de provisioning ; bien gated (flag off par défaut). |
| `origin.py` corrélation de contenu avant promotion HIGH | M7 | ~4h | Faible. |
| SCIM membership transactionnel (`with_tx` + match Result) | L7 | ~4h | Faible. |
| `import_scan` tenancy RBAC + scope per-engagement | L9 | ~4h | Faible — copie le pattern `run_create`. |
| `engagement_do_delete` : delete-then-attest | L8 | ~2h | Faible — réordonnancement + test rollback. |
| 4 handlers async : `tokio::process` / `spawn_blocking` | L10 | ~4h | Faible — pattern déjà présent ailleurs. |

### (c) Refactors d'architecture — plan incrémental, JAMAIS un big-bang

Ces items sont de la **dette de duplication/lisibilité**, pas des bugs. À faire **opportunistiquement** quand on touche déjà la zone, jamais comme réécriture spéculative.

1. **Factorisation front des panneaux grants** (L19) — extraire `components/grants-panel.js` + `loginError` partagé. Effort ~0.5j, risque faible. *Déclencheur : prochaine évolution de l'un des deux panneaux.*
2. **Factorisation préflight purple** (L20) — `_render_purple_preflight` + `_console_health_line`. Effort ~0.5j, risque faible.
3. **Découpage de `main.rs` (~5911 l)** — **incrémental et guidé par les couplages, pas un split cosmétique**. Approche proposée :
   - Étape 1 : extraire le **montage du router** (les `.route(...)` par domaine) dans des modules `routes_<domaine>.rs` qui exposent un `fn mount(router) -> router`. Zéro changement de logique, purement mécanique, testable par « le binaire compile + smoke test des routes ». Effort ~1j, risque faible.
   - Étape 2 : regrouper l'état applicatif (`App`) et ses helpers de résolution (`resolve_engagement`, tenancy) dans un module dédié si `main.rs` reste gros après l'étape 1.
   - **Ne PAS** viser un `main.rs` « propre » d'un coup ; chaque extraction doit laisser le build vert et passer les tests existants (258 Python + 31 Rust déjà en place selon la mémoire projet).
4. **Consolidation IPv6/IP-privé Rust↔Python** (I1) — un seul jeu de tests de littéraux partagé conceptuellement entre `runs.rs::v6_is_private` et `roe.py::_ip_is_private`, avec les cas IPv4-compatible ajoutés des deux côtés en lock-step. Effort ~2h.

**Séquencement recommandé** : (a) quick wins d'abord (ferment M1/M2/L16 et durcissent le fail-closed à peu de frais) → puis **H1 en priorité absolue** → puis le mini-chantier ROE unifié → puis les chantiers moyens auth/data → refactors uniquement à l'occasion.

---

## 5. Angles morts / non couverts par cet audit (honnête)

1. **Pas de test dynamique/runtime** — findings dérivés de la lecture de code + vérification adversariale statique. Les défauts de timing (H1, M2 transitoire, L10) sont **plausibles mais non reproduits sous charge réelle** ; il manque un test de course concret pour H1 et un bench de saturation des workers pour L10.
2. **Cryptographie non auditée en profondeur** — la signature ed25519 du ledger, la dérivation de clés du `backup_encrypt`, et la robustesse du chiffrement d'archive n'ont pas été analysées (choix d'algos, gestion des nonces, rotation de clés).
3. **Modèle de menace IdP/SSO partiellement couvert** — M4/L6 supposent des comportements d'IdP ; la validation complète des tokens OIDC (sig/iss/aud/nonce/exp, `jwks` rotation, clock-skew) n'a pas été revue exhaustivement.
4. **Dépendances tierces / supply-chain** — pas d'audit des crates Rust / paquets Python (versions vulnérables, `cargo audit`/`pip-audit`), ni des ToolSpecs invoquant des outils externes (nuclei, msf, etc.) au-delà du finding option-smuggling (L15).
5. **Concurrence HA / multi-process au-delà du ledger** — le finding H1 met en lumière un mode de course ; d'autres ressources partagées (DB SQLite locks, `App.events` bus, fichiers de config) n'ont pas fait l'objet d'une analyse de course systématique.
6. **Front-end au-delà du cosmétique** — CSP, gestion des tokens côté client, stockage des secrets opérateur (`OPERATOR_SECRET`), XSS DOM au-delà de `.title`, et les flux d'authent côté JS n'ont été touchés que superficiellement.
7. **`msf.py`/modules à forte surface** — signalés comme source de M6 (params non gardés) mais non audités ligne-à-ligne ; d'autres modules `contrib/`/`plugins/` (framework explicitement pluggable) peuvent porter des défauts analogues non listés.
8. **Couverture de tests réelle** — l'audit constate l'existence de tests mais n'a pas mesuré leur couverture des chemins d'erreur/fail-closed (précisément là où plusieurs findings se logent : M6, L5, L14).

> **Posture globale** : saine et défendable. Le cœur gouverné tient ; l'essentiel du travail est de **propager l'uniformité** des garde-fous (verrou cross-process, épinglage d'IP, parité canon, attestations post-commit) aux quelques chemins qui l'ont manquée — un effort de durcissement ciblé, pas une refonte.
# Architecture — comment Forge est construit

> [Sommaire](README.md) · Prérequis : [Vue d'ensemble](OVERVIEW.md) · Approfondir :
> [Concepts](CONCEPTS.md) · [Modèle de sécurité](SECURITY_MODEL.md)
>
> Le **rationale de design** (public/privé, cœur partagé, réutilisation secpipe/Plume) vit dans
> [`../ARCHITECTURE.md`](../ARCHITECTURE.md). Cette page décrit **les composants réels** et leur
> câblage, à jour du code.

## 1. Vue macro — trois processus, un contrat

```
GUATX/
  core/          guatx-core (lib Rust NEUTRE, publique) — le ~70 % commun (moteur soql v0)
  plume/         Plume (SOC bleu, public) — détection / BAS  [OPTIONNEL pour Forge]
  forge/         Forge (rouge) :
    forge/         MOTEUR Python (gate ROE, ledger, modules, oracles, évasion, collecteurs)
    console/       CONSOLE Rust (axum + rusqlite) — store rouge + API + RBAC + C2-light + dashboards
    console/web/   SPA vanilla-JS (skin Ember, dark) — findings / coverage / purple / runs / admin
```

Il n'y a **pas de process partagé** entre les couches : le moteur Python et la console Rust
communiquent par un **contrat HTTP/fichier** (`POST /api/ingest`, JSONL de run-records, ledger
JSONL sur disque). La console **spawne** le moteur (`python3 -m forge.cli campaign …`) pour les runs
lancés depuis le web (voir §3, C2-light). La console dépend du crate `guatx-core` en dép `path`
(voir [`DEPLOYMENT.md`](DEPLOYMENT.md) §4 pour la migration future en dép `git`).

**Empreinte** (mesurée) : moteur Python ~5.3 KLOC (`deps=[]`), console Rust ~4 KLOC, `guatx-core`
~1 KLOC, UI ~3.5 KLOC. Livrable cœur ≈ 5 MB ; image Docker 150-250 MB (mini) à 350-500 MB (full).
Chiffres et matrice de déploiement : [`DEPLOYMENT.md`](DEPLOYMENT.md) §6.

## 2. Le moteur Python (`forge/`)

Le moteur est **pur-stdlib** et INERTE par défaut. Sa boucle de contrôle : `plan → gate ROE →
dry|fire → ledger → findings`.

### 2.1 Cœur de sûreté

| Fichier | Rôle |
|---|---|
| `roe.py` | `Scope` (appartenance fail-closed) + `Roe` (gate 4 couches) + `Action`/`Decision`. **Le cœur.** |
| `ledger.py` | Ledger append-time : hash-chain SHA-256 + signature par-entrée + `verify()`/`verify_external()`, alg-aware (multi-algos). |
| `signing.py` | Signeurs : `Ed25519Signer` (défaut, non-répudiation) + repli `HmacSigner` (stdlib) ; `CONSOLE_ALG` (`sha256-console`) pour les entrées écrites par la console. |
| `anchor.py` | Ancrage hors-host : interface `Anchor` + témoin co-signataire + `reconcile` (détecte une réécriture re-signée localement). |
| `schema.py` | `Finding` (+ `mitre`, `status`, `cwe`, `fix`, `cvss_*`), `Target`, `Campaign`. Enrichissements additifs fail-open. |

**Invariant central** : un module n'est appelé en `fire()` **que** sur un verdict `FIRE`. En
`DRY_RUN`, seul `dry()` (génère le PoC, aucun effet de bord). En `VETO`, rien. Toute erreur
d'évaluation ⇒ `VETO` (fail-closed).

### 2.2 Orchestration

| Fichier | Rôle |
|---|---|
| `engine.py` | La boucle. `execute()` (une action), `run()` (liste), `campaign()` (**itératif** : plan → observe → replan sur `max_waves`). Applique la gouvernance des connecteurs, l'injection de scope pour la découverte, la session gouvernée, le dedup mémoire, l'émission des run-records purple. |
| `planner.py` | **Planner coverage-safe** : ordonne par EV = `value·confidence/cost`, avec un **FLOOR** sur les classes qualifiantes (IDOR/auth/RCE/SSRF/biz…) pour qu'une voie payable ne soit jamais affamée. `defer != delete` : hors-budget → `skipped_budget` (visible). |
| `brain.py` | Interface `Brain.propose(graph) -> [Action]`. `HeuristicBrain` = défaut autonome (cible → classes + chaînage sur findings). C'est le **seam** où l'orchestrateur Claude peut se brancher comme cerveau. |
| `graph.py` | `EngagementGraph` — world-model hosts→services→findings, enrichi à chaque vague (support du chaînage). |
| `techniques.py` | **Registre unique de techniques** (source de vérité) : mappe `kind`/classe/CWE → `Technique` (ATT&CK, CWE, qualifiant, remédiation, tactique/phase/capability). `planner`, `brain`, `schema`, `purple` en **dérivent** leurs vues (plus de recopie). |
| `purple.py` | Run-records ATT&CK (`{ts, target, kind, mitre, fired, run_id, campaign}`) émis pour chaque tir ; `emit()` en JSONL ingérable. |
| `report.py` | Rapport markdown d'engagement + section **anti-masquage** (tiré / simulé / vétoé / jamais tenté). |
| `memory.py`, `memory_faiss.py` | Mémoire : store JSONL + dedup (`JaccardMemory` floue stdlib, bridge FAISS optionnel qui dégrade proprement). |
| `session.py` | **Session gouvernée** (SECRET) : matériel d'auth attaché **uniquement** aux requêtes in-scope, jamais journalisé/ledgerisé/versé dans un finding. |
| `runner.py`, `browser_client.py`, `console_client.py` | Runner (binaire local ou docker, sans install), client browser-automation (`FORGE_BROWSER_URL`), client d'ingestion console. |

### 2.3 Le registre de modules (`forge/modules/`)

Un **module** respecte un contrat minimal (`registry.py`) :

```python
class Module:
    kind = "base"
    exploit = False        # => exige allow_exploit dans le scope
    destructive = False    # => exige allow_destructive
    available = True       # False si l'outil sous-jacent manque (auto-neutralisation)
    mitre = ""             # technique ATT&CK (badge console)
    description = ""
    def dry(self, action) -> str: ...          # ce qu'il FERAIT (PoC), sans rien envoyer
    def fire(self, action) -> list[Finding]: ... # exécute — jamais appelé sans verdict FIRE
```

`@register("kind")` inscrit la classe dans `REGISTRY`. Les modules restent des **outils autonomes**
orchestrés — l'engine ne les possède pas. Discipline (héritée des collecteurs Plume) : OFF par
défaut, **auto-neutralisation** si l'outil sous-jacent est absent, **zéro effet de bord en dry-run**.

Les **31 modules livrés** couvrent recon passif/actif, oracles à preuve (IDOR, SSRF, auth/ATO, CORS,
SSTI, path-traversal, SQLi, XSS, open-redirect, CSRF, JWT, GraphQL), évasion browser-automation, et
connecteurs (MSF, Burp). La table complète (générée depuis `forge modules --json`) est dans
**[MODULES.md](MODULES.md)** ; leur logique « à preuve » dans [Concepts §3](CONCEPTS.md#3-oracles-à-preuve).

### 2.4 Les collecteurs de détection (`forge/collectors/`)

Pour la boucle purple, les sources BLUE « riches » (CrowdSec, Elastic/OpenSearch, syslog/filterlog,
fichier, exec, ou HTTP en https/mTLS) sont **déléguées** au collecteur Python
(`forge.cli detections --source …`). Chaque `kind` a une classe qui normalise sa source native en
`[{mitre, count, first_ts}]` et respecte le **contrat fail-open lisible** (`reachable` distingue
« joignable mais vide » de « injoignable »). Kinds : `plume, generic_http, crowdsec, elastic,
opensearch, fortigate_syslog, pfsense, opnsense, file_jsonl, exec`. Modèle et mapping MITRE :
[`DETECTION.md`](DETECTION.md).

## 3. La console Rust (`console/src/main.rs`)

Binaire unique **axum + rusqlite** (SQLite bundlé, WAL). Store du modèle rouge + API + UI + RBAC +
C2-light. Elle **ne contient aucune capacité offensive** : elle stocke, corrèle, gouverne, et
**spawne** le moteur Python pour les runs web.

### 3.1 Couches de garde (middleware)

Toutes les routes sauf `/health`, `/api/login`, `/api/setup*` passent par deux gardes empilées :

1. **`host_guard`** (anti-DNS-rebinding) — le `Host` (port retiré) doit être NON VIDE et dans
   l'allowlist (`localhost`/`127.0.0.1`/`::1` par défaut, + `FORGE_CONSOLE_HOST`). Sinon **421**.
2. **`auth_guard`** — la gate s'engage sur `auth_required` (un hash env posé **OU** un compte activé
   en base). Engagée sans preuve valide ⇒ **401**. Preuves acceptées : session individuelle
   (cookie `forge_session` ou `Bearer <session>`), **Basic** viewer (hash env), **Bearer** = token
   d'ingestion.

Détail des rôles et de l'authz par route : [Modèle de sécurité](SECURITY_MODEL.md) et
[Référence API](HTTP_API.md).

### 3.2 RBAC — trois rôles

| Rôle | Peut | Preuve |
|---|---|---|
| **viewer** | Lecture (findings, coverage, runs, ledger, soql, dashboards) | session ; ou Basic (hash env `FORGE_CONSOLE_PASS_HASH`) |
| **operator** | Lancer/annuler un run C2-light (`/api/run*`), rafraîchir les modules | session operator|admin ; ou en-tête `X-Forge-Operator` (hash env `FORGE_CONSOLE_OPERATOR_HASH`) + politique source-CIDR |
| **admin** | Administration : comptes, settings, gouvernance des connecteurs, source de détection, backup/restore, setup | **session admin uniquement** (aucun repli env-hash — attribution individuelle obligatoire) |

Un **token d'ingestion** (`FORGE_CONSOLE_TOKEN`, Bearer) gate les écritures machine (`/api/ingest`,
panels/dashboards) — c'est le canal moteur→console.

### 3.3 Le run-flow « C2-light » gouverné

`POST /api/run` **n'est pas** un canal de commande persistant : c'est un **lanceur de campagne
gouverné et audité**. À chaque run :

1. **AuthZ opérateur** fail-closed (session operator|admin ou hash env) + contrainte **source-CIDR**
   si configurée.
2. **Validation stricte** de l'entrée (campagne, hôtes : allowlist de caractères anti-injection).
3. **Scope serveur** : chaque cible doit être ⊆ `in_scope` du scope serveur, sinon **400
   out_of_scope** *avant* tout spawn.
4. **Plancher exploit** : les modules `exploit`/`destructive` sont **refusés (400)** sauf **opt-in
   haut-impact gouverné** — honoré **uniquement** si `operator + arm=true + reason non vide`
   (`high_impact_gate`). Sinon le scope écrit pour le run **force** `allow_exploit=false`.
5. **FIFO** : un seul run vivant (409 sinon).
6. **Spawn** `python3 -m forge.cli campaign …` (setsid), avec un scope.json/targets.json temporaires,
   un watchdog (`FORGE_RUN_TIMEOUT`), des logs streamés en **SSE** (`/api/runs/:id/events`).

Chaque étape est **ledgerisée** (`console.*`). La gouvernance UI (désactiver un connecteur) est
**appliquée au spawn** : un module désactivé est SKIP même si son binaire est présent.

### 3.4 Persistance & configuration

- **SQLite** (`FORGE_CONSOLE_DB`) : tables `finding`, `runrecord`, `runrecord` de couverture, `users`,
  `session`, `settings` (KV), `module` (catalogue + gouvernance), `panel`, `dashboard`, `run_job`.
  Migrations additives idempotentes au boot (`migrate()`).
- **Ledger** (`FORGE_CONSOLE_LEDGER`) : mêmes fichier/format que le moteur ; la console écrit ses
  propres entrées `console.*` en `sha256-console` (chaîne non signée, intégrité par hash-chaining ;
  liaison alg↔kind qui interdit tout downgrade).
- **Settings** (table `settings`) : `detection_source`, `operator_policy`, `backup_policy`,
  `session_ttl`, `trusted_proxy`, `backup_last_run`. Configurables **dans l'UI** (admin, ledgerisé).
  Voir [Configuration](CONFIGURATION.md).
- **soql** : langage de requête type-SPL porté de Plume, compilé en **SQL read-only** (champs
  allowlistés, valeurs en params liés, un seul SELECT, LIMIT plafonné, connexion RO). `GET
  /api/query`. Les **dashboards** sont des panels soql sauvegardés (viz table/bar/stat).

## 4. Le SPA (`console/web/`)

SPA **vanilla-JS** (aucun framework, aucun CDN — CSP stricte), skin « Ember » (dark, l'antithèse
offensive de l'Aurora bleu de Plume). Au boot, il sonde `GET /api/setup/state` :
`needs_setup:true` ⇒ affiche le **wizard de 1er déploiement** ([FIRST_DEPLOYMENT.md](FIRST_DEPLOYMENT.md)) ;
sinon il affiche le portail de login puis les onglets **Findings / Coverage ATT&CK / Purple / Runs /
Ledger / Recherche (soql) / Dashboards / Administration**. Progressive Web App (`sw.js`,
`manifest.webmanifest`).

## 5. Le modèle de gouvernance (transversal)

Quatre garanties structurelles, appliquées à toutes les couches :

- **Fail-closed** — l'absence de config, une erreur d'évaluation, un secret manquant ⇒ **refus**,
  jamais une capacité par défaut. `in_scope` vide = rien ne tire. Rôle opérateur non provisionné =
  C2 fermé (403). Source de détection absente = mesure déclarée impossible (jamais inventée).
- **Proof-oriented (*tested-unless-proven*)** — un finding reste `tested`/`reported_by_tool` tant
  qu'un oracle n'a pas produit une **preuve concrète** (donnée d'un autre compte lue, callback reçu,
  jeton forgé accepté). Pas de sur-classement en `vulnerable`.
- **Plancher exploit opt-in** — `exploit`/`destructive` exigent un opt-in explicite par engagement
  (scope) ou par run (haut-impact gouverné). Un module `exploit=True` est INERTE sinon.
- **Tout est tracé** — chaque décision et action est dans le ledger append-time signé, avec une
  section **anti-masquage** dans le rapport (ce qui a été simulé/refusé/jamais tenté). Zéro trou
  silencieux.

Ces garanties sont détaillées dans [Concepts](CONCEPTS.md) et [Modèle de sécurité](SECURITY_MODEL.md).

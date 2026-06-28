<div align="center">

# 🔨 Forge

**The heavyweight red-team engine.** — l'antithèse offensive de [Plume](../plume), le SOC blue-team.
*Python · stdlib-only core · sûreté d'abord (ROE fail-closed + ledger tamper-evident).*

**·  by [GuatX](https://guatx.com)  ·  usage autorisé uniquement  ·**

</div>

Plume **observe** (la plume qui consigne, bleu). Forge **frappe** — et **trempe** les défenses de
Plume (la boucle purple-team). Forge orchestre des modules d'attaque (recon → enum → exploit) où
**chaque action passe par une gate ROE fail-closed** et est tracée dans un **ledger d'engagement
append-time, tamper-evident**. Par défaut, Forge est **INERTE** : rien ne peut tirer tant que
l'opérateur n'a pas armé chaque couche consciemment.

> ⚠️ **Cadre autorisé uniquement** (bug bounty in-scope, pentest sous contrat, CTF, infra propre).
> La gate ROE + le scope-guard + le ledger sont là pour **imposer ET prouver** l'autorisation.
> Passer un WAF/Cloudflare ≠ une faille : c'est un enabler d'accès, pas un bug.

## Sûreté d'abord — la gate à 4 couches (`forge/roe.py`)

Toutes doivent être franchies pour qu'une action LIVE parte. Sinon : `DRY_RUN` (simulation) ou
`VETO` (refus dur).

| Couche | Question | Échec → |
|---|---|---|
| 1 — armé ? | engagement explicitement armé (`--arm`) ? | `DRY_RUN` |
| 2 — scope ? | cible ∈ `in_scope` et ∉ `out_scope` ? (**fail-closed** : `in_scope` vide = rien) | `VETO` |
| 3 — capacité ? | exploit/destructif ⇒ `allow_exploit`/`allow_destructive` explicites ? | `VETO` |
| 4 — approuvé ? | action approuvée (`--approve`), ou mode `auto` ? | `DRY_RUN` |

`VETO` (couche 2/3) n'est **jamais** simulé ni tiré. Toute erreur d'évaluation ⇒ `VETO` (fail-closed).

## Install

```sh
pip install -e .          # met l'exécutable `forge` sur le PATH (forge = forge.cli:main)
forge doctor              # diagnostic : modules opérationnels + outil/service attendu par module
```

Sans installation, tout est aussi accessible via `python3 -m forge.cli <commande>`.

## Quickstart

```sh
# démonstration bout-en-bout — AUCUNE cible réelle, AUCUN I/O réseau
forge demo                                  # ou: python3 -m forge.cli demo

# suite complète (stdlib, zéro réseau) : Python unittest + cargo test de la console
make test                                   # = python3 -m unittest discover -s tests -t . + (cd console && cargo test)
python3 -m unittest discover -s tests -t .  # Python seul (150 tests)

# vérifier l'appartenance d'une cible
forge scope-check app.exemple.test --scope scope.json

# planifier (montre le verdict ROE de chaque action, ne tire rien)
forge plan --scope scope.json --actions actions.json

# exécuter — INERTE par défaut ; il faut armer ET approuver pour tirer
forge run --scope scope.json --actions actions.json \
    --ledger engagements/e1.jsonl --report rapport.md            # tout en DRY_RUN
forge run --scope scope.json --actions actions.json \
    --arm --approve demo.fingerprint:app.test --ledger engagements/e1.jsonl

# intégrité de l'engagement
forge ledger verify --ledger engagements/e1.jsonl
```

Copier `scope.example.json` → `scope.json` et renseigner `in_scope` **avec autorisation écrite**.
`scope.json`, `*.key`, `*.jsonl` sont gitignorés (secrets / état d'engagement).

## Console Rust (`console/` — le store + la boucle purple)

Fork minimal de la colonne Plume (axum + rusqlite, binaire unique) : store du modèle ROUGE
(`finding`/`runrecord`), API, et le **point de jonction purple** (`POST /api/ingest` reçoit les
findings + run-records ATT&CK du moteur Python ; Plume corrèle ensuite par champ `mitre`).

```sh
cd console && cargo build --release            # compile offline depuis le cache cargo
# (optionnel) activer l'auth opérateur : hash argon2id du mot de passe, jamais en clair
HASH=$(./target/release/forge-console hashpw 'mon-mot-de-passe')
FORGE_CONSOLE_TOKEN=$(openssl rand -hex 16) \
FORGE_CONSOLE_USER=forge FORGE_CONSOLE_PASS_HASH="$HASH" \
    ./target/release/forge-console            # http://127.0.0.1:7100  (sans PASS_HASH = dev localhost ouvert)
# côté moteur : expédier une campagne vers la console
python3 -m forge.cli campaign --scope scope.json --targets t.json --campaign op1 \
    --console http://127.0.0.1:7100 --console-token "$FORGE_CONSOLE_TOKEN"
```

**Auth/RBAC** (modèle `auth_guard`/`host_guard` de Plume) : `/health` ouvert ; toutes les autres
routes derrière (a) **host-guard** anti-DNS-rebinding (`Host` en allowlist → sinon `421`) et (b)
**auth-guard** si `FORGE_CONSOLE_PASS_HASH` est défini — **Basic** (opérateur=viewer, lecture) ou
**Bearer token** (agent/admin=écriture). Sans hash → mode dev localhost ouvert (les écritures
restent gatées par le token). Mot de passe **argon2id** via `forge-console hashpw '...'`.
Endpoints : `GET /health` · `POST /api/ingest` (token) · `GET /api/findings` · `GET /api/runrecords` ·
`GET /api/coverage` (rollup ATT&CK) · **`GET /api/query?q=...`** (soql) · **`/api/panels`** (GET liste ·
POST créer [token] · DELETE [token] · `GET /api/panels/:id/data`) · `GET /` (console opérateur dark,
vanilla-JS : barre de recherche soql + **dashboard de panels** table/bar/stat).
Dedup au niveau store (`UNIQUE(campaign,target,title)`). Bind 127.0.0.1 ; auth/RBAC complète = durcissement.

**soql (langage de requête type-SPL, porté de Plume)** — interroge `finding`/`runrecord`,
compilé en **SQL read-only** (champs en allowlist, valeurs en params liés, un seul SELECT, LIMIT
plafonné, connexion `SQLITE_OPEN_READ_ONLY`). Exemples :
```
search severity=HIGH | fields target,title,mitre
search | stats count by severity | sort -count
search title~Origine
runs | stats count by mitre
```
Un champ hors allowlist → `400` (anti-injection). Le SQL compilé est renvoyé (transparence).

### Quickstart console (≈5 min)

```sh
# 1) build du binaire (offline, depuis le cache cargo)
cd console && cargo build --release && cd ..

# 2) lancer la console (dev : localhost ouvert, écritures gatées par token)
FORGE_CONSOLE_TOKEN=$(openssl rand -hex 16) ./console/target/release/forge-console &
#    -> http://127.0.0.1:7100   (UI opérateur dark + API)

# 3) peupler le catalogue de modules côté UI
forge modules --json                       # liste les 11 modules (kind, mitre, dispo)

# 4) ingérer une campagne de démonstration (zéro réseau, finding synthétique)
FORGE_CONSOLE_URL=http://127.0.0.1:7100 FORGE_CONSOLE_TOKEN=$FORGE_CONSOLE_TOKEN \
    python3 demo_ingest.py                 # FIRE demo.fingerprint -> POST /api/ingest
```

> En conteneur : la console bind `127.0.0.1:7100` par défaut (`FORGE_CONSOLE_ADDR`). Pour
> l'exposer, fixer `FORGE_CONSOLE_ADDR=0.0.0.0:7100`, ajouter le nom d'hôte public au host-guard
> anti-rebinding via `FORGE_CONSOLE_HOST`, **et** définir `FORGE_CONSOLE_PASS_HASH` (auth argon2id)
> — ne jamais exposer le mode dev localhost-ouvert hors de la machine.

## Connecteurs (outils de pentest standards, pilotés par Forge)

Forge n'ajoute pas de capacité offensive propre : deux connecteurs **pilotent** des outils de
pentest standards que l'opérateur exécute déjà lui-même, et **mappent** leurs résultats en
Findings derrière la même gate ROE. Tous deux sondent leur service **à fire-time** (jamais au
catalogue) et s'auto-neutralisent si le service est injoignable.

| Module | Outil piloté | Variables d'env (défauts) |
|---|---|---|
| `msf.module` | **msfrpcd** (RPC msgpack) — lance le module MSF choisi par l'opérateur ; aucun payload généré par Forge | `MSF_RPC_HOST` (127.0.0.1) · `MSF_RPC_PORT` (55553) · `MSF_RPC_USER` (msf) · `MSF_RPC_PASS` · `MSF_RPC_SSL` (true) · `MSF_RPC_TOKEN` (token permanent, optionnel) |
| `burp.scan` | **REST API Burp Suite** Pro/Enterprise — lance un scan in-scope, rapatrie les issues | `BURP_API_URL` (http://127.0.0.1:1337) · `BURP_API_KEY` |

Gouvernance : `msf.module` déclare `exploit=True` (fail-safe → l'engine exige `allow_exploit`) ;
`burp.scan` reste `exploit=False` mais émet `reported_by_tool` (jamais `vulnerable` — comme nuclei,
pas de sur-classement sans preuve d'exploitabilité). `forge doctor` indique lesquels sont joignables.

## Architecture (en bref)

```
  cerveau (Claude / secpipe planner)
        │  propose des Actions (kind, target, exploit?, destructive?)
        ▼
  Engine ──► gate ROE ──► VETO | DRY_RUN | FIRE ──► Ledger (append-time, hash-chain + HMAC)
        │                                  │
        │                                  ▼ (FIRE seulement)
        └──► module.fire() ──► Findings ──► report.py (+ section anti-masquage)
                  ▲
        modules = OUTILS AUTONOMES orchestrés (toolkit/*.py, secpipe, évasion browser-automation)
```

- **Cœur** = `roe.py` (gate) + `ledger.py` (preuve) + `engine.py` + `schema.py`. Pur-stdlib.
- **Modules** restent indépendants (le `Module` ne fait que `dry()`→PoC et `fire()`→findings).
- **Boucle purple** : chaque finding porte un champ `mitre` (ATT&CK) = clé de jointure pour que
  Plume valide la détection (BAS). Voir [`ARCHITECTURE.md`](ARCHITECTURE.md).

## État (v0.0.1 — 150 tests passent, zéro réseau) — **P1 + P2 complets**

| Couche | État |
|---|---|
| Gate ROE fail-closed (4 couches) | ✅ construit + testé (10 tests) |
| Ledger append-time tamper-evident (**Ed25519** asymétrique + verify externe, repli HMAC) | ✅ construit + testé (8 tests) |
| Engine + report anti-masquage + CLI | ✅ construit, demo bout-en-bout OK |
| Planner coverage-safe (FLOOR sur classes payantes) | ✅ porté de secpipe + self-test |
| Cerveau (interface `Brain` + `HeuristicBrain`) | ✅ — seam pour l'orchestrateur Claude |
| Runner (binaire local ou docker, sans install) | ✅ porté de secpipe |
| Graphe d'engagement (world-model hosts→services→findings) | ✅ porté de secpipe |
| Handlers : `recon.httpx`/`recon.nmap`/`web.nuclei`/`access_control.idor`/`origin.find` | ✅ — gatés, auto-neutralisés si l'outil manque |
| Évasion : `evasion.xhr`/`evasion.turnstile`/`evasion.idor_intercept` (browser-automation) | ✅ — atteindre les cibles CF/WAF, auto-off si service injoignable |
| Connecteurs : `msf.module` (msfrpcd) / `burp.scan` (REST API Burp) | ✅ — pilotent des outils standards, sondés à fire-time, auto-off si service injoignable |
| Mémoire : store JSONL + dedup (`forge/memory.py`) | ✅ — backend FAISS (toolkit YWH) à brancher |
| Boucle purple : run-records ATT&CK + `forge campaign` | ✅ construit + testé |
| **Console Rust** (`console/`, fork de la colonne Plume) | ✅ — compile offline, ingest+coverage+PWA, intégration Python↔Rust prouvée |
| **soql `finding`/`runrecord`** (`GET /api/query`, read-only, anti-injection) + barre de recherche UI | ✅ porté de Plume, testé en live |
| **Dashboards query-driven** (panels soql sauvegardés, viz table/bar/stat, écriture gatée par token) | ✅ testé en live |
| **Auth/RBAC console** (argon2id Basic=viewer · Bearer=admin · host-guard anti-rebinding) | ✅ porté de Plume, 10/10 en live |
| **Ledger Ed25519** (signature asymétrique à l'append + `verify_external` par clé publique) | ✅ testé |
| **Ancrage hors-host** (`anchor.py` : interface `Anchor` + témoin co-signataire + `reconcile`) | ✅ testé (détecte une réécriture re-signée localement) |
| **Mémoire sémantique** (`JaccardMemory` floue stdlib + bridge FAISS embeddings optionnel) | ✅ Jaccard testé, FAISS dégrade proprement |
| **Cœur partagé `guatx-core`** (crate Rust **public neutre** en `GUATX/core/` ; console en dépend) | ✅ 6 tests Rust, déplacé hors du privé, console rebâtie |
| Migration Plume vers `guatx-core` + signeur témoin distant (HTTP) | ⏳ à la demande |

**11 modules** (table générée depuis `forge modules --json`) :

| kind | exploit | ATT&CK | description |
|---|:---:|---|---|
| `access_control.idor` | ✅ | T1190 | Oracle différentiel IDOR/BOLA sur 2 comptes (CWE-639). |
| `burp.scan` | — | T1595.002 | Pilote la REST API de Burp Suite : scan in-scope → issues → Findings. |
| `demo.fingerprint` | — | — | Démonstration du pipeline (plan→ROE→dry/fire→finding→ledger), zéro I/O. |
| `evasion.idor_intercept` | ✅ | T1190 | Arme l'interception IDOR en vol (browser intercept-modify, CWE-639). |
| `evasion.turnstile` | — | T1556 | Franchit le Turnstile interactif (vision-click-os) — enabler d'accès. |
| `evasion.xhr` | — | T1190 | Observation des requêtes XHR via la session browser (bypass WAF). |
| `msf.module` | ✅ | T1210 | Pilote msfrpcd : lance le module MSF choisi par l'opérateur. |
| `origin.find` | — | T1590.005 | IP d'origine derrière CDN/WAF (subfinder→DNS→drop-CF→vérif Host). |
| `recon.httpx` | — | T1595 | Fingerprint HTTP (status, titre, techno). |
| `recon.nmap` | — | T1046 | Découverte des services exposés (nmap -sV, top 1000). |
| `web.nuclei` | — | T1595.002 | Scan de vulnérabilités par templates nuclei (medium/high/critical). |

> Aucun module ne tire **rien** sans verdict `FIRE` (in-scope + armé + approuvé + capacité
> autorisée). Tous les tests sont hermétiques (aucun outil n'est exécuté contre une cible).
> `forge doctor` indique quels modules sont opérationnels sur la machine courante.

> Ledger : signature **Ed25519 à l'append** par défaut (asymétrique → un tiers vérifie avec la
> SEULE clé publique via `verify_external(pubkey)`, sans pouvoir forger), repli HMAC si
> `cryptography` absent. Caveat custody restant : la clé privée est encore **locale** ; l'ancrage
> hors-host (clé privée sur un signeur distant / co-signataire / transparency log) est la dernière
> étape — l'architecture asymétrique le permet déjà (seule la clé publique circule). Documenté, pas caché.

## Documentation

- [`docs/PLAN.md`](docs/PLAN.md) — positionnement, red/blue/purple, roadmap séquencée et statut des blockers.
- [`docs/PURPLE_PREREQS.md`](docs/PURPLE_PREREQS.md) — prérequis Plume pour câbler la boucle purple (le moat).
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — empreinte mesurée et matrice de déploiement (Docker / k8s / host / venv).

## Licence
Usage autorisé / éthique uniquement.

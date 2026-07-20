# Forge — Architecture

Forge est l'**antithèse offensive** du SOC blue-team **Plume** (`../plume`). Décision de design
(cf. analyse de réutilisation) : **cœur partagé, produits séparés, modules autonomes** — surtout
pas un all-in-one qui fusionnerait l'arsenal rouge dans le binaire bleu (cela casserait l'invariant
« le SOC ne doit jamais être un trou de sécu » : exec-on-demand interdit, read-only, localhost-only).

## Les trois couches

```
Ce dépôt — Forge (rouge, PUBLIC) : moteur Python (gate ROE, ledger, modules, évasion...) +
  console/        forge (bin Rust) : store rouge + API + dashboards — DÉPEND de guatx-core

Dépendances externes de la famille GUATX (repos séparés, PAS dans ce dépôt) :
  guatx-core      lib Rust — NEUTRE, PUBLIC : le ~70 % commun. v0 = moteur soql ; à étendre
                  (auth/host-guard, query-exec). RIEN d'offensif n'y descend. Consommée par la console
                  en git-dep publique épinglée (github.com/guatxlabs/core, tag v0.1.0).
  plume           Plume (bleu, PUBLIC) : event/metric, détection, collecteurs, BAS. PEUT adopter core.
```
**Frontière des repos** (décidée) : `core` **public neutre** + `plume` **public** (bleu) +
`forge` **public** (rouge, ce dépôt). Comme Plume doit pouvoir dépendre de `core`, **`core` DOIT être
public** — c'est ce qui force le découpage. Discipline : aucun élément offensif (module, évasion CF/WAF,
logique ROE) ne descend dans `core` ; il reste dans Forge, qui dépend du cœur public.
La console consomme `core` via une **dép `git` publique épinglée** (`tag = "v0.1.0"`, récupérée au
build) — la migration depuis l'ancienne dép `path` sibling est **faite**. L'extraction est réelle (la
console l'utilise), pas un plan.

v0 ne bâtit pas `core/` (extraction prématurée = friction tant que les interfaces bougent). On
**construit Forge d'abord** (Python, comme secpipe + le toolkit), puis on remontera les ~70 %
communs dans `core/` quand Plume et Forge auront convergé.

## Le moteur (ce repo)

```
roe.py      Scope (fail-closed) + Roe (gate 4 couches) + Action/Decision      ← LE cœur de sûreté
ledger.py   ledger append-time, hash-chain SHA256 + MAC HMAC par-entrée + verify()
schema.py   Finding (+ mitre, status) · Target · Campaign
engine.py   boucle : plan → roe.decide → (dry|fire|veto) → ledger → findings · coverage()
report.py   markdown + section « anti-masquage » (tiré/simulé/vétoé/jamais tenté)
modules/    registry.py (contrat dry/fire) + demo.py (no-op, illustre le contrat)
cli.py      forge scope-check | plan | run | campaign | ledger verify | modules | doctor | demo
```

**Invariant central** : un module n'est appelé en `fire()` **que** sur un verdict `FIRE`. En
`DRY_RUN` seul `dry()` (génère le PoC, aucun effet de bord). En `VETO`, rien.

### D'où vient quoi (réutilisation, pas réécriture)
- `Scope` ← `secpipe/scope.py` (appartenance fail-closed + exploit/destructif default-deny),
  **enrichi** du modèle d'armement de `plume/collectors/respond.sh` (opt-in → dry-run défaut →
  armement global → approbation par action → allowlist). Polarité inversée : allowlist **in-scope**
  (fail-closed), pas deny-list d'IP.
- `ledger.py` ← le ledger hash-chain + checkpoints Ed25519 de Plume, **corrigé** sur ses deux
  faiblesses relevées : couverture (ici TOUTES les entrées sont chaînées) et entre-checkpoints
  (MAC **par-entrée**, pas seulement au checkpoint).
- `Finding` ← `secpipe/schema.py`, + `mitre`/`status`.
- `report.py` ← la section transparence de `secpipe/report.py`.

## Les modules (P2) — outils autonomes orchestrés

Le contrat `Module` (`dry()`/`fire()`) enveloppe l'existant, qui **reste lançable seul** :
- `YesWeHack/toolkit/web/*.py` — 43 testeurs (SSRF, IDOR, SQLi, XXE, JWT, GraphQL…), CLI uniforme.
- `secpipe` — recon (nmap/httpx), `access_control` (IDOR 2-comptes), `origin_detection` (CDN-bypass
  PoC-vérifié) ; + son planner coverage-safe (FLOOR sur les classes payantes) et son graph.
- `YesWeHack/toolkit/browser-automation` — évasion : `vision-click-os` (Turnstile interactif),
  `capture-replay` (WAF-bloque-XHR), `intercept-modify` (IDOR GraphQL persisted-query), `os-drag`.
- `YesWeHack/toolkit/mcp/findings_db` (FAISS) — mémoire : dedup, knowledge base, dispatch par technique.

Discipline (héritée des collecteurs Plume) : OFF par défaut, auto-neutralisation si l'outil
sous-jacent manque, zéro effet de bord en dry-run.

## La boucle purple (interface Plume ↔ Forge)

Le cahier de Plume (`../plume/CAHIER-DES-CHARGES.md`) spécifie **déjà** le BAS / la couverture
MITRE ATT&CK (Phase P10) — Forge en est la **moitié exécutante** :

```
Forge exécute la technique T ─► run-record taggé {mitre: T} ─► Plume ingère
                                                                   │
                          Plume détecte ? alerte taggée {mitre: T} ┘
   corrélation = égalité de champ `mitre`  ─►  dashboard de couverture ATT&CK
   (Forge mesure le VRAI MTTD + le VRAI % de couverture de Plume)
```

Pas de process partagé : un contrat POST/fichier. Un mince adaptateur « mode-BAS » pourra vivre
dans Plume (own-infra, sandbox, opt-in) et appeler Forge ; **Forge-le-moteur reste un produit
séparé** dont la charte est le red-team autorisé en général, l'own-infra n'étant qu'un *mode*.

## Roadmap

- **P0/P1 (fait)** — moteur + gate ROE fail-closed + ledger tamper-evident + CLI + tests.
- **P2 (fait)** — planner coverage-safe, runner, cerveau (`Brain`/`HeuristicBrain`, seam Claude),
  **graphe d'engagement** (`graph.py` : world-model hosts→services→findings), handlers réels
  (`recon.httpx`/`recon.nmap`/`web.nuclei`/`access_control.idor`/`origin.find`), **évasion
  browser-automation** (`evasion.*` via `browser_client.py`, port 8080), **mémoire** (`memory.py` :
  store JSONL + dedup), run-records ATT&CK + `forge campaign`. Les gems secpipe (planner, runner,
  graph, access_control, origin) sont **portées proprement** dans le contrat Forge (pas d'import du
  sibling messy). Reste en durcissement : backend FAISS (toolkit YWH) derrière l'interface `Memory`.
- **P3 (v0 fait)** — console Rust `console/` (axum + rusqlite, binaire unique, compile offline) :
  store du modèle rouge (`finding`/`runrecord`), `POST /api/ingest` (token) = point de jonction
  purple, `GET /api/findings|runrecords|coverage`, console opérateur (PWA vanilla-JS). Loop
  Python↔Rust prouvée (`console_client.py` + `forge campaign --console`). **soql `event→finding`
  fait** (`console/src/soql.rs` : `search|stats|fields|sort|head` sur `finding`/`runrecord`,
  compilé en SQL read-only, champs allowlistés, valeurs en params liés, connexion RO ; `GET
  /api/query` + barre de recherche UI). **Dashboards faits** : panels soql sauvegardés
  (`panel` table, `/api/panels` CRUD, écriture gatée par token, `/:id/data` ré-exécute la requête),
  viz table/bar/stat dans l'UI. **Auth/RBAC fait** : `host_guard` (anti-DNS-rebinding, Host en
  allowlist) + `auth_guard` (argon2id Basic=opérateur/viewer · Bearer token=agent/admin/écriture ·
  `/health` ouvert · sans hash = dev localhost) + sous-commande `hashpw`. P3 ESSENTIELLEMENT
  COMPLET. Reste : extraction de `core/` partagé (le ~70 % commun Plume/Forge).
- **Durcissement (fait)** — ledger **Ed25519** (`signing.py`, `verify_external`) ; **ancrage hors-host**
  (`anchor.py` : interface `Anchor` + `Witness` co-signataire + `reconcile` qui détecte une réécriture
  re-signée localement) ; **mémoire sémantique** (`JaccardMemory` floue stdlib + `memory_faiss.py`
  embeddings optionnel, `make_memory` dégrade) ; **`guatx-core`** (moteur soql extrait, console dessus).
  Reste à la demande : migration de Plume vers `guatx-core` ; témoin distant en HTTP ; backend FAISS
  activé (nécessite le venv toolkit sur le PYTHONPATH).

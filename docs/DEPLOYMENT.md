# Forge — Empreinte & Déploiement

*(chiffres mesurés)*

## Composition

Forge lui-même :

| Langage | Périmètre | LOC |
|---|---|---|
| Python | moteur, stdlib pur, `deps=[]` | ~5256 |
| Rust | console | ~4006 |
| Rust | guatx-core | ~1032 |
| JS / HTML / CSS | UI | ~3513 |

**ZÉRO** Java / C / C++ / Go / bash dans le code Forge.

Les outils **ORCHESTRÉS** (jamais embarqués, tous **OPTIONNELS**, auto-neutralisés si absents) :

| Outil | Langage |
|---|---|
| nmap | C |
| httpx / nuclei / subfinder | Go |
| MSF | Ruby |
| Burp | Java |
| browser / camoufox | Python + Firefox |

## Poids

- **Livrable cœur ≈ 5 MB** :
  - binaire Rust console **4.2 MB** (SQLite bundlé)
  - Python **196 KB**
  - web **432 KB**
- Le **1.6 GB** dans `forge/` = cache Cargo `console/target/` (**NON expédié**).
- **Image Docker** :
  - **minimale ~150-250 MB** (console + python + nmap)
  - **complète ~350-500 MB** (+ binaires Go PD)
- `browser-automation` = image **4 GB** séparée (sidecar optionnel).

## Matrice de déploiement

### Docker ✅

- `docker compose config` valide.
- Multi-stage (builder rust jeté → runtime debian-slim).
- ⚠️ contexte de build = parent `GUATX/` (la console dépend du sibling `../core`).
- Non-root uid 10001, tini PID1, volumes DB / ledger / scope.

### k3s / k8s ✅

- Deployment **single-replica**.
- ⚠️① la console **SPAWN** `python3 -m forge.cli` (setsid) → python + package forge **DANS LE
  MÊME conteneur** (pas séparable).
- ⚠️② SQLite + ledger = **PVC ReadWriteOnce** → pas de scale horizontal.
- Outils externes (browser:8080, msfrpcd:55553, burp:1337) = Services / sidecars optionnels.

### Host natif ✅

- `pip install -e .` + `cargo build --release` + outils sur PATH.
- Unité systemd durcie fournie (`deploy/forge-console.service`).

### venv ✅

- `deps=[]` → la partie Python tient en venv **sans aucune dépendance pip**.

## Contrainte d'archi

- **STATEFUL single-replica + PVC RWO** (pas scale-out).
- HA / multi-tenant futur = ledger hors-host + store partagé (à repenser).
- **Profil idéal actuel** : mono-opérateur / petit MSSP.
- **Atout** : noyau gouverné minuscule + moteurs lourds branchables en sidecars optionnels
  (livrable « mini » ~200 MB ou « full » selon le client).

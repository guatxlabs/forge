# Référence CLI

> [Sommaire](README.md) · Voir aussi : [Configuration](CONFIGURATION.md) ·
> [Référence API HTTP](HTTP_API.md) · [Concepts](CONCEPTS.md)

Deux exécutables :

- **`forge`** — le moteur Python (`pip install -e .` met `forge` sur le PATH ; sinon `python3 -m
  forge.cli <commande>`). Gère scope, plan, run, campagne, ledger, diagnostic, collecteurs.
- **`forge-console`** — le binaire Rust : lancé **sans argument**, il démarre le serveur (API + UI) ;
  avec un sous-verbe, il expose des utilitaires (hash, comptes, seed, migration, backup, ledger,
  lecture locale).

> Sûreté : `forge` est **INERTE** par défaut. `run`/`campaign` **simulent** (`DRY_RUN`) tant que
> `--arm` **et** l'approbation (ou `--mode auto`) ne sont pas posés. Un `VETO` (hors scope / capacité
> non autorisée) n'est **jamais** tiré. Codes de sortie usuels : `0` OK, `1` échec/vuln trouvée,
> `2` erreur d'usage.

---

## 1. `forge` (moteur Python)

### `forge --version`
Imprime la version (source unique : le fichier [`../VERSION`](../VERSION)).

### `forge scope-check <target> --scope <S>`
Verdict d'appartenance d'une cible. Sortie `IN SCOPE ✅` / `HORS SCOPE ⛔` (+ `mode`,
`allow_exploit`, `allow_destructive`). Exit `0` si in-scope, `1` sinon.
```bash
forge scope-check api.lab.example --scope scope.json
```

### `forge plan --scope <S> [--actions <A>]`
Liste les actions et leur **verdict ROE**, **sans rien tirer** (jamais armé). `--actions` = fichier
JSON `[{kind,target,exploit?,destructive?,desc?,params?}]` ; absent ⇒ actions démo dérivées du scope.
```bash
forge plan --scope scope.json --actions actions.json
```

### `forge run --scope <S> [options]`
Exécute une **liste d'actions** via la gate ROE.

| Flag | Sens |
|---|---|
| `--actions <A>` | Fichier JSON d'actions (sinon démo). |
| `--arm` | Arme l'engagement (couche 1). Sans lui, tout reste `DRY_RUN`. |
| `--approve <KIND:TARGET> …` | Approuve des actions (couche 4). |
| `--mode propose\|auto` | `propose` (défaut, approbation requise) ou `auto` (approuve tout). |
| `--ledger <L>` | Ledger d'engagement (JSONL) — chaque décision y est scellée + checkpoint en fin. |
| `--report <R>` | Écrit le rapport markdown (sinon stdout). |
| `--reason <txt>` | Motif journalisé à l'armement. |
| `--memory <M>` | Store mémoire (dedup des findings). |
```bash
forge run --scope scope.json --actions actions.json \
    --arm --approve demo.fingerprint:app.test --ledger engagements/e1.jsonl --report rapport.md
```

### `forge campaign --scope <S> --targets <T> [options]`
Campagne **itérative** (plan → observe → replan) pilotée par le cerveau + le planner coverage-safe.
`--targets` = JSON `[{host, kind?, attrs?}]`.

| Flag | Sens |
|---|---|
| `--arm`, `--approve`, `--mode`, `--ledger`, `--report`, `--reason`, `--memory` | comme `run`. |
| `--budget <f>` | Budget du planner (borne le travail **non-qualifiant** ; les classes qualifiantes ne sont jamais affamées). |
| `--exhaustive` | Désactive l'ordonnancement → couverture maximale. |
| `--modules <k1,k2,…>` | **Restreint** le plan aux kinds listés (sélection UI/console). Vide = plan complet du cerveau. |
| `--purple <F>` | Émet les run-records ATT&CK (JSONL) ingérables par la source de détection. |
| `--campaign <name>` | Nom de campagne (corrélation console/purple). Défaut `default`. |
| `--console <URL>` | Pousse findings + run-records + couverture vers la console (`POST /api/ingest`). |
| `--console-token <tok>` | Bearer d'ingestion (préférer l'env `FORGE_CONSOLE_TOKEN` — argv est visible des autres users). |
| `--run-id <id>` | Corrèle ce tir à un run console précis. |

Sortie : `Tirées=… Simulées=… Refusées=… Erreurs=… Déférées(budget)=… Findings=… Dups=…
Run-records=…`, la liste des **lacunes de couverture** (classes jamais tentées), et le rapport.
```bash
export FORGE_CONSOLE_TOKEN='<token>'
python3 -m forge.cli campaign --scope scope.json --targets targets.json \
    --modules recon.httpx,recon.nmap,web.nuclei --mode auto --arm \
    --console http://127.0.0.1:7100 --campaign op1 \
    --purple runs/op1.jsonl --ledger runs/op1.ledger.jsonl --report runs/op1.md
```

### `forge ledger verify --ledger <L> [--pubkey <HEX>]`
Recalcule la chaîne + vérifie chaque signature. `--pubkey <hex>` ⇒ **vérification externe** par la
seule clé publique Ed25519 (non-répudiation, aucun secret). Exit `0` intègre / `1` cassé.
```bash
forge ledger verify --ledger engagements/e1.jsonl
forge ledger verify --ledger engagements/e1.jsonl --pubkey $(forge ledger pubkey --ledger engagements/e1.jsonl | head -1)
```

### `forge ledger pubkey --ledger <L>`
Imprime la clé publique Ed25519 brute (hex, ligne 1) + `# alg=ed25519` (ligne 2). En repli HMAC :
message clair + `public_id` (pas de non-répudiation asymétrique). Réutilisable en vérif externe.

### `forge ledger keygen --ledger <L> [--force]`
Crée **délibérément** la paire Ed25519 (`<L>.ed25519`, `0600`) au lieu de l'auto-gen paresseux.
`--force` = **ROTATION** (invalide les signatures ed25519 déjà écrites — `verify` casserait). Refuse
d'écraser sans `--force`. Imprime la clé publique.

### `forge modules [--json]`
Liste les modules enregistrés (`kind`, exploit, destructif, available). `--json` = table complète
(kind, cls, exploit, destructive, web_allowed, available, mitre, description). Voir [MODULES.md](MODULES.md).

### `forge doctor [--json] [--purple] [--timeout <s>]`
Diagnostic **lecture seule** (ne tire rien, ne touche ni scope ni ledger).
- Sans `--purple` : pour chaque module, dit s'il est **OPÉRATIONNEL** (sonde `.available`) + l'outil
  attendu + l'astuce d'install, plus une ligne de santé de la **source de détection** configurée.
- `--purple` : **préflight de la boucle purple** — GET console `/health` + sonde de la source de
  détection (Plume legacy **ou** collecteur configuré). Checklist claire ; dégrade gracieusement.
```bash
forge doctor
forge doctor --purple --json
```

### `forge demo`
Démonstration bout-en-bout, **aucune cible réelle, aucun I/O réseau** : montre VETO (hors scope),
DRY_RUN (non armé), FIRE (armé + approuvé), l'intégrité du ledger, puis une altération qui **casse**
`verify`.

### `forge detections --source <SPEC> [--since <N>]`
Collecteur de détections (délégué par la console pour les sources « riches »). `--source` =
`env:NOM` (**voie privilégiée** — pas de fuite du secret via argv), `@fichier`, ou JSON littéral.
Imprime `{"detections":[{mitre,count,first_ts}]}`. Contrat fail-open : source joignable (même 0
détection) ⇒ stdout + exit 0 ; injoignable/mal-configurée ⇒ stderr **rédigé du secret** + exit non
nul (la console bascule en `source_reachable:false`). Le secret d'auth n'est **jamais** imprimé.
```bash
FORGE_DETECTION_SOURCE='{"kind":"crowdsec","endpoint":"http://127.0.0.1:8080", …}' \
  forge detections --source env:FORGE_DETECTION_SOURCE --since 0
```

---

## 2. `forge-console` (binaire Rust)

Lancé **sans argument**, il démarre le serveur (bind `FORGE_CONSOLE_ADDR`, cf.
[Configuration](CONFIGURATION.md)). Avec un sous-verbe :

### `forge-console --version` (ou `-V`)
Imprime la version (fichier `VERSION`, `include_str!` à la compilation).

### `forge-console hashpw <password>` · `hashpw-operator <password>`
Calcule le hash **argon2id** (jamais en clair) du mot de passe, pour `FORGE_CONSOLE_PASS_HASH`
(viewer) / `FORGE_CONSOLE_OPERATOR_HASH` (opérateur C2). Imprime le hash.
```bash
HASH=$(forge-console hashpw 'mon-mot-de-passe')
```

### `forge-console useradd <login> <role> [--pass <pw>]`
Provisionne un **compte individuel**. `role ∈ {viewer|operator|admin}`. Le mot de passe est lu sur
**STDIN** par défaut (jamais en argv → pas de fuite via `ps`) ; `--pass` toléré pour le scripting.
Hash argon2id stocké dans `users` (upsert idempotent par login). Créer le premier admin ainsi engage
la gate d'auth.
```bash
forge-console useradd alice admin              # demande le mot de passe sur STDIN
```

### `forge-console findings | roe | coverage | query [args] [--json]`
**Parité lecture locale** : lit la MÊME base SQLite que l'API, en **READ-ONLY**, imprime en table
(défaut) ou JSON (`--json`). Aucune écriture, aucun spawn. `query` prend une requête soql.
```bash
forge-console findings --json
forge-console query 'search severity=HIGH | fields target,title,mitre'
```

### `forge-console seed-demo [--dir <path>] [--campaign <name>]`
Amorce la base avec l'**engagement de référence synthétique** ([`../examples/reference-engagement/`](../examples/reference-engagement/))
directement dans SQLite (hors-ligne, sans réseau, sans `/api/ingest`). Idempotent (purge la campagne
démo). Utilisé par `make demo`.

### `forge-console migrate --from <dir|db> --to <db> [--ledger <path>] [--verify] [--encrypt --key-env <ENVVAR>]`
Importe un install Forge existant (non-Docker) vers une base cible. Copie DB (`VACUUM INTO` /
SQLCipher), **ledger + clé `.ed25519`** (`0600`), puis `SCHEMA` + `migrate()` sur la cible. `--verify`
recompute la chaîne du ledger source et **avorte** sur rupture. `--encrypt` exige un binaire
`--features encryption`. La clé passe **par ENV** (`--key-env`), jamais en argv. UX primaire =
conteneur one-shot. Détails : [`MIGRATION.md`](MIGRATION.md).
```bash
forge-console migrate --from /var/lib/forge --to /data/db/forge-console.db \
    --ledger /data/ledger/engagement.jsonl --verify
```

### `forge-console backup --out <archive> --passphrase-env <ENVVAR> [--db <path>] [--ledger <path>]`
Crée une archive **TOUJOURS chiffrée** (argon2id + XChaCha20-Poly1305) regroupant snapshot DB
(`VACUUM INTO`) + ledger + clé `.ed25519` + `manifest.json`. Passphrase lue **uniquement depuis
l'ENV** (jamais argv). La chaîne du ledger est vérifiée avant ; le backup est tracé. Détails :
[`BACKUP.md`](BACKUP.md).
```bash
export FORGE_BK_PASS='une-passphrase-forte'
forge-console backup --out /backups/forge-$(date +%s).forge --passphrase-env FORGE_BK_PASS
```

### `forge-console restore --in <archive> --passphrase-env <ENVVAR> [--to <db>] [--ledger <path>] [--force]`
Déchiffre (mauvaise passphrase/altération ⇒ **rien écrit**), vérifie les `sha256` du manifest + la
chaîne du ledger, **refuse d'écraser** un install non vide sans `--force`, place db/ledger/clé
(`.ed25519` en `0600`). Un swap en place **exige un redémarrage** de la console.

### `forge-console ledger verify [--ledger <path>] [--json]`
Vérif **rapide, non interactive** : recompute la chaîne SHA-256 du ledger JSONL et exit immédiat
(`0` intègre / `1` rompu-absent / `2` usage). Ne démarre PAS le serveur, n'ouvre PAS la base. La
vérif **de signature** (Ed25519) reste côté `forge ledger verify --pubkey` (Python).

---

## 3. Cibles Make (raccourcis)

Le [`../Makefile`](../Makefile) expose : `make test` (Python + cargo), `make test-py`, `make
test-rust`, `make install`, `make console`, `make doctor`, `make check-version`, `make demo`,
`make demo-purple`, `make clean`. Voir [Démarrage](GETTING_STARTED.md) et [Installation](INSTALLATION.md).

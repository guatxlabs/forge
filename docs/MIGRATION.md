# Migration de données — importer un install Forge existant

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Administration](ADMINISTRATION.md#6-migration-de-données) ·
> [Installation](INSTALLATION.md) · [Sauvegarde & restauration](BACKUP.md)

Ce runbook migre un install **Forge Console existant** (typiquement un déploiement
`systemd`/bare-metal, non conteneurisé) vers un **install Docker** (ou toute autre cible),
sans perdre ni corrompre l'audit.

Trois artefacts couplés voyagent **ensemble** :

| Artefact | Fichier (défaut) | Rôle |
|----------|------------------|------|
| Base SQLite | `forge-console.db` | findings / runs / ROE / comptes / settings |
| Ledger d'engagement | `engagement.jsonl` | chaîne SHA-256 **tamper-evident** des mutations |
| **Clé de signature** | `engagement.jsonl.ed25519` | secret Ed25519 (0600) qui **signe** les entrées du ledger |

> ⚠️ **La clé `.ed25519` DOIT suivre le ledger.** Les entrées écrites par le moteur Python
> (`alg=ed25519`) ne sont vérifiables (non-répudiation) que par leur clé de signature sibling.
> Migrer le ledger **sans** sa clé casse la vérifiabilité : `forge ledger verify` ne pourra plus
> valider les signatures. La sous-commande `migrate` copie la clé automatiquement **en 0600** ; ne
> la laissez jamais derrière et ne relâchez jamais ses permissions.

L'outil **n'invente aucun défaut** : chaque chemin est explicite, la source est ouverte en
**lecture seule** (l'install d'origine n'est jamais modifié), et la migration est **elle-même
tracée** au ledger cible (entrée `console.migrate`, chaîne SHA-256 continue).

---

## UX primaire : la sous-commande `forge-console migrate`

```
forge-console migrate --from <dir|db> --to <db> [--ledger <path>] [--verify]
                      [--encrypt --key-env <ENVVAR>]
```

| Flag | Sens |
|------|------|
| `--from <dir\|db>` | Source. Un **dossier** ⇒ `{dir}/forge-console.db` + `{dir}/engagement.jsonl`. Un **fichier `.db`** ⇒ ce fichier + son sibling `engagement.jsonl`. |
| `--to <db>` | Base **cible** (ne doit pas préexister — `VACUUM INTO` refuse d'écraser). |
| `--ledger <path>` | Ledger **cible** (défaut : `engagement.jsonl` à côté de `--to`). La clé `.ed25519` est copiée à côté, en 0600. |
| `--verify` | Recompute la chaîne SHA-256 du **ledger source** et **AVORTE** (aucune écriture) sur une rupture. |
| `--encrypt` | Écrit une base **chiffrée SQLCipher**. Exige un binaire compilé `--features encryption` (sinon erreur claire). |
| `--key-env <ENVVAR>` | Nom de la **variable d'environnement** portant la clé de chiffrement (jamais la clé en argv → pas de fuite via `ps`/historique). |

Codes de sortie : `0` OK · `1` échec migration/vérification · `2` erreur d'usage.

---

## Runbook A — systemd → Docker (plaintext → plaintext)

Contexte : la console tournait sous systemd avec, disons :

```
/var/lib/forge/forge-console.db
/var/lib/forge/engagement.jsonl
/var/lib/forge/engagement.jsonl.ed25519   # 0600
```

Cible Docker (cf. `docker-compose.yml`) : volumes montés
`forge-db:/data/db` et `forge-ledger:/data/ledger`, avec

```
FORGE_CONSOLE_DB:     /data/db/forge-console.db
FORGE_CONSOLE_LEDGER: /data/ledger/engagement.jsonl
```

### 1. Arrêter la console source (cohérence)

```bash
sudo systemctl stop forge-console
```

Arrêter garantit une copie **cohérente** (pas d'écriture concurrente). `migrate` ouvre malgré tout
la source en lecture seule, mais un arrêt propre évite tout WAL en vol.

### 2. Vérifier + migrer dans un conteneur one-shot

Montez le dossier source **en lecture seule** et les volumes cible, puis lancez `migrate`. La même
image `forge-console` sert de conteneur jetable (`--rm`) :

```bash
docker run --rm \
  -v /var/lib/forge:/src:ro \
  -v forge-db:/data/db \
  -v forge-ledger:/data/ledger \
  forge-console:0.0.1 \
  forge-console migrate \
    --from   /src \
    --to     /data/db/forge-console.db \
    --ledger /data/ledger/engagement.jsonl \
    --verify
```

Ce que fait la commande, dans l'ordre :

1. ouvre `/src/forge-console.db` **en lecture seule** ;
2. `--verify` : recompute la chaîne SHA-256 de `/src/engagement.jsonl` ; **AVORTE** si rompue
   (rien n'est écrit côté cible) ;
3. copie la base par `VACUUM INTO` (copie cohérente, compatible source read-only) ;
4. applique `SCHEMA` + `migrate()` sur la cible → une base **plus ancienne est upgradée en place**
   (colonnes additives, nouvelles tables) ;
5. copie `engagement.jsonl` **et** `engagement.jsonl.ed25519` (**0600 forcé**) dans
   `/data/ledger/` ;
6. ajoute une entrée `console.migrate` au ledger cible (chaîne SHA-256 continue).

Sortie : un rapport JSON (`ok`, `source_db`, `target_db`, `target_ledger`, `encrypted:false`,
`ledger_copied`, `key_copied`, `verify:{ok,entries,…}`).

### 3. Démarrer la cible et re-vérifier

```bash
docker compose up -d forge-console
```

Puis, une fois la console up :

```bash
curl -s http://127.0.0.1:7100/api/ledger/verify | jq
# -> {"ok": true, "entries": N+1, "head": "...", "alg": "...", "sig_checked": false, ...}
```

`sig_checked:false` est normal côté console (elle ne détient pas la clé privée). Pour la
vérification **des signatures** (non-répudiation), utilisez le moteur, qui lit
`engagement.jsonl.ed25519` :

```bash
forge ledger verify --ledger /data/ledger/engagement.jsonl
```

Si la clé n'a **pas** voyagé, cette vérification signature échoue — c'est le symptôme d'une
migration incomplète. Recommencez en vous assurant que `.ed25519` est bien présent côté source.

---

## Runbook B — plaintext → chiffré au repos (SQLCipher)

Le chiffrement au repos est **opt-in** et **désactivé par défaut** : le binaire standard ne dépend
pas de SQLCipher/openssl. Pour l'utiliser, compilez un binaire avec la feature :

```bash
cd console
cargo build --release --features encryption   # exige un backend crypto (openssl) à la compilation
```

> Sans ce binaire, `migrate --encrypt` renvoie une **erreur claire** (« chiffrement au repos NON
> compilé »), jamais un faux succès en clair. De même, `GET /api/setup/state` publie
> `capabilities.sqlcipher:false` sur un build par défaut.

### 1. Migrer en chiffrant la cible

La clé de chiffrement est passée **par variable d'environnement** (jamais en argv). Nommez la
variable via `--key-env` :

```bash
export FORGE_DB_KEY='une-passphrase-forte-et-secrete'

forge-console migrate \
  --from   /var/lib/forge \
  --to     /data/db/forge-console.db \
  --ledger /data/ledger/engagement.jsonl \
  --verify \
  --encrypt --key-env FORGE_DB_KEY
```

Étapes spécifiques au chiffrement :

- la base source (en clair, read-only) est **exportée chiffrée** via un `ATTACH … KEY` +
  `SELECT sqlcipher_export(...)` ;
- la cible est ensuite ouverte avec `PRAGMA key` **avant tout autre statement**, puis
  `SCHEMA`+`migrate()` (upgrade en place) ;
- le **ledger et la clé `.ed25519` restent en clair** et voyagent comme au Runbook A (le ledger est
  déjà tamper-evident par sa chaîne de hachage ; sa clé Ed25519 est le secret à protéger en 0600).

### 2. Démarrer la console chiffrée

La console **doit** connaître la clé au boot. Elle lit `FORGE_DB_KEY` et émet `PRAGMA key`
**immédiatement après l'ouverture de la connexion, avant toute requête** (contrat SQLCipher).
Sous Docker, injectez la clé par l'environnement (ex. Docker secret monté en variable) :

```yaml
# extrait docker-compose.override.yml (image compilée --features encryption)
services:
  forge-console:
    image: forge-console:0.0.1-encryption
    environment:
      FORGE_DB_KEY: ${FORGE_DB_KEY}   # depuis un secret, jamais commité
```

Sans `FORGE_DB_KEY` correct, la base chiffrée est **illisible** (fail-closed) : la console ne
démarrera pas sur des données exploitables. C'est le comportement attendu.

---

## Checklist post-migration

- [ ] `GET /api/ledger/verify` → `ok:true` (chaîne de hachage intègre côté console).
- [ ] `forge ledger verify` → signatures OK (**la clé `.ed25519` a voyagé** et est en 0600).
- [ ] `ls -l <ledger>.ed25519` → `-rw-------` (0600).
- [ ] Onglets Findings / Runs / ROE peuplés comme sur la source (schéma upgradé, données présentes).
- [ ] Entrée `console.migrate` présente en fin de ledger cible (provenance tracée).
- [ ] (chiffré) démarrage KO **sans** `FORGE_DB_KEY`, OK **avec** — preuve du chiffrement au repos.
- [ ] Source d'origine conservée intacte (lecture seule) jusqu'à validation complète de la cible.

## Alternative : `POST /api/setup/migrate` (pré-provision uniquement)

Un endpoint **public mais pré-provision** existe pour piloter la même migration depuis le wizard de
1er déploiement, à partir d'une source **pointée** (chemins côté serveur) :

```bash
curl -s -X POST http://127.0.0.1:7100/api/setup/migrate \
  -H 'Content-Type: application/json' \
  -d '{"from":"/src","to":"/data/db/forge-console.db",
       "ledger":"/data/ledger/engagement.jsonl","verify":true}' | jq
```

Il renvoie le **résultat de vérification** du ledger et se **ferme (409)** dès que la console est
provisionnée (un admin activé existe). C'est un raccourci minimal : l'**UX documentée primaire
reste la sous-commande CLI** exécutée dans un conteneur one-shot (ci-dessus). Le chiffrement
(`"encrypt":true`) y exige également un binaire compilé `--features encryption` (sinon `400`).

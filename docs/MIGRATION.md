# Migration de données — importer un install Forge existant

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Administration](ADMINISTRATION.md#6-migration-de-données) ·
> [Installation](INSTALLATION.md) · [Sauvegarde & restauration](BACKUP.md)

Ce runbook migre un install **Forge Console existant** (typiquement un déploiement
`systemd`/bare-metal, non conteneurisé) vers un **install Docker** (ou toute autre cible),
sans perdre ni corrompre l'audit.

Trois artefacts couplés voyagent **ensemble** :

| Artefact | Fichier (défaut) | Rôle |
|----------|------------------|------|
| Base SQLite | `forge.db` | findings / runs / ROE / comptes / settings |
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

## UX primaire : la sous-commande `forge migrate`

```
forge migrate --from <dir|db> --to <db> [--ledger <path>] [--verify]
                      [--encrypt --key-env <ENVVAR>]
```

| Flag | Sens |
|------|------|
| `--from <dir\|db>` | Source. Un **dossier** ⇒ `{dir}/forge.db` + `{dir}/engagement.jsonl`. Un **fichier `.db`** ⇒ ce fichier + son sibling `engagement.jsonl`. |
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
/var/lib/forge/forge.db
/var/lib/forge/engagement.jsonl
/var/lib/forge/engagement.jsonl.ed25519   # 0600
```

Cible Docker (cf. `docker-compose.yml`) : volumes montés
`forge-db:/data/db` et `forge-ledger:/data/ledger`, avec

```
FORGE_CONSOLE_DB:     /data/db/forge.db
FORGE_CONSOLE_LEDGER: /data/ledger/engagement.jsonl
```

### 1. Arrêter la console source (cohérence)

```bash
sudo systemctl stop forge
```

Arrêter garantit une copie **cohérente** (pas d'écriture concurrente). `migrate` ouvre malgré tout
la source en lecture seule, mais un arrêt propre évite tout WAL en vol.

### 2. Vérifier + migrer dans un conteneur one-shot

Montez le dossier source **en lecture seule** et les volumes cible, puis lancez `migrate`. La même
image `forge` sert de conteneur jetable (`--rm`) :

```bash
docker run --rm \
  -v /var/lib/forge:/src:ro \
  -v forge-db:/data/db \
  -v forge-ledger:/data/ledger \
  forge:0.0.1 \
  forge migrate \
    --from   /src \
    --to     /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl \
    --verify
```

Ce que fait la commande, dans l'ordre :

1. ouvre `/src/forge.db` **en lecture seule** ;
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
docker compose up -d forge
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

forge migrate \
  --from   /var/lib/forge \
  --to     /data/db/forge.db \
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
  forge:
    image: forge:0.0.1-encryption
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
  -d '{"from":"/src","to":"/data/db/forge.db",
       "ledger":"/data/ledger/engagement.jsonl","verify":true}' | jq
```

Il renvoie le **résultat de vérification** du ledger et se **ferme (409)** dès que la console est
provisionnée (un admin activé existe). C'est un raccourci minimal : l'**UX documentée primaire
reste la sous-commande CLI** exécutée dans un conteneur one-shot (ci-dessus). Le chiffrement
(`"encrypt":true`) y exige également un binaire compilé `--features encryption` (sinon `400`).

---

## Migration vers le modèle **Engagement** (objet de 1re classe) — zéro perte

L'engagement est désormais un **objet de 1re classe** : chaque engagement porte **SON** scope (in/out),
**SON** mode et **SON** ledger dédié, et chaque ligne de données (`finding` / `runrecord` /
`roe_decision` / `run_job`) porte un `engagement_id`. Cette bascule est **rétro-compatible ZÉRO-PERTE**
pour tout install antérieur (mono-scope, mono-ledger) — **rien à faire, tout continue de fonctionner** :

- **Backfill automatique.** La migration de schéma ajoute `engagement_id INTEGER NOT NULL DEFAULT 1` :
  **toutes** les lignes existantes sont rétro-rattachées à l'**engagement #1**. Aucune donnée n'est
  déplacée, réécrite ni perdue.
- **Engagement #1 = ton install actuel.** Au 1er boot, `ensure_default_engagement` crée l'engagement #1
  **depuis le scope serveur COURANT** (`in_scope` + `mode`) et le **ledger COURANT**
  (`FORGE_CONSOLE_LEDGER`). Ton scope et ton ledger d'origine deviennent donc, à l'identique, ceux de
  l'engagement #1. L'opération est **idempotente** : elle ne réécrit jamais un engagement déjà présent.
- **Le `campaign` reste un sous-label.** Le champ free-text `campaign` existant reste un **sous-label
  AU SEIN** d'un engagement (il n'est **pas** un engagement) — tes campagnes historiques restent
  lisibles telles quelles sous l'engagement #1.
- **Ledger inchangé pour #1.** L'engagement #1 continue d'écrire dans le ledger console d'origine
  (`FORGE_CONSOLE_LEDGER`) ; la chaîne SHA-256 existante est **prolongée**, jamais rompue. Les nouveaux
  engagements reçoivent chacun un ledger **dédié** dérivé côté serveur (`engagement-<id>.jsonl`, frère
  du ledger console) — jamais un chemin fourni par le client (anti write-anywhere).

### Runs concurrents, isolés par engagement

Le slot de run n'est plus un FIFO console-global : c'est **un slot par engagement**. Conséquences,
toutes **fail-closed** :

- **Concurrence inter-engagement.** Plusieurs engagements peuvent avoir un run vivant **en même temps** ;
  lancer un run pour B pendant qu'un run de A tourne renvoie **202**, jamais un 409 croisé.
- **FIFO par engagement.** Un 2e `POST /api/run` sur le **même** engagement renvoie **409**
  (`{"error":"run_in_progress","engagement_id":<id>}`).
- **Isolation stricte.** Un run pour A applique le scope-guard de A et écrit le ledger de A **uniquement**
  — il ne peut ni lire ni écrire le scope, les findings, le ledger ou le slot d'un autre engagement
  (chaque requête porte son `engagement_id` ; isolation par construction). Un run de A ne peut pas
  tirer contre une cible qui n'est que dans le scope de B (**400 out_of_scope** avant tout spawn).

**Aucune action de migration n'est requise** pour bénéficier de tout cela : un install mono-engagement
est simplement un déploiement à **un seul** engagement (le #1), et le jour où tu crées un 2e engagement
(`POST /api/engagements`), il démarre isolé avec son propre scope et son propre ledger.

# Sauvegarde & restauration chiffrées

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Administration](ADMINISTRATION.md#5-sauvegarde--restauration) ·
> [Migration de données](MIGRATION.md) · [Configuration](CONFIGURATION.md#16-sauvegardes-programmées)

Ce runbook décrit la **sauvegarde** et la **restauration** de la Forge Console : le format
d'archive, le chiffrement, pourquoi **la clé de signature voyage à l'intérieur de l'archive
chiffrée**, les garde-fous de restauration, et la programmation + expédition **offsite**.

Une sauvegarde regroupe les **trois artefacts couplés** de l'engagement — exactement les mêmes
que la migration :

| Artefact | Entrée d'archive | Rôle |
|----------|------------------|------|
| Base SQLite | `db.sqlite` | findings / runs / ROE / comptes / settings (snapshot **cohérent** via `VACUUM INTO`) |
| Ledger d'engagement | `engagement.jsonl` | chaîne SHA-256 **tamper-evident** des mutations |
| **Clé de signature** | `signing.ed25519` | secret Ed25519 (0600) qui **signe** les entrées du ledger |
| Manifeste | `manifest.json` | schéma + `sha256` par fichier (ré-vérifié à la restauration) |

---

## 1. L'archive est TOUJOURS chiffrée — il n'existe aucun chemin en clair

Parce que l'archive embarque **la clé privée de signature `.ed25519` ET la base**, elle est
**toujours** scellée. Il **n'existe aucune variante non chiffrée** et **une passphrase est
obligatoire** (fail-closed : passphrase absente ⇒ refus, rien n'est écrit).

> ⚠️ **La clé `.ed25519` DOIT rester avec le ledger.** Sans elle, la chaîne signée devient
> invérifiable. La sauvegarde l'embarque, la restauration la replace **en 0600**.

### Format (auto-descriptif)

```
[ en-tête EN CLAIR ]                       [ ciphertext AEAD (tar chiffré) ]
 magic "FORGEBK1" (8o)                      XChaCha20-Poly1305( tar, key, nonce, AAD=en-tête )
 version (1o)                               │
 m_cost | t_cost | p_cost (argon2, 3×4o LE) │  tar = manifest.json
 salt_len(1o) | salt (16o)                  │        db.sqlite
 nonce_len(1o) | nonce (24o)                │        engagement.jsonl
                                            │        signing.ed25519
```

L'en-tête (magic | version | paramètres argon2 | sel | nonce) est écrit **en clair** devant le
ciphertext **ET lié comme donnée associée (AAD)** de l'AEAD.

### Chiffrement : argon2id + XChaCha20-Poly1305 (pur Rust, aucune dépendance C)

```
passphrase ──argon2id(sel 16o aléatoire, params par défaut)──▶ clé 32o
tar(archive) ──XChaCha20-Poly1305(clé, nonce 24o aléatoire, AAD = en-tête)──▶ ciphertext‖tag
```

- **KDF** : argon2id (Algorithme id, v0x13). Le sel (16o) et le nonce (24o) sont tirés par le
  **CSPRNG de l'OS** à chaque sauvegarde ⇒ deux sauvegardes du même état diffèrent, et rejouer un
  nonce est improbable. Les paramètres argon2 voyagent **dans l'en-tête** (auto-descriptif) pour
  être re-dérivables à la restauration ; ils sont **validés dans des bornes sûres** avant dérivation
  (un en-tête corrompu ⇒ erreur propre, jamais de panic/DoS).
- **AEAD** : XChaCha20-Poly1305. Le tag Poly1305 authentifie **le corps ET l'en-tête** (AAD) :
  altérer un seul octet (corps, sel, nonce ou paramètres) **fait échouer le déchiffrement**.
- **La passphrase / la clé dérivée ne sont JAMAIS stockées, loggées ni ledgerisées.** La clé
  dérivée est effacée du stack dès qu'elle n'est plus nécessaire.

**Mauvaise passphrase** ou **archive altérée** ⇒ échec **propre** (tag AEAD invalide) : la
restauration n'écrit **rien**.

---

## 2. Intégrité : le ledger est vérifié avant et après

- **Avant la sauvegarde** : la chaîne SHA-256 du ledger est vérifiée. Une chaîne **rompue avorte**
  la sauvegarde (aucune archive écrite).
- **À la restauration** : (1) l'AEAD authentifie l'archive ; (2) le `sha256` de **chaque** fichier
  du `manifest.json` est re-vérifié ; (3) la chaîne du ledger extrait est re-vérifiée **avant** tout
  placement ; (4) après placement, la chaîne est **re-vérifiée** puis l'action est tracée.

---

## 3. Restauration : garde anti-écrasement + « restart requis »

La restauration **refuse d'écraser** un install existant **non vide** (base ou ledger) sans un
**`--force`** (CLI) ou une **confirmation explicite** (API). Par défaut, elle **valide et rapporte**
sans rien écrire.

> ℹ️ **La console vivante tient déjà la base ouverte.** Un swap **en place** remplace
> `db.sqlite`/ledger/clé sous une connexion SQLite active : il **exige un redémarrage** de la
> console (`docker restart` / `systemctl restart forge-console`) pour charger l'état restauré. Tant
> que ce n'est pas fait, l'API répond `restart_required: true` avec une note de maintenance.

---

## 4. CLI (voie de confiance, locale)

La passphrase est lue **uniquement depuis une variable d'ENV** (jamais en `argv` — pas de fuite via
`ps`/`cmdline`), jamais depuis `--flag`.

```bash
# Sauvegarde CHIFFRÉE (argon2id + XChaCha20-Poly1305)
export FORGE_BK_PASS='une-passphrase-forte-et-unique'
forge-console backup --out /backups/forge-$(date +%s).forge --passphrase-env FORGE_BK_PASS \
    [--db forge-console.db] [--ledger engagement.jsonl]

# Restauration : déchiffre, vérifie sha256 + chaîne ledger, refuse d'écraser sans --force
forge-console restore --in /backups/forge-XXXX.forge --passphrase-env FORGE_BK_PASS \
    [--to forge-console.db] [--ledger engagement.jsonl] [--force]
```

Codes de sortie : `0` OK, `1` échec, `2` usage.

### One-shot Docker (sauvegarde manuelle)

Monte les volumes de données + un dossier de sortie, passe la passphrase par l'ENV du conteneur, et
lance la sous-commande `backup` en one-shot :

```bash
docker run --rm \
  -e FORGE_BK_PASS="$FORGE_BK_PASS" \
  -v forge_data:/data \
  -v "$PWD/backups:/backups" \
  forge-console \
  forge-console backup \
    --out /backups/forge-$(date +%Y%m%d-%H%M%S).forge \
    --passphrase-env FORGE_BK_PASS \
    --db /data/forge-console.db \
    --ledger /data/engagement.jsonl
```

L'archive de sortie (`/backups/*.forge`) est chiffrée et embarque base + ledger + clé.

---

## 5. API (admin-gated, ledgerisé)

Toutes les routes exigent une **session admin** (`check_admin`, sinon `403`). Chaque action est
**ledgerisée** (métadonnées **seules** — jamais la passphrase).

| Route | Rôle |
|-------|------|
| `POST /api/backup` | Corps `{passphrase}` ⇒ crée l'archive chiffrée et la **renvoie en téléchargement** (`Content-Disposition`). Ledger `console.backup` : acteur + horodatage + **taille + sha256** de l'archive. |
| `POST /api/restore` | Corps `{archive_b64, passphrase, apply?, confirm?}`. **Par défaut** : valide + vérifie + rapporte (aucune écriture). `apply:true` **exige** `confirm:true` ⇒ swap en place (**redémarrage requis**). Ledger `console.restore.validate` / `console.restore`. |
| `GET /api/backup/policy` | Politique programmée/offsite, **secrets rédigés** (`***REDACTED***`) ; `passphrase_env` (un NOM d'ENV) conservé. |
| `POST /api/backup/policy` | Enregistre la politique (validée) ; tout `passphrase` en clair est **retiré** avant persistance. Ledger `console.backup.policy.set`. |

La **passphrase** transite dans le corps de la requête, est utilisée une fois (dérivation) puis
**abandonnée** — jamais persistée côté serveur ni côté navigateur (les champs sont vidés après envoi).

### UI (`#admin` → « Sauvegarde & restauration »)

- **Créer une sauvegarde** : invite la passphrase (double saisie) ⇒ télécharge l'archive chiffrée.
- **Restaurer** : sélection de fichier + passphrase + cases *appliquer* / *confirmer* (le swap exige
  les deux). Par défaut : validation non destructive avec rapport.
- **Éditeur de politique** : intervalle, rétention, `passphrase_env`, staging, destination offsite.

---

## 6. Sauvegarde programmée + offsite

Configurée via `settings.backup_policy` (aucune valeur codée en dur ; **sans politique, aucune
sauvegarde programmée**). Un **runner périodique en console** vérifie à chaque tick si une sauvegarde
est **due** ; il est **fail-open** : un échec de sauvegarde/expédition est **loggé + ledgerisé**
(`console.backup.error`) mais ne fait **jamais crasher** la console.

```json
{
  "enabled": true,
  "interval_secs": 86400,
  "retention": 7,
  "passphrase_env": "FORGE_BACKUP_PASSPHRASE",
  "staging_dir": "/data/backups",
  "offsite": { "kind": "exec", "program": "/usr/bin/rclone",
               "args": ["copy", "{archive}", "remote:forge-backups/"], "timeout_secs": 300 }
}
```

- **`passphrase_env`** : la passphrase du backup **programmé** provient de cette **variable d'ENV**
  du process console — **jamais** stockée en clair dans `settings`. Si l'ENV est absente ⇒ le backup
  programmé **échoue en fail-closed** (loggé/ledgerisé), sans rien exposer.
- **`retention`** : conserve les *N* archives locales les plus récentes dans `staging_dir`
  (`0` = illimité).
- **`offsite.kind` ∈ {none, local_dir, exec}** (liste **fermée**) :
  - `none` : rien n'est expédié (défaut).
  - `local_dir` : copie l'archive dans `dir`.
  - `exec` : lance un **argv FIXE** (aucun shell, `program` = **chemin absolu**) avec un **timeout**.
    Le token littéral `{archive}` dans `program`/`args` est remplacé par le chemin de l'archive.
    Idéal pour `rclone`/`scp`/`aws s3`. **Aucun secret inline** : fournissez les identifiants via
    l'ENV du process (ex. `RCLONE_CONFIG_*`) ou un fichier de config monté, jamais dans la politique.

Le tick du runner est réglable via `FORGE_BACKUP_TICK_SECS` (défaut 60 s).

### Alternative : cron / systemd-timer

Si vous préférez piloter la sauvegarde **hors** console, désactivez la politique (`enabled:false`)
et planifiez la sous-commande CLI. Exemple systemd-timer :

```ini
# /etc/systemd/system/forge-backup.service
[Service]
Type=oneshot
Environment=FORGE_BK_PASS=%I
ExecStart=/usr/local/bin/forge-console backup \
  --out /data/backups/forge-%%Y%%m%%d.forge --passphrase-env FORGE_BK_PASS \
  --db /data/forge-console.db --ledger /data/engagement.jsonl

# /etc/systemd/system/forge-backup.timer
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
```

(La passphrase doit provenir d'une source protégée — `systemd` credential, fichier `0600`, ou
gestionnaire de secrets — jamais un littéral committé.)

---

## 7. Ce qui n'est JAMAIS écrit dans le ledger / les logs

- La **passphrase** ni la **clé dérivée** (aucune entrée, aucun log).
- Le contenu des **secrets offsite** (`GET /api/backup/policy` rédige tout champ *secretish*).

Les entrées ledger (`console.backup`, `console.restore`, `console.backup.scheduled`,
`console.backup.offsite`, `console.backup.policy.set`) ne portent que des **métadonnées** : acteur,
horodatage, taille/sha256 de l'archive, `kind` d'offsite, statut.

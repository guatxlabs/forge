# Secrets — indirection `*_FILE` (Docker & k8s secrets)

> **Principe** : *« la clé ne doit pas être posée à côté de la porte ».* Aucun secret ne vit en clair
> dans un `.env` posé à côté de l'app. L'environnement porte un **CHEMIN** ; le secret vit dans un
> **fichier monté, root-owned**, hors du répertoire de travail. C'est le pattern secret standard
> 12-factor (Docker secrets / Kubernetes Secret-as-file).

## TL;DR

Chaque variable d'environnement qui porte un secret accepte un **jumeau `<VAR>_FILE`** :

1. si `<VAR>` est posée **et non vide** → sa valeur est utilisée (voie directe, **défaut communautaire
   inchangé** — byte-identique à avant) ;
2. sinon, si `<VAR>_FILE` est posée → le fichier pointé est **lu**, son **newline/espace de fin est
   retiré**, et son contenu est utilisé ;
3. sinon → le secret est considéré **absent** (le repli propre de l'app s'applique : génération
   éphémère pour le token d'ingest, refus *fail-closed* pour une passphrase de backup, etc.).

**Fail-soft** : un `<VAR>_FILE` illisible (mauvais chemin, permissions) ne fait **jamais** planter le
process et ne produit **jamais** un secret vide silencieux qui affaiblirait l'auth — il journalise un
avertissement (nommant la **variable**, jamais la valeur) et retombe sur le repli de l'app.

La valeur d'un secret n'est **jamais** journalisée ni passée sur `argv`.

## Secrets couverts

| Variable | Rôle | Consommé par |
|----------|------|--------------|
| `FORGE_CONSOLE_TOKEN` | Bearer d'ingestion `/api/ingest` | console (Rust) + client `console_client` (Python) |
| `FORGE_DB_KEY` | Clé SQLCipher au repos (image `--features encryption`) | console (Rust) |
| `FORGE_BACKUP_PASSPHRASE` | Passphrase des sauvegardes chiffrées (nommée par `policy.passphrase_env`) | console (Rust) — backup/restore/scheduler/upgrade |
| `FORGE_COMPLIANCE_ARCHIVE_KEY` | Passphrase d'archive de purge gouvernée | console (Rust) |
| `FORGE_LEDGER_SIGNER_CREDENTIAL` | Jeton Bearer du signeur distant KMS/HSM/HTTP | moteur (Python, `signing.py`) |
| `FORGE_LEDGER_SIGNER_ARGV` | Argv du signeur exec (peut porter des creds) | moteur (Python, `signing.py`) |
| `FORGE_LEDGER_PKCS11_PIN` | PIN utilisateur du token PKCS#11 | moteur (Python, `signing_pkcs11.py`) |
| `PLUME_TOKEN` | Basic auth du préréglage détection legacy | console (Rust) + moteur (Python) |
| `FORGE_DETECTION_SOURCE` | Config source de détection (JSON porteur du secret d'auth) | moteur (Python, `collectors`) |
| `MSF_RPC_PASS`, `MSF_RPC_TOKEN` | Creds msfrpcd (connecteur `msf.module`) | moteur (Python) |
| `BURP_API_KEY` | Clé REST API Burp (connecteur `burp.scan`) | moteur (Python) |

Chacune accepte `<VAR>_FILE`. Exemple : la console lit `FORGE_CONSOLE_TOKEN`, sinon
`FORGE_CONSOLE_TOKEN_FILE`.

### Déjà write-only via l'UI — n'ont **jamais** besoin d'un `.env`

- **Secret de la source de détection** (`settings.detection_source`) : saisi au wizard du 1er
  déploiement ou dans *Administration → Source de détection*, stocké **write-only** en base (jamais
  relu en clair, jamais journalisé). Les variables `PLUME_*` / `FORGE_DETECTION_SOURCE` ne sont qu'un
  **repli rétro-compat** pour un pilotage hors-UI.
- **SSO `client_secret`** : réglé dans les settings via l'UI, **write-only**, jamais réémis. Aucune
  variable d'env, donc aucun `.env`, n'est nécessaire pour lui.

## Docker Compose

`docker-compose.yml` fournit un bloc `secrets:` (commenté, opt-in) et l'exemple de câblage
`FORGE_BACKUP_PASSPHRASE_FILE: /run/secrets/backup_passphrase`. Marche à suivre :

1. Écrire chaque secret dans un fichier hôte **hors du repo** (gitignored), p.ex. `./secrets/backup_passphrase`.
2. Décommenter le bloc `secrets:` (haut-niveau) et déclarer les fichiers (`file: ./secrets/...`) —
   ou, en mode Swarm, `external: true` + `docker secret create`.
3. Dans le service `forge`, ajouter la clause `secrets:` listant les secrets à monter (Docker les
   expose sous `/run/secrets/<nom>`, mode `0400` root).
4. Décommenter la ligne `environment:` correspondante `<VAR>_FILE: /run/secrets/<nom>`.

```yaml
# docker-compose.yml (extrait)
services:
  forge:
    environment:
      FORGE_BACKUP_PASSPHRASE_FILE: /run/secrets/backup_passphrase
    secrets:
      - backup_passphrase
secrets:
  backup_passphrase:
    file: ./secrets/backup_passphrase     # fichier hôte hors-repo (gitignored)
```

La valeur directe (`FORGE_BACKUP_PASSPHRASE: ...` via `.env`) reste supportée (rétro-compat).

## Kubernetes

Le pattern **Secret-monté-en-fichier** existe déjà pour la clé de signature du ledger
(`forge-ledger-key`, OPTION B dans `k8s/40-console.yaml`). On le **reflète** pour le token, la
passphrase et les creds connecteurs via le Secret `forge-secret-files` (dans
`k8s/10-secrets.example.yaml`, opt-in) :

1. Provisionner le Secret `forge-secret-files` **hors-bande** (SealedSecrets / ExternalSecrets / SOPS
   / `kubectl create secret`), ou, pour un lab, appliquer `kubectl apply -f 10-secrets.example.yaml`
   **explicitement** (eval only).
2. Dans la `Deployment` de la console : décommenter le **volume** `secret-files` (projette le Secret
   en fichiers, `defaultMode: 0400`), le **volumeMount** (`/etc/forge/secrets`, `readOnly: true`), et
   les env `FORGE_*_FILE` pointant sur les chemins montés.

```yaml
# k8s/40-console.yaml (extrait — env)
- name: FORGE_CONSOLE_TOKEN_FILE
  value: /etc/forge/secrets/console_token
# ... volume ...
- name: secret-files
  secret:
    secretName: forge-secret-files
    defaultMode: 0400
    items:
      - { key: console_token, path: console_token }
```

Préférer un Secret **monté en fichier** à un `secretKeyRef` env : avec `secretKeyRef`, la valeur en
clair atterrit dans l'**environnement du pod** (visible dans `kubectl describe pod`, les dumps de
crash, l'environ des process enfants) ; montée en fichier, elle reste dans un tmpfs root-owned lu à la
demande.

> ⚠️ **Les Secrets restent hors du `kubectl apply -k k8s/` par défaut.** `10-secrets.example.yaml` est
> **délibérément absent** de la liste `resources:` de `kustomization.yaml` — ses valeurs de
> placeholder ne partent jamais par défaut. `kubectl kustomize k8s/` rend un manifeste **identique**
> avec ou sans ce changement (les ajouts sont des commentaires + un Secret dans le fichier exclu).

## Implémentation (référence)

- **Rust** : `console/src/secret_env.rs` — `secret_from_env(name) -> Option<String>` (env direct →
  `<VAR>_FILE` lu + `trim_end` → `None` fail-soft). Points d'appel : `main.rs` (token), `dbmigrate.rs`
  (`FORGE_DB_KEY`), `backup.rs::read_passphrase_env` (partagé par backup/restore/scheduler/`upgrade`),
  `compliance.rs` (archive key), `detection.rs` (`PLUME_TOKEN` legacy).
- **Python** : `forge/portability.py` — `env_secret(name, env=None)` (même précédence + `rstrip`).
  Points d'appel : `console_client.py` (token), `modules/msf.py`, `modules/burp.py`, `cli/purple.py`,
  `collectors/base.py::load_source` (`env:NAME`), `signing.py` (credential/argv),
  `signing_pkcs11.py` (PIN).

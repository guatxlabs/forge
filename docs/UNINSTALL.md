# Désinstallation & suppression des données

> [Sommaire](README.md) · Voir aussi : [Installation](INSTALLATION.md) · [Backup](BACKUP.md) ·
> [Migration](MIGRATION.md)

Cette page explique comment **arrêter**, **supprimer** et **purger** un déploiement Forge, selon la
voie d'installation. Les données persistées sont **trois artefacts couplés** : la base SQLite, le
ledger d'engagement, et sa **clé de signature `.ed25519`**.

> ⚠️ **Avant de purger** : si l'engagement doit rester auditable, faites une **sauvegarde chiffrée**
> (elle embarque base + ledger + clé) — voir [`BACKUP.md`](BACKUP.md). Une fois le ledger et sa clé
> supprimés, la chaîne de custody n'est plus vérifiable.

---

## 1. Docker Compose

```sh
# depuis la racine du dépôt
# Arrêter (conserve les volumes/données)
docker compose down

# Arrêter + SUPPRIMER les volumes nommés (DB + ledger) — DESTRUCTIF
docker compose down -v

# Supprimer l'image
docker image rm forge:0.0.1 forge:0.0.1-mini 2>/dev/null

# Les volumes nommés restants (si -v non passé)
docker volume rm forge_forge-db forge_forge-ledger 2>/dev/null   # préfixe = nom du projet compose ("forge")
docker volume ls | grep forge                                    # vérifier qu'il n'en reste pas
```

Le **scope actif** est bind-monté depuis l'hôte (`scope.json`) — il reste sur l'hôte après
`down -v`. Supprimez-le explicitement s'il contient des périmètres sensibles.

---

## 2. Docker (conteneur seul)

```sh
docker rm -f forge                    # arrête + supprime le conteneur
docker volume rm forge-db forge-ledger        # DESTRUCTIF (si créés en volumes nommés)
docker image rm forge:0.0.1
```

Si vous aviez bind-monté un dossier de données (`-v /chemin/db:/data/db`), purgez-le à la main (§4).

---

## 3. Natif / systemd

```sh
# Arrêter + désactiver le service
sudo systemctl disable --now forge
sudo rm -f /etc/systemd/system/forge.service
sudo systemctl daemon-reload

# Binaire + application + assets
sudo rm -f /usr/local/bin/forge
sudo rm -rf /opt/forge

# EnvironmentFile (contient les hashes argon2id / secrets)
sudo rm -f /etc/forge/forge.env

# Données (DESTRUCTIF) — DB, ledger, clé de signature, scope
sudo rm -rf /var/lib/forge

# Compte système
sudo userdel forge 2>/dev/null
```

Si le moteur Python a été installé en editable : `pip uninstall forge`.

---

## 4. Purge des artefacts d'état (toutes voies)

Selon `FORGE_CONSOLE_DB` / `FORGE_CONSOLE_LEDGER` / `FORGE_CONSOLE_SCOPE` (cf.
[Configuration](CONFIGURATION.md)), supprimez :

```sh
# Base SQLite (+ WAL/SHM)
rm -f forge.db forge.db-wal forge.db-shm

# Ledger d'engagement + sa clé de signature (0600) — DESTRUCTIF pour l'auditabilité
rm -f engagement.jsonl engagement.jsonl.ed25519

# Scope actif (périmètre autorisé) + fichiers de secrets
rm -f scope.json *.env *.key

# Sauvegardes chiffrées éventuelles
rm -f /backups/*.forge
```

> La clé `.ed25519` est un **secret** (`0600`). Sur un support qui le permet, préférez un effacement
> sûr (`shred -u`) pour la clé et les `*.env` contenant des hashes/secrets.

---

## 5. Désinstaller les outils orchestrés (optionnels)

Forge **n'embarque pas** les moteurs offensifs — ils sont orchestrés en option. Les retirer est
indépendant de Forge :

| Outil | Retrait |
|---|---|
| httpx / nuclei / subfinder | supprimer les binaires du PATH (ou l'image `full` → passer `mini`) |
| nmap | `apt remove nmap` (ou retirer l'image) |
| weasyprint (moteur PDF) | `rm -rf /opt/pdfenv /usr/local/bin/weasyprint` |
| browser-automation | `docker compose --profile browser down` + `docker image rm browser-automation-browser` |
| msfrpcd / Burp REST | services BYO (hors Forge) — arrêter côté opérateur |

En `mini`, aucun de ces outils n'est présent dans l'image ; les modules correspondants sont
simplement `available:false`.

---

## 6. Nettoyage build/dev

```sh
# depuis la racine du dépôt
make clean                     # build/dist/egg-info/.pytest_cache + base démo + __pycache__ + cargo clean
# ou manuellement :
cd console && cargo clean      # supprime console/target/ (~1.6 GB de cache)
```

`make clean` **préserve** les fichiers gitignorés `scope.json` / ledger (état d'engagement) — à
supprimer explicitement (§4) si voulu.

---

## Checklist de suppression complète

- [ ] Sauvegarde chiffrée réalisée si l'audit doit survivre ([`BACKUP.md`](BACKUP.md)).
- [ ] Conteneur/service arrêté et supprimé.
- [ ] Volumes/dossiers de données supprimés (DB + WAL/SHM).
- [ ] Ledger `engagement.jsonl` **et** clé `engagement.jsonl.ed25519` purgés (effacement sûr).
- [ ] Scope actif + fichiers `.env`/`.key` (secrets, hashes argon2id) purgés.
- [ ] Image(s) Docker supprimée(s).
- [ ] Outils orchestrés retirés si non utilisés ailleurs.
- [ ] `docker volume ls` / `ls /var/lib/forge` confirment qu'il ne reste rien.

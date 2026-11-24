# Uninstall & data removal

[English](UNINSTALL.md) | [Français](UNINSTALL.fr.md)

> [Contents](README.md) · See also: [Installation](INSTALLATION.md) · [Backup](BACKUP.md) ·
> [Migration](MIGRATION.md)

This page explains how to **stop**, **remove** and **purge** a Forge deployment, depending on the
installation path. The persisted data are **three coupled artefacts**: the SQLite database, the
engagement ledger, and its **`.ed25519` signing key**.

> ⚠️ **Before purging**: if the engagement must remain auditable, make an **encrypted backup**
> (it bundles database + ledger + key) — see [`BACKUP.md`](BACKUP.md). Once the ledger and its key
> are deleted, the chain of custody can no longer be verified.

---

## 1. Docker Compose

```sh
# from the repository root
# Stop (keeps volumes/data)
docker compose down

# Stop + DELETE the named volumes (DB + ledger) — DESTRUCTIVE
docker compose down -v

# Remove the image
docker image rm forge:0.0.1 forge:0.0.1-mini 2>/dev/null

# Remaining named volumes (if -v was not passed)
docker volume rm forge_forge-db forge_forge-ledger 2>/dev/null   # prefix = compose project name ("forge")
docker volume ls | grep forge                                    # check that none remain
```

The **active scope** is bind-mounted from the host (`scope.json`) — it stays on the host after
`down -v`. Delete it explicitly if it contains sensitive scopes.

---

## 2. Docker (container only)

```sh
docker rm -f forge                    # stops + removes the container
docker volume rm forge-db forge-ledger        # DESTRUCTIVE (if created as named volumes)
docker image rm forge:0.0.1
```

If you had bind-mounted a data folder (`-v /chemin/db:/data/db`), purge it by hand (§4).

---

## 3. Native / systemd

```sh
# Stop + disable the service
sudo systemctl disable --now forge
sudo rm -f /etc/systemd/system/forge.service
sudo systemctl daemon-reload

# Binary + application + assets
sudo rm -f /usr/local/bin/forge
sudo rm -rf /opt/forge

# EnvironmentFile (contains the argon2id hashes / secrets)
sudo rm -f /etc/forge/forge.env

# Data (DESTRUCTIVE) — DB, ledger, signing key, scope
sudo rm -rf /var/lib/forge

# System account
sudo userdel forge 2>/dev/null
```

If the Python engine was installed as editable: `pip uninstall forge`.

---

## 4. Purging state artefacts (all paths)

Depending on `FORGE_CONSOLE_DB` / `FORGE_CONSOLE_LEDGER` / `FORGE_CONSOLE_SCOPE` (see
[Configuration](CONFIGURATION.md)), delete:

```sh
# SQLite database (+ WAL/SHM)
rm -f forge.db forge.db-wal forge.db-shm

# Engagement ledger + its sidecars (0600 signing key, high-water-mark, observed durations)
# — DESTRUCTIVE for auditability
rm -f engagement.jsonl engagement.jsonl.ed25519 engagement.jsonl.hwm engagement.jsonl.durations

# Active scope (authorized scope) + secret files
rm -f scope.json *.env *.key

# Any encrypted backups
rm -f /backups/*.forge
```

> The `.ed25519` key is a **secret** (`0600`). On media that allow it, prefer a secure
> erase (`shred -u`) for the key and the `*.env` files containing hashes/secrets.

---

## 5. Uninstalling the orchestrated tools (optional)

Forge **does not ship** the offensive engines — they are orchestrated optionally. Removing them is
independent of Forge:

| Tool | Removal |
|---|---|
| httpx / nuclei / subfinder | remove the binaries from the PATH (or the `full` image → switch to `mini`) |
| nmap | `apt remove nmap` (or remove the image) |
| weasyprint (PDF engine) | `rm -rf /opt/pdfenv /usr/local/bin/weasyprint` |
| browser-automation | `docker compose --profile browser down` + `docker image rm browser-automation-browser` |
| msfrpcd / Burp REST | BYO services (outside Forge) — stop them on the operator side |

In `mini`, none of these tools is present in the image; the corresponding modules are
simply `available:false`.

---

## 6. Build/dev cleanup

```sh
# from the repository root
make clean                     # build/dist/egg-info/.pytest_cache + demo database + __pycache__ + cargo clean
# or manually:
cd console && cargo clean      # removes console/target/ (several GB of cache)
```

`make clean` **preserves** the gitignored `scope.json` / ledger files (engagement state) — to be
deleted explicitly (§4) if wanted.

---

## Complete removal checklist

- [ ] Encrypted backup made if the audit must survive ([`BACKUP.md`](BACKUP.md)).
- [ ] Container/service stopped and removed.
- [ ] Data volumes/folders deleted (DB + WAL/SHM).
- [ ] Ledger `engagement.jsonl` **and** its sidecars (`.ed25519`, `.hwm`, `.durations`) purged
      (secure erase for the key). The `.durations` file contains **only** durations aggregated **per module
      kind** — no target, no host, no URL — but it is deleted along with the rest.
- [ ] Active scope + `.env`/`.key` files (secrets, argon2id hashes) purged.
- [ ] Docker image(s) removed.
- [ ] Orchestrated tools removed if not used elsewhere.
- [ ] `docker volume ls` / `ls /var/lib/forge` confirm that nothing remains.

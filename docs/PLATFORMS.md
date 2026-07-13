<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Matrice de support des plateformes

Forge est conçu **OS-agnostique** : aucun chemin absolu ni binaire n'est codé en dur dans le code
porteur. Les décisions spécifiques à l'OS sont **centralisées** dans deux seams :

- **Moteur Python** — `forge/portability.py` : `config_dir()` / `data_dir()` (répertoires par défaut
  PAR OS, override `FORGE_*` prioritaire) et `restrict_file_permissions()` (0600 sur POSIX,
  no-op best-effort ailleurs) ; résolution de binaire via `shutil.which` dans le tool-wrapper
  (`forge/runner.py`) — gère les suffixes `.exe`/`.bat`/`.cmd` (PATHEXT) sous Windows.
- **Console Rust** — chemins temporaires via `std::env::temp_dir()` (honore `TMPDIR`/`TMP`/`TEMP`),
  base et racines de données via variables d'environnement (`FORGE_CONSOLE_DB`, `FORGE_PKG_DIR`,
  `FORGE_CONSOLE_WEB`, `FORGE_CONSOLE_SCOPE`, …), interpréteur Python via `FORGE_PYTHON` résolu sur
  le `PATH`, et le spawn C2 gouverné **gardé par `#[cfg(unix)]` / `#[cfg(not(unix))]`**.

> **Filet anti-régression** : `tests/test_portability_guard.py` ÉCHOUE si un `/tmp`, `/usr/bin` ou
> `/home/` codé en dur réapparaît dans `forge/` ou `console/src/`. Il tourne dans la suite standard.

---

## Vue d'ensemble

| Plateforme | Statut | Détail |
|---|---|---|
| **Linux** (x86-64, arm64) | ✅ **Pleinement supporté — primaire** | Cible de dev/CI/déploiement. Toutes les fonctions, y compris le kill de sous-arbre `setsid`/`killpg` du run C2 gouverné, et les perms `0600` sur les clés/ledger. |
| **macOS** (Darwin, Intel/Apple Silicon) | ✅ **Pleinement supporté** | POSIX : `setsid`/`killpg` et `chmod 0600` fonctionnent à l'identique de Linux. Les répertoires par défaut retombent dans la branche POSIX (`~/.config/forge`, `~/.local/share/forge`) — prévisible. |
| **Windows** (10/11, Server) | 🟡 **Best-effort** | Console/DB/RBAC/wizard/détection/import + la plupart des tool-wrappers marchent. La **seule** dégradation : le run C2 gouverné n'a pas le kill de sous-arbre POSIX (voir plus bas). Aucun crash : tout dégrade proprement. |

Prérequis communs : **Rust ≥ 1.70** (console) et **Python ≥ 3.9, stdlib seule** pour le cœur du
moteur (les modules réseau/outillage utilisent `shutil.which` pour découvrir les binaires optionnels).

---

## Windows — ce qui marche vs ce qui est Unix-only

| Composant | Windows | Note |
|---|---|---|
| Console Rust/axum (HTTP, SPA, `/health`) | ✅ | Aucun appel POSIX sur le chemin de service. |
| Base SQLite + migration + backup chiffré | ✅ | `rusqlite` est cross-platform ; `FORGE_CONSOLE_DB` résout le chemin. |
| RBAC (admin/opérateur/viewer), auth, host-guard | ✅ | Logique pure, pas d'OS. |
| Wizard de 1er déploiement (`/api/setup`) | ✅ | Idem. |
| Sources de détection (Plume/CrowdSec/…/exec/file) | ✅ | `exec` résout le programme sur le `PATH`. |
| Import (nmap/nuclei/burp/httpx/ffuf/generic) + `/api/import` | ✅ | Staging sous `std::env::temp_dir()` → `%TEMP%`. |
| Tool-wrappers (résolution des binaires) | ✅ | `shutil.which` (Python) / `PATH` (Rust) — gèrent `.exe`/`.bat` via PATHEXT. Les outils absents dégradent en « indisponible », comme sur Linux. |
| Ledger tamper-evident (hash-chain + Ed25519/HMAC) | ✅ | Cryptographie portable ; **la clé atterrit** même si le `chmod 0600` est sauté. |
| Perms `0600` sur clés/ledger | 🟡 dégradé | `restrict_file_permissions()` est un **no-op best-effort** hors POSIX (Windows n'exprime pas `0600`) — sécuriser via les ACL NTFS / l'emplacement du fichier. |
| **Run C2 gouverné — kill de sous-arbre** (`setsid`/`killpg`) | 🟡 **dégradé (Unix-only)** | Le process enfant **spawn et tourne** ; cancel/watchdog le terminent via `kill_on_drop` et le reconciler marque le run terminal en base. Ce qui MANQUE sous Windows : couper **tout le sous-arbre détaché** en une fois (les groupes de session POSIX n'existent pas). Gardé par `#[cfg(not(unix))]`, documenté, **jamais un crash**. |

**Invariants préservés sur toutes les plateformes** : ROE fail-closed / scope-guard, plancher
opérateur+exploit, ledger tamper-evident, RBAC, host-guard, isolation par-engagement, spawn
sans-shell (`shell=false`). Aucun de ces invariants ne dépend de l'OS.

---

## Résolution des répertoires config / données / temp

L'override d'environnement **l'emporte toujours** ; seuls les DÉFAUTS sont per-OS.

| Rôle | Override | Défaut Linux/macOS (POSIX) | Défaut Windows |
|---|---|---|---|
| **Config** (moteur) | `FORGE_CONFIG_DIR` | `$XDG_CONFIG_HOME/forge` sinon `~/.config/forge` | `%APPDATA%\forge` (repli `~/AppData/Roaming/forge`) |
| **Données** (ledger, mémoire, index) | `FORGE_DATA_DIR` | `$XDG_DATA_HOME/forge` sinon `~/.local/share/forge` | `%LOCALAPPDATA%\forge` (repli `~/AppData/Local/forge`) |
| **Temp** (plans de run, rapports, staging import — console) | `TMPDIR`/`TMP`/`TEMP` (via `std::env::temp_dir()`) | `/tmp` (ou `$TMPDIR`) | `%TEMP%` |
| **Base console** | `FORGE_CONSOLE_DB` | `forge.db` (relatif au cwd) | idem |

`config_dir()` / `data_dir()` retournent un `pathlib.Path` ; `create=True` fait le `mkdir(parents,
exist_ok)`. Voir [`CONFIGURATION.md`](CONFIGURATION.md) pour la table exhaustive des variables.

---

## Backend Postgres (`store-postgres`) — dépendances hôte

Le backend Postgres OPT-IN (feature Cargo `store-postgres`, cf. [`DEPLOYMENT.md`](DEPLOYMENT.md) §3bis)
reste **openssl-free** (TLS `rustls`/`ring`) et la **connexion** ne requiert **aucun** binaire externe
(pas de libpq — client Rust pur). La **SAUVEGARDE Postgres** appelle en revanche le binaire externe
**`pg_dump`** (et `pg_restore` à la restauration) : il doit être **sur le PATH** de l'hôte/du conteneur,
**dans une version ≥ celle du serveur** (un `pg_dump` v15 refuse un serveur v16). L'image Docker buildée
avec la feature installe `postgresql-client-16` depuis le dépôt PGDG (ARG `FORGE_PG_CLIENT_VERSION`) ;
en natif, installer le paquet client correspondant. Sans `pg_dump`, la sauvegarde **échoue clairement**
(jamais de repli silencieux). Multi-plateforme : `pg_dump` existe sous Linux/macOS/Windows.

---

## Limitation Unix-only documentée (récapitulatif)

Une seule capacité est strictement Unix : **le kill de groupe de process (`setsid` + `killpg`) du
run C2 gouverné**, qui permet de couper d'un coup tout le sous-arbre d'un moteur détaché. Hors Unix,
le run reste pilotable (spawn, cancel via `kill_on_drop`, réconciliation au boot, statut terminal en
base) mais **sans** la garantie « couper tout le sous-arbre détaché ». C'est un choix explicite,
gardé par `cfg`, non-crashant, et sans incidence sur les invariants de gouvernance. Pour cet usage,
préférer **Linux ou macOS**.

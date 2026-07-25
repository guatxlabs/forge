# Forge — Console in-UI (runner gouverné de sous-commandes)

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Administration](ADMINISTRATION.md) ·
> [Sauvegarde & restauration](BACKUP.md) · [Upgrade / migration](UPGRADE.md) ·
> [Modèle de sécurité](SECURITY_MODEL.md)

> **Usage AUTORISÉ uniquement.** La Console in-UI n'arme rien : elle expose un petit ensemble
> d'opérations d'exploitation **déjà** disponibles en CLI, derrière une gouvernance stricte.

La **Console Forge** (roadmap **P5**) permet de lancer un petit nombre de sous-commandes `forge`
**depuis l'UI web** (panneau **Administration → Console Forge**), sans ouvrir de shell Linux. Elle
**supprime le besoin** d'un accès shell au conteneur pour les ops courantes :

```bash
# AVANT — accès shell au conteneur requis
docker compose exec forge forge status
docker compose exec forge forge ledger verify
docker compose exec forge forge backup --out /data/snap.forge --passphrase-env FORGE_BACKUP_PASSPHRASE
docker compose exec forge forge upgrade --passphrase-env FORGE_BACKUP_PASSPHRASE

# APRÈS — un clic dans Administration → Console Forge (admin uniquement), sortie streamée en direct
```

## Ce n'est PAS un shell

C'est le point le plus important. La Console **n'exécute pas de commande libre**. Il n'y a :

- **aucun champ « tapez votre commande »** — l'UI n'affiche qu'une **liste fixe** de commandes, chacune
  avec seulement ses **options typées** (cases à cocher / champs) ;
- **aucun flag arbitraire** — chaque commande a un **schéma d'arguments** (jeu fermé de flags + types) ;
  tout flag/argument hors schéma est **rejeté (400)** ;
- **aucun passage par un shell** — le serveur construit un **`argv` FIXE**
  `[sous-commande, --flag, valeur-typée, …]` à partir du triplet **validé**
  (commande allowlistée, flag allowlisté, valeur typée) et lance le **binaire `forge`** directement
  (`spawn`, jamais `sh -c`, jamais de chaîne shell, jamais du texte utilisateur promu en flag) ;
- **aucun métacaractère shell** — toute valeur contenant un métacaractère (`; & | $ \` < > ( ) … `
  espace, octet de contrôle) est **refusée fail-closed** (défense en profondeur — l'`argv` est fixe de
  toute façon).

Endpoint : `POST /api/console/exec` — corps `{command, args?:{…}, confirm?:bool}`. Le back-end vit dans
`console/src/exec.rs` ; l'UI dans `console/web/js/views/admin/console.js`.

## L'allowlist (curée conservativement)

| Commande UI | `forge …` réel | Effet | Arguments (schéma) |
|-------------|----------------|-------|--------------------|
| `status` | `forge status` | **lecture seule** | aucun |
| `ledger verify` | `forge ledger verify` | **lecture seule** | aucun |
| `read findings` | `forge findings` | **lecture seule** | `--campaign <ident>?`, `--json`? |
| `read roe` | `forge roe` | **lecture seule** | `--campaign <ident>?`, `--json`? |
| `read coverage` | `forge coverage` | **lecture seule** | `--campaign <ident>?`, `--json`? |
| `backup` | `forge backup` | crée un fichier chiffré | `--out <nom-géré>` (dossier managé, anti-traversal) + `--passphrase-env <VAR>` |
| `upgrade` | `forge upgrade` | **à effet d'état** (fail-closed + rollback) | `--passphrase-env <VAR>`, `--dry-run`? — **exige `confirm:true`** hors dry-run |

### Exclues volontairement (jamais exposées)

- **`restore`** — écrasement **destructif** de la base + ledger + clé (irréversible). Reste en CLI.
- **`migrate-store` / `migrate`** — bascule de store / import — **destructifs**, réservés à la CLI
  opérateur. (Si un jour exposés : **dry-run uniquement**.)
- **`seed-demo`** — fixture de **développement**.
- **`useradd` / `hashpw`** — l'UI **gère déjà les comptes** (panneau Administration → comptes).
- **`blob-selftest`** — round-trip de dev.

Justification : on n'expose que du **lecture-seule** + deux opérations d'exploitation à faible risque
(`backup` crée un fichier ; `upgrade` est **fail-closed** avec snapshot pré-upgrade + rollback), en
excluant tout ce qui **écrase** ou **mute** irréversiblement.

## Gouvernance & sûreté

- **Admin uniquement** — `check_admin` (session au rôle `admin`, **fail-closed** ; pas de repli par
  secret partagé). Un non-admin reçoit **403** et le panneau **n'apparaît pas** dans la nav (le serveur
  reste l'autorité). Une requête forgée vers `/api/console/exec` par un non-admin est **refusée**.
- **Allowlist + schéma d'args** — commande hors allowlist → **400** ; flag/argument hors schéma → **400** ;
  métacaractère shell / traversal dans une valeur → **400**. Tout est **fail-closed**.
- **Confirmation des commandes à effet d'état** — `upgrade` (hors `--dry-run`) exige `confirm:true`
  dans le corps ; l'UI impose une **case à cocher** de confirmation. Sans confirmation → **refus**.
- **Secrets résolus côté serveur** — pour `--passphrase-env` vous ne fournissez qu'un **NOM de variable**
  d'ENV, **jamais la valeur**. Le serveur la résout via `secret_from_env` (qui gère aussi l'indirection
  `*_FILE` Docker/k8s) uniquement pour **confirmer** qu'elle existe ; la **valeur** est aussitôt jetée et
  n'entre **jamais** dans l'`argv`, le ledger, la sortie ou les logs. Le binaire `forge` enfant la
  re-résout lui-même.
- **Ledger** — chaque exécution écrit une entrée **`console.exec`** dans le ledger tamper-evident :
  `{command, by (admin acteur), args (rédigés — noms de variables/fichiers seulement), argv, confirm}`.
  Aucune **valeur** de secret n'y figure jamais.
- **Plafonds (anti-DoS)** — la sortie est plafonnée (256 KiB ; au-delà on tronque proprement) et la durée
  est plafonnée (défaut **300 s**, `FORGE_CONSOLE_EXEC_TIMEOUT_SECS`) ; au dépassement le **groupe de
  process** est tué (`killpg`).
- **Streaming** — la sortie stdout/stderr est **streamée en direct** (SSE, événements `log`/`status`) dans
  un volet **en lecture seule** ; l'UI rend chaque ligne **échappée** (`textContent`, jamais d'`innerHTML`
  de texte serveur → pas de XSS). L'UI affiche aussi **la commande qui va tourner** (transparence).

## Variables d'environnement

| Variable | Rôle | Défaut |
|----------|------|--------|
| `FORGE_CONSOLE_BACKUP_DIR` | Dossier **géré** où `backup --out <nom>` écrit (le nom fourni est un simple *basename* joint à ce dossier — anti-traversal). | `console-backups` |
| `FORGE_CONSOLE_EXEC_TIMEOUT_SECS` | Plafond de durée d'une exécution (1..3600). | `300` |
| `FORGE_CONSOLE_EXEC_BIN` | Binaire `forge` à lancer (fixe ; jamais dérivé de l'entrée utilisateur). Override de test / install non standard. | binaire console courant |

## Build community / par défaut

La Console est **additive** et **admin-gated** : le build **community** (par défaut) démarre
inchangé, le panneau ne s'affiche que pour un admin, et aucune surface n'est ouverte à un non-admin.

# Référence de configuration

> [Sommaire](README.md) · Voir aussi : [Installation](INSTALLATION.md) ·
> [Premier déploiement](FIRST_DEPLOYMENT.md) · [Administration](ADMINISTRATION.md) ·
> [Modèle de sécurité](SECURITY_MODEL.md)

Forge se configure à **deux niveaux complémentaires** :

1. **Variables d'environnement** — fixées **au déploiement** (image / `.env` / EnvironmentFile
   systemd). Elles pilotent le bind, les chemins d'état, les secrets d'amorçage, les services
   pilotés. Gabarit commenté : [`../.env.example`](../.env.example).
2. **Table `settings`** (SQLite) — configurée **dans l'UI** (wizard de 1er boot ou
   *Administration*), réservée admin, **ledgerisée**. Elle porte la source de détection, la politique
   opérateur, la politique de sauvegarde, etc. **Rien n'y est codé en dur.**

> Sûreté : les défauts laissent Forge **INERTE** et en **loopback**. Rien n'est armé. Les secrets
> ([SECRET]) ne doivent JAMAIS être committés ; garder `.env` en `0600`.

---

## 1. Variables d'environnement

### 1.1 Console — bind, chemins d'état, session

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_CONSOLE_ADDR` | Adresse de bind API/UI. **Jamais** `0.0.0.0` sans reverse-proxy + auth + host-allowlist. | `127.0.0.1:7100` (binaire) · `0.0.0.0:7100` (image, réseau isolé) | `127.0.0.1:7100` |
| `FORGE_CONSOLE_DB` | Chemin du store SQLite. | `forge.db` | `/data/db/forge.db` |
| `FORGE_CONSOLE_LEDGER` | Chemin du ledger d'engagement (JSONL). | `engagement.jsonl` | `/data/ledger/engagement.jsonl` |
| `FORGE_CONSOLE_SCOPE` | Chemin du scope/ROE **actif** (in_scope vide = INERTE). Pré-filtre fail-closed des cibles lançables depuis le web. | `<pkg_dir>/scope.json` | `/data/scope/scope.json` |
| `FORGE_CONSOLE_WEB` | Racine des assets UI servis en fallback. | résolu auto (`console/web`) | `/opt/forge/console/web` |
| `FORGE_CONSOLE_USER` | Identifiant du rôle **viewer** (Basic auth). | `forge` | `forge` |
| `FORGE_CONSOLE_SESSION_TTL` | Durée de vie d'une session (s). **C'est la valeur effective** de la TTL de session. | `3600` | `1800` |
| `FORGE_CONSOLE_HOST` | Allowlist `Host` anti-DNS-rebinding (CSV) si exposé via proxy. `localhost`/`127.0.0.1`/`::1` sont toujours acceptés. | *(vide)* | `console.exemple.test` |
| `FORGE_CONSOLE_LEDGER_PUBKEY` | Clé publique Ed25519 (hex 64) pour la vérif côté console. **Publique, non secrète.** | *(vide)* | `a1b2…` |

### 1.2 Console — secrets d'authentification / RBAC

Vides ⇒ **mode dev localhost-ouvert** pour le viewer, token d'ingestion **généré au boot**, rôle
opérateur **non provisionné** (C2 fermé). Renseigner pour un déploiement durci (ou tout provisionner
via le [wizard](FIRST_DEPLOYMENT.md)).

| Variable | Sens | Défaut | Comment l'obtenir |
|---|---|---|---|
| `FORGE_CONSOLE_TOKEN` | **[SECRET]** Bearer d'**ingestion** (canal moteur→console). Sinon généré au boot (éphémère). | *(auto)* | `openssl rand -hex 16` |
| `FORGE_CONSOLE_PASS_HASH` | **[SECRET]** Hash argon2id du rôle **viewer** (Basic). Sa présence engage la gate d'auth. | *(vide)* | `forge hashpw '<pw>'` |
| `FORGE_CONSOLE_OPERATOR_HASH` | **[SECRET]** Hash argon2id du rôle **opérateur** C2 (en-tête `X-Forge-Operator`). Vide = **C2 fermé** (fail-closed). | *(vide)* | `forge hashpw-operator '<pw>'` |

> **Attribution individuelle** : l'administration (`check_admin`) **n'accepte PAS** de repli
> env-hash — elle exige une **session admin** nommée (créée via le wizard ou `forge useradd
> <login> admin`). Les hashes env sont un mécanisme d'**amorçage headless** (viewer/opérateur).

### 1.3 Moteur Python — spawn & timeouts

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_PKG_DIR` | Racine du package python `forge` spawné par la console (cwd du spawn). | `..` | `/opt/forge` |
| `FORGE_PYTHON` | Interpréteur pour `python3 -m forge.cli`. | `python3` | `python3` |
| `FORGE_DURATIONS` | Kill-switch du **magasin de durées observées** (`<ledger>.durations`, sidecar du ledger de l'engagement — donc **par engagement**, supprimé avec lui). Il agrège la durée des tirs **PAR KIND DE MODULE UNIQUEMENT** (jamais par cible/hôte/URL : ce serait un journal de reconnaissance survivant à l'engagement), en taille **bornée** (≤ 256 kinds, agrégat fixe par kind, ~quelques Kio). Il sert **uniquement** à l'ordre de SOUMISSION du préchauffage intra-vague (`engine._preheat_key`) — **aucune** décision de tir, de scope ou de ROE n'en dépend. `0`/`off`/`false`/`no` ⇒ aucun fichier, aucune mesure, préchauffage sur `action.cost` (comportement d'avant la version). Sans `--ledger`, il n'y a de toute façon aucun fichier. | *(actif)* | `0` |
| `FORGE_RUN_TIMEOUT` | Budget max (s) d'un run C2-light (watchdog). | `1800` (binaire) · `900` (image) | `900` |
| `FORGE_KIND_BUDGET_SHARE` | **Part du budget de temps qu'UN SEUL kind de module peut consommer** sur un run, en fraction. Sert la seconde clause de la porte de budget (`engine._budget_gate` → `interrupt.KindShare`) : on ne DÉMARRE pas un tir dont la consommation **prévue** (moyenne observée du kind sur ce run, à défaut le sidecar `.durations`, à défaut la borne déclarée — jamais au-delà de cette borne), ajoutée à ce que le kind a **déjà** consommé, dépasserait cette part. Motivé par la mesure : sur une campagne réelle, `web.testssl` a pris **1 484 s (41 %)** d'un budget de 3 600 s — trois tirs individuellement raisonnables dont deux tués à leur mur de 600 s — pendant que la vague 1 ne finissait pas. **Ce n'est pas une troncature** : l'action refusée sort en **SKIP nommé**, listé au rapport, **sans aucun verdict** (ni `tested`, ni `not_vulnerable`, ni finding). Trois garde-fous : le **1er tir d'un kind n'est jamais refusé** (un scanner lent tourne toujours au moins une fois) ; les **classes qualifiantes** (IDOR/auth/RCE/SSRF/biz — `planner.is_floored`) sont **exemptées** ; et **sans budget de temps posé, la clause est totalement inerte**. `0` la désactive. Valeur illisible → défaut. | `0.3333` (1/3) | `0.25` |
| `FORGE_PLAN_TIMEOUT` | Budget max (s) d'un **dry-plan** (`POST /api/plan`, inerte). Au dépassement : le **groupe** moteur est tué et l'appelant reçoit `504 plan_timeout` (jamais d'aperçu partiel). Valeur invalide ou `0` → défaut. | `300` | `60` |
| `FORGE_PLAN_MAX_CONCURRENT` | Nombre de **dry-plans en vol** simultanés (chacun spawne un process moteur). Au-delà : `429 plan_busy` — erreur explicite, **pas** de file d'attente muette. **Relue à chaque dry-plan** (comme `FORGE_PLAN_TIMEOUT`) : une modification prend effet sans redémarrer. Valeur invalide ou `0` → défaut. | `2` | `4` |
| `FORGE_ENGINE_TIMEOUT` | Budget (s) du **travail moteur** des autres spawns : catalogue `GET /api/techniques`, `GET /api/workflows`, collecteur de détections, rendu **DOCX/PDF** du livrable, et sonde du registre (`POST /api/modules/refresh`, boot). Au dépassement : le **groupe** est tué et la route rend sa cause NOMMÉE (`techniques_unavailable`/`builtins_unavailable` en fail-soft, `504 docx_engine_timeout` pour le livrable). Relue à chaque appel. Valeur invalide ou `0` → défaut. **Le mur-à-mur d'une requête coupée vaut ce budget PLUS le temps de mort effective du spawn** (SIGTERM, puis SIGKILL après 5 s si un membre l'ignore) : mesuré à **5,02–5,06 s** (9 mesures) pour un budget de 5 s sur un moteur qui sort au SIGTERM. | `120` | `30` |
| `FORGE_ENGINE_MAX_CONCURRENT` | Nombre de spawns moteur de **LECTURE** vivants (compteur distinct de celui du dry-plan et de celui de l'opérateur : une rafale de lectures n'affame pas l'opérateur, et réciproquement — le total machine est la **somme** des trois). Un slot est tenu par la **vie du process ET de ses descendants**, pas par celle de la requête HTTP : abandonner la requête ne le rend pas. Un descendant qui QUITTE le groupe (`setsid`/double-fork) est retrouvé par le marqueur d'environnement du spawn et par la chaîne de parenté (subreaper) — mesuré : 40 requêtes abandonnées laissaient **40** descendants vivants avec un plafond de 4, elles en laissent **0** et la borne refuse (rafale de 20 : 16 × `429`). Limites écrites dans `docs/HTTP_API.md`, et elles sont MOINS CHÈRES POUR L'ÉVADÉ QUE LEUR NOM NE LE SUGGÈRE : il suffit de retirer UNE variable d'environnement (`env -u FORGE_ENGINE_SPAWN` → **7 survivants**, exactement comme `env -i`) quand le leader est déjà sorti ; et un travail délégué à un NON-descendant (`systemd-run --user`) sort simplement du domaine (**5 survivants** pour 4 requêtes abandonnées, slot rendu aussitôt). Hors Linux, pas de `/proc` : repli sur le kill de groupe. COÛT SUR LE CHEMIN NOMINAL, mesuré, ET IL DÉPEND DE LA FORME DU DESCENDANT (une seule forme avait été mesurée et son chiffre généralisé à tort) : aucun descendant **0,030–0,040 s** ; descendant qui REDIRIGE ses fd et meurt au SIGTERM **0,133–0,146 s** ; qui REDIRIGE ses fd et IGNORE SIGTERM **5,17–5,24 s** (slot tenu jusqu'au SIGKILL de la fenêtre de grâce, et il est bien tué) ; qui HÉRITE du pipe stdout — le défaut d'un `fork`/`Popen` sans redirection — **0,380–0,396 s**, contre le BUDGET MOTEUR ENTIER avant correctif (**5,13 s** à `FORGE_ENGINE_TIMEOUT=5`, **9,13 s** à 9, **120,061 s** au défaut livré, et la sortie valide était JETÉE). Le levier de ce cas-là n'était pas `CANCEL_GRACE_SECS` mais `FORGE_ENGINE_TIMEOUT` ; il est traité à la cause (on n'attend plus la fermeture d'un pipe hérité pour répondre, cf. `docs/HTTP_API.md`). Au-delà : refus **explicite** (le message nomme la variable), **pas** de file d'attente muette. Relue à chaque appel. Valeur invalide ou `0` → défaut. | `4` | `8` |
| `FORGE_ENGINE_OPERATOR_MAX_CONCURRENT` | Nombre de spawns moteur **OPÉRATEUR** vivants : `POST /api/import`, `POST /api/modules/refresh`, `POST`/`DELETE /api/tools`, sonde du registre au boot. Gate séparée de la lecture pour deux raisons mesurées : une rafale de lectures viewer ne doit pas faire échouer un import opérateur, et 40 refresh concurrents ne doivent pas rendre une lecture viewer 50× plus lente (mesuré **0,21 s → 11,4 s** avant borne, **0,34 s → 3,7 s** après). Au-delà : refus explicite (`429 import_busy`, `429` + `probe_error` pour le refresh). Relue à chaque appel. | `2` | `4` |
| `FORGE_IMPORT_TIMEOUT` | Budget (s) du parse d'un **import de scan** (`POST /api/import`) — distinct de `FORGE_ENGINE_TIMEOUT` parce qu'un export de scanner (jusqu'à 64 Mio, le plafond d'entrée de la route) est légitimement plus long qu'un catalogue. Au dépassement : spawn tué, `504 import_timeout`, **aucun** finding partiel inséré. Relue à chaque appel. Valeur invalide ou `0` → défaut. **Pourquoi 600 s par défaut** : le budget est dimensionné sur le PLAFOND D'ENTRÉE de la route (64 Mio), pas sur un import typique. Mesuré sur cette machine (moteur `python3` réel, cibles in-scope) : 1,3 Mio / 9 000 entrées → **4,7 s** ; 11,1 Mio / 72 000 entrées → **49,2 s** (croissance supra-linéaire). À 64 Mio, l'ordre de grandeur dépasse donc les 285 s : un défaut plus court couperait un import légitime au pire moment. Ce que coûte un import lent : **un** des 2 slots de la gate OPÉRATEUR (jamais la gate de lecture), sur une route authentifiée opérateur, sans fuite de process (mesuré : 0 survivant après déconnexion du client). Un exploitant qui veut un mur-à-mur court le baisse — c'est le sens de la variable. | `600` | `120` |
| `FORGE_CONSOLE_URL` | Cible d'ingestion `POST /api/ingest` pour le **client Python** (`campaign`, `demo_ingest`, `doctor`). Doit matcher `FORGE_CONSOLE_ADDR`. | `http://127.0.0.1:7100` | `http://127.0.0.1:7100` |
| `FORGE_LEDGER_KEY` | **[SECRET]** Matériel de clé de signature du ledger côté moteur. Vide = clé locale auto-générée (`<base>.ed25519`, `0600`). | *(vide)* | *(matériel de clé)* |
| `FORGE_TOOLS_DIR` | Racine du **volume outils runtime** (`forge tools install\|update\|remove`) : les binaires vont dans `<dir>/bin`, les reçus dans `<dir>/state`. `<dir>/bin` doit être sur le `PATH` pour être résolu (l'image l'y met, devant le `/usr/local/bin` baké). **Rien n'est créé tant qu'aucune action opérateur n'a eu lieu** → vide = comportement identique à la baseline. Cf. `docs/TOOLS_LIFECYCLE.md`. | `<data_dir>/tools` | `/data/tools` |
| `FORGE_TOOLS_MANIFEST` | Chemin du **manifeste** des outils (versions + pins SHA256 par architecture + gabarits d'URL). Vide = `tools.json` livré dans le package. Un manifeste opérateur reste soumis aux **mêmes** validations fail-closed (URL `https://` obligatoire, digest 64 hexa, `bin` sans séparateur de chemin) : il déplace l'allowlist, il ne la supprime pas. | *(livré)* | `/etc/forge/tools.json` |
| `PYTHONPATH` / `PYTHONUNBUFFERED` | Résolution du package `forge` / logs non bufferisés (fixés par l'image/systemd). | image | `/opt/forge` / `1` |

> **Plafond d'octets (non configurable).** La sortie d'un spawn moteur est collectée en RAM : elle est
> plafonnée à **8 Mio** (sorties texte : dry-plan, catalogues) et **64 Mio** (sorties binaires : DOCX/PDF).
> Au-delà, le groupe est tué et l'appelant reçoit une erreur explicite (`502 plan_output_too_large` pour le
> dry-plan, dégradation `501` pour le livrable) — **aucune sortie partielle n'est rendue comme complète**.
> Ce n'est pas un réglage d'exploitation mais une digue anti-OOM : ces valeurs sont des constantes du binaire.

### 1.4 Chiffrement au repos

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_FIELD_KEY` | **[SECRET]** Passphrase de **chiffrement de champ**. Couvre (a) le **matériel d'authentification** d'engagement (bearers/cookies/en-têtes des comptes de test) et (b) les **trois secrets d'intégration** : jeton de source de détection, jeton de canal de notification, `client_secret` SSO. **Build PAR DÉFAUT** — AEAD pur Rust, aucune dépendance ajoutée. Requise **uniquement** si l'un de ces secrets est posé : sans elle, toute écriture est refusée (**503** `field_key_missing`), un run dont le matériel est scellé **refuse de démarrer**, et une intégration dont le secret est scellé **refuse de partir** (jamais un contexte ni une authentification vides en silence). Accepte `FORGE_FIELD_KEY_FILE`. | *(vide)* | *(passphrase forte)* |
| `FORGE_DB_KEY` | **[SECRET]** Clé SQLCipher (chiffrement **intégral**). La console émet `PRAGMA key` **avant toute requête**. Sans elle (sur build chiffré), la base est **illisible** (fail-closed). **Ignorée** sur le build par défaut (base en clair). | *(vide)* | *(passphrase forte)* |

Les deux couches sont **indépendantes et composables** : `FORGE_FIELD_KEY` protège les credentials
**dans le build par défaut** (openssl-freedom intacte) ; `FORGE_DB_KEY` chiffre **tout le reste**, au
prix d'un backend crypto système à la compilation (image `encryption`).

Voir [`DEPLOYMENT.md` §1.6](DEPLOYMENT.md#16-chiffrement-de-champ-du-matériel-dauthentification-build-par-défaut)
(champ), [`MIGRATION.md`](MIGRATION.md) Runbook B et [Installation §6](INSTALLATION.md#6-image-encryption-chiffrement-au-repos--sqlcipher-opt-in) (SQLCipher).

### 1.4bis Egress sortant — confiance TLS et identité cliente

Les **trois** sorties TCP de la console (échange de jeton OIDC, webhook de notification, fetcher de
source de détection) passent par un **seam TLS unique** (`console/src/tls.rs`) dont la vérification est
**pleine et sans échappatoire** : chaîne, nom d'hôte, validité. Le magasin de CA du **système n'est pas
lu** (posture sans dépendance OS : pas de `schannel`/`security-framework`/`openssl`), donc une **AC
privée d'entreprise** doit être **fournie explicitement**.

Deux directions à ne pas confondre : `FORGE_EXTRA_CA_PEM` sert à **vérifier le pair** ; `FORGE_CLIENT_*`
sert à **nous authentifier auprès de lui** (mTLS). Poser la seconde ne relâche rien de la première.

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_EXTRA_CA_PEM` | Ancres de confiance **SUPPLÉMENTAIRES** au format **PEM verbatim** (un ou plusieurs blocs `CERTIFICATE`), **ajoutées** aux racines Mozilla — jamais substituées. Pour un IdP OIDC ou un collecteur signé par l'AC privée de l'organisation. **La vérification reste PLEINE** : ce n'est **pas** un interrupteur, il n'existe toujours aucun moyen d'accepter une chaîne inconnue, un mauvais nom d'hôte ou un certificat périmé. **FAIL-CLOSED** : un PEM illisible/vide/invalide **tue le boot** (`FATAL`, code 2) plutôt que de dégrader en silence vers « pas d'ancre ». Accepte `FORGE_EXTRA_CA_PEM_FILE` (un **chemin**). | *(vide = racines Mozilla seules)* | `-----BEGIN CERTIFICATE-----…` |
| `FORGE_CLIENT_CERT_PEM` | **Chaîne de certificats CLIENTE** (PEM, **feuille d'abord**, intermédiaires ensuite) que la console **présente au pair qui l'exige** (mTLS). Elle n'est envoyée **que si le pair la demande** : la poser ne change **rien** pour les endpoints ordinaires. Publique — le pair la reçoit sur le fil. Accepte `FORGE_CLIENT_CERT_PEM_FILE` (un **chemin**). | *(vide = aucun certificat présenté)* | `-----BEGIN CERTIFICATE-----…` |
| `FORGE_CLIENT_KEY_PEM` | **[SECRET — le plus sensible du binaire]** Clé privée de la chaîne ci-dessus (PKCS#8, PKCS#1 ou SEC1). Elle n'apparaît **nulle part** : ni au boot, ni dans un log, ni dans une erreur, ni dans le ledger, ni dans une réponse d'API. Un refus dit **que** la clé est invalide, jamais **ce qu'elle contient**. **Préférer franchement `FORGE_CLIENT_KEY_PEM_FILE`** (un **chemin** vers un fichier `0600`) : l'environnement d'un processus se lit dans `/proc/<pid>/environ` et se recopie dans tout dump de configuration. | *(vide = aucun certificat présenté)* | `/etc/forge/client.key` via `…_FILE` |
| `FORGE_ALLOW_INTERNAL_INTEGRATIONS` | Autorise les fetches d'**intégration** à joindre une cible **interne/privée** (SIEM/IdP on-prem). Absent/faux ⇒ deny-list SSRF (loopback, RFC1918, link-local, métadonnées cloud, ULA). **Ne couvre pas** l'envoi d'un secret en clair vers une cible **publique** : ce refus-là n'a **aucune** échappatoire. | *(vide = refusé)* | `1` |

**Les deux `FORGE_CLIENT_*` vont ensemble, ou aucune.** Un certificat sans clé ne peut rien signer,
une clé sans certificat ne prouve aucune identité : dans les deux cas rustls n'enverrait tout
simplement rien, et le pair mTLS refuserait la connexion avec un message qui ne désigne pas la
variable manquante. Le boot **meurt** donc (`FATAL`, code 2) sur une identité à moitié posée, sur un
PEM illisible, et sur une **clé qui ne correspond pas au certificat** (comparaison des
`SubjectPublicKeyInfo`) — la faute qu'on commet en renouvelant l'un sans l'autre.

### 1.5 Migration via API (opt-in, pré-provision)

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_ALLOW_API_MIGRATE` | Ouvre `POST /api/setup/migrate` (sinon **403** — la CLL `forge migrate` reste l'UX primaire). | *(off)* | `1` |
| `FORGE_CONSOLE_IMPORT_DIR` | Racine allowlistée des chemins d'import de la migration API (anti path-traversal). | *(racine de données)* | `/import` |

### 1.6 Sauvegardes programmées

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_BACKUP_TICK_SECS` | Période de réveil du scheduler de sauvegarde. | `60` | `60` |
| `FORGE_BACKUP_PASSPHRASE` | **[SECRET]** Passphrase du backup **programmé**. **Le NOM de cette variable** est référencé par `backup_policy.passphrase_env` (jamais la passphrase en DB). | *(vide)* | *(passphrase)* |

Détails : [`BACKUP.md`](BACKUP.md).

### 1.7 Boucle purple — source de détection (legacy / collecteur)

La source se configure **de préférence dans l'UI** (`settings.detection_source`, §2). Les variables
ci-dessous sont des **replis** :

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `PLUME_URL` | **[PURPLE]** Préréglage rétro-compat `kind=plume` (utilisé seulement si `settings.detection_source` est absent). `http://` interne uniquement. | *(vide = purple OFF)* | `http://plume-internal:8000` |
| `PLUME_TOKEN` | **[SECRET][PURPLE]** Basic auth = `base64("user:pass")`. | *(vide)* | `dXNlcjpwYXNz` |
| `FORGE_DETECTION_SOURCE` | **[SECRET]** Spécification JSON complète d'une source (kinds « riches » : crowdsec/elastic/syslog/mTLS/exec). La console la passe **par ENV** au collecteur Python (jamais en argv). | *(vide)* | `{"kind":"crowdsec",…}` |

Modèle complet et préréglages : [`DETECTION.md`](DETECTION.md). Prérequis Plume :
[`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).

### 1.8 Couche accès/évasion (browser-automation, optionnelle)

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_BROWSER_URL` | Service Camoufox + Xvfb pour les modules `evasion.*`. Injoignable = connecteur inerte. | `http://localhost:8080` (image : `http://browser-automation:8080`) | `http://browser-automation:8080` |

### 1.9 Connecteurs opérateur (optionnels)

Vides/injoignables ⇒ connecteur inerte à fire-time (aucune capacité offensive embarquée).

| Variable | Sens | Défaut |
|---|---|---|
| `MSF_RPC_HOST` | Hôte msfrpcd. | `127.0.0.1` |
| `MSF_RPC_PORT` | Port RPC msfrpcd. | `55553` |
| `MSF_RPC_USER` | Utilisateur RPC. | `msf` |
| `MSF_RPC_SSL` | TLS vers msfrpcd. | `true` |
| `MSF_RPC_PASS` | **[SECRET]** Mot de passe RPC (`msfrpcd -P`). | *(vide)* |
| `MSF_RPC_TOKEN` | **[SECRET]** Token RPC permanent (alternative au user/pass). | *(vide)* |
| `BURP_API_URL` | Base REST API Burp. | `http://127.0.0.1:1337` |
| `BURP_API_KEY` | **[SECRET]** Clé API Burp (souvent intégrée à l'URL). | *(vide)* |

### 1.10 Build-time (image)

| Variable | Sens | Défaut | Exemple |
|---|---|---|---|
| `FORGE_TOOLS_PROFILE` | `--build-arg` : `full` (httpx/nuclei/subfinder vérifiés SHA256 + moteur PDF weasyprint) ou `mini` (les omet). | `full` | `mini` |

Voir [Installation §1](INSTALLATION.md#1-profils-dimage--mini-vs-full).

---

## 2. Table `settings` (configurée dans l'UI, ledgerisée)

Clés de la table SQLite `settings`, mutées via l'API (admin) ou le wizard. **Aucune valeur codée en
dur** : une clé absente = comportement par défaut, jamais une valeur inventée.

| Clé | Sens | Défaut | Écrite par |
|---|---|---|---|
| `detection_source` | Objet `DetectionSource` (source de la boucle purple). Secret d'auth **write-only** (jamais renvoyé). | *(absente = purple OFF, fail-open lisible)* | wizard · `POST /api/detection/source` · `POST /api/setup` |
| `operator_policy` | Politique du rôle opérateur (C2). Champ clé : `source_cidrs` (allowlist d'IP client). Absent/vide = **aucune restriction** source. | *(absente)* | wizard · `POST /api/setup` |
| `backup_policy` | Politique de sauvegarde programmée/offsite (`enabled`, `interval_secs`, `retention`, `passphrase_env`, `staging_dir`, `offsite`). Secrets rédigés au GET. | *(absente = aucune sauvegarde programmée)* | `POST /api/backup/policy` |
| `backup_last_run` | Horodatage interne du dernier tick de sauvegarde dû (état du scheduler). | *(absente)* | scheduler (interne) |
| `session_ttl` | TTL de session **persistée** par le wizard/setup (substrat de config). La durée **effective** est pilotée par `FORGE_CONSOLE_SESSION_TTL` (§1.1). | *(absente)* | `POST /api/setup` |
| `trusted_proxy` | CIDR(s) du/des proxy(ies) amont de confiance. Un `X-Forwarded-For` n'est honoré **que** si le pair TCP tombe dans l'un d'eux ; sinon repli **fail-closed** sur le pair TCP. Une valeur non-CIDR ⇒ XFF ignoré. | *(absente = XFF non honoré)* | admin (settings) |

### Gouvernance des modules (table `module`)

Distincte de `settings` : la table `module` porte le **catalogue** (peuplé au boot depuis `forge
modules`) **et** la gouvernance par connecteur, mutée par `POST /api/modules/:kind` (admin,
ledgerisé) :

| Champ | Sens | Effet |
|---|---|---|
| `enabled` (bool) | Connecteur activé/désactivé. | `enabled=false` ⇒ SKIP au tir (comme un outil absent), **même si le binaire est présent**. |
| `web_allowed` (bool) | Le connecteur peut être lancé depuis le web (C2-light). | Contrôle le plancher `web_allowed` des modules sélectionnables via `/api/run`. |
| `available_override` (bool\|null) | Force/efface l'état de disponibilité affiché (3 états : inchangé / effacé / forcé). | Reflète la disponibilité dans l'UI. |

Voir [Administration → Gouvernance des connecteurs](ADMINISTRATION.md#3-gouvernance-des-connecteurs-installerdésinstaller).

---

## 2bis. Débit (`rate`) — ce qu'il bride, et ce qu'il ne bride pas

Réglé dans **`scope.json`**, pas en environnement. Le point à connaître, parce qu'il surprend :

| | bridé par `rate` ? |
|---|---|
| Les **36 modules NATIFS** de forge (ses propres sondes urllib : oracles d'injection, contrôle d'accès, recon passif, en-têtes…) | **oui, toujours** |
| Les **outils EXTERNES** (nmap, nuclei, naabu, httpx, feroxbuster, katana, dnsx, subfinder, sqlmap, wfuzz, dalfox, gobuster, wpscan) | **non, sauf demande explicite** |

Le défaut est donc « **forge se bride, les outils gardent le leur** » — et ce n'est pas un oubli : ces
outils ont leur propre gestion de débit, et leur imposer celui du scope coûte cher. Mesuré à `rate: 5` :

    naabu       1,1 min  ->  3,6 h   (65 535 ports à 5 paquets/s)
    feroxbuster ~qq min  ->  ~100 min
    nuclei      1,0 min  ->   30 min
    httpx       0,1 min  ->  3,3 min

**Pour brider AUSSI les outils : `"rate_explicit": true`** dans le scope. Le drapeau natif de chaque
outil est alors dérivé du `rate` (`-rl` / `-rate` / `--rate-limit`, ou une dérivée en **délai** pour
sqlmap/wfuzz/dalfox/gobuster/wpscan dont le drapeau est un délai par requête). Sans lui, l'argv des
outils est **byte-identique** à leur défaut.

> **Quatre outils y échappaient en silence** (corrigé) : `recon.katana`, `recon.dnsx`,
> `recon.subfinder` et `web.wpscan` déclaraient un groupe `{param:rate}` dans leur gabarit d'argv
> **sans jamais recevoir de débit** — la liste des kinds concernés était tenue à la main et avait
> dérivé du catalogue. Un groupe de gabarit dont le param manque est simplement **abandonné**, donc
> rien ne le signalait : l'UI affichait bien un champ « rate-limit (-rl req/s) » pour katana, et
> katana — un **crawler HTTP** — tournait à plein régime sous `rate_explicit`. La liste est
> désormais **dérivée du registre** ; un outil ajouté au catalogue avec un groupe de débit est
> couvert d'office (garde-fou : `tests/test_run_rate_cap.py::TestEveryToolThatDeclaresARateGetsOne`).

À armer quand l'engagement l'exige : programme qui interdit le trafic soutenu, cible fragile, ou
clause « *avoid service degradation* ».

> Ce levier **existe et fonctionne depuis toujours** ; il n'était documenté **nulle part** (0
> occurrence dans la doc et l'exemple de scope au 2026-08-11), ce qui l'a fait passer pour mort lors
> d'un audit. Un levier qu'on ne peut pas trouver équivaut à un levier absent — d'où cette section.

---

## 2ter. `run_rate` — le plafond de débit du **RUN** (le second étage)

`rate` borne le débit d'une **ACTION**. Il ne bornait rien au niveau d'un **RUN**, et ce n'était pas
un détail : le seau est reconstruit à **chaque `fire()`** et vit en **thread-local**, donc le premier
tir de chaque action trouve son créneau libre, et le plafond effectif est **multiplié par le
parallélisme**. Mesuré (`tests/test_run_rate_cap.py`, horloge injectée, `rate: 5` déclaré) :

| | débit du RUN observé |
|---|---|
| sériel, 30 actions × 1 requête | **NON BORNÉ** (0 s d'attente sur tout le run) |
| sériel, 12 actions × 3 requêtes | 7,29 req/s |
| sériel, 24 actions × 2 requêtes | 9,79 req/s |
| **parallèle pool=4**, 24 × 2 | **33,5 req/s** (médiane de 5) |
| **parallèle pool=8**, 24 × 2 | **59,0 req/s** |

`rate: 5` délivrait donc jusqu'à **11,8× le débit annoncé**. Le coût est établi : une cible (Juice
Shop) laissée **34 min sans être ciblée** reste stable (102 → 21 Mio) ; campagne lancée à 13:12:42 →
**3,78 Gio à 13:13:24** → `Exited(139)` à 13:14:47. Mettre une cible à genoux viole
« *avoid service degradation* », clause de la quasi-totalité des programmes — motif d'exclusion.

**Le plafond de run est un SECOND étage, pas un remplacement.** Les deux sont **chaînés** : une
requête attend le créneau du RUN, **puis** celui de son ACTION. Le débit résultant est celui du plus
serré des deux ; aucun n'annule l'autre (un `rate` serré garde ses rafales lissées même sous un
`run_rate` large, et réciproquement).

| Clé de `scope.json` | Effet |
|---|---|
| `"run_rate": N` | Plafond de **N req/s pour tout le run**, partagé par toutes les actions **et tous les workers**. **PRIME** sur la ligne suivante — y compris `0`, qui **désarme**. |
| `"rate_explicit": true` | À défaut de `run_rate`, arme le plafond à la valeur de `rate`. C'est le seul armement automatique, et il est cohérent : ce levier dit déjà « bride tout, outils compris, cet engagement l'exige ». |
| *(rien)* | **AUCUN plafond de run** — le défaut, byte-identique à avant. |

**Pourquoi le défaut est « aucun plafond »** : armer un plafond d'office effondrerait la couverture
de tout run existant qui n'a rien demandé (cf. §2bis — `rate: 5` imposé aux outils fait passer naabu
de 1,1 min à 3,6 h). Un frein est une **décision d'opérateur** ; sans décision, pas de frein — la
même règle que `--run-timeout`.

> **RUPTURE NOMMÉE — le chemin CONSOLE.** `console/src/runs_proc.rs` pose
> `"rate_explicit": spec.rate.is_some()` : renseigner le champ *Rate-limit* de la vue **Launch**
> arme donc désormais **aussi** le plafond de run. C'est un changement de comportement, et il est
> voulu — c'est ce que l'UI promettait déjà (« règle le débit (req/s) », cf. `docs/QUICKSTART.md`)
> et qu'elle ne tenait pas : jusqu'ici un `rate: 5` posé dans Launch délivrait jusqu'à **59 req/s**.
> Le run est plus lent parce qu'il respecte enfin le débit demandé. Pour l'ancien comportement sans
> renoncer aux drapeaux d'outils : `"run_rate": 0` dans le scope.

**Un run bridé le DIT.** Avant le premier tir : une ligne de progression `[DÉBIT RUN]` nommant la
valeur **et le réglage d'origine**, plus une entrée de ledger `engine.run_rate`. À la fin : le débit
**observé** et les secondes d'attente imposées, également exposés dans `Engine.coverage()['run_rate']`.
Un frein invisible est pire qu'un frein absent : l'opérateur conclurait que forge est lent.

**Portée honnête** : le plafond borne ce qui passe par le chokepoint HTTP des oracles
(`Oracle._http`) — les **36 modules natifs**. Un **sous-process** (nuclei, feroxbuster, naabu…) n'y
passe pas ; son débit se bride par **son propre drapeau**, c'est-à-dire par `rate_explicit` (§2bis).
Pour brider *réellement tout* : `"rate_explicit": true` — qui arme les deux à la fois.

---

## 2quater. Egress tiers d'un module — `allow_tool_egress`

Forge gate déjà l'assist LLM (`scope.llm.allow_external`) et le backend mémoire à embeddings par un
egress **explicite**. Il ne gatait pas ses **outils**, et la mesure a rendu l'incohérence intenable :
`recon.httpx`, retenu comme *loopback-safe*, a téléchargé **92,6 Mio depuis huggingface.co à chacun de
ses 4 tirs** (~370 Mio) via son drapeau `-tech-detect` — **seul egress prouvé sur 4 906 findings**,
dans un banc annoncé « loopback strict ». Il n'avait échappé à aucune interdiction : il avait échappé
au **regard**, parce que l'exclusion portait sur l'**intention déclarée**, jamais sur l'egress
**observé**.

Le principe : **un module qui sort vers un tiers le DÉCLARE, et l'opérateur peut le REFUSER.**

| Valeur de `allow_tool_egress` | Effet |
|---|---|
| *(absente)* / `false` | **Refus** de tout egress déclaré (défaut, fail-closed) |
| `true` | Autorise les hôtes **déclarés** (jamais les autres : la déclaration reste le contrat) |
| `["*.huggingface.co", …]` | **Allowlist** par motif (`fnmatch`) ; liste vide ⇒ refus |

Côté module (duck-typé, aucun module existant n'a à changer) : `egress = ("hôte", …)` et, si le
module ne sait **pas** s'en passer, `egress_required = True`.

* module qui sait **dégrader** (le cas de `recon.httpx`) → il tire quand même, et reçoit
  `action.params['_egress_allowed'] = False` : à lui de retirer la fonctionnalité qui sort.
  Coverage-safe : on **borne**, on ne supprime pas ;
* module qui ne sait **pas** s'en passer → **VETO nommé** par le ROE (couche 3bis), qui cite l'hôte
  et la clé qui lève le refus. Aucun verdict n'est émis pour l'action.

Le constat est dit **une fois par module** (progression `[EGRESS TIERS]` + ledger
`engine.tool_egress` + `coverage()['tool_egress']`) — **y compris quand l'egress est autorisé** : un
egress qu'on autorise sans le voir se reproduira à l'identique.

---

## 3. Qu'est-ce qui est configurable où ?

| Réglage | Au déploiement (env) | Dans l'UI (settings) |
|---|:---:|:---:|
| Bind, chemins d'état, TTL session | ✅ | — |
| Secrets d'amorçage (token, hash viewer/opérateur) | ✅ | (comptes créés via UI/CLI ensuite) |
| Admin & comptes individuels | (amorçage) | ✅ (wizard + *Administration → Comptes*) |
| Source de détection (purple) | ✅ (legacy `PLUME_*`/`FORGE_DETECTION_SOURCE`) | ✅ **recommandé** (`detection_source`) |
| Politique opérateur (source-CIDR) | — | ✅ (`operator_policy`) |
| Politique de sauvegarde (schedule/offsite) | (2 knobs : tick, passphrase env) | ✅ (`backup_policy`) |
| Gouvernance des connecteurs | — | ✅ (`module`) |
| Chiffrement au repos | ✅ (image `encryption` + `FORGE_DB_KEY`) | (reflété : `capabilities.sqlcipher`) |
| Proxy de confiance (XFF) | — | ✅ (`trusted_proxy`) |

Le **provisioning headless** (sans navigateur) est possible : poser `FORGE_CONSOLE_PASS_HASH` /
`FORGE_CONSOLE_OPERATOR_HASH` / `FORGE_CONSOLE_TOKEN` — l'état de setup bascule alors `provisioned:true`
sans wizard. Voir [Premier déploiement](FIRST_DEPLOYMENT.md).

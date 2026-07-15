# Ajouter votre propre outil — depuis l'UI (gouverné)

> [Sommaire](README.md) · Voir aussi : [Catalogue de modules](MODULES.md) · [Administration](ADMINISTRATION.md) ·
> [Modèle de sécurité](SECURITY_MODEL.md) · [API HTTP](HTTP_API.md)

Un red-teamer peut déclarer **son propre outil CLI** depuis la console web — **sans éditer de fichier dans
le conteneur, sans variable d'environnement, sans redémarrage**. L'outil ajouté est gouverné **exactement
comme un module natif** : scope-guard fail-closed, argv **fixe no-shell**, **allowlist** de drapeaux, statut
**jamais** promu `vulnerable`, plancher **exploit** (arm + raison). C'est de la **donnée déclarative** (un
`ToolSpec`), **jamais du code arbitraire**.

---

## ⚡ Ajouter un outil PENDANT un pentest (sans redémarrage)

**Les deux voies sûres sont montées PAR DÉFAUT** (`docker-compose.yml`, binds `:ro` `./tools` + `./toolspecs`) —
rien à activer, rien à reconstruire. **Une analyse en cours n'est JAMAIS interrompue ; le conteneur continue de
tourner ; vous ne faites JAMAIS `docker build` / `down` / `up` pour ajouter un outil.**

- **(a) Un binaire / script exécutable** → déposez-le dans **`forge/tools/`** (`chmod +x`). `/opt/tools` est
  sur le `PATH` et la disponibilité est vérifiée **à fire-time** (`runner.available`→`shutil.which`) → l'outil
  est **utilisable au PROCHAIN run**, **rien à cliquer**.

  ```bash
  cp ~/bin/myfuzzer forge/tools/ && chmod +x forge/tools/myfuzzer   # c'est tout
  ```

- **(b) Un ToolSpec gouverné** (JSON/YAML, zéro code) → déposez-le dans **`forge/toolspecs/`** *(ou ajoutez-le
  via **Administration → Ajouter un outil**)** → cliquez **« Rafraîchir modules »** (bouton `#mod-refresh`,
  opérateur ; ou `POST /api/modules/refresh`) → il **apparaît en direct**. Le dir `./toolspecs` est **fusionné**
  avec le dir server-managed des outils ajoutés par l'UI (`probe_toolspecs_env`) → les deux **coexistent**.

- **(c) Un module Python custom** (`@register`) → **activez d'abord** le montage `./plugins` (**OPT-IN** — code
  arbitraire) : décommentez le bind `./plugins` + l'env `FORGE_PLUGINS` dans `docker-compose.yml`, déposez le
  module, puis **« Rafraîchir modules »**.

> **La SEULE exception au « jamais de recréation »** : activer le montage opt-in `./plugins` (ou si vous aviez
> retiré les montages par défaut) exige **un** `docker compose up` de recréation (on ne peut pas ajouter un
> bind-mount à un conteneur déjà lancé). C'est précisément pourquoi `./tools` + `./toolspecs` restent **ON par
> défaut** : vous n'y êtes **jamais** confronté en plein pentest. Détail complet : [§5](#5-rendre-le-binaire-disponible).

---

- [1. En bref](#1-en-bref)
- [2. Le formulaire (Administration → Ajouter un outil)](#2-le-formulaire)
- [3. Anatomie d'un ToolSpec](#3-anatomie-dun-toolspec)
- [4. Gouvernance (ce qui est garanti)](#4-gouvernance)
- [5. Rendre le binaire disponible en conteneur / k3s](#5-rendre-le-binaire-disponible)
- [6. API](#6-api)
- [7. Upload de plugin Python (haute confiance — désactivé par défaut)](#7-upload-de-plugin-python)

---

## 1. En bref

1. Ouvrez **Administration → Ajouter un outil** (session **admin** requise).
2. Renseignez : `kind` (dans le namespace **`custom.*`**), `vuln_class`, `binary` (et/ou `docker_image`),
   `argv_template` (liste de tokens), éventuellement `params_schema`, `flag_allowlist`, `parser`, `mitre`/`cwe`,
   `phase`, `capability`, `severity`, `hit_status`, description.
3. **Ajouter** → l'outil est **validé fail-closed**, **persisté** (JSON `0600` dans le dossier server-managed),
   puis le catalogue est **rechargé à chaud** : l'outil apparaît **immédiatement** dans **Capacités** et dans
   **Lancement** (son `params_schema` est rendu **dynamiquement** en formulaire de configuration).
4. **Supprimer** : le bouton en regard de l'outil (dans la liste « Outils ajoutés ») le retire (fichier +
   catalogue). Un **module natif n'est jamais supprimable**.

Chaque ajout/suppression est **admin-only**, **attribué** à votre compte et **ledgerisé**
(`console.tool.add` / `console.tool.remove`).

## 2. Le formulaire

| Champ | Rôle |
|-------|------|
| **kind** | Clé unique **`custom.<nom>`** (impossible de surcharger un module natif ; anti-traversée). |
| **vuln_class** | Catégorie (`Recon`, `XSS`, `PortScan`, `TLS`…) — pilote le regroupement du catalogue. |
| **binary** | Binaire résolu via `PATH` (ou présent dans l'image). |
| **docker_image** | Repli conteneurisé **optionnel** (nécessite le socket docker — cf. §5). |
| **argv_template** | **Liste de tokens** (jamais une chaîne shell). Placeholders : `{target}`, `{target_host}`, `{target_url}`, `{param:NAME}`, `{args}`. |
| **flag_allowlist** | Drapeaux autorisés pour `{args}` (ex `-t`, `--rate`). **Requis si `{args}` est utilisé.** |
| **params_schema** | Champs de configuration typés (`text`/`number`/`select`/`list`/`flag`) → rendus dans **Lancement**. |
| **parser** | Comment extraire les hits : `lines`/`regex`/`json`/`jsonl`/`none`. |
| **phase / capability** | `recon`/`access`/`exploit` · `passive`/`active`/`exploit`. |
| **severity / hit_status** | Sévérité par défaut d'un hit · `tested` \| `reported_by_tool` (**jamais `vulnerable`**). |
| **exploit / destructif** | Capacités gouvernées (voir §4 — un outil exploit reste **gaté** par l'opt-in armé). |

## 3. Anatomie d'un ToolSpec

Exemple minimal (enrobe `httpx` pour récupérer le `<title>`) :

```json
{
  "kind": "custom.httptitle",
  "vuln_class": "Recon",
  "binary": "httpx",
  "docker_image": "projectdiscovery/httpx",
  "argv_template": ["-silent", "-title", "-u", "{target_url}", "{args}"],
  "flag_allowlist": ["-timeout", "-rate-limit"],
  "params_schema": [
    { "name": "note", "type": "text",   "label": "note libre" },
    { "name": "mode", "type": "select", "label": "mode", "allowed": ["fast", "deep"] }
  ],
  "parser": "lines",
  "phase": "recon",
  "capability": "passive",
  "hit_status": "tested",
  "severity": "INFO",
  "mitre": "T1595",
  "cwe": "CWE-200",
  "description": "httpx <title> (ToolSpec ajouté par l'UI)"
}
```

- Un token **placeholder** est résolu en **élément d'argv séparé** — une cible contenant des métacaractères
  shell reste **un seul argument** (anti-injection). Un `{param:NAME}` lit la valeur saisie dans le formulaire
  de Lancement ; `{param:NAME:DEFAUT}` fournit un défaut.
- `{args}` s'étend en les **extra-args** validés contre la `flag_allowlist` (chaque drapeau **hors liste** est
  refusé fail-closed — aucun processus lancé).

## 4. Gouvernance

Un outil ajouté par l'UI **hérite** de toutes les garanties du wrapper d'outils externes (prouvées par les
tests) — **rien** n'est affaibli par cet endpoint, qui ne fait que **déclarer** l'outil :

- **Admin-only** (`check_admin`, fail-closed 403), **attribué**, **ledgerisé**.
- **Validation fail-closed** au dépôt : `kind` bien formé dans `custom.*` (**pas de surcharge d'un natif**) ;
  `argv_template` = **liste** (jamais une chaîne shell) ; **seuls** les placeholders listés ; `{args}` **exige**
  une `flag_allowlist` ; **binaires interpréteurs** (`sh`/`bash`/`python`/…) **refusés** (sinon `bash -c` ré-
  introduirait le shell) ; **drapeaux d'exfiltration** (écriture-fichier `-o`/`--output`, lecture-config
  `--config`, **proxy** `--proxy`, `--file-read/-write`, `--os-shell`…) **refusés** — même curation que les
  allowlists natives ; caps de taille + rejet des octets NUL.
- **Anti-traversée** : le fichier de spec est écrit dans le **dossier server-managed** sous un nom dérivé du
  `kind` assaini — **impossible d'écrire hors du dossier**.
- **À l'exécution** (moteur) : **scope-guard ROE fail-closed** (cible hors périmètre → `skipped`, **zéro I/O**) ;
  **argv fixe no-shell** ; statut **CLAMPÉ** à `{tested, reported_by_tool}` (**jamais `vulnerable`** : un
  scanner *rapporte*, il ne *prouve* pas) ; **plancher exploit** — un outil `exploit=true` reste gaté par
  `operator + arm + reason` (il n'est **pas** lançable depuis le web sans l'opt-in gouverné).

## 5. Rendre le binaire disponible

Un outil dont le `binary`/`docker_image` **n'est pas présent** dans le runtime dégrade proprement en
`available:false` et est **skippé** au run — **jamais** un faux résultat, jamais un `vulnerable` inventé.
**Trois façons** de rendre un outil disponible :

### (a) Il est déjà dans l'image `full`

Le profil `full` (défaut) embarque **`nmap`**, **`curl`**, **`dig`** (dnsutils), **`httpx`**, **`nuclei`**,
**`subfinder`**. Ces `binary:` sont résolus d'office — rien à faire. *(En profil `mini`, seuls nmap/curl/dig
sont présents ; httpx/nuclei/subfinder dégradent en `available:false`.)*

### (b) Image custom mince (`FROM forge:0.0.1`) — jeu d'outils figé, production

Recommandé quand le jeu d'outils est **arrêté** (déploiement reproductible, conteneur/k3s durci sans montage).
Dérivez l'image et installez/copiez vos binaires dans le `PATH` :

```dockerfile
FROM forge:0.0.1
USER root
RUN apt-get update && apt-get install -y --no-install-recommends sqlmap ffuf \
    && rm -rf /var/lib/apt/lists/*
COPY ./bin/myfuzzer /usr/local/bin/myfuzzer        # binaire ou script auto-contenu (chmod +x)
USER forge
```

### (c) Monter SANS rebuild — `./tools`, `./toolspecs` (défaut), `./plugins` (opt-in)

Un red-teamer **itère** sur beaucoup d'outils : inutile de reconstruire l'image à chaque ajout. L'image expose
**trois dossiers de montage** `:ro` (binds dans `docker-compose.yml`, section « OUTILLAGE OPÉRATEUR SANS
REBUILD ») — **deux ON par défaut, un opt-in** :

| Dossier hôte | → conteneur | Contenu | Câblage | Défaut | Prise en compte |
|--------------|-------------|---------|---------|--------|-----------------|
| `./tools` | `/opt/tools` | binaires **ou scripts auto-contenus exécutables** (shebang + `chmod +x`) | **déjà sur le `PATH`** (aucune env) | **✅ ON** | résolu sur PATH par `shutil.which` à **fire-time** — **sans redémarrage, rien à cliquer** |
| `./toolspecs` | `/opt/toolspecs` | **ToolSpecs déclaratifs** JSON/YAML (zéro code) | env `FORGE_TOOLSPECS=/opt/toolspecs` (**ON**) | **✅ ON** | chargé à la **re-sonde** (« Rafraîchir modules » / `POST /api/modules/refresh`) ; **fusionné** avec le dir server-managed |
| `./plugins` | `/opt/forge/plugins` | modules **Python `@register`** (code) | env `FORGE_PLUGINS=/opt/forge/plugins` | **⚠️ OPT-IN** | chargé au **boot / re-sonde** — décommenter le bind **et** l'env |

**Pourquoi `./tools` + `./toolspecs` sont ON par défaut, `./plugins` non.** Un bind-mount ne peut **pas** être
ajouté à un conteneur **déjà lancé** — il doit exister dès le premier `up`. Pour ne **jamais** vous bloquer en
plein pentest, les deux voies **sûres** (un binaire/script que vous choisissez ; un ToolSpec **déclaratif
gouverné, zéro code**) sont donc montées d'emblée. `./plugins` = **code Python arbitraire** dans le process
moteur → l'opérateur l'active **explicitement**. Les dossiers hôte existent déjà (tracked via `.gitkeep`), donc
le bind par défaut **ne crée pas** de dossier root-owned, et un dossier **vide** monté est inoffensif (aucun
outil chargé tant que rien n'est déposé — cf. §4/§5(a) : binaire absent → `skipped`).

**Exemple — ajouter `myfuzzer` sans redémarrage (montage déjà actif) :**

```bash
# déposer le binaire/script exécutable côté hôte — c'est tout : utilisable au PROCHAIN run
cp ~/bin/myfuzzer forge/tools/ && chmod +x forge/tools/myfuzzer
```

Puis déclarez un ToolSpec pointant `"binary": "myfuzzer"` (via **Administration → Ajouter un outil**, §2, ou un
fichier JSON déposé dans `./toolspecs` + **« Rafraîchir modules »**). `/opt/tools` étant sur le `PATH`,
`runner.tool` le résout au run. **Aucun `docker build` / `down` / `up`.** *(La seule exception : activer le
montage opt-in `./plugins` exige un `docker compose up` de recréation one-shot — voir le tableau ci-dessus.)*

> **Posture de sécurité — à assumer.** `./tools` et `./plugins` sont **OPÉRATEUR-DE-CONFIANCE** : vous
> exécutez des **binaires / du code Python arbitraires que VOUS choisissez de monter** (un plugin `.py` tourne
> dans le process moteur). La **gouvernance ToolSpec** (scope-guard fail-closed, argv **no-shell**, **allowlist**
> de drapeaux, statut jamais promu `vulnerable`, plancher exploit) borne **COMMENT** un outil est invoqué — elle
> ne sandboxe pas ce qu'un binaire/plugin fait en interne. `./toolspecs` est la voie **gouvernée sans code**
> (déclaratif uniquement) — c'est pourquoi elle, comme `./tools`, est **ON par défaut** tandis que `./plugins`
> (code) reste **opt-in**. Tous les montages sont **`:ro`** ; le conteneur tourne en user **non-root** `forge`
> (uid 10001) et lit un dossier hôte `0755` sans souci. Rien n'est chargé tant que vous ne déposez rien.

### `docker_image` (repli conteneurisé) — nécessite le socket docker

Un ToolSpec peut fixer un `docker_image` de repli. Il **nécessite le socket docker** monté dans le conteneur
Forge ; **sans** socket (le défaut durci), un outil `docker_image` **ne peut pas** tourner → privilégiez un
**binaire présent** (image `full`, image custom, ou `./tools`) ou un script auto-contenu.

### Scripts Python personnalisés — deux voies légitimes

Un ToolSpec **ne peut PAS** invoquer un interpréteur (`python3 script.py`, `sh`, `bash`… sont **refusés
fail-closed** — sinon `bash -c` ré-introduirait le shell). Pour un outil écrit en Python :

- **soit** un **plugin** `@register` déposé dans `./plugins` (`FORGE_PLUGINS`) — la voie code ;
- **soit** un **exécutable auto-contenu** (shebang `#!/usr/bin/env python3` + `chmod +x`) déposé dans `./tools`,
  invoqué par son **nom** (`"binary": "monoutil"`), pas via un interpréteur.

Dans tous les cas : **binaire absent au runtime → `skipped`** (offline-safe), jamais un faux résultat.

## 6. API

Toutes admin-only (session admin ; fail-closed 401/403 sinon), ledgerisées.

| Méthode & route | Effet |
|-----------------|-------|
| `POST /api/tools` | Valide + persiste + **hot-reload** un ToolSpec ; renvoie l'outil créé (`registered`, `available`, `params_schema`). |
| `GET /api/tools` | Liste les outils ajoutés par l'UI (`user_added`) + le dossier managé. |
| `DELETE /api/tools/:kind` | Retire un outil UI (fichier + catalogue). **Refuse** un module natif (403). |

Dossier server-managed : `FORGE_TOOLSPECS_DIR` s'il est posé, sinon un `toolspecs/` **sibling de la base**
(dossier de `FORGE_CONSOLE_DB`). Il est injecté dans `FORGE_TOOLSPECS` lors de chaque re-sonde du catalogue
(`forge modules --json`) — c'est ce qui rend l'ajout **immédiat** sans redémarrage, et **persistant** au reboot.

## 7. Upload de plugin Python

L'endpoint d'ajout accepte **UNIQUEMENT** un `ToolSpec` déclaratif (binaire + argv no-shell + allowlist) — la
**voie sûre par défaut**. Il **ne prend jamais** de code Python arbitraire.

Charger un **plugin Python** (`FORGE_PLUGINS`, code exécutable arbitraire) est une voie **haute confiance
distincte**, **hors UI**, réservée à l'opérateur du serveur (dépôt de fichier `.py` + variable
d'environnement). Elle **exécute du code arbitraire** : à réserver à un plugin dont vous maîtrisez la source.
Le build **community/défaut démarre avec zéro outil utilisateur** (comportement byte-identique).

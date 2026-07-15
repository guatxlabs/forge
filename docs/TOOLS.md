# Ajouter votre propre outil — depuis l'UI (gouverné)

> [Sommaire](README.md) · Voir aussi : [Catalogue de modules](MODULES.md) · [Administration](ADMINISTRATION.md) ·
> [Modèle de sécurité](SECURITY_MODEL.md) · [API HTTP](HTTP_API.md)

Un red-teamer peut déclarer **son propre outil CLI** depuis la console web — **sans éditer de fichier dans
le conteneur, sans variable d'environnement, sans redémarrage**. L'outil ajouté est gouverné **exactement
comme un module natif** : scope-guard fail-closed, argv **fixe no-shell**, **allowlist** de drapeaux, statut
**jamais** promu `vulnerable`, plancher **exploit** (arm + raison). C'est de la **donnée déclarative** (un
`ToolSpec`), **jamais du code arbitraire**.

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

### (c) Monter SANS rebuild — `./tools`, `./plugins`, `./toolspecs`

Un red-teamer **itère** sur beaucoup d'outils : inutile de reconstruire l'image à chaque ajout. L'image expose
**trois dossiers de montage OPT-IN** (binds `:ro` **commentés** dans `docker-compose.yml` — décommenter + créer
le dossier hôte ; cf. la section « OUTILLAGE OPÉRATEUR SANS REBUILD » du compose) :

| Dossier hôte | → conteneur | Contenu | Câblage | Prise en compte |
|--------------|-------------|---------|---------|-----------------|
| `./tools` | `/opt/tools` | binaires **ou scripts auto-contenus exécutables** (shebang + `chmod +x`) | **déjà sur le `PATH`** (aucune env) | résolu sur PATH par `shutil.which` — **sans redémarrage** |
| `./plugins` | `/opt/forge/plugins` | modules **Python `@register`** (code) | env `FORGE_PLUGINS=/opt/forge/plugins` | chargé au **boot / re-sonde** du catalogue |
| `./toolspecs` | `/opt/toolspecs` | **ToolSpecs déclaratifs** JSON/YAML (zéro code) | env `FORGE_TOOLSPECS=/opt/toolspecs` | chargé au **boot / re-sonde** du catalogue |

**Exemple — ajouter `myfuzzer` sans rebuild :**

```bash
# 1) déposer le binaire/script exécutable côté hôte
mkdir -p forge/tools && cp ~/bin/myfuzzer forge/tools/ && chmod +x forge/tools/myfuzzer
# 2) décommenter le bind dans forge/docker-compose.yml (bloc volumes du service `forge`) :
#      - ./tools:/opt/tools:ro
# 3) (re)démarrer — aucune reconstruction d'image
docker compose -f forge/docker-compose.yml up -d
```

Puis déclarez un ToolSpec pointant `"binary": "myfuzzer"` (via **Administration → Ajouter un outil**, §2, ou un
fichier JSON déposé dans `./toolspecs`). `/opt/tools` étant sur le `PATH`, `runner.tool` le résout au run.

> **Posture de sécurité — à assumer.** `./tools` et `./plugins` sont **OPÉRATEUR-DE-CONFIANCE** : vous
> exécutez des **binaires / du code Python arbitraires que VOUS choisissez de monter** (un plugin `.py` tourne
> dans le process moteur). La **gouvernance ToolSpec** (scope-guard fail-closed, argv **no-shell**, **allowlist**
> de drapeaux, statut jamais promu `vulnerable`, plancher exploit) borne **COMMENT** un outil est invoqué — elle
> ne sandboxe pas ce qu'un binaire/plugin fait en interne. `./toolspecs` est la voie **gouvernée sans code**
> (déclaratif uniquement). Tous les montages sont **`:ro`** et **opt-in** (rien de monté par défaut).

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

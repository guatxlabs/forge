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
`available:false` et est **skippé** au run (il ne *prétend* jamais tourner). Trois façons de le rendre exécutable :

1. **Baker le binaire dans une image custom** (recommandé en conteneur/k3s) — dérivez l'image Forge et
   `COPY`/installez votre binaire dans le `PATH` :
   ```dockerfile
   FROM forge:latest
   RUN apk add --no-cache your-tool     # ou COPY ./bin/your-tool /usr/local/bin/
   ```
2. **Script auto-contenu** que l'`argv` invoque (déposé dans le `PATH` de l'image, exécutable).
3. **`docker_image`** : **nécessite le socket docker** monté dans le conteneur Forge. En conteneur **sans**
   socket docker (le défaut durci), un outil `docker_image` **ne peut pas** tourner → privilégiez un **binaire
   présent dans l'image** (chemin primaire) ou un script auto-contenu.

Sinon (binaire absent) : l'outil reste visible dans le catalogue mais **`indispo`** — il est simplement **skippé**
(offline-safe), jamais un faux résultat.

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

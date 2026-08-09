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

**Exemples gradués** (copier-coller-fonctionnels — ils chargent, s'enregistrent et passent la sûreté ;
prouvés par `tests/test_contrib_graded_toolspecs.py`). Namespace **`custom.*` obligatoire**. Se chargent via
`FORGE_TOOLSPECS=forge/modules/contrib`, `--toolspec <fichier>`, ou le formulaire UI (coller le JSON) :

- [`forge/modules/contrib/simple.toolspec.json`](../forge/modules/contrib/simple.toolspec.json) — **SIMPLE**
  (`custom.whatweb`) : le strict minimum — binaire + cible, **aucun** param, **aucune** `flag_allowlist`,
  pas de `{args}`. Juste la cible → run.
- [`forge/modules/contrib/medium.toolspec.json`](../forge/modules/contrib/medium.toolspec.json) — **MOYEN**
  (`custom.dirfuzz`, ffuf) : `params_schema` typés (wordlist/threads/rate/codes) rendus en formulaire,
  `flag_allowlist` gouvernant `{args}`, et le mot-clé positionnel `FUZZ` injecté dans l'URL.
- [`forge/modules/contrib/hard.toolspec.json`](../forge/modules/contrib/hard.toolspec.json) — **DIFFICILE**
  (`custom.nuclei_scan`) : **exploit-class** (`exploit:true` → gaté par le plancher operator+arm), repli
  **docker** (`projectdiscovery/nuclei`), parser **JSONL** + `parser_json_path` (extraction de champs), et
  `params_schema` riche (select `severity` + tags/templates/rate).

(L'exemple historique [`forge/modules/contrib/example.toolspec.json`](../forge/modules/contrib/example.toolspec.json)
reste disponible — enrobe `httpx` pour le `<title>`.)

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

Le profil `full` (défaut) embarque une **suite de scanners complète** — ces `binary:` sont résolus d'office,
rien à faire :

- **Cœur / recon de base** : `nmap`, `curl`, `dig` (dnsutils), `httpx`, `nuclei`, `subfinder`.
- **Suite ProjectDiscovery étendue** : `dnsx` (recon.dnsx), `naabu` (recon.naabu), `katana` (recon.katana).
- **Recon / énumération** : `amass` (recon.amass), `gau` (recon.gau), `gospider` (recon.gospider),
  `feroxbuster` (recon.feroxbuster), `ffuf` (recon.content), `masscan` (recon.masscan),
  `gobuster` (recon.gobuster_dns), `whatweb` (recon.whatweb), `wafw00f` (recon.wafw00f), `wfuzz` (fuzz.wfuzz).
- **Scan web / TLS / XSS / SQLi** : `nikto` (web.nikto), `testssl.sh` (web.testssl), `dalfox` (xss.dalfox),
  `sqlmap` (sqli.sqlmap, gaté par le plancher exploit).

*(En profil `mini`, seuls `nmap`/`curl`/`dig` sont présents ; **tous** les outils ci-dessus dégradent en
`available:false` — l'image `mini` reste minimale et byte-identique.)*

**Non embarqués (par design)** — restent joignables autrement :
`wpscan` (web.wpscan) et `zap-baseline.py` (web.zap_baseline, `prefer_docker`) via leur `docker_image` de repli ;
**Burp** (burp.py) et **Metasploit** (msf.py) sont des **services externes** pilotés via ENV/réseau (jamais cuits
dans l'image) ; le **service d'automatisation navigateur** des modules `evasion.*` (et de `xss.stored`) est
lui aussi un **service externe** — voir l'encadré ci-dessous.
Sur une arche **non-amd64**, les binaires Go/Rust ci-dessus (dnsx…ffuf) sont omis (pins amd64 seulement) — les
outils apt/git (sqlmap, nikto, testssl.sh, whatweb, wafw00f, wfuzz, gobuster) restent disponibles.

> **Retirés du catalogue (2026-08) — `recon.theharvester` et `recon.masscan`.** Ni l'un ni l'autre
> n'avait jamais tourné : leur argv était refusé par l'outil, ou leur image n'existait pas (52 findings
> chacun dans le ledger `gxrun2`, tous rendus en « j'ai vérifié, rien trouvé »).
> `theHarvester` : l'image déclarée `laramies/theharvester` **n'existe pas** sur Docker Hub ; l'image
> officielle de l'auteur (`ghcr.io/laramies/theharvester`) a pour entrypoint `restfulHarvest` — un
> **serveur REST**, pas la CLI. *(Ce blocage-là est **levé** depuis 2026-08 : `runner` construit
> désormais `--entrypoint` — voir plus bas. **L'entrée reste retirée** pour une autre raison, qui
> suffit seule : `-b all` exige des clés d'API et, sans elles, theHarvester sort **rc=0 quasi vide** —
> le silence exact que la garde d'honnêteté `rc != 0` ne peut pas rattraper, celui qui a fait retirer
> `masscan`.)* Les sous-domaines restent couverts par `recon.subfinder`, `recon.amass` et
> `recon.subdomains` (crt.sh) ; ce qui est perdu, ce sont les **emails** (qui n'étaient de toute façon
> pas des assets scannables).
> `masscan` : son argv était réparable (consommer l'IP épinglée par le ROE), mais un scan SYN brut ne
> voit pas la réponse sur un hôte multi-homed -> **rc=0, stdout vide** = un « aucun hit » que la garde
> d'honnêteté (`rc != 0`) ne rattrape pas. **`recon.naabu` couvre les ports** (connect TCP, `params.ports
> = "1-65535"` pour la plage complète) et, lui, il tourne.
>
> **`recon.gobuster_dns` et `recon.dnsx` exigent désormais `params.wordlist`.** Sans elle, le module
> rend un `skipped` NOMMÉ sans lancer de processus (inerte, mais honnête) : aucune wordlist n'est
> embarquée — ce serait figer une politique de volume d'énumération au nom de l'opérateur. `dnsx`
> accepte une liste **inline** séparée par des virgules (`-w www,mail,dev`), donc sans fichier ;
> `gobuster` exige un **chemin de fichier lisible par le processus** (attention : via le repli
> `docker_image`, `runner` ne monte aucun volume — une wordlist de l'hôte n'y est pas visible ;
> installer le binaire local, ou utiliser `dnsx` avec une liste inline).

### La voie `docker run` du runner — ce qu'elle construit, et ce qu'elle refuse

`runner` lance `docker run --rm --network host [--entrypoint E] <image> <args…>`.

**Aucun `-v` / `--mount` — refus délibéré, pas un oubli.** Ce que ça coûte est nommé : `gobuster` exige
un **chemin** de wordlist et n'est donc utilisable que par son **binaire local** ; `web.nuclei` a dû
abandonner `-list <fichier>` au profit de `-u a,b,c`. Ce qui n'a pas été retenu, et pourquoi :

| Propriété exigée d'un montage | Verdict |
|---|---|
| **lecture seule** (`:ro`) | Insuffisant **ici** : `:ro` borne les écritures, pas les **lectures** — et `--network host` est déjà sur chaque invocation, donc une lecture est à un `curl` de l'exfiltration. |
| **borné** (allowlist de racines) | Faisable, mais le défaut devrait être **vide** (sinon `/` ou `~/.ssh` passent par inadvertance) → capacité **inerte par défaut**, gain nul. |
| **explicite** (jamais deviné d'un argv) | Le chemin viendrait de `params.wordlist`, un champ **texte du formulaire console** : le canal de plus basse confiance du moteur. Toute la posture (`check_extra_args`, `safe_value`, `unsafe_positional_target`) consiste à empêcher qu'une **valeur de param** devienne une **capacité** ; en faire un chemin hôte **monté** ferait l'inverse. |
| **visible** dans la décision | Satisfaisable (le PoC affiché est construit par le même code que la commande lancée) — mais ne rachète pas les trois lignes ci-dessus. |

Les deux voies qui restent sont **mesurées et documentées** : installer le **binaire local** (il lit le
chemin hôte avec les privilèges du moteur, sans image tierce), ou `dnsx -w www,mail,dev` (liste
**inline**, aucun fichier). Un opérateur qui veut vraiment monter un fichier dans un conteneur d'outil
le fait **hors moteur** ; le moteur, lui, ne fabrique jamais d'accès au système de fichiers de l'hôte
pour une image tierce.

**`--entrypoint` est livré** (opt-in, champ `docker_entrypoint` d'un ToolSpec) : il **n'expose aucun
fichier** et débloque les images dont l'entrypoint n'est pas la CLI attendue — cas mesuré :
`ghcr.io/laramies/theharvester` démarre `restfulHarvest`, un serveur REST. **Gouverné fail-closed** :
un entrypoint **interprète/shell** (`sh`, `bash`, `/bin/busybox`, `python3.11`, `env`…) est **refusé**
(`rc=126`, aucun processus lancé), et un entrypoint hors charset borné (`-…`, espace, métacaractère,
chemin relatif) aussi. Sans ce refus, un ToolSpec **déclaratif** du dossier `./toolspecs` — monté `:ro`
**par défaut** et présenté comme « gouverné, zéro code » — pourrait poser `docker_entrypoint: "sh"` +
`argv_template: ["-c", …]` et **réintroduire le shell**. Le refus est posé dans `runner`, au chokepoint
unique où l'entrypoint atteint `docker run` : il couvre **toutes** les voies de déclaration (code,
fichier, plugin). *(L'endpoint console `/api/tools` n'accepte pas ce champ : sa liste de champs est une
allowlist explicite — fail-closed par omission.)*

> ℹ️ **Modules `evasion.*` : indisponibles par conception sans service navigateur.** Les modules
> `evasion.xhr` / `evasion.turnstile` / `evasion.idor_intercept` / `evasion.discover` (et l'oracle
> `xss.stored`, qui exige un rendu DOM) parlent à un **service HTTP d'automatisation navigateur** que
> Forge **ne fournit pas** : n'importe quelle implémentation exposant le contrat attendu sur `:8080`
> convient, adressée par `FORGE_BROWSER_URL` (défaut `http://localhost:8080`). Sans ce service, ces
> modules restent `available:false` et leurs techniques (T1190 / T1556) apparaissent comme **non
> tentées** dans la matrice de couverture — ce n'est **pas** une lacune de détection, c'est un
> capteur absent, et le rapport le dit explicitement.

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

### (d) Installer/mettre à jour un outil **du catalogue Forge** sans rebuild — `forge tools`

Les trois voies ci-dessus servent à apporter **votre** outil. Pour les binaires que Forge connaît déjà
(httpx, nuclei, subfinder, dnsx, naabu, katana, amass, gau, gospider, dalfox, feroxbuster, ffuf), il
existe une voie dédiée : `forge tools install|update|remove <nom>`. Elle télécharge la version du
**manifeste** [`forge/tools.json`](../forge/tools.json), **vérifie son SHA256 épinglé**, et pose le
binaire dans le volume outils persistant `/data/tools/bin` — en tête du `PATH`, devant le
`/usr/local/bin` baké. Utile pour (a) rattraper un outil omis par un build `mini`, (b) mettre à jour
sans reconstruire l'image. Aucune URL arbitraire n'est acceptée et chaque acte est journalisé au ledger.
Voir [TOOLS_LIFECYCLE.md](TOOLS_LIFECYCLE.md).

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

### Langages supportés

Un outil peut être écrit dans **n'importe quel langage** — ce qui compte, c'est que le runtime sache le
lancer par son **nom** (pas via un interpréteur, cf. l'argv no-shell §4). Le tableau ci-dessous résume
**comment fournir** l'outil selon son langage, et si un **redémarrage** est nécessaire.

| Langage de l'outil | Comment le fournir | Redémarrage ? |
|--------------------|--------------------|---------------|
| **Binaire compilé** (C/C++/Rust/Go) | Déposez le binaire dans **`forge/tools/`** (`chmod +x`). **Statique de préférence** : un binaire **dynamiquement lié** exige que ses `.so` soient présents dans l'image (sinon `skipped` au run). | **Non** — résolu sur le `PATH` à **fire-time**, sans restart. |
| **Script Python** | `python3` est présent (c'est le moteur). **Deux voies** : (1) shebang `#!/usr/bin/env python3` + `chmod +x` dans **`forge/tools/`**, invoqué par son **nom** ; (2) module **`@register`** dans **`forge/plugins/`** (montage **opt-in**, code arbitraire). ⚠️ Rappel : un ToolSpec `"binary": "python3", "argv_template": ["script.py"]` est **REJETÉ** (python = interpréteur banni, anti-shell §4) — d'où le **shebang-exécutable** ou le **plugin**. | **Non** (`tools/`) — dispo au prochain run. Le plugin `./plugins` exige d'activer le montage opt-in (recréation one-shot). |
| **Node/JS, PHP, etc.** | L'interpréteur **n'est PAS** dans l'image `full` → **fournissez-le** : soit un **binaire statique** (`node`/`php`) déposé dans **`forge/tools/`**, soit une **image custom** (`FROM forge:0.0.1` + `apt install nodejs php-cli`, cf. §5(b)). | **Non** si binaire statique dans `tools/` ; **oui** (rebuild) pour l'image custom. |

> **Ce qui est réellement dans l'image `full`** (vérifié dans le `Dockerfile`) : l'interpréteur du **moteur**
> est **`python3`** (le profil `full` ajoute aussi `python3-pip`/`python3-venv` pour le moteur PDF weasyprint,
> toujours du Python) ; la suite de scanners étendue tire en plus **`ruby`** (dépendance de `whatweb`) et
> **`perl`** (+ modules, pour `nikto`). Les **binaires/scripts** livrés en `full` : `nmap`, `curl`, `dig`
> (dnsutils), `httpx`, `nuclei`, `subfinder`, `dnsx`, `naabu`, `katana`, `amass`, `gau`, `gospider`,
> `feroxbuster`, `ffuf`, `masscan`, `gobuster`, `whatweb`, `wafw00f`, `wfuzz`, `nikto`, `testssl.sh`,
> `dalfox`, `sqlmap` (liste §4(a)). **Ni `node` ni `php`** — pour ces langages, fournissez l'interpréteur
> vous-même (colonne ci-dessus).

### Ajouter un outil PACKAGÉ (ex. `hydra`, un paquet apt) en live

Certains outils ne sont pas un simple binaire auto-contenu mais un **paquet** (dépendances système). Options,
**du plus rapide au plus reproductible** :

1. **`docker compose exec -u root forge apt-get update && apt-get install -y <paquet>`** — installe le paquet
   dans le **conteneur EN COURS**, **sans `build` / `down` / `up`**. À savoir : c'est **éphémère** (reperdu dès
   que le conteneur est recréé), **non-reproductible**, et ça **nécessite l'accès réseau** (OK en Docker local ;
   **bloqué en k8s** si une `NetworkPolicy` `egress-deny` est en place). Déclarez ensuite son **ToolSpec**
   (formulaire **Administration → Ajouter un outil**, §2) puis **« Rafraîchir modules »**.
2. **Binaire statique / portable dans `forge/tools/`** — pas de souci de dépendances, **persistant** tant que le
   dossier est monté, **sans redémarrage** (cf. §5(c)).
3. **Image custom `FROM forge:0.0.1` + `apt install <paquet>`** (§5(b)) — la voie **reproductible / permanente**.
   Elle implique un **rebuild**, donc **PAS pendant un run** — à **préparer avant** l'engagement.

**Gouvernance — vrai pour tout outil packagé ajouté :**

- Il reste **scope-gardé** : le scope-guard ROE fail-closed s'applique (cible hors périmètre → `skipped`, **zéro
  I/O**) — **jamais** une action hors-scope, quel que soit l'outil.
- Un outil d'**exploit / brute-force** doit être **déclaré `exploit=true`** dans son ToolSpec → il n'est
  **lançable** qu'avec **operator + arm + reason** (le gate C2 existant, cf. §4).
- ⚠️ Les outils de **brute-force / cred-cracking** (`hydra`, `hashcat`, `john`) sont **hors du catalogue par
  défaut** : Forge est **proof-oriented** (et le brute-force est **banni** côté bug-bounty). **MAIS** l'opérateur
  **peut** les ajouter pour un **pentest autorisé** — le mécanisme **ne l'interdit pas** : ils restent
  **admin-gated**, **scope-gardés** et **armés** (classe exploit). C'est un **choix de politique**, **pas un
  blocage technique**.

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

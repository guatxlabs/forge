# Cycle de vie des outils — manifeste unique + surcouche runtime

Forge télécharge une douzaine de binaires de sécurité externes (httpx, nuclei, subfinder, dnsx, naabu,
katana, amass, gau, gospider, dalfox, feroxbuster, ffuf ; `nmap` et la suite `apt` sont installés
autrement). Cette page décrit **où vivent leurs versions**, **comment ils sont vérifiés**, et **comment
en installer ou en mettre à jour un sans reconstruire l'image**.

> Prérequis de lecture : [Installation](INSTALLATION.md) (profils `mini`/`full`) et
> [Ajouter votre propre outil](TOOLS.md) (ToolSpec — déclarer un outil CLI *gouverné*, sans code).
> La présente page traite du **binaire** ; `TOOLS.md` traite de sa **déclaration** comme module.

---

## 1. Le manifeste — `forge/tools.json`

Une seule source de vérité. Elle porte, **par outil** : la version, un gabarit d'URL, le format
d'archive, le chemin du binaire *dans* l'archive, le nom posé sur le `PATH`, et un **SHA256 par
architecture**.

```json
{
  "name": "httpx",
  "group": "core",
  "enabled": true,
  "profiles": ["full"],
  "version": "1.6.9",
  "archive": "zip",
  "url": "https://github.com/projectdiscovery/httpx/releases/download/v{version}/httpx_{version}_linux_{arch}.zip",
  "member": "httpx",
  "bin": "httpx",
  "sha256": { "amd64": "c8d3…fb5f", "arm64": "8cf1…aa95" }
}
```

Gabarits disponibles : `{version}`, `{arch}` (nomenclature Docker : `amd64`/`arm64`) et `{arch_uname}`
(`x86_64`/`aarch64` — certains éditeurs nomment leurs assets ainsi). Principe **bring-your-own-tool** :
ajouter un outil = ajouter une entrée JSON, **aucun code**.

**Pourquoi ce fichier existe.** Les versions et les digests étaient des `ARG` codés en dur, **dupliqués**
entre `Dockerfile` et `docker-compose.yml`. Deux copies d'un pin, c'est une divergence silencieuse qui
attend son heure. Elles n'existent plus qu'ici — et une garde statique
(`tests/test_tools_manifest.py`) échoue si une version, un digest ou une URL d'outil réapparaît dans le
`Dockerfile` ou le compose.

**Bumper une version** : éditer `version` + les digests (relevés dans le `*_checksums.txt` de la release
amont), puis soit reconstruire l'image, soit — sans rebuild — `forge tools update <nom>` (§3).

### Qui lit le manifeste

| Consommateur | Quand | Effet |
|---|---|---|
| `Dockerfile` (`python3 forge/toolsmanifest.py --arch … --profile full`) | au **build** | baseline bakée dans `/usr/local/bin`, selon `FORGE_TOOLS_PROFILE` |
| `forge tools list\|install\|update\|remove` | au **runtime** | surcouche persistante dans `/data/tools/bin` |
| console — `GET/POST /api/tools/runtime` + panneau **Administration → cycle de vie des outils** | au **runtime** | pilote la CLI ci-dessus, admin-only + ledgerisé (§3.1) |

---

## 2. Baseline au build — inchangée

`FORGE_TOOLS_PROFILE=full` (défaut) installe les outils du manifeste ; `mini` les omet et les modules
dégradent proprement (`available: false`). La vérification est celle qu'elle a toujours été : chaque
archive est validée par `sha256sum -c` contre le pin de son architecture, **toute non-correspondance
fait échouer le build**.

Deux garde-fous s'ajoutent, tous deux fail-closed :

- un outil **sans pin** pour l'architecture cible est **écarté du plan** — jamais téléchargé non
  vérifié — et listé sur `stderr` (c'est le cas de la suite étendue hors `amd64`, comme avant) ;
- le groupe socle `core` (httpx/nuclei/subfinder) passe par `--require-complete core` : un pin manquant
  **fait échouer le build** plutôt que produire une image silencieusement amputée.

---

## 3. Surcouche runtime — installer / mettre à jour sans rebuild

```bash
forge tools list                              # état : version cible, résolution PATH, provenance
forge tools install nuclei  --actor alice     # installe la version du manifeste
forge tools update  nuclei  --actor alice     # repose la version du manifeste (après un bump)
forge tools remove  nuclei  --actor alice     # retire de la couche runtime ; la baseline reste
```

Le binaire atterrit dans **`/data/tools/bin`** — volume persistant, propriété de l'utilisateur `forge`
(uid 10001), **en tête du `PATH`** devant le `/usr/local/bin` baké. Il survit donc à un *recreate* du
conteneur, et une mise à jour ne demande plus de reconstruire l'image.

Ordre de résolution du `PATH` : `/opt/tools` (bind-mount opérateur, priorité inchangée) →
`/data/tools/bin` (couche runtime) → `/usr/local/bin` (baseline bakée) → reste du système.

Hors conteneur, le répertoire par défaut est `<data_dir>/tools` ; `FORGE_TOOLS_DIR` le surcharge.

> **Sur Kubernetes, la surcouche est indisponible telle quelle — et elle le dit.** Le Deployment
> `k8s/40-console.yaml` pose `readOnlyRootFilesystem: true` et ne monte que `/data/db`, `/data/ledger`
> et `/data/scope`. `/data/tools` y est donc en lecture seule : `forge tools install` **refuse
> proprement** (« répertoire outils non inscriptible »), il ne dégrade rien silencieusement. Pour
> l'activer, montez un volume sur `/data/tools` — un PVC si vous voulez que les installs survivent au
> redémarrage du pod, un `emptyDir` si des installs éphémères par pod vous suffisent. Rien d'autre à
> changer : `FORGE_TOOLS_DIR` et le `PATH` viennent déjà de l'image.

### 3.1 Depuis la console (API + panneau)

La même chose, sans shell dans le conteneur. `Administration → cycle de vie des outils` liste le
manifeste (version cible, version installée lue **dans le reçu**, provenance runtime/baseline/absent,
chemin résolu, présence du pin pour l'architecture) et attache trois actions à chaque ligne.

```
GET  /api/tools/runtime                              # état (n'exécute aucun outil)
POST /api/tools/runtime  {"action":"install","name":"nuclei"}
```

**Le corps n'accepte QUE `{action, name}`.** Tout autre champ — `url`, `sha256`, `digest`, `version` —
fait **échouer** la requête en 400, avant le moindre sous-processus. Ce n'est pas un filtrage
silencieux : c'est la même propriété qu'en CLI, exprimée à l'étage HTTP. Le `name` doit en outre
figurer dans le manifeste **tel que le moteur le rapporte** (`forge tools list --json`) ; si cette
sonde n'aboutit pas, la mutation est **refusée** plutôt que tentée à l'aveugle. L'`argv` est fixe et
construit côté serveur. Un outil sans pin pour l'architecture courante n'a **aucun bouton** dans le
panneau : il n'existe pas de chemin, même cosmétique, vers un téléchargement non vérifié.

Gouvernance : **admin-only** (`check_admin`, 403 sinon — installer un binaire est au moins aussi
privilégié que déclarer un outil via `/api/tools`, et exige une attribution individuelle), spawn
**borné** (budget de temps, plafond de concurrence, cap d'octets, kill de groupe), et **double
journalisation** — `console.tools.install|update|remove` (qui a demandé quoi, et l'issue) en plus de
l'entrée `tools.install` que l'installeur écrit lui-même avec **le digest vérifié**.

### Ce que ça ne fait pas

- **Pas d'installation depuis une URL arbitraire.** Il n'existe ni `--url` ni `--sha256`. La source est
  calculée depuis le manifeste : c'est l'allowlist.
- **Pas d'« update vers la dernière version amont ».** Ce serait un téléchargement non épinglé.
  Mettre à jour = bumper le manifeste (changement revu et pinné) puis `forge tools update`.
- **Pas d'auto-update, pas de tâche de fond.** Action opérateur explicite, uniquement.
- **Aucune élévation.** L'outil installé reste soumis exactement aux mêmes portes que celui de la
  baseline : scope-guard ROE fail-closed, plancher exploit, argv fixe no-shell, sonde de disponibilité.

---

## 4. Le modèle de gouvernance, point par point

Installer un binaire au runtime dans un outil offensif est précisément la capacité qui annule une
gouvernance si elle est mal posée. Chaque garantie ci-dessous est couverte par un test
(`tests/test_tools_runtime_install.py`, `tests/test_tools_manifest.py`).

| Garantie | Mise en œuvre | Ce qui se passe en cas d'écart |
|---|---|---|
| **Intégrité obligatoire** | SHA256 calculé **sur le flux** pendant l'écriture, comparé au pin du manifeste | refus, temporaire détruit, **rien** sur le `PATH`, refus **journalisé** |
| **Pin requis** | pas de digest pour l'architecture → refus **avant tout octet réseau** | aucune requête n'est émise |
| **Source allowlistée** | URL dérivée du manifeste ; aucun paramètre d'URL n'existe | nom hors manifeste → refus, rien n'est téléchargé |
| **HTTPS strict** | gabarit `https://` exigé au chargement ; redirection quittant HTTPS refusée | `URLError`, téléchargement abandonné |
| **Pas de shell** | `urllib` + `zipfile`/`tarfile` — ni `curl`, ni `unzip`, ni `tar`, aucun sous-processus | (test : toute création de processus fait échouer la suite) |
| **Pas d'évasion de chemin** | un seul membre extrait ; la destination est **calculée par nous**, jamais lue dans l'archive | un membre nommé `../../evil` atterrit sous le nom `bin` prévu, dans le répertoire outils |
| **Journalisation** | `tools.install` / `tools.update` / `tools.remove` / `tools.refused` chaînés + signés | ledger injoignable → **action refusée** (aucune install non tracée) |
| **Pose atomique** | staging + `os.replace`, mode `0755` | jamais de binaire à moitié écrit sur le `PATH` |
| **No-op par défaut** | rien n'est créé ni sondé à l'import ; aucun module du moteur n'importe l'installeur | sans action opérateur, comportement identique à la baseline |

Une entrée de ledger porte le nom, la version, l'architecture, **le digest vérifié**, l'URL, le chemin
et l'acteur :

```json
{"kind": "tools.install", "detail": {
  "name": "httpx", "version": "1.6.9", "arch": "amd64", "actor": "alice",
  "sha256": "c8d36461…fb5f", "previous_version": "",
  "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip"}}
```

`forge ledger verify --ledger …` continue de valider la chaîne de bout en bout.

---

## 5. Ce qui n'est pas construit (et pourquoi)

- **Versions hors manifeste.** Installer une version absente du manifeste supposerait d'accepter un
  digest saisi par l'opérateur (ou récupéré puis confirmé). C'est une UX d'intégrité à part entière,
  laissée à une itération dédiée plutôt que bâclée : tant qu'elle n'existe pas, il n'y a **aucun**
  chemin vers un téléchargement non épinglé.
- ~~**API et panneau console.**~~ **Livré** (§3.1) : `GET/POST /api/tools/runtime` + le panneau
  `Administration → cycle de vie des outils`. La contrainte qui rendait ce chantier délicat est tenue —
  la route n'accepte qu'un **nom du manifeste**, jamais une URL ni une empreinte.
- **Sonde de version par exécution.** `forge tools list` ne lance **rien** : la version installée est
  lue dans le reçu déposé à l'installation. Lister ne doit pas être une exécution.

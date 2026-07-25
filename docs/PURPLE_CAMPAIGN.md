# Runbook — campagne purple « recon-large » (gabarit)

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Prérequis Plume](PURPLE_PREREQS.md) · [Référence CLI](CLI.md) · [MTTD](MTTD.md)

> **Statut : GABARIT — rien ne s'exécute en le lisant.** À lancer uniquement sur le « go » explicite
> de l'opérateur, et uniquement contre une cible **dont vous avez l'autorisation écrite**. Ce document
> définit une campagne **RECON-ONLY** large (plus de techniques tirées → matrice purple plus riche,
> avec des trous visibles). Les exemples utilisent le domaine de documentation `lab.example` :
> remplacez-le par **votre** cible autorisée. Le runbook ne modifie **rien** par lui-même : ni
> `scope.json`, ni l'environnement.

## 1. But

La boucle purple mesure « technique T tirée → détectée par Plume ? » par égalité du champ `mitre`
(cf. [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md)). Une campagne riche en techniques **recon/non-exploit**
fait tirer un éventail d'ATT&CK distincts (T1595, T1046, T1595.002, T1590.005, T1556) sans franchir
la barrière d'impact fort. Résultat attendu : une matrice de couverture avec des cases **detected**,
des cases **missed** (technique tirée, aucune détection corrélée), et des MTTD par technique —
exactement le livrable purple.

Étape 1 (ce runbook) = **PRÉP + amorce de la matrice MTTD**. Les oracles à preuve d'impact fort
(IDOR/SSRF/auth/CORS) restent **DRY_RUN/VETO** ici (voir §6) et ne tireront que sur un opt-in
fort-impact séparé, hors de cette campagne.

## 2. Modules recon / non-exploit à inclure (ceux qui FIRENT en recon-only)

En recon-only, le ROE autorise au plus DRY_RUN pour toute action `exploit=True`. Seuls les modules
`exploit=False` peuvent atteindre FIRE (sous réserve d'armement + approbation/mode auto). La liste
ci-dessous = les modules **qui tireront réellement** dans cette campagne et leur technique ATT&CK :

| `kind`               | exploit | ATT&CK     | Ce qui est tiré (recon-only)                                            |
|----------------------|---------|------------|--------------------------------------------------------------------------|
| `recon.httpx`        | non     | T1595      | Fingerprint HTTP : status, titre, technos détectées.                     |
| `recon.nmap`         | non     | T1046      | Découverte des services exposés (`nmap -sV -Pn`, top 1000 ports).        |
| `web.nuclei`         | non     | T1595.002  | Scan par templates nuclei (medium/high/critical par défaut).             |
| `origin.find`        | non     | T1590.005  | IP d'origine derrière le CDN (subfinder→DNS→drop-CF→vérif Host-header).   |
| `evasion.xhr`        | non     | T1190      | Observation des requêtes XHR via la session browser-automation.          |
| `evasion.turnstile`  | non     | T1556      | Tentative de franchissement du Turnstile interactif (vision-click-os).   |

Notes :
- `evasion.*` n'est tiré que si le **service d'automatisation navigateur** (port 8080) répond ; sinon
  le module s'auto-neutralise (`available=False`) et n'est jamais tiré. Le rapport le dit
  explicitement : la technique apparaît comme **non tentée**, jamais comme « testée sans résultat ».
- `recon.nmap` / `recon.httpx` / `web.nuclei` / `origin.find` exigent le binaire **OU** l'image
  Docker correspondante. Vérifier avec `forge doctor` avant le « go ». Un module indisponible ⇒
  aucune action tirée ⇒ la case correspondante n'est **pas** comptée comme détectée ni comme
  manquée : elle est **non tentée** dans la matrice (c'est la discipline anti-masquage, pas une
  erreur).
- Les techniques `evasion.turnstile` (T1556) et `evasion.xhr`/`evasion.idor_intercept` (T1190)
  partagent l'idée « enabler d'accès » — passer Cloudflare **n'est pas** une faille, juste un accès.

## 3. Commande EXACTE (copier-collable) — à lancer au « go » seulement

> ⚠️ N'EXÉCUTE PAS cette commande tant que l'opérateur n'a pas dit « go ». Elle suppose un scope
> **recon-only** (`allow_exploit=false`, `allow_destructive=false`) listant votre cible autorisée, et
> une console joignable.

```bash
# Le token console se passe par variable d'env (jamais en argv — argv est visible des autres
# utilisateurs locaux). console_client lit FORGE_CONSOLE_TOKEN en repli quand --console-token absent.
export FORGE_CONSOLE_TOKEN='<token-ingest-console>'

python3 -m forge.cli campaign \
    --scope    "$SCOPE" \
    --targets  "$TARGETS" \
    --modules  recon.httpx,recon.nmap,web.nuclei,origin.find,evasion.xhr,evasion.turnstile \
    --mode     auto \
    --arm \
    --reason   'purple-lab-large recon-only : amorce matrice MTTD sur lab.example (autorisé)' \
    --console       http://127.0.0.1:7100 \
    --console-token "$FORGE_CONSOLE_TOKEN" \
    --campaign purple-lab-large \
    --purple   runs/purple-lab-large.jsonl \
    --ledger   runs/purple-lab-large.ledger.jsonl \
    --report   runs/purple-lab-large.report.md
```

Où :
- `SCOPE` = chemin d'un scope **recon-only** listant votre cible autorisée in-scope (voir §4 —
  exemple de doc ; **ne pas** écraser un `scope.json` en service).
- `TARGETS` = chemin d'un fichier targets (voir §5 — exemple de doc).
- `--mode auto` + `--arm` : nécessaire pour atteindre FIRE sans approuver chaque action une à une
  (couche 4 du ROE). Reste fail-closed sur le scope (couche 2) et la capacité (couche 3).
- `--modules` : RESTREINT le plan du cerveau aux kinds listés. Tous sont `exploit=False` → ils
  peuvent FIRE en recon-only ; aucun oracle d'impact n'est inclus (voir §6).
- `--purple <fichier>` : émet les run-records ATT&CK (JSONL) ingérables par Plume.
- `--console …` : pousse findings + run-records + couverture vers la console (JOIN MTTD côté console).

### Techniques attendues au tir

`T1595` (httpx), `T1046` (nmap), `T1595.002` (nuclei), `T1590.005` (origin.find), `T1190`
(evasion.xhr), `T1556` (evasion.turnstile, si browser-automation joignable). Chaque tir produit un
run-record taggé `mitre` → la matrice purple corrèle ces techniques contre les détections Plume.

## 4. Exemple de scope recon-only (DOC — ne pas écraser le live)

> Écrire dans un fichier **séparé** (ex. `runs/scope.purple-lab-large.json`) et le passer via
> `--scope`. **Ne touche pas** `scope.json`.

```json
{
  "_comment": "Scope DOC recon-only pour la campagne purple-lab-large — lab.example autorisé.",
  "mode": "grey",
  "in_scope": ["lab.example"],
  "out_scope": [],
  "rate": 5,
  "allow_exploit": false,
  "allow_destructive": false,
  "known_creds": [],
  "idor_targets": [],
  "notes": "Recon-only. allow_exploit/destructive restent false : les oracles d'impact ne peuvent que DRY_RUN/VETO."
}
```

## 5. Exemple de fichier targets (DOC — ne pas écraser le live)

> Écrire dans un fichier **séparé** (ex. `runs/targets.purple-lab-large.json`) et le passer via
> `--targets`. Chaque cible exige `host` ; `kind`/`attrs` sont optionnels.

```json
[
  { "host": "lab.example", "kind": "app", "attrs": { "service": "http" } }
]
```

`kind: "app"` + `service: "http"` oriente le cerveau (`HeuristicBrain`) vers les classes web
(recon + scan). Le planner coverage-safe garantit qu'aucune classe qualifiante n'est affamée même
si le cerveau la sous-note — mais ici `--modules` borne déjà le plan aux kinds recon/non-exploit.

## 6. Les oracles d'impact restent DRY_RUN / VETO (recon-only)

Ces modules sont `exploit=True` (et parfois `destructive=True`). En recon-only (`allow_exploit=false`),
la couche 3 du ROE les place en **VETO** s'ils sont proposés en armé, ou ils restent en **DRY_RUN**
(simulation, génère le PoC, ne tire rien). **Ils ne sont pas dans `--modules` ci-dessus** et ne
produiront donc aucun tir dans cette campagne :

| `kind`                   | exploit | destructive | ATT&CK | Pourquoi pas en recon-only                              |
|--------------------------|---------|-------------|--------|----------------------------------------------------------|
| `access_control.idor`    | oui     | non (GET)   | T1190  | Accède à l'objet d'un autre user → `allow_exploit`.      |
| `ssrf.callback`          | oui     | non         | T1190  | Provoque une requête sortante de la cible → `allow_exploit`. |
| `auth.takeover`          | oui     | oui         | T1212  | Prend le contrôle d'un compte → `allow_exploit`/`destructive`. |
| `cors.credentials`       | oui     | non         | T1539  | Lecture cross-origin authentifiée → `allow_exploit`.     |
| `evasion.idor_intercept` | oui     | non         | T1190  | Tamper d'identifiant en vol → `allow_exploit`.           |

Ces oracles ne tireront qu'avec un **opt-in fort-impact** distinct (scope `allow_exploit=true`,
voire `allow_destructive=true` pour `auth.takeover`/IDOR-write), sur une campagne séparée — **hors
du périmètre de ce runbook**. Tant que cet opt-in n'est pas posé, ils restent fail-closed.

## 7. Pré-vol (au « go »)

1. `forge doctor` → vérifier quels modules de §2 sont OPÉRATIONNELS (un module indisponible =
   technique **non tentée** dans la matrice, à documenter comme telle).
2. Confirmer que la cible est in-scope dans le scope passé via `--scope` (`forge scope-check
   lab.example --scope "$SCOPE"` doit dire IN SCOPE).
3. Confirmer la joignabilité + auth Plume côté console (cf. `PURPLE_PREREQS.md` §5) pour que le JOIN
   MTTD fonctionne.
4. Lancer la commande §3, puis lire `runs/purple-lab-large.report.md` + la matrice de couverture
   côté console (`/api/purple/coverage`).

## ⚠️ Sûreté

- **Recon-only** : aucun module d'impact dans `--modules`. Le ROE reste fail-closed (scope + capacité).
- **Ne pas** écraser `scope.json` / `targets.json` live : utiliser des fichiers DOC séparés (§4–§5).
- Tirer des techniques = **uniquement** sur une cible dont l'autorisation est écrite. ROE / scope dur.
- Le token console passe par `FORGE_CONSOLE_TOKEN` (env), jamais en clair dans l'historique shell.

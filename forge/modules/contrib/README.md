# Forge — plugins DROP-IN (extrêmement modulaire)

Trois façons d'ajouter un module, **toutes gouvernées à l'identique** (scope-guard fail-closed,
plancher exploit, statut clampé à `tested`/`reported_by_tool`) — elles convergent vers le même
`registry.REGISTRY` + `register_spec` + le dispatch `Engine.execute → roe.decide`.

## 1. Déposer un `.py` in-tree (auto-découvert)

Créer `forge/modules/mon_module.py` avec une classe `@register("ma.technique")` (contrat `dry`/`fire`,
cf. `registry.py`) **ou** un `ToolSpec` + `register_spec(...)`. **Aucune** édition d'`__init__.py` :
le package se scanne tout seul au premier import (`pkgutil.iter_modules`), en excluant l'infra
(`registry`, `toolspec`, `oracle`, `_scopeguard`, `loader`, `contrib`).

## 2. Ajouter un outil CLI SANS toucher au dépôt — deux voies

### a) Un fichier `.py` externe (FORGE_PLUGINS)

```bash
export FORGE_PLUGINS=/opt/forge-plugins:/chemin/mon_plugin.py   # dossiers (scan *.py) ou fichiers, `:`-séparés
python -m forge.cli modules --json        # le kind du plugin apparaît
```
Voir `example_plugin.py`. Chargé **après** l'in-tree → peut surcharger un kind. **Fail-soft** : un
plugin cassé est journalisé (warning nommant le fichier + la cause) et ignoré, le moteur démarre.

### b) Un spec déclaratif JSON/YAML — **zéro Python** (FORGE_TOOLSPECS / --toolspec)

```bash
export FORGE_TOOLSPECS=/opt/forge-toolspecs        # dossier scanné pour *.json / *.yaml / *.yml
# ou, ponctuel et fail-CLOSED (erreur dure si spec invalide) :
python -m forge.cli run --scope scope.json --toolspec forge/modules/contrib/example.toolspec.json ...
```
Voir `example.toolspec.json`. Les champs sont validés **fail-closed** contre le constructeur de
`ToolSpec` (champ inconnu / requis manquant → erreur nommant le fichier). YAML n'est lu que si `pyyaml`
est installé (dépendance **optionnelle** ; sinon JSON only, aucune dépendance dure ajoutée).

Champs requis d'un ToolSpec : `kind`, `vuln_class`, `binary`, `argv_template`. Le reste a des défauts
(cf. `toolspec.py`). `argv_template` : liste de tokens ; un token peut être un groupe (liste imbriquée =
tout-ou-rien). Placeholders : `{target}` `{target_host}` `{target_url}` `{param:NOM}` `{param:NOM:DEFAUT}`.

## Gouvernance — invariant

Un plugin/spec chargé par **n'importe laquelle** de ces voies ne peut PAS tirer hors périmètre
(scope-guard fail-closed → `skipped`, zéro I/O), ni s'auto-promouvoir en `vulnerable` (clampé), ni
franchir le plancher exploit sans opt-in. Rien à câbler : tout passe par le même registre + le ROE.

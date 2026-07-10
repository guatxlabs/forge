# SPDX-License-Identifier: AGPL-3.0-only
"""Chargeur DROP-IN de modules Forge — remplace la liste d'imports câblée à la main par une découverte
automatique, SANS affaiblir la gouvernance.

Trois voies d'ajout, TOUTES funnellées vers le MÊME registre (`registry.REGISTRY`) + `register_spec` +
le dispatch `Engine.execute` -> `roe.decide` : un plugin chargé par n'importe laquelle est gaté
EXACTEMENT comme un module natif (scope-guard fail-closed, plancher exploit, clamp de statut).

  1. AUTO-DÉCOUVERTE in-tree — `discover_intree()` scanne le package `forge/modules/` et importe chaque
     sous-module SAUF l'infrastructure (`_INFRA` + tout nom `_préfixé`). L'import déclenche `@register`
     / `register_spec`. Idempotent (le registre écrase par kind ; re-scan sûr). Déposer
     `forge/modules/x.py` avec une classe `@register` suffit — plus AUCUNE édition d'`__init__.py`.

  2. PLUGINS UTILISATEUR EXTERNES — `load_env_plugins()` lit `FORGE_PLUGINS` (chemins séparés par `:` ;
     un dossier est scanné pour ses `*.py`, un fichier est importé directement) via
     `importlib.util.spec_from_file_location`. Chargés APRÈS l'in-tree -> un plugin utilisateur peut
     surcharger un kind. FAIL-SOFT par plugin : un plugin cassé est journalisé (warning nommant le
     fichier + la cause) puis ignoré — le moteur démarre quand même ; il ne DISPARAÎT jamais en silence.

  3. TOOLSPEC DÉCLARATIF (ZÉRO Python) — `load_toolspec_file()` lit un `ToolSpec` depuis un JSON (ou YAML
     si `pyyaml` est importable — sinon JSON only, aucune dépendance dure) et appelle `register_spec`.
     Validé FAIL-CLOSED contre le constructeur de `ToolSpec` (champ inconnu / requis manquant -> erreur
     claire NOMMANT le fichier). `load_env_toolspecs()` scanne le dossier `FORGE_TOOLSPECS` (miroir de
     FORGE_PLUGINS, fail-soft par fichier) ; le chemin CLI `--toolspec <file>` charge fail-CLOSED (dur).

Zéro dépendance dure ajoutée (stdlib ; YAML optionnel-gardé) — cohérent avec le cœur Forge.
"""
import importlib
import importlib.util
import inspect
import json
import logging
import os
import re
import sys

log = logging.getLogger("forge.modules.loader")

# Modules d'INFRASTRUCTURE du package — PAS des plugins (aucun `@register`/`register_spec` à déclencher) :
#   registry    = le registre + la classe de base `Module` + `@register` ;
#   toolspec    = la base `ExternalToolModule` (abstraite) + `ToolSpec`/`register_spec` ;
#   oracle      = les bases `Oracle`/`ScopeGuardedOracle` (abstraites, importées par les vrais modules) ;
#   _scopeguard = le mixin scope-guard (préfixe `_`) ;
#   loader      = ce fichier ;
#   contrib     = les EXEMPLES (chargés à la demande via FORGE_PLUGINS/FORGE_TOOLSPECS, jamais auto).
# `toolcatalog` n'est PAS ici : il s'auto-enregistre (register_spec) à l'import et DOIT être importé.
_INFRA = frozenset({"registry", "toolspec", "oracle", "_scopeguard", "loader", "contrib", "__init__"})

_PLUGINS_ENV = "FORGE_PLUGINS"
_TOOLSPECS_ENV = "FORGE_TOOLSPECS"


class SpecError(ValueError):
    """Spec ToolSpec invalide (fail-closed) — le message nomme TOUJOURS le fichier fautif."""


def _is_infra(name):
    """Un sous-module à NE PAS traiter comme plugin (infra ou nom privé `_préfixé`)."""
    return name in _INFRA or name.startswith("_")


# =================================================================================================
#  1) AUTO-DÉCOUVERTE des modules in-tree
# =================================================================================================
def discover_intree(package_path, package_name):
    """Importe tous les sous-modules-plugins de `package_name` (chemin `package_path` = `__path__`) SAUF
    l'infra. Tri déterministe (dépendances recon.* avant toolcatalog). L'import déclenche `@register` /
    `register_spec`. Idempotent (le registre écrase par kind). Retourne la liste des noms importés."""
    import pkgutil
    loaded = []
    for mi in sorted(pkgutil.iter_modules(package_path), key=lambda m: m.name):
        if _is_infra(mi.name):
            continue
        importlib.import_module(f"{package_name}.{mi.name}")   # side-effect: @register / register_spec
        loaded.append(mi.name)
    return loaded


# =================================================================================================
#  2) PLUGINS UTILISATEUR EXTERNES via FORGE_PLUGINS (fail-soft par plugin)
# =================================================================================================
def _iter_paths(raw):
    """Éclate une variable d'env `:`-séparée en chemins non vides (ordre préservé)."""
    for part in (raw or "").split(os.pathsep):
        part = part.strip()
        if part:
            yield part


def _iter_plugin_files(paths):
    """Résout des chemins (dossiers -> `*.py` triés, hors `_préfixés` ; fichiers -> tels quels). Un
    chemin introuvable est journalisé et ignoré (fail-soft)."""
    for p in paths:
        if os.path.isdir(p):
            for fn in sorted(os.listdir(p)):
                if fn.endswith(".py") and not fn.startswith("_"):
                    yield os.path.join(p, fn)
        elif os.path.isfile(p):
            yield p
        else:
            log.warning("%s: chemin introuvable, ignoré: %s", _PLUGINS_ENV, p)


def _module_name_for(filepath):
    """Nom de module sys.modules DÉTERMINISTE et unique pour un fichier plugin (dérivé du chemin absolu)."""
    return "forge_plugin_" + re.sub(r"\W", "_", os.path.abspath(filepath))


def load_plugin_file(filepath):
    """Importe UN fichier `.py` comme module (déclenche `@register`/`register_spec`) via
    `spec_from_file_location`. FAIL-SOFT : toute erreur d'import est journalisée (warning nommant le
    fichier + la cause) et le fichier est ignoré — jamais de disparition silencieuse. Retourne True/False."""
    name = _module_name_for(filepath)
    try:
        spec = importlib.util.spec_from_file_location(name, filepath)
        if spec is None or spec.loader is None:
            log.warning("%s: plugin ignoré (impossible de résoudre le spec d'import): %s",
                        _PLUGINS_ENV, filepath)
            return False
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module                    # requis avant exec (imports relatifs/dataclasses)
        spec.loader.exec_module(module)               # side-effect: @register / register_spec
        return True
    except Exception as e:                            # noqa: BLE001 — fail-soft VOULU (plugin tiers hostile)
        sys.modules.pop(name, None)                   # ne pas laisser un module à moitié importé
        log.warning("%s: plugin ignoré (erreur à l'import): %s -> %s: %s",
                    _PLUGINS_ENV, filepath, type(e).__name__, e)
        return False


def load_env_plugins(raw=None):
    """Charge les plugins `.py` déclarés dans `FORGE_PLUGINS` (fichiers/dossiers `:`-séparés). N'importe
    QUE depuis les chemins EXPLICITES de l'env (jamais le CWD implicite). Retourne les fichiers chargés."""
    raw = os.environ.get(_PLUGINS_ENV, "") if raw is None else raw
    loaded = []
    for f in _iter_plugin_files(_iter_paths(raw)):
        if load_plugin_file(f):
            loaded.append(f)
    return loaded


# =================================================================================================
#  3) TOOLSPEC DÉCLARATIF (JSON / YAML optionnel) via FORGE_TOOLSPECS ou --toolspec
# =================================================================================================
def _try_yaml():
    """Retourne le module `yaml` s'il est importable, sinon None (dépendance OPTIONNELLE, jamais dure)."""
    try:
        import yaml
        return yaml
    except Exception:                                 # noqa: BLE001
        return None


def _read_spec_data(filepath):
    """Lit un fichier de spec en dict. JSON toujours ; YAML seulement si `pyyaml` présent (sinon
    SpecError clair). Fail-closed : contenu non-dict -> SpecError nommant le fichier."""
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        raise SpecError(f"{filepath}: illisible ({e})") from e
    if filepath.lower().endswith((".yaml", ".yml")):
        yaml = _try_yaml()
        if yaml is None:
            raise SpecError(f"{filepath}: spec YAML mais pyyaml absent — installer pyyaml OU fournir du JSON")
        try:
            data = yaml.safe_load(text)
        except Exception as e:                        # noqa: BLE001
            raise SpecError(f"{filepath}: YAML invalide ({e})") from e
    else:
        try:
            data = json.loads(text)
        except ValueError as e:
            raise SpecError(f"{filepath}: JSON invalide ({e})") from e
    if not isinstance(data, dict):
        raise SpecError(f"{filepath}: le spec doit être un objet (dict), obtenu {type(data).__name__}")
    return data


def _validate_spec_fields(ToolSpec, data, filepath):
    """Valide `data` contre la signature du constructeur `ToolSpec` (fail-closed). Rejette tout champ
    INCONNU et signale tout champ REQUIS manquant, avec un message NOMMANT le fichier. Retourne data."""
    params = [p for p in inspect.signature(ToolSpec.__init__).parameters.values() if p.name != "self"]
    allowed = {p.name for p in params}
    required = {p.name for p in params if p.default is inspect.Parameter.empty
                and p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)}
    unknown = set(data) - allowed
    if unknown:
        raise SpecError(f"{filepath}: champ(s) inconnu(s) {sorted(unknown)} "
                        f"(attendus parmi {sorted(allowed)})")
    missing = required - set(data)
    if missing:
        raise SpecError(f"{filepath}: champ(s) requis manquant(s) {sorted(missing)}")
    return data


def load_toolspec_file(filepath):
    """Charge UN ToolSpec déclaratif (JSON/YAML) et l'enregistre via `register_spec` (FOLD technique +
    `@register` -> gouverné comme un module natif). FAIL-CLOSED : spec invalide -> `SpecError` nommant le
    fichier (aucun enregistrement partiel). Retourne le `kind` enregistré."""
    from .toolspec import ToolSpec, register_spec       # local: évite tout cycle d'import au chargement
    data = _read_spec_data(filepath)
    _validate_spec_fields(ToolSpec, data, filepath)
    try:
        spec = ToolSpec(**data)
    except (TypeError, ValueError) as e:
        raise SpecError(f"{filepath}: spec ToolSpec invalide ({e})") from e
    register_spec(spec)
    return spec.kind


def _iter_toolspec_files(paths):
    """Résout des chemins toolspec (dossiers -> `*.json`/`*.yaml`/`*.yml` triés ; fichiers -> tels quels)."""
    exts = (".json", ".yaml", ".yml")
    for p in paths:
        if os.path.isdir(p):
            for fn in sorted(os.listdir(p)):
                if fn.lower().endswith(exts) and not fn.startswith("_"):
                    yield os.path.join(p, fn)
        elif os.path.isfile(p):
            yield p
        else:
            log.warning("%s: chemin introuvable, ignoré: %s", _TOOLSPECS_ENV, p)


def load_env_toolspecs(raw=None):
    """Charge les ToolSpecs déclaratifs de `FORGE_TOOLSPECS` (miroir de FORGE_PLUGINS). FAIL-SOFT par
    fichier : une spec invalide est journalisée (warning nommant le fichier + la cause) puis ignorée —
    le moteur démarre quand même. Retourne les kinds enregistrés."""
    raw = os.environ.get(_TOOLSPECS_ENV, "") if raw is None else raw
    kinds = []
    for f in _iter_toolspec_files(_iter_paths(raw)):
        try:
            kinds.append(load_toolspec_file(f))
        except SpecError as e:
            log.warning("%s: toolspec ignoré -> %s", _TOOLSPECS_ENV, e)
        except Exception as e:                        # noqa: BLE001 — défense en profondeur, jamais crasher le boot
            log.warning("%s: toolspec ignoré (%s): %s -> %s", _TOOLSPECS_ENV, f, type(e).__name__, e)
    return kinds


# =================================================================================================
#  Orchestrateur — appelé une fois à l'import de `forge.modules`
# =================================================================================================
def autoload(package_path, package_name):
    """Ordre : (1) in-tree, puis (2) FORGE_PLUGINS, puis (3) FORGE_TOOLSPECS — un plugin/spec utilisateur
    chargé APRÈS peut donc surcharger un kind natif (register écrase par kind). Retourne un récap dict."""
    intree = discover_intree(package_path, package_name)
    plugins = load_env_plugins()
    toolspecs = load_env_toolspecs()
    return {"intree": intree, "plugins": plugins, "toolspecs": toolspecs}

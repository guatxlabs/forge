"""Modules Forge — système de plugins DROP-IN (auto-découverte + FORGE_PLUGINS + ToolSpec JSON/YAML).

Importer ce package ENREGISTRE tous les modules, SANS liste d'imports câblée à la main :
  1. AUTO-DÉCOUVERTE in-tree — chaque `forge/modules/*.py` portant `@register` / `register_spec` est
     importé automatiquement (déposer un fichier suffit ; plus AUCUNE édition ici) ;
  2. FORGE_PLUGINS — fichiers/dossiers `.py` utilisateur (chargés APRÈS l'in-tree -> peuvent surcharger) ;
  3. FORGE_TOOLSPECS — ToolSpecs déclaratifs JSON/YAML (zéro Python), gouvernés comme un module natif.

TOUTES ces voies convergent vers le MÊME `registry.REGISTRY` + `register_spec` + le dispatch
`Engine.execute -> roe.decide` : un plugin est gaté EXACTEMENT comme un natif (scope-guard fail-closed,
plancher exploit, clamp de statut). Détail + politique fail-soft/fail-closed : `forge/modules/loader.py`.
"""
from . import loader as _loader

# (1) AUTO-DÉCOUVERTE in-tree (les sous-modules importent via `from .registry import ...`, jamais le
#     package -> aucun cycle avec les exports ci-dessous).
_INTREE = _loader.discover_intree(__path__, __name__)

# --- Exports publics (INCHANGÉS — rétro-compat de l'API du package) — LIÉS AVANT les plugins env, pour
#     qu'un plugin utilisateur puisse importer soit `forge.modules.register`, soit `.registry.register`. ---
from .registry import REGISTRY, register, get, kinds, Module  # noqa: E402,F401
# Wrapper GÉNÉRIQUE d'outils externes (absorbe la propriété wrap-any-tool de Trickest/Faraday/Osmedeus) :
# un utilisateur déclare `ToolSpec(...)` + `register_spec(spec)` — ou dépose un spec JSON/YAML (loader).
from .toolspec import ToolSpec, register_spec, build_argv, parse_output, ExternalToolModule  # noqa: E402,F401

# (2) FORGE_PLUGINS puis (3) FORGE_TOOLSPECS — APRÈS l'in-tree ET les exports : un plugin/spec utilisateur
#     peut surcharger un kind natif (register écrase par kind).
_PLUGINS = _loader.load_env_plugins()
_TOOLSPECS = _loader.load_env_toolspecs()
_LOADED = {"intree": _INTREE, "plugins": _PLUGINS, "toolspecs": _TOOLSPECS}

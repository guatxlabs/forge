# SPDX-License-Identifier: AGPL-3.0-or-later
"""Forge — moteur red-team gated par ROE. Antithèse offensive du SOC blue-team Plume (GuatX).

Sûreté d'abord : tout passe par la gate `roe.Roe` (fail-closed, inerte par défaut) et est
tracé dans un `ledger.Ledger` append-time tamper-evident. Les modules d'attaque restent des
outils autonomes orchestrés par l'`engine.Engine`.
"""
from pathlib import Path as _Path


def _read_version(default="0.0.1"):
    """Version = SOURCE DE VÉRITÉ UNIQUE : le fichier `VERSION` à la racine du repo, lu à l'import.

    Le même fichier alimente la console Rust (include_str! à la compilation) et est vérifié en
    dérive par la CI (`make check-version`). Repli sur `default` codé en dur quand le fichier est
    absent — cas d'un wheel installé où `VERSION` (hors package) n'est pas empaqueté.
    """
    try:
        return (_Path(__file__).resolve().parent.parent / "VERSION").read_text(
            encoding="utf-8").strip() or default
    except OSError:
        return default


__version__ = _read_version()

from .roe import Scope, Roe, Action, Decision, ScopeError, VETO, DRY_RUN, FIRE  # noqa: F401,E402
from .ledger import Ledger  # noqa: F401,E402
from .engine import Engine  # noqa: F401,E402
from .schema import Finding, Target, Campaign  # noqa: F401,E402

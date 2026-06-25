"""Forge — moteur red-team gated par ROE. Antithèse offensive du SOC blue-team Plume (GuatX).

Sûreté d'abord : tout passe par la gate `roe.Roe` (fail-closed, inerte par défaut) et est
tracé dans un `ledger.Ledger` append-time tamper-evident. Les modules d'attaque restent des
outils autonomes orchestrés par l'`engine.Engine`.
"""
__version__ = "0.0.1"

from .roe import Scope, Roe, Action, Decision, ScopeError, VETO, DRY_RUN, FIRE  # noqa: F401
from .ledger import Ledger  # noqa: F401
from .engine import Engine  # noqa: F401
from .schema import Finding, Target, Campaign  # noqa: F401

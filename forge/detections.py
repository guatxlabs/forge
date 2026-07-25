"""Compat shim — le collecteur monolithique historique a été ÉCLATÉ en paquet `forge.collectors`
(une classe par `kind`, contrat `fetch()`/`doctor()` fail-open lisible ; cf. `forge/collectors/base.py`).

Ce module RÉEXPORTE l'API stable pour ne rien casser côté appelants historiques :
- `load_source(spec)` / `collect(source, since)` (LÈVE sur erreur) / `safe_error(exc, source)`
- helpers `_aggregate` / `_to_epoch` (alias des `aggregate` / `to_epoch` du paquet)
- familles de kinds `HTTP_KINDS` / `SYSLOG_KINDS` / `FILE_KINDS` / `EXEC_KINDS`

Nouveau code : préférer `from forge import collectors` et `collectors.get_collector(source).fetch(since)`
(contrat NE-LÈVE-JAMAIS + `doctor()`), la voie que la console/CLI utilisent désormais.
"""
from .collectors import (                     # noqa: F401 — réexport rétro-compat
    load_source, safe_error, collect, get_collector,
    aggregate as _aggregate, to_epoch as _to_epoch,
    HTTP_KINDS, SYSLOG_KINDS, FILE_KINDS, EXEC_KINDS,
)

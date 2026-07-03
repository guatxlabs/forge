"""Paquet `forge.collectors` — collecteurs de détection INFRA-AGNOSTIQUES (une classe par `kind`).

La console Rust délègue ici (`forge.cli detections --since N --source <spec>`) pour toutes les sources
BLUE qui ne parlent PAS MITRE nativement (SIEM/IDS/pare-feu hétérogènes). Chaque collecteur lit sa
source, la normalise en `[{mitre,count,first_ts}]`, et respecte le contrat fail-open lisible
(cf. `base.Collector`). La jointure MITRE reste côté console, INCHANGÉE.

API stable (importée par la CLI et le shim rétro-compat `forge.detections`) :
- `get_collector(source) -> Collector|None`, `kinds()`, `REGISTRY`, `register`
- `load_source`, `safe_error`, `describe`
- `aggregate`, `to_epoch`, `resolve_mitre`, `records_from`, `syslog_aggregate` (helpers de normalisation)
- `Collector` (classe de base)

Kinds enregistrés : plume, generic_http, crowdsec, elastic, opensearch, fortigate_syslog, pfsense,
opnsense, file_jsonl, exec.
"""
from .base import (                       # noqa: F401 — API réexportée
    Collector, REGISTRY, register, get_collector, kinds,
    load_source, safe_error, describe,
    aggregate, to_epoch, resolve_mitre, records_from, syslog_aggregate,
    apply_auth, http_json, parse_query_into_url,
)

# Import des modules de collecteurs -> effet de bord : enregistrement dans REGISTRY.
from . import generic_http   # noqa: F401,E402  (plume, generic_http)
from . import crowdsec       # noqa: F401,E402
from . import elastic        # noqa: F401,E402  (elastic, opensearch)
from . import syslog         # noqa: F401,E402  (fortigate_syslog, pfsense, opnsense)
from . import file_jsonl     # noqa: F401,E402
from . import exec_cmd       # noqa: F401,E402  (exec)

# Familles de kinds (rétro-compat : réexportées par le shim `forge.detections`).
HTTP_KINDS = ("plume", "generic_http", "crowdsec", "elastic", "opensearch")
SYSLOG_KINDS = ("fortigate_syslog", "pfsense", "opnsense")
FILE_KINDS = ("file_jsonl",)
EXEC_KINDS = ("exec",)


def collect(source, since):
    """API STRICTE (LÈVE sur erreur) — voie legacy. Normalise `source` en `[{mitre,count,first_ts}]`.
    Lève ValueError si le kind est inconnu, ou l'exception sous-jacente si la source est mal
    configurée/injoignable (l'appelant CLI bascule alors en `source_reachable:false`). Pour le contrat
    NE-LÈVE-JAMAIS, utiliser `get_collector(source).fetch(since)`."""
    col = get_collector(source)
    if col is None:
        raise ValueError("kind de source non pris en charge par le collecteur Python: "
                         + str((source or {}).get("kind", "none")))
    return col.collect_strict(int(since))

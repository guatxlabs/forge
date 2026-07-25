"""Collecteurs syslog/filterlog : `fortigate_syslog`, `pfsense`, `opnsense`.

Ces infras émettent du SYSLOG texte (FortiGate) ou des lignes filterlog (pf/OPNsense), JAMAIS taggées
MITRE : la normalisation passe par des RÈGLES regex `mapping.rules = [{match, mitre}]` (REQUISES).
Chaque ligne matchée incrémente le count de la technique ; `first_ts` vient d'un groupe nommé
`(?P<ts>epoch)` si présent.

`fortigate_syslog` lit un fichier/flux syslog (`endpoint`/`path`). `pfsense`/`opnsense` sont DUAL :
- chemin de fichier -> mode filterlog (règles regex, comme FortiGate) ;
- `endpoint` http(s):// -> mode REST (JSON piloté par `mapping`, `records`/`mitre`/`table`), pour les
  déploiements exposant leur API.

Sécurité : le chemin est lu tel quel (garde-fou `max_lines` optionnel) ; un « flux » doit être un
fichier journal matérialisé (un FIFO sans écrivain bloquerait — responsabilité de l'admin intégrateur).
"""
from .base import (Collector, register, http_json, apply_auth, records_from,
                   aggregate, syslog_aggregate, parse_query_into_url)


class _SyslogFileCollector(Collector):
    """Base syslog fichier : `endpoint`/`path` + `mapping.rules` regex -> MITRE."""
    requires_mapping = True

    def _path(self):
        return self.source.get("endpoint") or self.source.get("path")

    def config_error(self):
        if not self._path():
            return f"{self.kind}: 'endpoint' (chemin du fichier syslog) requis"
        rules = self.mapping.get("rules")
        if not (isinstance(rules, list) and rules):
            return (f"{self.kind}: 'mapping.rules' (règles regex -> MITRE) requis — "
                    f"le syslog n'est PAS taggé MITRE nativement (aucune supposition)")
        return None

    def _collect(self, since):
        max_lines = self.source.get("max_lines")
        return syslog_aggregate(self._path(), self.mapping.get("rules"),
                                max_lines=int(max_lines) if max_lines else None)


@register("fortigate_syslog")
class FortigateSyslogCollector(_SyslogFileCollector):
    pass


class _FilterlogDualCollector(_SyslogFileCollector):
    """pf/OPNsense : filterlog (fichier) OU REST (endpoint http). Le scheme de `endpoint` arbitre."""

    def _is_rest(self):
        ep = (self.source.get("endpoint") or "").strip()
        return ep.startswith("http://") or ep.startswith("https://")

    def config_error(self):
        if self._is_rest():
            table = self.mapping.get("table")
            if not (isinstance(table, dict) and table) and not self.mapping.get("mitre"):
                return (f"{self.kind} (REST): 'mapping.table' ou 'mapping.mitre' requis — "
                        f"l'API n'est pas garantie taggée MITRE (aucune supposition)")
            return None
        return super().config_error()

    def _collect(self, since):
        if self._is_rest():
            url = parse_query_into_url((self.source.get("endpoint") or "").strip(),
                                       self.source.get("query"), since)
            headers = {"Accept": "application/json"}
            apply_auth(self.source, headers)
            parsed = http_json(url, headers=headers, timeout=self._timeout(),
                               insecure_tls=self.source.get("insecure_tls"))
            return aggregate(records_from(parsed, self.mapping), self.mapping)
        return super()._collect(since)


@register("pfsense")
class PfSenseCollector(_FilterlogDualCollector):
    pass


@register("opnsense")
class OpnSenseCollector(_FilterlogDualCollector):
    pass

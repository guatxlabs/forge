"""Collecteur CrowdSec (LAPI). `GET {endpoint}/v1/decisions` (défaut) ou `/v1/alerts` avec l'en-tête
`X-Api-Key`. CrowdSec émet des SCÉNARIOS (`crowdsecurity/ssh-bf`, ...), PAS des techniques MITRE :
le `mapping.table` {scénario -> 'Txxxx'} est donc REQUIS — on ne devine aucune technique.

Config : `endpoint` (URL LAPI, ex http://127.0.0.1:8080), `path` (défaut `/v1/decisions`),
`auth:{type:api_key_header, secret:<clé LAPI>, header:X-Api-Key}`, `query` optionnelle (`{since}`
substitué), `mapping:{table:{...}, field:'scenario', ts:'created_at'}`.
"""
from .base import Collector, register, http_json, apply_auth, records_from, aggregate, parse_query_into_url


@register("crowdsec")
class CrowdSecCollector(Collector):
    requires_mapping = True

    def config_error(self):
        if not (self.source.get("endpoint") or "").strip():
            return "crowdsec: 'endpoint' (URL LAPI, ex http://127.0.0.1:8080) requis"
        table = self.mapping.get("table")
        if not (isinstance(table, dict) and table):
            return ("crowdsec: 'mapping.table' (scénario CrowdSec -> technique MITRE) requis — "
                    "CrowdSec n'est PAS taggé MITRE nativement (aucune supposition)")
        return None

    def _collect(self, since):
        base = (self.source.get("endpoint") or "").strip().rstrip("/")
        path = self.source.get("path") or "/v1/decisions"
        if not str(path).startswith("/"):
            path = "/" + str(path)
        url = parse_query_into_url(base + path, self.source.get("query"), since)
        headers = {"Accept": "application/json"}
        apply_auth(self.source, headers, default_api_header="X-Api-Key")
        parsed = http_json(url, headers=headers, timeout=self._timeout(),
                           insecure_tls=self.source.get("insecure_tls"))
        # Défauts CrowdSec : la signature est le champ `scenario`, l'horodatage `created_at` (ISO).
        mp = dict(self.mapping)
        mp.setdefault("field", "scenario")
        mp.setdefault("ts", "created_at")
        return aggregate(records_from(parsed, mp), mp)

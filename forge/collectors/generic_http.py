"""Collecteurs HTTP génériques : `generic_http` (JSON piloté par config) et `plume` (préréglage —
contrat Plume historique : `GET {endpoint}/api/coverage/detections?since=N` -> `{detections:[{mitre,
count,first_ts}]}`, Basic auth, mapping IDENTITÉ).

`generic_http` : `GET {endpoint}` (+ `query` avec `{since}` substitué), auth selon `auth.type`,
puis `records_from` + `aggregate` via `mapping`. Une source qui porte déjà un champ `mitre` (Plume,
index SIEM taggé) n'a pas besoin de mapping ; une infra native fournit `mapping.table`/`mapping.field`.
"""
from .base import Collector, register, http_json, apply_auth, records_from, aggregate, parse_query_into_url


@register("generic_http")
class GenericHttpCollector(Collector):
    def config_error(self):
        if not (self.source.get("endpoint") or "").strip():
            return "generic_http: 'endpoint' (URL) requis"
        return None

    def _build(self, since):
        """(url, method, data, headers) pour la requête. GET par défaut."""
        endpoint = (self.source.get("endpoint") or "").strip()
        url = parse_query_into_url(endpoint, self.source.get("query"), since)
        headers = {"Accept": "application/json"}
        apply_auth(self.source, headers)
        return url, "GET", None, headers

    def _collect(self, since):
        url, method, data, headers = self._build(since)
        parsed = http_json(url, method=method, data=data, headers=headers,
                           timeout=self._timeout(), insecure_tls=self.source.get("insecure_tls"))
        return aggregate(records_from(parsed, self.mapping), self.mapping)


@register("plume")
class PlumeCollector(GenericHttpCollector):
    """Préréglage rétro-compat : chemin/param/mapping fixes du contrat Plume. Note : en pratique la
    console Rust interroge `plume`/`generic_http`(http) elle-même ; ce collecteur sert le diagnostic
    (`forge doctor --purple`) et les endpoints https délégués au Python de façon uniforme."""

    def config_error(self):
        if not (self.source.get("endpoint") or "").strip():
            return "plume: 'endpoint' (URL base Plume) requis"
        return None

    def _build(self, since):
        base = (self.source.get("endpoint") or "").strip().rstrip("/")
        url = f"{base}/api/coverage/detections?since={int(since)}"
        headers = {"Accept": "application/json"}
        apply_auth(self.source, headers)   # type basic attendu -> Authorization: Basic <b64>
        return url, "GET", None, headers

    def _collect(self, since):
        url, _m, _d, headers = self._build(since)
        parsed = http_json(url, headers=headers, timeout=self._timeout(),
                           insecure_tls=self.source.get("insecure_tls"))
        # Réponse Plume déjà normalisée {mitre,count,first_ts} -> mapping IDENTITÉ (le count porté par
        # la source est repris tel quel, comme le fetcher Rust `parse_plume_detections`).
        mp = dict(self.mapping)
        mp.setdefault("records", "detections")
        mp.setdefault("mitre", "mitre")
        mp.setdefault("ts", "first_ts")
        mp.setdefault("count", "count")
        return aggregate(records_from(parsed, mp), mp)

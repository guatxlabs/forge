"""Collecteurs Elasticsearch / OpenSearch. `POST {endpoint}` (URL `_search` d'un index de détections)
avec le corps `query` (dict) — sinon un range par défaut sur `@timestamp >= since`. Les hits sont lus
dans `hits.hits` (défaut) ; chaque hit étant `{_source:{...}}`, les chemins `mapping` visent
typiquement `_source.<champ>` (ex `mapping.mitre='_source.signal.rule.threat.technique.id'`, ou
`mapping.table` + `mapping.field='_source.rule.name'` pour une règle nommée).
"""
import json

from .base import Collector, register, http_json, apply_auth, records_from, aggregate


@register("elastic")
class ElasticCollector(Collector):
    def config_error(self):
        if not (self.source.get("endpoint") or "").strip():
            return "elastic: 'endpoint' (URL _search de l'index de détections) requis"
        return None

    def _collect(self, since):
        url = (self.source.get("endpoint") or "").strip()
        query = self.source.get("query")
        body = query if isinstance(query, dict) else {
            "size": int(self.source.get("size", 1000)),
            "query": {"range": {"@timestamp": {"gte": int(since) * 1000}}},
        }
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        apply_auth(self.source, headers)
        data = json.dumps(body).encode("utf-8")
        parsed = http_json(url, method="POST", data=data, headers=headers,
                           timeout=self._timeout(), insecure_tls=self.source.get("insecure_tls"))
        return aggregate(records_from(parsed, self.mapping), self.mapping)


@register("opensearch")
class OpenSearchCollector(ElasticCollector):
    """OpenSearch parle le même dialecte `_search`/`hits.hits` : même collecteur, kind distinct."""

    def config_error(self):
        if not (self.source.get("endpoint") or "").strip():
            return "opensearch: 'endpoint' (URL _search de l'index de détections) requis"
        return None

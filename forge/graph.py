"""Graphe d'engagement — le world-model partagé (porté de `secpipe/graph.py`).

L'état structuré qui manque à un LLM seul : hosts → services → findings, avec arêtes typées.
Le cerveau le lit pour décider l'action suivante ; les modules l'enrichissent au fil de
l'engagement (recon découvre des services, les attaques ajoutent des findings).

v0 : en mémoire + `to_dict()`/`from_dict()` pour persistance JSON. (secpipe utilisait sqlite ;
on le branchera si besoin de très gros engagements.) Zéro dépendance.
"""


class EngagementGraph:
    def __init__(self):
        self.nodes = {}     # (kind, id) -> attrs dict
        self.edges = []     # (src_key, etype, dst_key)

    def _add(self, ntype, nid, **attrs):
        key = (ntype, str(nid))         # ntype (pas 'kind') -> évite la collision avec un attr 'kind'
        if key in self.nodes:
            self.nodes[key].update({k: v for k, v in attrs.items() if v is not None})
        else:
            self.nodes[key] = dict(attrs)
        return key

    def _link(self, src, etype, dst):
        e = (src, etype, dst)
        if e not in self.edges:
            self.edges.append(e)

    # --- construction ---
    def add_host(self, host, **attrs):
        return self._add("host", host, **attrs)

    def add_service(self, host, port, name="", **attrs):
        h = self.add_host(host)
        s = self._add("service", f"{host}:{port}", host=host, port=port, name=name, **attrs)
        self._link(h, "exposes", s)
        return s

    def add_finding(self, finding):
        d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        host = d.get("target", "?")
        h = self.add_host(host)
        fid = f"{d.get('target')}::{d.get('title')}"
        f = self._add("finding", fid, **d)
        self._link(h, "has_finding", f)
        return f

    # --- lecture (pour le cerveau / le rapport) ---
    def hosts(self):
        return [k[1] for k in self.nodes if k[0] == "host"]

    def services(self, host=None):
        out = [v for k, v in self.nodes.items() if k[0] == "service"]
        return [s for s in out if host is None or s.get("host") == host]

    def findings_for(self, host):
        return [v for (kind, _), v in self.nodes.items()
                if kind == "finding" and v.get("target") == host]

    def summary(self):
        c = {"host": 0, "service": 0, "finding": 0}
        for (kind, _) in self.nodes:
            c[kind] = c.get(kind, 0) + 1
        return c

    def to_dict(self):
        # structurels (kind/id) APRÈS **v : un attr 'kind'/'id' dans les données du nœud (ex: un
        # finding qui porte sa propre 'kind') ne doit JAMAIS écraser le type/identité structurels du nœud.
        return {"nodes": [{**v, "kind": k[0], "id": k[1]} for k, v in self.nodes.items()],
                "edges": [{"src": list(s), "etype": t, "dst": list(d)} for (s, t, d) in self.edges]}

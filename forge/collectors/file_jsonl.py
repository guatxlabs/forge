"""Collecteur `file_jsonl` : lit un fichier JSONL d'événements NATIFS (une ligne = un objet JSON) et
les normalise via `mapping` (chemins pointés ou `table`/`field`). Utile pour ingérer un export d'un
SIEM/pare-feu, un tap de collecteur maison, ou une fixture de test. Lignes vides / non-objet ignorées.
"""
import json
from pathlib import Path

from .base import Collector, register, aggregate


@register("file_jsonl")
class FileJsonlCollector(Collector):
    def _path(self):
        return self.source.get("endpoint") or self.source.get("path")

    def config_error(self):
        if not self._path():
            return "file_jsonl: 'endpoint' (chemin du fichier JSONL) requis"
        return None

    def _records(self):
        out = []
        max_lines = self.source.get("max_lines")
        cap = int(max_lines) if max_lines else None
        with Path(self._path()).open("r", encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if cap is not None and i >= cap:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    out.append(obj)
        return out

    def _collect(self, since):
        return aggregate(self._records(), self.mapping)

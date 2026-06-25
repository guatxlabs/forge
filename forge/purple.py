"""Boucle purple — run-records ATT&CK que Plume consomme pour valider la détection.

Chaque action TIRÉE produit un run-record taggé `mitre`. Plume ingère sa propre télémétrie
taggée `mitre` ; la corrélation « mon attaque T a-t-elle produit une détection T ? » devient
une simple égalité de champ. C'est l'interface (contrat fichier/POST), pas un process partagé.
"""
import json
from datetime import datetime, timezone
from pathlib import Path


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_record(target, kind, mitre, fired=True, detail=""):
    return {"ts": _now(), "target": target, "kind": kind, "mitre": mitre,
            "fired": fired, "detail": detail, "source": "forge"}


def emit(path, records):
    """Écrit les run-records en JSONL (append) — ingérable par Plume (POST /api/ingest)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
    return len(records)

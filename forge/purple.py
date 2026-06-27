"""Boucle purple — run-records ATT&CK que Plume consomme pour valider la détection.

Chaque action TIRÉE produit un run-record taggé `mitre`. Plume ingère sa propre télémétrie
taggée `mitre` ; la corrélation « mon attaque T a-t-elle produit une détection T ? » devient
une simple égalité de champ. C'est l'interface (contrat fichier/POST), pas un process partagé.
"""
import json
from datetime import datetime, timezone
from pathlib import Path


# Fallback ATT&CK par `kind` — DERNIER recours quand une action tirée n'a produit AUCUN mitre
# (ni finding taggé, ni params.mitre, ni module.mitre). Le vrai mitre PRIME toujours : ce mapping
# ne sert qu'à garantir un run-record NON VIDE pour chaque tir, sinon Plume ne peut pas corréler
# « technique T tirée -> détectée ? » sur les tirs « rien trouvé » (trou de couverture purple).
# Le mitre réel (finding/params/module) reste la source de vérité ; ceci n'élargit aucune capacité.
DEFAULT_MITRE_BY_KIND = {
    "demo.fingerprint": "T1595",        # Active Scanning (démo no-op, reconnaissance)
    "recon.httpx": "T1595",             # Active Scanning
    "recon.nmap": "T1046",              # Network Service Discovery
    "web.nuclei": "T1595.002",          # Active Scanning: Vulnerability Scanning
    "access_control.idor": "T1190",     # Exploit Public-Facing Application
    "origin.find": "T1590.005",         # Gather Victim Network Info: IP Addresses
}


def mitre_for_kind(kind):
    """ATT&CK de repli pour un `kind` (chaîne vide si inconnu). Pur, sans effet de bord."""
    return DEFAULT_MITRE_BY_KIND.get(kind, "")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_record(target, kind, mitre, fired=True, detail="", run_id=None, campaign=None):
    """Un run-record ATT&CK par action TIRÉE. `run_id`/`campaign` corrèlent ce tir à la
    campagne/au run côté console+Plume (None si non fournis — champs additifs, rétro-compatibles)."""
    return {"ts": _now(), "target": target, "kind": kind, "mitre": mitre,
            "fired": fired, "detail": detail, "source": "forge",
            "run_id": run_id, "campaign": campaign}


def emit(path, records):
    """Écrit les run-records en JSONL (append) — ingérable par Plume (POST /api/ingest)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
    return len(records)

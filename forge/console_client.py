"""Client de la console Forge — POST des findings + run-records vers le store Rust.

Ferme la boucle : moteur Python (engine) -> console (`forge`, port 7100) -> store +
boucle purple (run-records ATT&CK ingérés, prêts pour la corrélation Plume). URL via
FORGE_CONSOLE_URL (défaut http://127.0.0.1:7100), token via FORGE_CONSOLE_TOKEN. Zéro dépendance.
"""
import json
import os
import urllib.request

DEFAULT_URL = "http://127.0.0.1:7100"


def base_url():
    return os.environ.get("FORGE_CONSOLE_URL", DEFAULT_URL).rstrip("/")


def _coverage_counts(coverage):
    """Réduit le dict coverage (listes par verdict) à des compteurs sérialisables."""
    cov = coverage or {}
    return {k: len(cov.get(k) or []) for k in ("fired", "dry_run", "vetoed", "errors")}


def _skipped_budget(skipped):
    """Sérialise les actions déférées par le budget (defer != delete) : kind/target/cls."""
    out = []
    for a in (skipped or []):
        if hasattr(a, "kind"):
            out.append({"kind": a.kind, "target": getattr(a, "target", ""),
                        "cls": getattr(a, "cls", "")})
        else:
            out.append(dict(a))
    return out


def build_payload(campaign, findings, run_records, run_id=None,
                  roe_decisions=None, coverage=None, coverage_gaps=None,
                  skipped_budget=None):
    """Payload d'ingest (pur, testable sans réseau).

    Ajoute la transparence anti-masquage à la boucle purple : `run_id` (corrèle un run
    lancé depuis la console), `roe_decisions` (verdict par action), `coverage` (compteurs
    fired/dry_run/vetoed/errors), `coverage_gaps` (classes jamais tentées par cible),
    `skipped_budget` (actions déférées). Champs additifs — la console ignore les inconnus."""
    return {
        "campaign": campaign or "default",
        "run_id": run_id,
        "findings": [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in (findings or [])],
        "run_records": [dict(r) for r in (run_records or [])],
        "roe_decisions": [dict(d) for d in (roe_decisions or [])],
        "coverage": _coverage_counts(coverage),
        "coverage_gaps": {k: list(v) for k, v in (coverage_gaps or {}).items()},
        "skipped_budget": _skipped_budget(skipped_budget),
    }


def ingest(campaign, findings, run_records, url=None, token=None, timeout=30,
           run_id=None, roe_decisions=None, coverage=None, coverage_gaps=None,
           skipped_budget=None):
    """POST /api/ingest. Retourne (status, json) ; lève sur erreur réseau/HTTP."""
    endpoint = (url or base_url()).rstrip("/") + "/api/ingest"
    token = token if token is not None else os.environ.get("FORGE_CONSOLE_TOKEN", "")
    if not token:                                  # token vide -> requête probablement rejetée (401) côté console
        import sys
        print("[forge] avertissement : token console vide (FORGE_CONSOLE_TOKEN non défini) "
              "— l'ingest sera probablement refusé (401)", file=sys.stderr)
    payload = build_payload(campaign, findings, run_records, run_id=run_id,
                            roe_decisions=roe_decisions, coverage=coverage,
                            coverage_gaps=coverage_gaps, skipped_budget=skipped_budget)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=data, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode("utf-8", "replace")
    try:
        return r.status, json.loads(body)
    except ValueError:
        return r.status, body

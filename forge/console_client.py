"""Client de la console Forge — POST des findings + run-records vers le store Rust.

Ferme la boucle : moteur Python (engine) -> console (`forge`, port 7100) -> store +
boucle purple (run-records ATT&CK ingérés, prêts pour la corrélation Plume). URL via
FORGE_CONSOLE_URL (défaut http://127.0.0.1:7100), token via FORGE_CONSOLE_TOKEN. Zéro dépendance.
"""
import json
import os
import urllib.request

from .portability import env_secret

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
                  skipped_budget=None, not_planned=None, partial=False):
    """Payload d'ingest (pur, testable sans réseau).

    Ajoute la transparence anti-masquage à la boucle purple : `run_id` (corrèle un run
    lancé depuis la console), `roe_decisions` (verdict par action), `coverage` (compteurs
    fired/dry_run/vetoed/errors), `coverage_gaps` (classes jamais tentées par cible),
    `skipped_budget` (actions déférées), `not_planned` (modules disponibles JAMAIS ordonnancés
    par le plan, {kind: raison} — le bucket anti-lacune au niveau module).

    `partial` (défaut False) : marque un CHECKPOINT INCRÉMENTAL (run encore EN COURS). Côté console,
    un ingest `partial` persiste findings/run-records/décisions + met à jour les compteurs SANS
    marquer le run_job 'done' (le statut 'running' reste, pour que le superviseur/watchdog marque
    ensuite 'done'/'timeout' honnêtement). Champs additifs — la console ignore les inconnus."""
    return {
        "campaign": campaign or "default",
        "run_id": run_id,
        "partial": bool(partial),
        "findings": [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in (findings or [])],
        "run_records": [dict(r) for r in (run_records or [])],
        "roe_decisions": [dict(d) for d in (roe_decisions or [])],
        "coverage": _coverage_counts(coverage),
        "coverage_gaps": {k: list(v) for k, v in (coverage_gaps or {}).items()},
        "skipped_budget": _skipped_budget(skipped_budget),
        "not_planned": {str(k): str(v) for k, v in (not_planned or {}).items()},
    }


def ingest(campaign, findings, run_records, url=None, token=None, timeout=30,
           run_id=None, roe_decisions=None, coverage=None, coverage_gaps=None,
           skipped_budget=None, not_planned=None, partial=False):
    """POST /api/ingest. Retourne (status, json) ; lève sur erreur réseau/HTTP.

    `partial=True` -> checkpoint incrémental (voir build_payload) : le run reste 'running' côté console."""
    endpoint = (url or base_url()).rstrip("/") + "/api/ingest"
    # FORGE_CONSOLE_TOKEN with a `*_FILE` fallback (Docker/k8s secret) — env holds a path, not the token.
    token = token if token is not None else (env_secret("FORGE_CONSOLE_TOKEN") or "")
    if not token:                                  # token vide -> requête probablement rejetée (401) côté console
        import sys
        print("[forge] avertissement : token console vide (FORGE_CONSOLE_TOKEN non défini) "
              "— l'ingest sera probablement refusé (401)", file=sys.stderr)
    payload = build_payload(campaign, findings, run_records, run_id=run_id,
                            roe_decisions=roe_decisions, coverage=coverage,
                            coverage_gaps=coverage_gaps, skipped_budget=skipped_budget,
                            not_planned=not_planned, partial=partial)
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


class IncrementalIngest:
    """Flush DELTA vers la console — la brique de durabilité incrémentale du moteur.

    Un run n'envoie plus ses findings/run-records/décisions en un unique POST « tout ou rien » en
    fin de campagne (perdu si le watchdog tue le run en cours) : ce sink est appelé AU FIL DE L'EAU
    (par batch intra-vague ET à chaque vague, via le checkpoint du moteur) puis une DERNIÈRE fois en
    fin de run. Il suit trois OFFSETS (findings, run-records, résultats/décisions — les trois listes
    du moteur sont APPEND-ONLY pendant un run) et n'envoie à chaque flush QUE le nouveau segment :
      • aucun double-envoi sur un run complet normal (chaque item posté exactement une fois) ;
      • les offsets n'avancent QU'APRÈS un envoi réussi (un flush qui lève ne perd rien : le delta
        repart au flush suivant — les findings sont idempotents côté console via UNIQUE(campaign,
        target,title) ; le sink est le point d'idempotence des run-records/décisions par les offsets).

    `sender` (défaut `ingest`) est injectable pour les tests (aucun réseau requis)."""

    def __init__(self, campaign, run_id, url=None, token=None, sender=None):
        self.campaign = campaign
        self.run_id = run_id
        self.url = url
        self.token = token
        self._send = sender or ingest
        self._nf = 0   # findings déjà envoyés
        self._nr = 0   # run-records déjà envoyés
        self._nd = 0   # résultats/décisions déjà envoyés (index dans engine.results)

    def flush(self, engine, *, partial, coverage=None, coverage_gaps=None,
              skipped_budget=None, not_planned=None):
        """Envoie le delta accumulé depuis le dernier flush. Retourne (status, resp) sur envoi, ou
        None si `partial` ET rien de neuf (checkpoint vide -> pas de bruit réseau). Les offsets
        n'avancent qu'après le retour du sender (succès) : une exception les laisse intacts."""
        findings = engine.findings[self._nf:]
        run_records = engine.run_records[self._nr:]
        roe = engine.roe_decisions(start=self._nd)
        # rien de neuf sur un checkpoint intermédiaire -> ne pas poster (le flush FINAL, lui, poste
        # toujours pour transmettre gaps/skipped/not_planned et — si partial=False — marquer 'done').
        if partial and not findings and not run_records and not roe:
            return None
        cov = coverage if coverage is not None else engine.coverage()
        st, resp = self._send(
            self.campaign, findings, run_records, url=self.url, token=self.token,
            run_id=self.run_id, roe_decisions=roe, coverage=cov, coverage_gaps=coverage_gaps,
            skipped_budget=skipped_budget, not_planned=not_planned, partial=partial)
        # avance les offsets APRÈS l'envoi réussi (au-delà de len(engine.*) capturé à l'entrée).
        self._nf += len(findings)
        self._nr += len(run_records)
        self._nd += len(roe)
        return st, resp

"""Cerveau — propose des actions à partir de l'état d'engagement.

Interface (le seam où Forge branche l'orchestrateur Claude) :
    Brain.propose(targets: list[Target]) -> list[Action]

En usage orchestré, le cerveau EST l'orchestrateur (Claude Code) : il lit l'état et passe
des actions (via un actions.json ou directement). `HeuristicBrain` est le défaut autonome
sûr (mapping cible→classes, repris de secpipe) pour tourner sans orchestrateur. La priorité
réelle est ensuite garantie par le planner coverage-safe, pas par le cerveau (anti-starvation).
"""
from .roe import Action


class Brain:
    def propose(self, targets):
        raise NotImplementedError


class HeuristicBrain(Brain):
    """Mapping minimal cible→actions candidates. Volontairement bête : le planner protège
    les classes qualifiantes même si le cerveau les sous-note."""

    def propose(self, targets):
        out, seen = [], set()
        for t in targets:
            host = t.host
            svc = (t.attrs or {}).get("service", "").lower()
            is_web = t.kind in ("url", "app") or "http" in svc or t.kind == "host" and not svc

            cands = []
            if is_web:
                cands += [
                    Action("recon.httpx", host, value=0.3, confidence=0.7, cost=1, desc="fingerprint HTTP"),
                    Action("web.nuclei", host, value=0.4, confidence=0.6, cost=2, desc="scan nuclei (medium+)"),
                    # classes qualifiantes : sous-notées mais le planner les plancher-protège
                    Action("access_control.idor", host, cls="access_control", exploit=True,
                           value=0.8, confidence=0.3, cost=2, desc="IDOR/BOLA 2-comptes (diff oracle)"),
                ]
            if t.kind in ("host", "service"):
                cands += [Action("recon.nmap", host, value=0.3, confidence=0.7, cost=2, desc="nmap -sV")]

            for a in cands:
                if a.id not in seen:
                    seen.add(a.id)
                    out.append(a)
        return out

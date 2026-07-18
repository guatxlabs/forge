"""Planner coverage-safe — porté de `secpipe/planner.py` (le joyau).

Ordonne les actions par espérance de valeur EV = value*confidence/cost, MAIS applique un
plancher (FLOOR) aux classes QUALIFIANTES (idor/access_control/auth/ato/rce/sqli/ssrf/biz/
privesc) pour qu'une voie payable ne soit JAMAIS affamée même si le cerveau la sous-note.

Garanties anti-masquage :
  - `defer != delete` : les actions hors-budget vont dans `skipped_budget` (VISIBLE), pas jetées.
  - `coverage_gaps()` : par cible, les classes de la checklist jamais tentées.
  - `exhaustive=True` : désactive l'ordonnancement -> couverture maximale.

Self-test en __main__ : une action qualifiante sous-notée reste planifiée. Zéro dépendance.

SOURCE DE VÉRITÉ : QUALIFYING et DEFAULT_CHECKLIST sont DÉRIVÉS de forge/techniques.py (la table
unique) — plus de recopie de la taxonomie entre planner, brain, schema et les modules.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

try:                                            # import package normal
    from . import techniques
except ImportError:                             # exécution directe (python3 forge/planner.py — self-test)
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from forge import techniques

if TYPE_CHECKING:                                         # imports paresseux (type-checking uniquement)
    from .roe import Action

FLOOR = 0.5
# classes qualifiantes (plancher anti-starvation) = jetons `qualifying=True` de la table unique.
QUALIFYING = techniques.qualifying_classes()
# checklist par défaut = ce qu'on veut couvrir sur une cible web (ordre = priorité hacktivity)
DEFAULT_CHECKLIST = list(techniques.DEFAULT_CHECKLIST)


def _floored(action: Action) -> bool:
    """True si l'action doit recevoir le PLANCHER anti-starvation. Trois voies COMPLÉMENTAIRES :

      1. `action.cls ∈ QUALIFYING` : les 12 jetons de classe historiques (idor/access_control/auth/
         ato/rce/sqli/ssrf/biz/privesc…) — inchangé.
      2. le KIND est `bug_bounty_eligible` dans le catalogue : couvre les 22 classes payables dont le
         `cls` par défaut (`kind.split('.')[-1]`) n'est PAS un jeton qualifiant (`graphql.access` ->
         "access", `xss.stored` -> "stored", `ssti.eval` -> "eval", `xxe.probe`, `cmdi.probe`,
         `oauth.flow`, `race.condition`, `csrf.state_change`…). Sans cette voie, ces voies payables
         gardaient une EV ~0.003 vs le plancher 0.5 et étaient affamées par un budget fini / un SIGTERM.
      3. le `cls` DÉCLARÉ du KIND dans le catalogue est qualifiant (`CATALOG[kind].cls ∈ QUALIFYING`).
         Ferme le trou de `rce.probe` (`vuln_class='RCE'`, `phase='exploit'`, cls déclaré "rce" MAIS
         `bug_bounty_eligible=False` — c'est un EXPLOIT pentest-only, PAS une classe BB payable). Le
         `cls` de l'Action DÉRIVE par défaut du suffixe du kind ("probe") quand le cerveau ne pose pas
         l'override -> voies 1 & 2 le manquaient et la classe la PLUS forte (RCE) tombait entièrement
         (EV ~0.003 vs plancher 0.5, affamable). On ne TOUCHE PAS `bug_bounty_eligible` (qui rangerait
         cet exploit dans le profil bug_bounty et casserait `pentest_only`) : on planche par la classe
         planner déclarée, qui EST qualifiante par construction (`_t("rce", qualifying=True)`).

    Ainsi TOUTE classe payable/qualifiante reçoit le MÊME plancher que l'IDOR REST — et une action de
    scan non-qualifiante (`web.nuclei`, `recon.subfinder`, cls déclaré "" ) n'est JAMAIS planchée
    (`"" ∉ QUALIFYING`, pas over-flooring). Pur, ne lève jamais."""
    if action.cls in QUALIFYING:
        return True
    t = techniques.CATALOG.get(action.kind)
    if t is None:
        return False
    return bool(t.bug_bounty_eligible) or t.cls in QUALIFYING


class Planner:
    def __init__(self, budget: float | None = None, exhaustive: bool = False,
                 checklist: Iterable[str] | None = None) -> None:
        self.budget = budget                       # None = illimité
        self.exhaustive = exhaustive
        self.checklist = list(checklist or DEFAULT_CHECKLIST)

    @staticmethod
    def ev(action: Action) -> float:
        base = action.value * action.confidence / max(action.cost, 0.01)
        if _floored(action):                       # plancher : jamais affamer une voie payable
            return max(base, FLOOR)
        return base

    def order(self, actions: list[Action]) -> tuple[list[Action], list[Action]]:
        """Retourne (ordered, skipped_budget). Préserve toutes les actions (defer != delete).

        Le budget ne borne QUE le travail NON-QUALIFIANT : une action dont `cls` est dans
        QUALIFYING est toujours conservée dans `ordered`, même si le budget est dépassé (elle
        ne tombe jamais dans `skipped_budget`). Seules les classes non-qualifiantes hors-budget
        sont reportées (defer != delete : visibles dans `skipped_budget`, jamais jetées)."""
        if self.exhaustive:
            return list(actions), []
        ranked = sorted(actions, key=self.ev, reverse=True)
        if self.budget is None:
            return ranked, []
        ordered: list[Action] = []
        skipped: list[Action] = []
        spent = 0.0
        for a in ranked:
            qualifying = _floored(a)
            if spent + a.cost <= self.budget or qualifying:  # qualifiant = toujours gardé
                ordered.append(a)
                if not qualifying:
                    # le budget ne BORNE que le travail non-qualifiant : une action qualifiante est
                    # gardée sans consommer le budget, donc elle n'affame jamais les non-qualifiantes.
                    spent += a.cost
            else:
                skipped.append(a)
        return ordered, skipped

    def coverage_gaps(self, actions: list[Action], targets: Iterable[str]) -> dict[str, list[str]]:
        """Par cible : classes de la checklist jamais présentes dans les actions proposées."""
        gaps: dict[str, list[str]] = {}
        for t in targets:
            attempted = {a.cls for a in actions if a.target == t}
            missing = [c for c in self.checklist if c not in attempted]
            if missing:
                gaps[t] = missing
        return gaps


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from forge.roe import Action
    # IDOR délibérément sous-noté vs un scan bien noté
    idor = Action("access_control.idor", "app.test", cls="access_control", value=0.1, confidence=0.1, cost=3)
    scan = Action("web.nuclei", "app.test", value=0.9, confidence=0.9, cost=1)
    ordered, skipped = Planner(budget=1.0).order([scan, idor])
    assert idor in ordered, "REGRESSION : l'IDOR sous-noté a été affamé !"
    assert not skipped or idor not in skipped
    print("OK — planner coverage-safe : l'IDOR sous-noté reste planifié malgré le budget.")

"""Planner coverage-safe — porté de `secpipe/planner.py` (le joyau).

Ordonne les actions par espérance de valeur EV = value*confidence/cost, MAIS applique un
plancher (FLOOR) aux classes QUALIFIANTES (idor/access_control/auth/ato/rce/sqli/ssrf/biz/
privesc) pour qu'une voie payable ne soit JAMAIS affamée même si le cerveau la sous-note.

Garanties anti-masquage :
  - `defer != delete` : les actions hors-budget vont dans `skipped_budget` (VISIBLE), pas jetées.
  - `coverage_gaps()` : par cible, les classes de la checklist jamais tentées.
  - `exhaustive=True` : désactive l'ordonnancement -> couverture maximale.

Self-test en __main__ : une action qualifiante sous-notée reste planifiée. Zéro dépendance.
"""
FLOOR = 0.5
QUALIFYING = {
    "idor", "bola", "access_control", "auth", "auth_bypass", "ato",
    "rce", "sqli", "ssrf", "business_logic", "biz", "privesc",
}
# checklist par défaut = ce qu'on veut couvrir sur une cible web (ordre = priorité hacktivity)
DEFAULT_CHECKLIST = ["access_control", "auth", "ato", "ssrf", "sqli", "rce", "business_logic"]


class Planner:
    def __init__(self, budget=None, exhaustive=False, checklist=None):
        self.budget = budget                       # None = illimité
        self.exhaustive = exhaustive
        self.checklist = list(checklist or DEFAULT_CHECKLIST)

    @staticmethod
    def ev(action):
        base = action.value * action.confidence / max(action.cost, 0.01)
        if action.cls in QUALIFYING:               # plancher : jamais affamer une voie payable
            return max(base, FLOOR)
        return base

    def order(self, actions):
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
        ordered, skipped, spent = [], [], 0.0
        for a in ranked:
            qualifying = a.cls in QUALIFYING
            if spent + a.cost <= self.budget or qualifying:  # qualifiant = toujours gardé
                ordered.append(a)
                if not qualifying:
                    # le budget ne BORNE que le travail non-qualifiant : une action qualifiante est
                    # gardée sans consommer le budget, donc elle n'affame jamais les non-qualifiantes.
                    spent += a.cost
            else:
                skipped.append(a)
        return ordered, skipped

    def coverage_gaps(self, actions, targets):
        """Par cible : classes de la checklist jamais présentes dans les actions proposées."""
        gaps = {}
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

# SPDX-License-Identifier: AGPL-3.0-or-later
"""Invariants de GOUVERNANCE du SPA de la console (console/web/js) vérifiés sur la SOURCE.

Portée mesurée : ces tests lisent le JavaScript servi par la console et vérifient PAR QUEL CHEMIN les
routes gouvernées sont appelées. Ils ne font PAS tourner le SPA — ils ferment le trou qui a laissé
passer la régression du dry-plan (les tests Rust appellent les handlers directement, donc aucun d'eux
ne pouvait voir que le CLIENT n'envoyait pas les en-têtes opérateur).

INVARIANT COUVERT — `POST /api/plan` (dry-plan INERTE) ne doit JAMAIS être plus restreint que
`POST /api/run` (campagne ARMÉE) : qui peut TIRER doit pouvoir PRÉVISUALISER. Le serveur applique la
même gate aux deux ; il faut donc que le client fournisse la même preuve d'opérateur aux deux. Un
`fetch()` brut ne le fait pas : seul le helper partagé `write()` (core/api.js -> operatorHeaders)
injecte `X-Forge-Operator`.
"""
import re
import unittest
from pathlib import Path

JS_DIR = Path(__file__).resolve().parents[1] / "console" / "web" / "js"
#: lignes de code (pas de commentaire) qui émettent une requête vers une route donnée.
_CALL = re.compile(r"\b(fetch|write|api|adminApi)\s*\(")


def _call_sites(route):
    """(fichier, n° de ligne, ligne) de chaque appel réseau visant `route`. Ignore les commentaires."""
    out = []
    for path in sorted(JS_DIR.rglob("*.js")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.strip()
            if code.startswith("//") or code.startswith("*") or code.startswith("/*"):
                continue
            if route in code and _CALL.search(code):
                out.append((path.name, n, code))
    return out


class TestDryPlanIsNotMoreRestrictedThanRun(unittest.TestCase):
    #: preuve d'opérateur acceptable sur un call site : le helper partagé (qui injecte l'en-tête) OU
    #: l'en-tête posé explicitement (cas de la SONDE de posture C2, qui l'envoie VIDE à dessein).
    def _has_operator_proof(self, code):
        return "write(" in code or "X-Forge-Operator" in code

    def test_plan_carries_the_same_operator_proof_as_run(self):
        sites = _call_sites("/api/plan")
        self.assertTrue(sites, "aucun appel à /api/plan trouvé dans le SPA (test devenu aveugle)")
        for name, n, code in sites:
            self.assertTrue(
                self._has_operator_proof(code),
                f"{name}:{n} appelle /api/plan sans preuve opérateur (ni `write()` ni X-Forge-Operator) : "
                f"le dry-plan INERTE devient plus restreint que le lancement ARMÉ -> {code}",
            )

    def test_run_call_sites_all_carry_it_too(self):
        sites = _call_sites("/api/run'")
        self.assertTrue(sites, "aucun appel à /api/run trouvé dans le SPA (test devenu aveugle)")
        for name, n, code in sites:
            self.assertTrue(self._has_operator_proof(code),
                            f"{name}:{n} : /api/run sans preuve opérateur -> {code}")

    def test_plan_uses_exactly_the_helper_used_by_the_launch_form(self):
        """Le formulaire de lancement poste /api/run via `write(..., auth: 'operator')`. Le dry-plan doit
        emprunter LE MÊME helper : c'est ce qui rend les deux en-têtes identiques PAR CONSTRUCTION plutôt
        que par recopie (la recopie est exactement ce qui avait dérivé)."""
        plan = [c for _, _, c in _call_sites("/api/plan")]
        run = [c for _, _, c in _call_sites("/api/run'") if "write(" in c]
        self.assertTrue(run, "le lancement n'utilise plus `write()` : invariant à réécrire")
        self.assertTrue(any("write(" in c and "operator" in c for c in plan),
                        "aucun appel /api/plan via `write(..., auth: 'operator')` : " + " | ".join(plan))


if __name__ == "__main__":
    unittest.main()

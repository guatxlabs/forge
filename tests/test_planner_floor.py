"""M4 — le PLANCHER anti-starvation du planner couvre TOUTE classe payable (`bug_bounty_eligible`).

Avant le fix, `Planner.ev`/`order` ne planchaient que les 12 jetons de classe `qualifying=True`
(`idor`/`access_control`/`ssrf`/…). Or le `cls` d'une action DÉRIVE par défaut de `kind.split('.')[-1]`
(roe.py) : `graphql.access` -> "access", `xss.stored` -> "stored", `ssti.eval` -> "eval"… — 22 kinds
`bug_bounty_eligible` dont le `cls` par défaut n'est PAS un jeton qualifiant. Ils gardaient une EV ~0.003
vs le plancher 0.5 et étaient AFFAMÉS par un budget fini / un SIGTERM.

Ce fichier prouve : (a) toute classe payable est planchée EXACTEMENT comme l'IDOR REST ; (b) une action
de scan/recon NON-qualifiante n'est PAS planchée ; (c) `defer != delete` intact (un non-qualifiant
hors-budget va dans `skipped_budget`, jamais jeté) ; (d) `QUALIFYING` (constante) reste inchangé.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import techniques                                    # noqa: E402
from forge.planner import Planner, FLOOR, QUALIFYING, _floored  # noqa: E402
from forge.roe import Action                                    # noqa: E402

# les 22 classes payables dont le `cls` par défaut n'est PAS un jeton `qualifying` (le trou historique).
_PAYABLE_NON_QUALIFYING = (
    "graphql.access", "xss.stored", "xss.reflected", "ssti.eval", "xxe.probe", "cmdi.probe",
    "nosql.probe", "oauth.flow", "race.condition", "csrf.state_change", "path.traversal",
    "jwt.weakness", "redirect.open", "request_smuggling.probe",
)


class TestPayableFloor(unittest.TestCase):
    def _low(self, kind):
        # action DÉLIBÉRÉMENT sous-notée (EV brute ~0.003) : seul le plancher peut la sauver.
        return Action(kind, "app.test", value=0.1, confidence=0.1, cost=3)

    def test_all_bug_bounty_eligible_kinds_are_floored(self):
        # (a) — TOUTE technique `bug_bounty_eligible` du catalogue reçoit le plancher, quel que soit son cls.
        elig = [k for k, t in techniques.CATALOG.items() if getattr(t, "bug_bounty_eligible", False)]
        self.assertGreaterEqual(len(elig), 30)
        for kind in elig:
            a = self._low(kind)
            self.assertTrue(_floored(a), f"{kind}: classe payable NON planchée")
            self.assertEqual(Planner.ev(a), FLOOR, f"{kind}: EV != plancher")

    def test_payable_floored_exactly_like_idor(self):
        # (a bis) — graphql/xss/ssti sous-notés ont la MÊME EV planchée que l'IDOR REST.
        idor_ev = Planner.ev(self._low("access_control.idor"))
        for kind in _PAYABLE_NON_QUALIFYING:
            self.assertEqual(Planner.ev(self._low(kind)), idor_ev, f"{kind} != IDOR floor")

    def test_non_qualifying_scan_not_floored(self):
        # (b) — un scan/recon générique NON payable garde son EV brute (jamais planchée).
        scan = Action("web.nuclei", "app.test", value=0.9, confidence=0.9, cost=1)
        self.assertFalse(_floored(scan))
        self.assertGreater(Planner.ev(scan), FLOOR)             # sa vraie EV, pas le plancher
        recon = Action("recon.subfinder", "app.test", value=0.1, confidence=0.1, cost=3)
        self.assertFalse(_floored(recon))
        self.assertLess(Planner.ev(recon), FLOOR)               # sous-notée ET non planchée -> reste basse

    def test_budget_keeps_payable_classes_starves_only_non_qualifying(self):
        # (a+c) — sous un budget SERRÉ, les classes payables sous-notées restent dans `ordered` ;
        # seul le non-qualifiant hors-budget tombe dans `skipped_budget` (defer != delete : VISIBLE).
        scan_hi = Action("web.nuclei", "app.test", value=0.9, confidence=0.9, cost=1)
        graphql = self._low("graphql.access")
        xss = self._low("xss.stored")
        extra_scan = Action("recon.katana", "app.test", value=0.2, confidence=0.2, cost=5)
        ordered, skipped = Planner(budget=1.0).order([scan_hi, graphql, xss, extra_scan])
        self.assertIn(graphql, ordered, "graphql.access affamé par le budget !")
        self.assertIn(xss, ordered, "xss.stored affamé par le budget !")
        self.assertNotIn(graphql, skipped)
        self.assertNotIn(xss, skipped)
        # rien n'est jeté : chaque action est soit ordonnée soit reportée (defer != delete).
        self.assertEqual(sorted(id(a) for a in ordered + skipped),
                         sorted(id(a) for a in [scan_hi, graphql, xss, extra_scan]))

    def test_qualifying_constant_unchanged(self):
        # (d) — la constante QUALIFYING n'a PAS bougé (le fix agit dans ev/order, pas sur la table).
        self.assertEqual(set(QUALIFYING), techniques.qualifying_classes())
        self.assertNotIn("access", QUALIFYING)                  # le cls dérivé de graphql.access n'y est pas
        self.assertNotIn("stored", QUALIFYING)


if __name__ == "__main__":
    unittest.main()

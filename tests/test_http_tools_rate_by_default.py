# SPDX-License-Identifier: AGPL-3.0-or-later
"""Un outil qui compte en REQUÊTES HTTP doit-il attendre un opt-in pour être bridé ? (D20)

L'opt-in (`rate_explicit`) reposait sur un coût chiffré : `rate: 5` imposé aux outils fait passer
naabu de 1,1 min à 3,6 h. Le chiffre est exact — et il vient d'un SCANNER DE PORTS bridé à 5
PAQUETS/s sur 65 535 ports. Ce qui coûte cher, c'est d'appliquer un débit HTTP à ce qui ne compte
pas en requêtes HTTP.

CE QUE LE COÛT DE NE **PAS** BRIDER N'AVAIT JAMAIS CHIFFRÉ — mesuré le 2026-08-11, machine propre
(aucun conteneur orphelin, cf. D21), lignes de base vérifiées, Juice Shop en loopback, campagne
autonome de 900 s :

    rate 20 (ce que le banc écrivait)  167 -> 5 023 Mio   MORTE à t+145s      8 actions, 1660 erreurs
    rate  5 armé                       162 ->   484 Mio   VIVANTE, HTTP 200   1360 actions, 2730 findings

**170 fois plus d'actions tirées en bridant.** Une cible morte transforme tout le reste du plan en
erreurs : brider ne coûte pas de la couverture ici, brider EST la couverture.

Le tueur a été isolé SEUL, sans campagne (feroxbuster `--rate-limit 20` -> 5 051 Mio et mort ;
`--rate-limit 5` -> 384 Mio et vivante), et la désambiguïsation à UNE variable dit que c'est le
DÉBIT et non la concurrence : 4 fils à 20 req/s tuent, 50 fils à 5 req/s ne font rien.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import engine                                                       # noqa: E402
from forge.roe import Action, Scope                                            # noqa: E402


class _Eng(engine.Engine):
    """Engine minimal : on n'exerce que l'injection de params, pas un run."""

    def __init__(self, **scope_kw):
        data = {"mode": "grey", "in_scope": ["t.test"], "rate": 8}
        data.update(scope_kw)
        super().__init__(Scope(data))


def _prepare(eng, kind):
    return eng._prepare([Action(kind, "t.test")], None, {}, {})[0]


class HttpToolsFollowRateWithoutOptIn(unittest.TestCase):

    def test_le_crawler_qui_tue_est_bride_par_defaut(self):
        """feroxbuster non bridé fait passer la cible de 167 Mio à 5 Gio et la TUE en 145 s."""
        self.assertEqual(_prepare(_Eng(), "recon.feroxbuster").params.get("rate"), 8)

    def test_les_autres_outils_HTTP_aussi(self):
        for kind in ("recon.katana", "web.nuclei", "recon.httpx"):
            with self.subTest(kind=kind):
                self.assertEqual(_prepare(_Eng(), kind).params.get("rate"), 8)

    def test_le_SCANNER_DE_PORTS_garde_son_opt_in(self):
        """C'est LUI qui porte la facture (1,1 min -> 3,6 h) : elle ne doit pas être payée d'office."""
        for kind in ("recon.naabu", "recon.nmap"):
            with self.subTest(kind=kind):
                self.assertIsNone(_prepare(_Eng(), kind).params.get("rate"))

    def test_les_outils_a_DELAI_gardent_leur_opt_in(self):
        """Leur drapeau est un délai par requête, pas un req/s — unité différente, décision séparée."""
        for kind in ("sqli.sqlmap", "xss.dalfox", "fuzz.wfuzz"):
            with self.subTest(kind=kind):
                self.assertIsNone(_prepare(_Eng(), kind).params.get("rate"))

    def test_l_opt_in_continue_de_TOUT_brider(self):
        eng = _Eng(rate_explicit=True)
        for kind in ("recon.naabu", "recon.nmap", "sqli.sqlmap", "recon.feroxbuster"):
            with self.subTest(kind=kind):
                self.assertEqual(_prepare(eng, kind).params.get("rate"), 8)

    def test_sans_rate_declare_rien_n_est_impose(self):
        """On ne FABRIQUE pas un débit : sans `rate` au scope, l'argv reste celui de l'outil.
        (Un opérateur qui ne déclare aucun débit reste donc exposé — c'est une décision de
        politique, pas un oubli : elle est écrite dans docs/CONFIGURATION.md §2bis.)"""
        a = _prepare(_Eng(rate=0), "recon.feroxbuster")
        self.assertIn(a.params.get("rate"), (None, 0))


class TheSplitIsDerivedNotHandWritten(unittest.TestCase):
    """La liste manuelle est précisément ce qui avait laissé katana crawler à plein régime."""

    def test_l_unite_vient_de_la_declaration_de_l_outil(self):
        derives = engine._http_request_rate_kinds()
        self.assertIn("recon.feroxbuster", derives)          # libellé « --rate-limit req/s »
        self.assertNotIn("recon.naabu", derives)             # libellé « -rate paquets/s »

    def test_aucun_kind_incapable_de_recevoir_un_debit(self):
        """On ne peut pas brider un outil qui n'a pas de drapeau : le sous-ensemble est STRICT."""
        self.assertTrue(engine._HTTP_RATE_FLAG_KINDS <= engine._RATE_FLAG_KINDS)

    def test_les_deux_familles_sont_disjointes_et_non_vides(self):
        opt_in = engine._RATE_FLAG_KINDS - engine._HTTP_RATE_FLAG_KINDS
        self.assertTrue(engine._HTTP_RATE_FLAG_KINDS, "aucun outil HTTP bridé -> le défaut est inerte")
        self.assertTrue(opt_in, "plus aucun opt-in -> la facture naabu est payée d'office")


if __name__ == "__main__":
    unittest.main()

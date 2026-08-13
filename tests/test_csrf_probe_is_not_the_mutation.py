# SPDX-License-Identifier: AGPL-3.0-or-later
"""« Je ne fais qu'un GET, donc je ne mute rien » — le raisonnement circulaire de l'oracle CSRF (D18)

Cet oracle cherche **une action critique atteignable sans jeton**. Or l'une des formes les plus
courantes de cette faille est précisément **une action mutante exposée en GET**. Se prémunir en
disant « je ne fais qu'un GET » revient donc à supposer faux exactement ce qu'on teste.

MESURÉ le 2026-08-13 sur DVWA, avec l'URL que le banc donnait LUI-MÊME à cet oracle :

    GET /vulnerabilities/csrf/?password_new=a&password_conf=a&Change=Change  ->  « Password Changed »
    admin/password  ->  302 vers login.php   (REFUSÉ)
    admin/a         ->  302 vers index.php   (ACCEPTÉ)

Le mot de passe administrateur de la cible avait donc été CHANGÉ par la sonde, sous un scope
déclarant `allow_destructive: False`, pendant que l'évidence affirmait « NON DESTRUCTIF: probe GET
seul ». Deux défauts en un : le banc mutait sa cible sans le déclarer, et l'oracle affirmait une
innocuité qu'il ne pouvait pas garantir.

REMÈDE — action déclarée critique + aucun `probe_url` fourni => on sonde la même URL SANS sa chaîne
de requête : la page/le formulaire porte ce que l'oracle vient lire (Set-Cookie, jeton), pas ce qui
mute. Et l'abstention est NOMMÉE dans l'évidence : une garde muette serait le défaut symétrique.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))




def _oracle():
    from forge import modules as mods
    return mods.get("csrf.state_change")


class _Action:
    def __init__(self, target, **params):
        self.kind = "csrf.state_change"
        self.target = target
        self.params = {"in_scope": ["app.test"], **params}


MUTANT = "http://app.test/account/csrf/?password_new=a&password_conf=a&Change=Change"
FORM = "http://app.test/account/csrf/"


def _fire(action):
    """Joue l'oracle en interceptant le seul aller réseau ; rend (url sondée, findings)."""
    seen = {}

    def fake_fetch(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
        seen["url"] = url
        seen["method"] = method
        return (200, "<html><form><input name='password_new'></form></html>",
                [("Set-Cookie", "PHPSESSID=abc; path=/")])

    o = _oracle()
    with mock.patch.object(type(o), "_fetch", staticmethod(fake_fetch)):
        return seen, o.fire(action)


class TheProbeMustNotBeTheMutation(unittest.TestCase):

    def test_la_chaine_de_requete_est_ecartee_sur_une_action_critique(self):
        """LE DÉFAUT MESURÉ : sonder l'URL complète changeait le mot de passe admin."""
        seen, _f = _fire(_Action(MUTANT, critical=True))
        self.assertEqual(seen["url"], FORM,
                         "la sonde a rejoué l'URL mutante que l'action déclare critique")
        self.assertEqual(seen["method"], "GET")

    def test_l_abstention_est_NOMMEE_dans_l_evidence(self):
        """Une garde muette serait le défaut symétrique : le rapport doit dire ce qui a été écarté."""
        _seen, findings = _fire(_Action(MUTANT, critical=True))
        ev = findings[0].get("evidence", "") if isinstance(findings[0], dict) else findings[0].evidence
        self.assertIn("chaîne de requête ÉCARTÉE", ev)
        self.assertIn(FORM, ev)

    def test_un_probe_url_EXPLICITE_reste_prioritaire(self):
        """L'opérateur qui désigne lui-même la page à sonder n'est jamais contredit."""
        seen, _f = _fire(_Action(MUTANT, critical=True, probe_url="http://app.test/autre/"))
        self.assertEqual(seen["url"], "http://app.test/autre/")


class NothingElseChanges(unittest.TestCase):
    """L'EXCÈS INVERSE — la garde ne doit rien retirer d'autre."""

    def test_une_action_NON_critique_garde_sa_chaine_de_requete(self):
        """Sans déclaration de criticité, rien n'autorise à réécrire la cible de l'opérateur."""
        seen, _f = _fire(_Action(MUTANT, critical=False))
        self.assertEqual(seen["url"], MUTANT)

    def test_une_criticite_DEDUITE_ne_declenche_pas_la_garde(self):
        """La garde se déclenche sur `critical=True` DÉCLARÉ — pas sur une heuristique de mot-clé :
        réécrire la cible sur un indice serait une décision prise à la place de l'opérateur."""
        seen, _f = _fire(_Action("http://app.test/admin/?role=admin", action="role_change"))
        self.assertEqual(seen["url"], "http://app.test/admin/?role=admin")

    def test_une_url_SANS_chaine_de_requete_est_inchangee(self):
        seen, _f = _fire(_Action(FORM, critical=True))
        self.assertEqual(seen["url"], FORM)


class TheBenchNoLongerMutatesItsTarget(unittest.TestCase):
    """Le banc donnait lui-même l'URL mutante ; il fournit désormais un `probe_url` explicite."""

    def test_l_action_dvwa_du_banc_porte_un_probe_url_non_mutant(self):
        from bench.detection import seeded
        from bench.detection.groundtruth import APPS
        from bench.detection.provision import AuthMaterial
        acts = seeded.build(APPS["dvwa"], AuthMaterial(declared="test", extra={"cookie": "x=1"}))
        csrf = [a for a in acts if a["kind"] == "csrf.state_change"]
        self.assertEqual(len(csrf), 1)
        probe = csrf[0]["params"].get("probe_url", "")
        self.assertTrue(probe.endswith("/vulnerabilities/csrf/"), probe)
        self.assertNotIn("password_new", probe,
                         "le banc sonderait de nouveau l'URL qui change le mot de passe admin")


if __name__ == "__main__":
    unittest.main()

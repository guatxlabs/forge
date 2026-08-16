# SPDX-License-Identifier: AGPL-3.0-or-later
"""`recon.forms` — un crawler découvre des CHEMINS, pas des PARAMÈTRES.

LE MUR MESURÉ. DVWA piste B rend **0 sur 9 classes opposables** quand la piste AMORCÉE en trouve 5.
Le jugement va bien ; c'est l'ALIMENTATION qui manque, et l'écart tient en deux lignes :

    `/vulnerabilities/sqli/` nu              ->  3 oracles, AUCUN paramètre
    `/vulnerabilities/sqli/?id=1&Submit=…`   -> 23 actions, 12 oracles

Les paramètres de DVWA — et de toute application à formulaires — vivent dans `<input name=…>`.
Forge ne savait pas les lire, donc ses oracles à injection restaient sans cible sur une surface
pourtant banale.

LE GESTE EST MINUSCULE À DESSEIN : lire les champs, reconstruire une URL PORTEUSE, déléguer au
chaînage existant. Aucun mécanisme d'injection nouveau — `inject_request` PRÉSERVE déjà les
co-paramètres depuis le défaut D6 (le `Submit` de DVWA, sans lequel la branche vulnérable est hors
d'atteinte). **Le travail d'hier porte celui d'aujourd'hui.**
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import modules as mods                                              # noqa: E402
from forge import techniques as T                                              # noqa: E402
from forge.brain import AutoPentestBrain                                       # noqa: E402
from forge.modules.form_surface import parse_forms                             # noqa: E402
from forge.roe import Action                                                   # noqa: E402

PAGE = """<html><body>
<form action="" method="GET">
  <input type="text" name="id" value="1">
  <input type="submit" name="Submit" value="Submit">
</form>
<form action="/login.php" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="user_token" value="abc123">
  <input type="submit" name="Login" value="Login">
</form>
</body></html>"""

URL = "http://app.test/vulnerabilities/sqli/"


class ReadingAForm(unittest.TestCase):

    def test_les_champs_NOMMES_sont_lus(self):
        forms = parse_forms(PAGE, URL)
        self.assertEqual(len(forms), 2)
        noms = [n for n, _v, _i in forms[0][2]]
        self.assertEqual(noms, ["id", "Submit"])

    def test_un_bouton_de_soumission_est_un_CO_PARAMETRE_pas_une_cible(self):
        """DVWA exige `Submit=Submit` pour entrer dans la branche vulnérable (défaut D6) : il doit
        VOYAGER dans l'appel, sans jamais devenir une cible d'injection."""
        champs = parse_forms(PAGE, URL)[0][2]
        submit = [(n, v, inj) for n, v, inj in champs if n == "Submit"][0]
        self.assertEqual(submit[1], "Submit", "la valeur exigée par l'application a été perdue")
        self.assertFalse(submit[2], "un bouton de soumission ne s'injecte pas")

    def test_une_action_VIDE_resout_sur_la_page_elle_meme(self):
        """`<form method=GET>` sans action poste sur sa propre URL : sinon le paramètre découvert
        n'est rattaché à rien."""
        self.assertEqual(parse_forms(PAGE, URL)[0][1], URL)

    def test_une_action_RELATIVE_est_resolue(self):
        self.assertEqual(parse_forms(PAGE, URL)[1][1], "http://app.test/login.php")

    def test_la_METHODE_est_conservee(self):
        self.assertEqual([f[0] for f in parse_forms(PAGE, URL)], ["GET", "POST"])

    def test_un_champ_cache_est_un_co_parametre_LEGITIME(self):
        """Un `user_token` est exactement ce qu'une application exige et qu'un crawler ignore."""
        noms = [n for n, _v, _i in parse_forms(PAGE, URL)[1][2]]
        self.assertIn("user_token", noms)

    def test_une_page_sans_formulaire_ne_fabrique_rien(self):
        self.assertEqual(parse_forms("<html><p>rien</p></html>", URL), [])

    def test_pur_et_ne_leve_jamais(self):
        for corps in (None, "", "<form>", "<form><input name=", "<<<>>>", "x" * 5000):
            with self.subTest(corps=str(corps)[:20]):
                parse_forms(corps, URL)


class TheModuleEmitsASurface(unittest.TestCase):

    def _fire(self, body=PAGE, status=200):
        o = mods.get("recon.forms")
        with mock.patch.object(type(o), "_get",
                               staticmethod(lambda url, headers=None, timeout=15: (status, body))):
            fs = o.fire(Action("recon.forms", URL, params={"in_scope": ["app.test"]}))
        return [f if isinstance(f, dict) else f.__dict__ for f in fs]

    def test_un_finding_par_formulaire_avec_champs(self):
        titres = [f["title"] for f in self._fire() if T.parse_form_title(f["title"])]
        self.assertEqual(len(titres), 2)

    def test_il_ne_SOUMET_rien(self):
        o = mods.get("recon.forms")
        self.assertFalse(o.exploit)
        self.assertFalse(o.destructive)
        for f in self._fire():
            self.assertEqual(f["status"], "tested")

    def test_reseau_mort_degrade_proprement(self):
        f = self._fire(body="", status=None)[0]
        self.assertIn("réseau indisponible", f["title"])

    def test_page_sans_formulaire_le_DIT(self):
        f = self._fire(body="<html></html>")[0]
        self.assertIn("Aucun formulaire", f["title"])


class TheBrainRebuildsACarryingUrl(unittest.TestCase):

    def _acts(self, champs=(("id", "1", True), ("Submit", "Submit", False))):
        f = [{"title": T.form_title("GET", list(champs)), "target": URL}]
        return AutoPentestBrain()._chain_from_forms(f)

    def test_l_URL_reconstruite_PORTE_les_champs(self):
        acts = self._acts()
        self.assertTrue(acts)
        self.assertEqual(acts[0].target, f"{URL}?id=1&Submit=Submit")

    def test_le_fan_out_passe_de_3_a_DOUZE_oracles(self):
        """LE CHIFFRE DU MUR : c'est toute la distance entre DVWA piste B et la piste amorcée."""
        nu = {a.kind for a in AutoPentestBrain()._endpoint_oracles(URL)}
        porteuse = {a.kind for a in self._acts()}
        # On compare ce que la mesure compare : le PANEL D'INJECTION. L'endpoint nu n'a que le
        # minimum qui dégrade proprement (+ `recon.forms`, qui va justement chercher les paramètres) ;
        # l'URL porteuse ouvre le panel entier. Compter les oracles bruts ferait casser ce test à
        # chaque enrichissement du chaînage sans rien protéger de plus.
        panel = {k for k, *_ in AutoPentestBrain._PARAM_INJECTION_ORACLES}
        self.assertEqual(nu & panel, set(), f"un endpoint SANS paramètre ne peut rien injecter : {nu}")
        self.assertGreaterEqual(len(porteuse & panel), 8, f"panel non ouvert : {porteuse}")

    def test_le_CO_PARAMETRE_voyage_dans_la_cible(self):
        for a in self._acts():
            self.assertIn("Submit=Submit", a.target)

    def test_la_lecture_de_formulaire_SUIT_la_decouverte(self):
        """LE MAILLON QUE LA MESURE A RÉVÉLÉ MANQUANT. `recon.forms` ne tournait que sur la RACINE
        du site — où DVWA sert un login sans champ vulnérable (« Aucun formulaire sur cette page »).
        Les formulaires qui comptent vivent sur les pages PROFONDES que la découverte vient de
        trouver. Un producteur de paramètres qui ne suit pas la découverte ne sert à rien."""
        nu = AutoPentestBrain()._endpoint_oracles("http://app.test/vulnerabilities/sqli/")
        self.assertIn("recon.forms", {a.kind for a in nu},
                      "un endpoint découvert SANS paramètre doit voir ses formulaires lus")

    def test_un_endpoint_QUI_A_DEJA_ses_parametres_ne_les_relit_pas(self):
        """Pas de travail inutile : si la query porte déjà des paramètres, il n'y a rien à lire."""
        av = AutoPentestBrain()._endpoint_oracles("http://app.test/x?id=1")
        self.assertNotIn("recon.forms", {a.kind for a in av})

    def test_un_finding_etranger_est_ignore(self):
        self.assertEqual(AutoPentestBrain()._chain_from_forms(
            [{"title": "Endpoint in-scope : http://x/y", "target": "http://x/y"}]), [])

    def test_le_fan_out_est_BORNE(self):
        gros = [{"title": T.form_title("GET", [("a", "1", True)]), "target": f"{URL}?n={i}"}
                for i in range(100)]
        acts = AutoPentestBrain()._chain_from_forms(gros)
        self.assertLessEqual(len(acts), AutoPentestBrain.MAX_FORMS_CHAINED * 30)


if __name__ == "__main__":
    unittest.main()

"""Tests hermetiques de l'oracle `cspt.redirect` — aucun reseau, aucun navigateur.

Les deux seams navigateur (`_browser_available`, `_probe`) sont remplaces par des doubles, si
bien que la suite tourne sans service et de facon deterministe.

Ce qui est epingle ici n'est pas decoratif : c'est le contrat qui separe **« pas de CSPT »** de
**« pas teste »**. Un oracle qui rend un negatif alors qu'il n'a rien pu observer est pire
qu'inutile — il clot une piste que personne ne rouvrira.
"""
from __future__ import annotations

import contextlib
import unittest

from forge.roe import Action
from forge.modules import cspt as mod
from forge.modules.cspt import CsptRedirect, canary, depth, paths_containing

TGT = "https://app.test/profile"
SCOPE = {"in_scope": ["app.test"]}


@contextlib.contextmanager
def _seams(**remplacants):
    """Remplace des seams de `CsptRedirect` et les restaure DEPUIS `__dict__`.

    Forme imposee par `test_seam_restoration.py`, et elle n'est pas pointilleuse : lire
    `cls.attr` rend la FONCTION, pas le descripteur `staticmethod`. La reposer telle quelle en
    ferait une methode d'INSTANCE, ce qui decale tous les arguments du seam — un bug qui ne se
    voit qu'au test suivant, dans un autre fichier.
    """
    sauve = {n: (n in CsptRedirect.__dict__, CsptRedirect.__dict__.get(n))
             for n in remplacants}
    for nom, fn in remplacants.items():
        setattr(CsptRedirect, nom, staticmethod(fn))
    try:
        yield
    finally:
        for nom, (avait, orig) in sauve.items():
            if avait and orig is not None:
                setattr(CsptRedirect, nom, orig)
            else:
                try:
                    delattr(CsptRedirect, nom)
                except AttributeError:
                    pass


def _fire(probe, available=True, params=None, target=TGT):
    """Tire l'oracle avec ses seams navigateur remplaces. `probe(url, token)` -> (abouti, chemins)."""
    with _seams(_browser_available=lambda: available,
                _probe=lambda url, token, tab=None: probe(url, token),
                _reset=lambda tab=None: None):
        p = dict(SCOPE, param="id")
        p.update(params or {})
        return CsptRedirect().fire(Action("cspt.redirect", target, params=p))


class TestHelpers(unittest.TestCase):

    def test_canari_deterministe_et_prefixe(self):
        a, b = canary(TGT, "id"), canary(TGT, "id")
        self.assertEqual(a, b, "le canari doit etre rejouable")
        self.assertTrue(a.startswith("forgecspt"))
        self.assertNotEqual(a, canary(TGT, "autre"), "distinct par parametre")

    def test_depth_compte_les_segments(self):
        self.assertEqual(depth("/a/b/c"), 3)
        self.assertEqual(depth("/c"), 1)
        self.assertEqual(depth("/"), 0)

    def test_paths_containing_filtre_sur_le_canari(self):
        dump = {"requests": [{"url": "https://app.test/api/u/forgecsptAAA"},
                             {"url": "https://app.test/static/app.js"}]}
        self.assertEqual(paths_containing(dump, "forgecsptAAA"), ["/api/u/forgecsptAAA"])

    def test_paths_containing_survit_a_un_schema_inconnu(self):
        # Defensif A DESSEIN : le schema de /capture-dump n'est pas fige. Un oracle qui casse au
        # premier renommage de champ ne sert personne.
        self.assertEqual(paths_containing('{"x":[{"uri":"https://app.test/z/tokAAA"}]}', "tokAAA"),
                         ["/z/tokAAA"])

    def test_inject_garde_les_points_lisibles(self):
        url = CsptRedirect._inject("https://app.test/p", "id", "../../x")
        self.assertIn("../../x", url, "encoder les '..' ou les '/' viderait le vecteur de son sens")


class TestDegradations(unittest.TestCase):
    """« Pas teste » ne doit JAMAIS etre rendu comme « pas vulnerable »."""

    def test_hors_scope_skipped_sans_navigation(self):
        appels = []

        def probe(url, token):
            appels.append(url)
            return True, []

        out = _fire(probe, target="https://evil.test/p")
        self.assertEqual(out[0].status, "skipped")
        self.assertEqual(appels, [], "fail-closed : AUCUNE navigation hors perimetre")

    def test_parametre_absent_skipped(self):
        out = _fire(lambda u, t: (True, []), params={"param": None})
        self.assertEqual(out[0].status, "skipped")

    def test_navigateur_absent_skipped_pas_negatif(self):
        out = _fire(lambda u, t: (True, []), available=False)
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("navigateur", out[0].title.lower())

    def test_sonde_non_aboutie_skipped(self):
        out = _fire(lambda u, t: (False, []))
        self.assertEqual(out[0].status, "skipped")


class TestVerdicts(unittest.TestCase):

    def _probe_pair(self, temoin_paths, trav_paths):
        """Double : distingue les deux sondes par la presence de `../` dans l'URL."""
        def probe(url, token):
            return (True, trav_paths if "../" in url else temoin_paths)
        return probe

    def test_preuve_quand_le_chemin_remonte(self):
        out = _fire(self._probe_pair(["/api/v1/users/TOK"], ["/TOK"]))
        self.assertEqual(out[0].status, "vulnerable")
        self.assertEqual(out[0].severity, "HIGH")
        self.assertIn("CSPT CONFIRME", out[0].title)

    def test_pas_de_remontee_est_un_vrai_negatif(self):
        # Meme profondeur des deux cotes : les `../` ont ete neutralises.
        out = _fire(self._probe_pair(["/api/v1/users/TOK"], ["/api/v1/users/TOK"]))
        self.assertEqual(out[0].status, "tested")

    def test_temoin_absent_ne_conclut_pas_a_une_vuln(self):
        # Le parametre n'alimente aucune requete : on ne sait pas d'ou l'on part, donc pas de preuve.
        out = _fire(self._probe_pair([], ["/TOK"]))
        self.assertEqual(out[0].status, "tested")
        self.assertNotEqual(out[0].status, "vulnerable")

    def test_traversal_absent_est_un_vrai_negatif(self):
        out = _fire(self._probe_pair(["/api/v1/users/TOK"], []))
        self.assertEqual(out[0].status, "tested")

    def test_chemin_plus_profond_n_est_pas_une_preuve(self):
        # Garde-fou : seule une REMONTEE prouve la normalisation. Un chemin plus long ne prouve rien.
        out = _fire(self._probe_pair(["/a/TOK"], ["/a/b/c/TOK"]))
        self.assertEqual(out[0].status, "tested")


class TestGardes(unittest.TestCase):

    def test_flags_declares(self):
        # exploit=True : la sonde fait emettre a l'app une requete non prevue -> le ROE doit
        # exiger allow_exploit. destructive=False : le canari est inexistant, rien n'est mute.
        self.assertTrue(CsptRedirect.exploit)
        self.assertFalse(CsptRedirect.destructive)

    def test_profondeur_bornee(self):
        appels = []

        def probe(url, token):
            appels.append(url)
            return True, []
        _fire(probe, params={"depth": 999})
        trav = [u for u in appels if "../" in u]
        self.assertTrue(trav)
        self.assertLessEqual(trav[0].count("../"), mod.MAX_DEPTH,
                             "la profondeur doit etre bornee — pas de fan-out silencieux")

    def test_canari_absent_des_routes_reelles(self):
        # Le canari ne doit jamais viser un point de service REEL : detourner vers une route
        # mutante reviendrait a agir au nom de l'utilisateur.
        self.assertTrue(canary(TGT, "id").startswith("forgecspt"))
        self.assertEqual(len(canary(TGT, "id")), len("forgecspt") + 12)


if __name__ == "__main__":
    unittest.main(verbosity=2)

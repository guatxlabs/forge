"""Tests hermetiques de `massassign.params` — aucun reseau.

TROIS CONTRATS SONT EPINGLES, et les deux derniers portent sur la sûrete plus que sur la mesure.

Le premier est la CONJONCTION : un champ n'est prouve assignable que s'il etait ABSENT de l'etat
de reference ET present a la relecture. Sans l'etat initial, une valeur observee ensuite pouvait
deja etre la — ce serait une coincidence presentee comme une preuve.

Le deuxieme est le CANARI : la valeur injectee n'a aucun pouvoir. Ecrire `admin` pour prouver
qu'on aurait pu ecrire `admin` reviendrait a s'octroyer le privilege pour demontrer qu'on aurait
pu se l'octroyer — inutile, et c'est le genre de geste qui fait fermer un programme.

Le troisieme est la RETENUE SUR LA PROPRIETE : les champs `userId`, `ownerId`, `tenantId` ne sont
JAMAIS sondes en ecriture. Les reassigner detacherait l'objet de son proprietaire legitime, et
aucune preuve ne vaut ce risque.
"""
from __future__ import annotations

import json
import unittest

from forge.roe import Action
from forge.modules import massassign as mod
from forge.modules.massassign import (MassAssignment, canari, valeur_sonde,
                                      champs_candidats, extrait_json)

TGT = "https://app.test/api/me"
BASE = {"in_scope": ["app.test"]}


def _fire(lire, ecrire=None, params=None, target=TGT):
    """Tire l'oracle avec `_get` et `_write` remplaces. `lire()` -> (status, objet)."""
    sauve = {}
    for nom in ("_get", "_write"):
        sauve[nom] = (nom in MassAssignment.__dict__, MassAssignment.__dict__.get(nom))
    ecrits = []

    def faux_get(self, action, timeout):
        return lire(len(ecrits))

    def faux_write(self, action, objet, timeout):
        ecrits.append(objet)
        return (ecrire(objet) if ecrire else 200), ""

    MassAssignment._get = faux_get
    MassAssignment._write = faux_write
    try:
        p = dict(BASE)
        p.update(params or {})
        return MassAssignment().fire(Action("massassign.params", target, params=p)), ecrits
    finally:
        for nom, (avait, orig) in sauve.items():
            if avait and orig is not None:
                setattr(MassAssignment, nom, orig)
            else:
                try:
                    delattr(MassAssignment, nom)
                except AttributeError:
                    pass


class TestCanari(unittest.TestCase):
    """La valeur injectee ne doit JAMAIS accorder un privilege."""

    def test_canari_inerte_et_rejouable(self):
        a, b = canari(TGT, "role"), canari(TGT, "role")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("forgema"))
        self.assertNotIn("admin", a.lower())

    def test_champ_texte_recoit_un_canari_pas_admin(self):
        v = valeur_sonde("role", TGT)
        self.assertTrue(str(v).startswith("forgema"))
        self.assertNotEqual(str(v).lower(), "admin")

    def test_booleens_fermes_par_defaut(self):
        # Un booleen ne peut pas porter de canari : le prouver exige un effet reel.
        for c in ("isAdmin", "verified", "enabled"):
            self.assertIsNone(valeur_sonde(c, TGT, destructif=False))
            self.assertIsNotNone(valeur_sonde(c, TGT, destructif=True))

    def test_montants_fermes_par_defaut(self):
        self.assertIsNone(valeur_sonde("balance", TGT, destructif=False))
        self.assertEqual(valeur_sonde("balance", TGT, destructif=True), 133742)

    def test_champs_de_propriete_JAMAIS_sondes(self):
        # Meme avec `destructive` : les reassigner detacherait l'objet de son proprietaire.
        for c in mod.CHAMPS_PROPRIETE:
            self.assertIsNone(valeur_sonde(c, TGT, destructif=False))
            self.assertIsNone(valeur_sonde(c, TGT, destructif=True),
                              f"« {c} » ne doit JAMAIS etre sonde en ecriture")


class TestCandidats(unittest.TestCase):

    def test_champ_deja_present_n_est_pas_candidat(self):
        # Un champ deja dans l'objet et modifiable est une FONCTIONNALITE, pas une faille.
        self.assertNotIn("role", champs_candidats({"role": "user", "name": "x"}))

    def test_champ_absent_est_candidat(self):
        self.assertIn("role", champs_candidats({"name": "x"}))

    def test_fan_out_borne(self):
        self.assertLessEqual(len(champs_candidats({}, destructif=True)), mod.MAX_CHAMPS)

    def test_extrait_json_tolere_les_enveloppes(self):
        self.assertEqual(extrait_json('{"data":{"a":1}}'), {"a": 1})
        self.assertEqual(extrait_json("pas du json"), {})


class TestDegradations(unittest.TestCase):
    """« Pas sondable » ne doit jamais etre rendu comme « pas vulnerable »."""

    def test_hors_scope(self):
        out, e = _fire(lambda n: (200, {"name": "x"}), target="https://evil.test/api/me")
        self.assertEqual(out[0].status, "skipped")
        self.assertEqual(e, [], "fail-closed : aucune ecriture hors perimetre")

    def test_reseau_indisponible(self):
        out, _ = _fire(lambda n: (None, {}))
        self.assertEqual(out[0].status, "skipped")

    def test_objet_non_json_ne_conclut_pas(self):
        out, e = _fire(lambda n: (200, {}))
        self.assertEqual(out[0].status, "skipped")
        self.assertEqual(e, [], "sans etat de reference, aucune ecriture ne doit partir")


class TestConjonction(unittest.TestCase):

    def test_persistance_prouve(self):
        etat = {"n": 0}

        def lire(n):
            if etat["n"] == 0:
                return (200, {"name": "x"})
            return (200, dict({"name": "x"}, role=canari(TGT, "role")))

        def ecrire(objet):
            etat["n"] = 1
            return 200
        out, _ = _fire(lire, ecrire)
        self.assertEqual(out[0].status, "vulnerable")
        self.assertEqual(out[0].severity, "HIGH")
        self.assertIn("role", out[0].title)

    def test_non_persiste_est_un_vrai_negatif(self):
        out, _ = _fire(lambda n: (200, {"name": "x"}))
        self.assertEqual(out[0].status, "tested")

    def test_champ_deja_la_avant_ne_prouve_pas(self):
        # Le champ etait DEJA present : sa presence a la relecture ne prouve rien.
        objet = {"name": "x", "role": canari(TGT, "role")}
        out, _ = _fire(lambda n: (200, dict(objet)))
        self.assertEqual(out[0].status, "tested")

    def test_negatif_dit_ce_qu_il_n_a_PAS_teste(self):
        # Sans `destructive`, booleens et montants ne sont pas sondes : le negatif ne porte que
        # sur les champs textuels, et doit le dire pour ne pas clore la classe a tort.
        out, _ = _fire(lambda n: (200, {"name": "x"}))
        self.assertIn("ne porte que sur les champs textuels", out[0].evidence)


class TestSurete(unittest.TestCase):

    def test_aucune_valeur_privilegiee_n_est_ecrite(self):
        out, ecrits = _fire(lambda n: (200, {"name": "x"}))
        self.assertTrue(ecrits)
        envoye = json.dumps(ecrits[0]).lower()
        for interdit in ('"admin"', '"superuser"', '"root"'):
            self.assertNotIn(interdit, envoye)

    def test_aucun_champ_de_propriete_dans_la_charge(self):
        out, ecrits = _fire(lambda n: (200, {"name": "x"}), params={"destructive": True})
        self.assertTrue(ecrits)
        for c in mod.CHAMPS_PROPRIETE:
            self.assertNotIn(c, ecrits[0], f"« {c} » ne doit jamais partir en ecriture")

    def test_l_objet_est_renvoye_entier(self):
        # On renvoie l'objet LU augmente des candidats : envoyer un objet partiel effacerait
        # des champs legitimes de l'operateur sur une API qui remplace au lieu de fusionner.
        out, ecrits = _fire(lambda n: (200, {"name": "x", "email": "a@b.c"}))
        self.assertEqual(ecrits[0].get("name"), "x")
        self.assertEqual(ecrits[0].get("email"), "a@b.c")

    def test_flags_declares(self):
        self.assertFalse(MassAssignment.exploit)
        self.assertFalse(MassAssignment.destructive)


if __name__ == "__main__":
    unittest.main(verbosity=2)

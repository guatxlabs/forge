"""Tests hermetiques de `business_logic.invariants` — aucun reseau.

CE QUI EST EN JEU. Cet oracle DERIVE ses regles de l'objet observe au lieu de les tirer d'un
catalogue. C'est sa force et son risque : une regle mal derivee produirait une fausse preuve —
on accuserait l'application de ne pas valider un invariant qu'elle n'a jamais eu.

Les tests ci-dessous epinglent donc d'abord la DERIVATION (une borne, une somme, et surtout
l'absence de regle inventee quand il n'y en a pas), puis la SÛRETE : toutes les valeurs
envoyees doivent etre INVALIDES par construction, et l'etat initial restaure.
"""
from __future__ import annotations

import json
import unittest

from forge.roe import Action
from forge.modules import bizinvariants as mod
from forge.modules.bizinvariants import (BusinessInvariants, champs_numeriques,
                                         paires_bornees, sommes_probables)

TGT = "https://app.test/api/claim/1"
BASE = {"in_scope": ["app.test"]}


def _fire(lire, ecrire=None, params=None, target=TGT):
    """Tire l'oracle avec `_get` et `_write` remplaces."""
    sauve = {}
    for nom in ("_get", "_write"):
        sauve[nom] = (nom in BusinessInvariants.__dict__, BusinessInvariants.__dict__.get(nom))
    ecrits = []

    def faux_get(self, action, timeout):
        return lire(ecrits)

    def faux_write(self, action, objet, timeout):
        ecrits.append(dict(objet))
        return (ecrire(objet) if ecrire else 200), ""

    BusinessInvariants._get = faux_get
    BusinessInvariants._write = faux_write
    try:
        p = dict(BASE)
        p.update(params or {})
        return BusinessInvariants().fire(Action("business_logic.invariants", target, params=p)), ecrits
    finally:
        for nom, (avait, orig) in sauve.items():
            if avait and orig is not None:
                setattr(BusinessInvariants, nom, orig)
            else:
                try:
                    delattr(BusinessInvariants, nom)
                except AttributeError:
                    pass


class TestDerivation(unittest.TestCase):
    """Une regle mal derivee produirait une fausse preuve : on accuserait l'application de ne
    pas valider un invariant qu'elle n'a jamais eu."""

    def test_champs_numeriques_ecarte_les_booleens(self):
        n = champs_numeriques({"a": 3, "b": 1.5, "ok": True, "nom": "x"})
        self.assertEqual(set(n), {"a", "b"})

    def test_borne_derivee_dans_le_bon_sens(self):
        # effectif=10, remboursables=4 -> l'invariant est « remboursables <= effectif ».
        p = paires_bornees({"remboursables": 4, "effectif": 10})
        self.assertIn(("remboursables", "effectif"), p)

    def test_somme_reconnue(self):
        s = sommes_probables({"total": 90, "m1": 30, "m2": 30, "m3": 30})
        self.assertTrue(s)
        self.assertEqual(s[0][0], "total")
        self.assertEqual(set(s[0][1]), {"m1", "m2", "m3"})

    def test_aucune_somme_inventee(self):
        # Rien ne s'additionne : l'oracle ne doit PAS fabriquer une regle.
        self.assertEqual(sommes_probables({"a": 7, "b": 13, "c": 41}), [])

    def test_somme_bornee_a_quatre_termes(self):
        # Au-dela, une egalite fortuite devient plus probable qu'un invariant reel.
        nums = {"total": 15, "a": 1, "b": 2, "c": 3, "d": 4, "e": 5}
        s = sommes_probables(nums)
        if s:
            self.assertLessEqual(len(s[0][1]), 4)


class TestSurete(unittest.TestCase):
    """Toutes les valeurs envoyees doivent etre INVALIDES par construction."""

    def test_les_valeurs_envoyees_sont_invalides(self):
        # Un negatif reconnaissable, jamais une valeur valide mais mensongere : declarer un
        # montant plausible et faux serait, sur une plateforme reelle, une fausse declaration.
        out, ecrits = _fire(lambda e: (200, {"montant": 100, "effectif": 10}))
        self.assertTrue(ecrits)
        negatifs = [o for o in ecrits if mod.NEGATIF in o.values()]
        self.assertTrue(negatifs, "au moins une sonde doit porter le negatif reconnaissable")

    def test_etat_restaure_apres_une_violation_persistee(self):
        etat = {"objet": {"montant": 100, "effectif": 10}}

        def lire(ecrits):
            return (200, dict(etat["objet"]))

        def ecrire(objet):
            etat["objet"] = dict(objet)      # le serveur accepte tout
            return 200
        out, ecrits = _fire(lire, ecrire)
        self.assertEqual(out[0].status, "vulnerable")
        # La derniere ecriture doit etre la remise en etat, pas une valeur invalide.
        self.assertNotIn(mod.NEGATIF, ecrits[-1].values(),
                         "l'objet de l'operateur ne doit pas rester dans un etat invalide")

    def test_fan_out_borne(self):
        out, ecrits = _fire(lambda e: (200, {f"c{i}": i + 1 for i in range(12)}))
        self.assertLessEqual(len(ecrits), mod.MAX_SONDES * 2 + 2)

    def test_flags_declares(self):
        self.assertFalse(BusinessInvariants.exploit)
        self.assertFalse(BusinessInvariants.destructive)


class TestVerdicts(unittest.TestCase):

    def test_serveur_qui_valide_est_un_vrai_negatif(self):
        # Le serveur refuse tout : l'objet lu ne change jamais.
        out, _ = _fire(lambda e: (200, {"montant": 100, "effectif": 10}))
        self.assertEqual(out[0].status, "tested")

    def test_negatif_dit_ce_qu_il_n_atteint_PAS(self):
        # Les regles d'un tunnel multi-etapes ne sont pas atteintes par cet oracle : le taire
        # ferait passer un negatif partiel pour une classe close.
        out, _ = _fire(lambda e: (200, {"montant": 100, "effectif": 10}))
        self.assertIn("multi-etapes", out[0].evidence)

    def test_sans_champ_numerique_on_ne_conclut_pas(self):
        out, ecrits = _fire(lambda e: (200, {"nom": "x"}))
        self.assertEqual(out[0].status, "skipped")
        self.assertEqual(ecrits, [], "sans invariant derivable, aucune ecriture ne part")

    def test_hors_scope(self):
        out, ecrits = _fire(lambda e: (200, {"a": 1}), target="https://evil.test/x")
        self.assertEqual(out[0].status, "skipped")
        self.assertEqual(ecrits, [])

    def test_reseau_indisponible(self):
        out, _ = _fire(lambda e: (None, {}))
        self.assertEqual(out[0].status, "skipped")


class TestComplementarite(unittest.TestCase):

    def test_les_deux_modules_coexistent(self):
        # `business_logic.scan` garde son utilite d'aide-memoire ; celui-ci fait le travail
        # automatique qui lui manquait. Les deux portent la meme classe.
        from forge import modules as mods
        kinds = set(mods.kinds())
        self.assertIn("business_logic.scan", kinds)
        self.assertIn("business_logic.invariants", kinds)


if __name__ == "__main__":
    unittest.main(verbosity=2)

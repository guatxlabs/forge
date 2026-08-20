# SPDX-License-Identifier: AGPL-3.0-or-later
"""Une ENTITÉ est un pivot, jamais une cible — et un refus doit être NOMMÉ.

CE QUI EST GARDÉ ICI. Toute la sûreté de forge est ancrée sur une IP épinglable : le ROE rend
son verdict (privé / LAN / hors-scope-par-IP) CONTRE la liste résolue. Un nom, un pseudonyme
ou un numéro n'a aucune IP — le laisser passer pour une cible, ce serait tirer sans verdict
réseau. Ces tests figent les deux sens : ce qui doit être refusé l'est, et ce qui doit
continuer de passer passe INCHANGÉ.
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

RACINE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE))

from forge import seeds                                            # noqa: E402
from forge.cli.engine import _load_targets                         # noqa: E402


class LesCiblesReseauPassentINCHANGEES(unittest.TestCase):
    """L'EXCÈS INVERSE — un filtre de refus trop large refuse du travail légitime."""

    def test_les_formes_reseau_usuelles(self):
        for brut in ("https://example.com/a", "example.com", "sub.dom.example.com",
                     "example.com:8443", "localhost:8080", "http://user@ex.com/x"):
            with self.subTest(brut=brut):
                s = seeds.normalize(brut)
                self.assertTrue(s.acceptee, f"refusé à tort : {brut}")
                self.assertEqual(s.cible, brut.casefold() if "://" not in brut else brut)

    def test_les_litteraux_IP_ne_sont_PAS_pris_pour_des_numeros(self):
        """`1.2.3.4` : chiffres et points, sept caractères — la forme d'un téléphone.

        Trouvé par sonde AVANT la première exécution réelle : le motif de téléphone testé
        avant les littéraux IP refusait une IPv4 valide. L'ordre des tests de forme est donc
        une propriété, pas un détail d'écriture."""
        for brut in ("1.2.3.4", "8.8.8.8", "192.168.1.10", "[::1]:8081", "10.0.0.1"):
            with self.subTest(brut=brut):
                s = seeds.normalize(brut)
                self.assertTrue(s.acceptee, f"IP refusée à tort : {brut}")
                self.assertEqual(s.genre, "hote")


class LEmailEstUnPivotEXPLICITE(unittest.TestCase):

    def test_un_email_donne_son_DOMAINE(self):
        """Ce comportement existait par EFFET DE BORD : `Scope._host()` retire le `userinfo`
        d'une URL, et un e-mail a la même forme. Il est ici décidé, nommé et tracé."""
        s = seeds.normalize("Alice@Example.COM")
        self.assertEqual((s.genre, s.cible), ("email", "example.com"))

    def test_la_partie_locale_ne_survit_PAS_dans_la_cible(self):
        self.assertNotIn("alice", seeds.normalize("alice@example.com").cible)


class LesENTITESdePersonneSontRefuseesNOMMEMENT(unittest.TestCase):

    def test_nom_pseudonyme_telephone(self):
        for brut in ("Alice Martin", "@alice_m", "+33612345678", "+33 6 12 34 56 78", ""):
            with self.subTest(brut=brut):
                s = seeds.normalize(brut)
                self.assertFalse(s.acceptee, f"accepté à tort : {brut!r}")
                self.assertTrue(s.motif.strip(), "refus sans raison écrite")

    def test_le_refus_dit_QUOI_FAIRE(self):
        """Un refus qui n'indique pas la sortie fait conclure « l'outil est cassé »."""
        motif = seeds.normalize("@alice_m").motif
        self.assertIn("scope", motif.lower())
        self.assertIn("IP", motif)


class LeRefusTombeALENTREE(unittest.TestCase):
    """Trois couches plus bas, l'absence d'IP ressemblerait à « rien trouvé »."""

    def _fichier(self, cibles):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(cibles, f)
        f.close()
        return f.name

    def test_une_entite_fait_echouer_le_CHARGEMENT(self):
        with self.assertRaises(SystemExit) as ctx:
            _load_targets(self._fichier([{"host": "Alice Martin"}]))
        self.assertIn("targets[0]", str(ctx.exception))

    def test_un_email_est_PIVOTÉ_et_son_origine_TRACÉE(self):
        cibles = _load_targets(self._fichier([{"host": "alice@example.com"}]))
        self.assertEqual(cibles[0].host, "example.com")
        self.assertEqual(cibles[0].attrs.get("seed"), "alice@example.com")

    def test_une_cible_reseau_reste_BYTE_IDENTIQUE(self):
        """Sans quoi la normalisation serait un changement de comportement déguisé."""
        cibles = _load_targets(self._fichier([{"host": "example.com", "kind": "app",
                                               "attrs": {"note": "x"}}]))
        self.assertEqual((cibles[0].host, cibles[0].kind, cibles[0].attrs),
                         ("example.com", "app", {"note": "x"}))


if __name__ == "__main__":
    unittest.main()

"""Tests hermetiques de `ormleak.filter` — aucun reseau.

DEUX CONTRATS SONT EPINGLES ICI, et le second est le plus important.

Le premier est la CONJONCTION : la preuve exige un discriminant etabli sur une donnee connue,
un champ non expose accepte comme critere, ET une discrimination sur ce champ. Aucune des trois
observations ne suffit seule — un serveur qui repond pareil a tout n'a pas de fuite, il n'a pas
d'oracle pour la mesurer, et confondre les deux clot une piste a tort.

Le second est la RETENUE : l'oracle doit prouver la primitive SANS jamais deduire un caractere
du secret. Un test verifie explicitement qu'aucune sonde ne balaie un alphabet — c'est la ligne
qui separe la demonstration de l'exfiltration de donnees d'autrui.
"""
from __future__ import annotations

import json
import unittest

from forge.roe import Action
from forge.modules import ormleak as mod
from forge.modules.ormleak import OrmLeak, discernables, _empreinte

TGT = "https://app.test/api/search"
BASE = {"in_scope": ["app.test"], "known_field": "city", "known_value": "Paris"}


def _fire(repondre, params=None, target=TGT):
    """Tire l'oracle avec `_send` remplace. `repondre(corps) -> empreinte`."""
    avait = "_send" in OrmLeak.__dict__
    orig = OrmLeak.__dict__.get("_send")

    def faux(self, action, corps, timeout):
        return repondre(corps)

    OrmLeak._send = faux
    try:
        p = dict(BASE)
        p.update(params or {})
        return OrmLeak().fire(Action("ormleak.filter", target, params=p))
    finally:
        if avait and orig is not None:
            OrmLeak._send = orig
        else:
            try:
                delattr(OrmLeak, "_send")
            except AttributeError:
                pass


def _rep(discrimine_connu=True, champs_ouverts=(), refuse_autres=True):
    """Fabrique une reponse simulee. `champs_ouverts` = champs sensibles qui discriminent."""
    def r(corps):
        d = json.loads(corps)
        f = d["filters"][0]
        champ, val = f["property"], str(f["value"])
        if champ == "city":
            if not discrimine_connu:
                return _empreinte(200, "constant")
            return _empreinte(200, "resultat" if val == "Paris" else "")
        if champ in champs_ouverts:
            return _empreinte(200, "resultat" if val == "a" else "")
        return _empreinte(400, "") if refuse_autres else _empreinte(200, "constant")
    return r


class TestHelpers(unittest.TestCase):

    def test_empreinte_ne_porte_pas_le_corps(self):
        # L'empreinte doit etre une SIGNATURE, pas un extrait : un finding ne doit jamais
        # transporter le contenu de reponses qui portent des donnees reelles.
        e = _empreinte(200, "donnee sensible de production")
        self.assertNotIn("sensible", str(e))
        self.assertEqual(e[0], 200)

    def test_discernables(self):
        self.assertTrue(discernables(_empreinte(200, "a"), _empreinte(200, "bb")))
        self.assertFalse(discernables(_empreinte(200, "a"), _empreinte(200, "a")))

    def test_gabarit_par_defaut_est_la_forme_rencontree_en_vrai(self):
        corps = OrmLeak()._filtre(Action("ormleak.filter", TGT, params={}), "x", "Equals", "v")
        d = json.loads(corps)
        self.assertEqual(d["filters"][0], {"property": "x", "type": "Equals", "value": "v"})

    def test_gabarit_personnalise(self):
        a = Action("ormleak.filter", TGT,
                   params={"filter_template": '{"where":{"{field}__{op}":"{value}"}}'})
        self.assertEqual(json.loads(OrmLeak()._filtre(a, "pwd", "startswith", "a")),
                         {"where": {"pwd__startswith": "a"}})


class TestDegradations(unittest.TestCase):
    """« Pas mesurable » ne doit jamais etre rendu comme « pas vulnerable »."""

    def test_hors_scope(self):
        appels = []
        _fire(lambda c: (appels.append(c), _empreinte(200, "x"))[1], target="https://evil.test/s")
        self.assertEqual(appels, [], "fail-closed : aucune requete hors perimetre")

    def test_config_manquante(self):
        out = _fire(lambda c: _empreinte(200, "x"), params={"known_field": None})
        self.assertEqual(out[0].status, "skipped")

    def test_reseau_indisponible(self):
        out = _fire(lambda c: _empreinte(None, ""))
        self.assertEqual(out[0].status, "skipped")

    def test_sans_discriminant_on_ne_conclut_pas(self):
        # Le serveur repond pareil a tout : ce n'est PAS « pas de fuite », c'est « pas d'oracle
        # pour la mesurer ». Confondre les deux clot une piste a tort.
        out = _fire(_rep(discrimine_connu=False, champs_ouverts=("password",)))
        self.assertEqual(out[0].status, "tested")
        self.assertIn("ne se distinguent pas", out[0].title)


class TestConjonction(unittest.TestCase):

    def test_champs_sensibles_refuses_est_un_vrai_negatif(self):
        out = _fire(_rep(champs_ouverts=()))
        self.assertEqual(out[0].status, "tested")
        self.assertIn("refuses", out[0].title)

    def test_champ_sensible_ouvert_prouve(self):
        out = _fire(_rep(champs_ouverts=("password",)))
        self.assertEqual(out[0].status, "vulnerable")
        self.assertEqual(out[0].severity, "HIGH")
        self.assertIn("password", out[0].title)

    def test_champ_accepte_mais_non_discriminant_ne_prouve_pas(self):
        # Accepte (200) mais reponse constante : aucun bit ne sort, donc pas de fuite.
        out = _fire(_rep(champs_ouverts=(), refuse_autres=False))
        self.assertEqual(out[0].status, "tested")

    def test_plusieurs_champs_sont_listes(self):
        out = _fire(_rep(champs_ouverts=("password", "token")))
        self.assertEqual(out[0].status, "vulnerable")
        self.assertIn("password", out[0].title)
        self.assertIn("token", out[0].title)


class TestRetenue(unittest.TestCase):
    """La ligne a ne pas franchir : prouver qu'on peut lire n'exige pas de lire."""

    def test_aucune_extraction_caractere_par_caractere(self):
        vus = []

        def r(corps):
            vus.append(json.loads(corps)["filters"][0])
            return _rep(champs_ouverts=("password",))(corps)
        out = _fire(r)
        self.assertEqual(out[0].status, "vulnerable")
        # Sur un champ sensible, DEUX sondes exactement : jamais un balayage d'alphabet.
        pwd = [f for f in vus if f["property"] == "password"]
        self.assertEqual(len(pwd), 2, "un balayage d'alphabet exfiltrerait la donnee d'autrui")
        self.assertEqual({str(f["value"]) for f in pwd}, {"a", "zz9forge"})

    def test_le_fan_out_est_borne(self):
        vus = []

        def r(corps):
            vus.append(json.loads(corps)["filters"][0]["property"])
            return _rep(champs_ouverts=())(corps)
        _fire(r)
        sensibles = [c for c in vus if c != "city"]
        self.assertLessEqual(len(set(sensibles)), mod.MAX_FIELD_PROBES)

    def test_la_preuve_renvoie_l_extraction_au_rapport(self):
        out = _fire(_rep(champs_ouverts=("password",)))
        self.assertIn("AUCUN caractere", out[0].evidence)
        self.assertIn("accord du programme", out[0].evidence)


class TestGardes(unittest.TestCase):

    def test_flags_declares(self):
        # Lectures seules, aucune donnee deduite -> ni exploit ni destructif.
        self.assertFalse(OrmLeak.exploit)
        self.assertFalse(OrmLeak.destructive)

    def test_classe_rattachee_au_controle_d_acces(self):
        # Une fuite par filtre EST une lecture non autorisee. Lui donner une classe neuve la
        # sortirait du plancher anti-famine qui protege deja `access_control` dans le planner.
        self.assertEqual(OrmLeak.category, "access_control")


if __name__ == "__main__":
    unittest.main(verbosity=2)

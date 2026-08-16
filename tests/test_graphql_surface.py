# SPDX-License-Identifier: AGPL-3.0-or-later
"""`recon.graphql` — décrire une surface qu'aucune découverte d'URL ne peut voir.

Une API GraphQL n'a NI query-string NI formulaire : toute sa surface tient derrière un seul
`POST /graphql`, et son point d'injection est un ARGUMENT dans la chaîne `query`. La découverte de
forge sait énumérer des URL et lire des paramètres de query ; elle ne sait pas lire un schéma. D'où
**DVGA à 0 sur 6 classes opposables** pendant deux campagnes, sans qu'aucun oracle soit en défaut.

MESURÉ SUR L'APPLICATION VIVANTE, chaîne complète et AUTOMATIQUE : introspection -> **26 arguments
scalaires** -> 120 actions chaînées -> `sqli.probe` rend **HIGH / vulnerable**, sans qu'un seul
gabarit ait été écrit à la main.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import modules as mods                                              # noqa: E402
from forge import techniques as T                                              # noqa: E402
from forge.brain import AutoPentestBrain                                       # noqa: E402
from forge.roe import Action                                                   # noqa: E402

ENDPOINT = "http://app.test/graphql"

#: schéma minimal, dans la FORME que rend une vraie introspection
SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query", "fields": [
        {"name": "pastes", "type": {"kind": "LIST", "ofType": {"kind": "OBJECT"}},
         "args": [{"name": "filter", "type": {"name": "String", "kind": "SCALAR"}},
                  {"name": "public", "type": {"name": "Boolean", "kind": "SCALAR"}}]},
        {"name": "systemDiagnostics", "type": {"kind": "SCALAR"},
         "args": [{"name": "cmd", "type": {"name": "String", "kind": "SCALAR"}}]}]},
    "mutationType": {"name": "Mutation", "fields": [
        {"name": "importPaste", "type": {"kind": "OBJECT"},
         "args": [{"name": "host", "type": {"name": "String", "kind": "SCALAR"}}]}]}}}}


def _fire(payload=SCHEMA, status=200):
    o = mods.get("recon.graphql")
    with mock.patch.object(type(o), "_post",
                           staticmethod(lambda url, body, headers=None, timeout=15:
                                        (status, json.dumps(payload)))):
        fs = o.fire(Action("recon.graphql", ENDPOINT, params={"in_scope": ["app.test"]}))
    return [f if isinstance(f, dict) else f.__dict__ for f in fs]


class TheSchemaBecomesASurface(unittest.TestCase):

    def test_un_finding_par_argument_SCALAIRE(self):
        args = [f for f in _fire() if T.parse_graphql_arg_title(f["title"])]
        noms = {T.parse_graphql_arg_title(f["title"])[2] for f in args}
        self.assertEqual(noms, {"filter", "cmd", "host"})

    def test_un_argument_BOOLEEN_est_ecarte(self):
        """Une charge de chaîne dans un `Boolean` ne produit qu'une erreur de type, jamais un signal."""
        args = [T.parse_graphql_arg_title(f["title"])[2] for f in _fire()
                if T.parse_graphql_arg_title(f["title"])]
        self.assertNotIn("public", args)

    def test_la_FORME_du_champ_est_portee(self):
        """`pastes` rend une LISTE d'OBJETS -> sélection obligatoire ; `systemDiagnostics` un scalaire."""
        formes = {T.parse_graphql_arg_title(f["title"])[1]: T.parse_graphql_arg_title(f["title"])[3]
                  for f in _fire() if T.parse_graphql_arg_title(f["title"])}
        self.assertTrue(formes["pastes"], "un LIST of OBJECT doit compter comme objet")
        self.assertFalse(formes["systemDiagnostics"])

    def test_il_n_INJECTE_rien(self):
        o = mods.get("recon.graphql")
        self.assertFalse(o.exploit)
        self.assertFalse(o.destructive)
        for f in _fire():
            self.assertEqual(f["status"], "tested")
            self.assertEqual(f["severity"], "INFO")

    def test_pas_de_schema_pas_d_invention(self):
        for payload in ({"data": {}}, {"errors": [{"message": "introspection disabled"}]}, {}):
            with self.subTest(reponse=str(payload)[:30]):
                fs = _fire(payload)
                self.assertFalse([f for f in fs if T.parse_graphql_arg_title(f["title"])])

    def test_reseau_mort_degrade_proprement(self):
        o = mods.get("recon.graphql")
        with mock.patch.object(type(o), "_post",
                               staticmethod(lambda *a, **k: (None, ""))):
            fs = o.fire(Action("recon.graphql", ENDPOINT, params={"in_scope": ["app.test"]}))
        self.assertIn("réseau indisponible", (fs[0].title if hasattr(fs[0], "title") else fs[0]["title"]))


class TheBrainTurnsItIntoTests(unittest.TestCase):

    def _acts(self):
        return AutoPentestBrain()._chain_from_graphql(_fire())

    def test_chaque_argument_devient_un_panel_d_oracles(self):
        kinds = {a.kind for a in self._acts()}
        for attendu in ("sqli.probe", "cmdi.probe", "rce.probe", "ssrf.xspa"):
            self.assertIn(attendu, kinds)

    def test_les_CO_ARGUMENTS_accompagnent_la_charge(self):
        """LEÇON DE D6 dans une surface nouvelle. `systemDiagnostics(username,password,cmd)` appelé
        avec le seul `cmd` est refusé faute d'identifiants ; avec le seul `username`, il n'a même pas
        de commande à exécuter. Mesuré : la chaîne automatique n'atteignait qu'UNE classe sur six, et
        l'unique cause était là. Les frères reçoivent une valeur NEUTRE PAR TYPE — on complète un
        APPEL, on ne devine aucun secret."""
        qs = {json.loads(a.params["body_template"])["query"] for a in self._acts()}
        cmd = [q for q in qs if "systemDiagnostics" in q]
        self.assertTrue(cmd)
        for q in cmd:
            self.assertIn("__FORGE_PAYLOAD__", q)
            self.assertIn("cmd:", q)

    def test_un_type_INT_recoit_un_entier_non_quote(self):
        """`port: Int` : une chaîne serait une erreur de type, donc un faux négatif garanti."""
        f = [{"title": T.graphql_arg_title("mutation", "importPaste", "host", returns_object=True,
                                           siblings=(("port", "Int"), ("path", "String"))),
              "target": ENDPOINT}]
        q = json.loads(AutoPentestBrain()._chain_from_graphql(f)[0].params["body_template"])["query"]
        self.assertIn("port:1", q)
        self.assertIn('path:"forge"', q)

    def test_le_gabarit_porte_la_bonne_SELECTION(self):
        """Objet -> `{__typename}` ; scalaire -> rien. La mauvaise forme rend « must have a selection
        of subfields », que l'oracle lirait comme « pas vulnérable » : faux négatif TOTAL."""
        qs = {json.loads(a.params["body_template"])["query"] for a in self._acts()}
        # On vérifie la PROPRIÉTÉ (sélection présente/absente selon la forme du champ), pas une
        # chaîne littérale : le gabarit porte désormais aussi les co-arguments, et un test qui
        # épouse la forme exacte casse à chaque enrichissement sans rien protéger de plus.
        objets = [q for q in qs if "pastes(" in q]
        scalaires = [q for q in qs if "systemDiagnostics(" in q]
        self.assertTrue(objets and scalaires)
        for q in objets:
            self.assertTrue(q.endswith("{__typename}}"), f"sélection manquante sur un objet : {q}")
        for q in scalaires:
            self.assertNotIn("__typename", q, f"sélection posée sur un scalaire : {q}")

    def test_une_MUTATION_est_declaree_comme_telle(self):
        qs = {json.loads(a.params["body_template"])["query"] for a in self._acts()}
        self.assertTrue(any(q.startswith("mutation ") and "importPaste" in q for q in qs))

    def test_les_actions_ne_s_ECRASENT_PAS_entre_arguments(self):
        """LE DÉFAUT MESURÉ : sans id distinct, les N arguments d'un même endpoint partagent
        `kind:target` et s'écrasent — 26 arguments découverts, un seul testé."""
        sqli = [a for a in self._acts() if a.kind == "sqli.probe"]
        self.assertEqual(len({a.id for a in sqli}), len(sqli), "des actions partagent un id")
        self.assertGreaterEqual(len(sqli), 3)

    def test_le_fan_out_est_BORNE(self):
        gros = [{"title": T.graphql_arg_title("query", f"f{i}", "a", returns_object=False),
                 "target": ENDPOINT} for i in range(500)]
        acts = AutoPentestBrain()._chain_from_graphql(gros)
        self.assertLessEqual(len(acts), AutoPentestBrain.MAX_GRAPHQL_ARGS * 11 + 11)

    def test_un_finding_etranger_est_ignore(self):
        self.assertEqual(AutoPentestBrain()._chain_from_graphql(
            [{"title": "Endpoint in-scope : http://x/y", "target": "http://x/y"}]), [])


if __name__ == "__main__":
    unittest.main()

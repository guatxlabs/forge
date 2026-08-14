# SPDX-License-Identifier: AGPL-3.0-or-later
"""Les oracles d'injection atteignent-ils VRAIMENT un argument GraphQL ?

`inject_request` sait désormais écrire un corps à gabarit — mais savoir écrire ne sert à rien si
aucun appelant ne le lui demande. Ce fichier vérifie le CHEMIN COMPLET : `action.params` ->
oracle -> `inject_request` -> corps réellement envoyé au serveur. C'est la différence entre « la
plomberie existe » et « la capacité existe ».

RAPPEL DU CHIFFRE QUI JUSTIFIE CE CHEMIN : DVGA rend 0 sur 6 classes opposables, toutes derrière un
seul `POST /graphql` dont le point d'injection est un argument DANS la chaîne `query`. Aucun de ces
oracles n'était en défaut — ils ne pouvaient simplement pas écrire à cet endroit.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import modules as mods                                              # noqa: E402
from forge.modules.oracle import Oracle                                        # noqa: E402
from forge.roe import Action                                                   # noqa: E402

SLOT = Oracle.PAYLOAD_SLOT
ENDPOINT = "http://app.test/graphql"
HDR = {"Content-Type": "application/json"}


def _tmpl(query):
    return json.dumps({"query": query})


class _Capture:
    """Remplace le seam `_fetch` de l'oracle et retient tout ce qui part sur le réseau."""

    def __init__(self, status=200, body="{}"):
        self.calls = []
        self._status, self._body = status, body

    def __call__(self, url, headers=None, timeout=15, method="GET", data=None, **kw):
        self.calls.append({"url": url, "method": method, "data": data, "headers": headers})
        return (self._status, self._body)

    def bodies(self):
        return [c["data"] for c in self.calls if c["data"]]


def _fire(kind, params, cap):
    o = mods.get(kind)
    with mock.patch.object(type(o), "_fetch", staticmethod(cap)):
        o.fire(Action(kind, ENDPOINT, params={"in_scope": ["app.test"], **params}))
    return cap


class InjectionOraclesReachAGraphqlArgument(unittest.TestCase):

    def test_sqli_vise_l_argument_filter(self):
        cap = _fire("sqli.probe", {
            "param": "filter", "method": "POST", "headers": HDR,
            "body_template": _tmpl('{pastes(filter:"%s"){id}}' % SLOT)}, _Capture())
        self.assertTrue(cap.bodies(), "aucun corps émis : l'oracle n'a rien tiré")
        for raw in cap.bodies():
            q = json.loads(raw)["query"]                      # corps JSON toujours valide
            self.assertIn("pastes(filter:", q, f"la charge n'a pas atterri dans l'argument : {q}")

    def test_rce_vise_l_argument_cmd(self):
        cap = _fire("rce.probe", {
            "param": "cmd", "method": "POST", "headers": HDR,
            "body_template": _tmpl('{systemDiagnostics(cmd:"%s")}' % SLOT)}, _Capture())
        self.assertTrue(cap.bodies())
        for raw in cap.bodies():
            self.assertIn("systemDiagnostics(cmd:", json.loads(raw)["query"])

    def test_ssrf_vise_l_argument_host(self):
        cap = _fire("ssrf.xspa", {
            "param": "host", "method": "POST", "headers": HDR,
            "body_template": _tmpl('{importPaste(host:"%s",port:80,path:"/")}' % SLOT)}, _Capture())
        self.assertTrue(cap.bodies())
        for raw in cap.bodies():
            self.assertIn("importPaste(host:", json.loads(raw)["query"])

    def test_le_corps_reste_TOUJOURS_un_JSON_valide(self):
        """Sur TOUTES les charges de l'oracle, pas seulement la première — c'est là qu'un
        échappement partiel se voit : une seule charge à guillemet suffit à casser le corps."""
        for kind, tmpl, param in (
                ("sqli.probe", '{pastes(filter:"%s"){id}}' % SLOT, "filter"),
                ("rce.probe", '{systemDiagnostics(cmd:"%s")}' % SLOT, "cmd")):
            with self.subTest(kind=kind):
                cap = _fire(kind, {"param": param, "method": "POST", "headers": HDR,
                                   "body_template": _tmpl(tmpl)}, _Capture())
                for raw in cap.bodies():
                    json.loads(raw)                            # lève -> échec

    def test_l_URL_reste_l_endpoint_graphql(self):
        """Un gabarit décrit un CORPS : l'URL ne doit pas gagner de query-string parasite."""
        cap = _fire("sqli.probe", {
            "param": "filter", "method": "POST", "headers": HDR,
            "body_template": _tmpl('{pastes(filter:"%s"){id}}' % SLOT)}, _Capture())
        for c in cap.calls:
            self.assertEqual(c["url"], ENDPOINT)


class WithoutATemplateNothingChanges(unittest.TestCase):

    def test_la_forme_urlencodee_historique_est_intacte(self):
        cap = _fire("sqli.probe", {"param": "id", "method": "POST"}, _Capture())
        self.assertTrue(cap.bodies())
        for raw in cap.bodies():
            self.assertTrue(raw.startswith("id="), f"corps historique altéré : {raw}")

    def test_le_GET_historique_est_intact(self):
        cap = _Capture()
        o = mods.get("sqli.probe")
        with mock.patch.object(type(o), "_fetch", staticmethod(cap)):
            o.fire(Action("sqli.probe", "http://app.test/x?id=1",
                          params={"in_scope": ["app.test"], "param": "id"}))
        self.assertTrue(cap.calls)
        for c in cap.calls:
            self.assertIsNone(c["data"])
            self.assertIn("id=", c["url"])


if __name__ == "__main__":
    unittest.main()

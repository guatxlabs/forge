# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hôte NU et port séparé — la forme que `ssrf.xspa` ne savait pas produire.

MESURÉ sur DVGA. `importPaste(host: String, port: Int)` déclare l'hôte et le port SÉPARÉMENT.
L'oracle poussait son URL complète dans l'unique créneau de charge, et le serveur composait
`http://http://127.0.0.1:5013:5013/` -> **12 × `Could not resolve host: http`** dans le journal du
conteneur. La SSRF était ATTEINTE (13 `curl` internes le prouvent) et le signal ILLISIBLE : l'oracle
concluait « les 12 réponses sont identiques, rien à mesurer ».

Un créneau de port (`Oracle.PORT_SLOT`) suffit à rendre la forme exprimable. `inject_request` ne le
connaît pas : c'est l'oracle qui FAIT VARIER le port qui le remplit — chacun sa compétence.

APRÈS CORRECTIF, sur l'application vivante : **MEDIUM / vulnerable — XSPA CONFIRMÉ**, différentiel
`5013:diff(HTTP None, 8.232s)` contre une baseline fermée à `HTTP 200, 0.134s`, contrôle négatif passé.
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

S, P = Oracle.PAYLOAD_SLOT, Oracle.PORT_SLOT
TMPL = json.dumps({"query": 'mutation{importPaste(host:"%s",port:%s,path:"/"){result}}' % (S, P)})
TMPL_SANS_PORT = json.dumps({"query": 'mutation{importPaste(url:"%s"){result}}' % S})


def _sent(template, ports=(80, 5013)):
    out = []
    o = mods.get("ssrf.xspa")

    def spy(url, headers=None, timeout=15, method="GET", data=None, **kw):
        out.append(data)
        return (200, "{}")

    with mock.patch.object(type(o), "_fetch", staticmethod(spy)):
        o.fire(Action("ssrf.xspa", "http://127.0.0.1:5013/graphql", params={
            "in_scope": ["127.0.0.1:5013"], "param": "host", "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "ports": list(ports), "body_template": template}))
    return [json.loads(d)["query"] for d in out if d]


class TheHostIsBareAndThePortIsItsOwn(unittest.TestCase):

    def test_l_hote_injecte_est_NU(self):
        for q in _sent(TMPL):
            self.assertIn('host:"127.0.0.1"', q, f"une URL complète a été poussée dans l'hôte : {q}")
            self.assertNotIn("http://http", q, "la faute mesurée sur DVGA est revenue")

    def test_le_port_VARIE_dans_son_creneau(self):
        qs = _sent(TMPL, ports=(80, 5013))
        vus = {q.split("port:")[1].split(",")[0] for q in qs}
        for attendu in ("80", "5013"):
            self.assertIn(attendu, vus, f"le port {attendu} n'a jamais été sondé : {vus}")
        self.assertGreaterEqual(len(vus), 3, "les baselines fermées doivent varier elles aussi")

    def test_aucun_creneau_ne_survit_dans_ce_qui_part(self):
        for q in _sent(TMPL):
            self.assertNotIn(P, q)
            self.assertNotIn(S, q)

    def test_le_port_reste_un_ENTIER_non_quote(self):
        """`port: Int` en GraphQL : un port entre guillemets serait une erreur de type, pas une sonde."""
        for q in _sent(TMPL):
            self.assertNotIn('port:"', q, f"port passé comme chaîne : {q}")


class WithoutAPortSlotNothingChanges(unittest.TestCase):

    def test_le_gabarit_SANS_creneau_de_port_recoit_l_URL_COMPLETE(self):
        """Chemin historique : une surface qui prend une URL doit continuer d'en recevoir une."""
        qs = _sent(TMPL_SANS_PORT)
        self.assertTrue(qs)
        for q in qs:
            self.assertIn("http://127.0.0.1:", q, f"l'URL complète a été perdue : {q}")

    def test_sans_gabarit_du_tout_la_forme_urlencodee_demeure(self):
        out = []
        o = mods.get("ssrf.xspa")

        def spy(url, headers=None, timeout=15, method="GET", data=None, **kw):
            out.append((url, data))
            return (200, "ok")

        with mock.patch.object(type(o), "_fetch", staticmethod(spy)):
            o.fire(Action("ssrf.xspa", "http://127.0.0.1:5013/fetch",
                          params={"in_scope": ["127.0.0.1:5013"], "param": "url", "ports": [80]}))
        self.assertTrue(out)
        for url, _d in out:
            self.assertIn("url=http", url, f"forme historique altérée : {url}")


if __name__ == "__main__":
    unittest.main()

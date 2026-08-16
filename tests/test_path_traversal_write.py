# SPDX-License-Identifier: AGPL-3.0-or-later
"""Traversée en ÉCRITURE — prouver ce que la lecture ne peut pas prouver.

MESURÉ sur DVGA. `uploadPaste(filename:"../../x", content:…)` écrit un fichier arbitraire et ne rend
RIEN à lire. L'oracle, qui prouvait une LECTURE (« le canari revient dans la réponse »), rendait
« le canari bénin n'est pas revenu » — un verdict EXACT sur une question qui n'était pas celle de la
cible. **Mauvais primitif, pas mauvais jugement** : le même piège que `ssrf.xspa` poussant une URL
complète dans un argument attendant un hôte nu.

Prouver une écriture EXIGE un canal de RELECTURE, et seul l'opérateur peut le nommer : rien dans une
réponse d'upload ne dit où le fichier a atterri. `params.read_url` l'apporte. Sans lui, la question
reste sans réponse — ce qui vaut mieux qu'une réponse inventée.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import modules as mods                                              # noqa: E402
from forge.roe import Action                                                   # noqa: E402

TARGET = "http://app.test/upload"
READ = "http://app.test/files/forge-canary.txt"
MARK = "FORGE_WRITE_CANARY_4T8"


def _fire(read_url=None, relecture_rend=""):
    """Joue l'oracle. `relecture_rend` = corps servi par `read_url` ; la réponse au TIR est vide,
    comme le fait un upload."""
    vus = {"tirs": 0, "relectures": 0}
    o = mods.get("path.traversal")

    def fake_fetch(url, headers=None, timeout=15, method="GET", data=None, **kw):
        if read_url and url == read_url:
            vus["relectures"] += 1
            return (200, relecture_rend)
        vus["tirs"] += 1
        return (200, '{"data":{"uploadPaste":{"result":"ok"}}}')

    params = {"in_scope": ["app.test"], "param": "filename", "canary_marker": MARK,
              "canary_name": "forge-canary.txt"}
    if read_url:
        params["read_url"] = read_url
    with mock.patch.object(type(o), "_fetch", staticmethod(fake_fetch)):
        f = o.fire(Action("path.traversal", TARGET, params=params))[0]
    return (f if isinstance(f, dict) else f.__dict__), vus


class AWriteIsProvenByReadingItBack(unittest.TestCase):

    def test_le_marqueur_relu_PROUVE_la_traversee(self):
        f, vus = _fire(read_url=READ, relecture_rend=f"contenu {MARK} fin")
        self.assertEqual(f["status"], "vulnerable")
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("ÉCRITURE", f["title"])
        self.assertGreaterEqual(vus["relectures"], 1, "aucune relecture émise")

    def test_sans_relecture_reussie_AUCUN_verdict_positif(self):
        """Le fichier a peut-être été écrit — mais rien ne dit OÙ. On ne promeut pas."""
        f, _v = _fire(read_url=READ, relecture_rend="404 not found")
        self.assertEqual(f["status"], "tested")
        self.assertIn("n'est pas relisible", f["title"])

    def test_le_canal_de_relecture_est_NOMME_dans_la_preuve(self):
        f, _v = _fire(read_url=READ, relecture_rend=f"{MARK}")
        self.assertIn(READ, f["evidence"])
        self.assertIn("écriture", f["evidence"])

    def test_la_reponse_au_TIR_ne_suffit_pas(self):
        """Un upload qui répond « ok » ne prouve rien : le marqueur doit venir de la RELECTURE."""
        o = mods.get("path.traversal")

        def fetch_qui_echo_le_marqueur(url, headers=None, timeout=15, method="GET", data=None, **kw):
            # le TIR renvoie le marqueur (echo), la RELECTURE non
            return (200, MARK) if url != READ else (200, "vide")

        with mock.patch.object(type(o), "_fetch", staticmethod(fetch_qui_echo_le_marqueur)):
            f = o.fire(Action("path.traversal", TARGET, params={
                "in_scope": ["app.test"], "param": "filename", "canary_marker": MARK,
                "read_url": READ}))[0]
        f = f if isinstance(f, dict) else f.__dict__
        self.assertEqual(f["status"], "tested", "un echo du tir a été pris pour une écriture")


class TheReadModeIsUntouched(unittest.TestCase):
    """Sans `read_url` — c'est-à-dire pour TOUS les appels d'aujourd'hui — rien ne bouge."""

    def test_le_mode_LECTURE_historique_promeut_toujours(self):
        f, vus = _fire(read_url=None)
        self.assertEqual(f["status"], "tested")           # la réponse au tir ne porte pas le marqueur
        self.assertEqual(vus["relectures"], 0, "une relecture a été émise sans read_url")

    def test_le_marqueur_dans_la_REPONSE_prouve_la_lecture(self):
        o = mods.get("path.traversal")
        with mock.patch.object(type(o), "_fetch",
                               staticmethod(lambda url, **kw: (200, f"root:x:0:0 {MARK}"))):
            f = o.fire(Action("path.traversal", TARGET, params={
                "in_scope": ["app.test"], "param": "file", "canary_marker": MARK}))[0]
        f = f if isinstance(f, dict) else f.__dict__
        self.assertEqual(f["status"], "vulnerable")
        self.assertIn("lecture", f["title"])

    def test_config_manquante_reste_un_skip(self):
        o = mods.get("path.traversal")
        f = o.fire(Action("path.traversal", TARGET, params={"in_scope": ["app.test"]}))[0]
        f = f if isinstance(f, dict) else f.__dict__
        # `skipped`, pas `tested` : une config manquante est une ABSTENTION, pas un verdict —
        # c'est le tout premier correctif de cette série (1 750 findings qui mentaient).
        self.assertEqual(f["status"], "skipped")
        self.assertIn("config manquante", f["title"])


if __name__ == "__main__":
    unittest.main()

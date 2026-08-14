# SPDX-License-Identifier: AGPL-3.0-or-later
"""Un même engagement bride-t-il pareil selon la porte d'entrée ?

Le débit de l'engagement était posé dans `Engine._prepare` — c'est-à-dire sur le chemin CAMPAGNE
seulement. Mesuré : `_prepare` -> `params.rate = 5` ; `forge run --actions` -> `None`. Les actions
tiraient donc SANS lissage par-action et, pour les outils, SANS drapeau de débit.

C'est la forme EXACTE du défaut D10, déjà corrigé pour le contexte d'auth : celui-ci ne vivait lui
aussi que dans `_prepare`, et `forge run --actions` rendait « IDOR non testé — config manquante »
avec un `scope.auth` pourtant complet. Deux portes d'entrée, deux comportements, un seul scope.

CE QUI N'ÉTAIT PAS EN CAUSE, et qu'il faut distinguer : le plafond de RUN (`RunCap`) couvrait déjà
ce chemin — il est lié depuis l'Engine, pas depuis les params. Les deux étages sont distincts et ne
se remplacent pas : le plafond borne le RUN, le seau par-action empêche une rafale de 30 sondes en
30 ms.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.engine import Engine                                                # noqa: E402
from forge.roe import Action, Scope                                            # noqa: E402


def _scope(**kw):
    data = {"mode": "grey", "in_scope": ["app.test"], "rate": 5}
    data.update(kw)
    return Scope(data)


class BothEntryPointsInjectTheRate(unittest.TestCase):

    def _via_campagne(self, kind, **scope_kw):
        return Engine(_scope(**scope_kw))._prepare([Action(kind, "app.test")], None, {}, {})[0]

    def _via_run(self, kind, **scope_kw):
        """`run()` exécuterait les actions ; on n'observe que l'injection, le tir est neutralisé."""
        eng = Engine(_scope(**scope_kw))
        a = Action(kind, "app.test")
        with mock.patch.object(Engine, "_run_serial", lambda _self, acts, *_a, **_k: list(acts)), \
             mock.patch.object(Engine, "_say_run_cap", lambda _self: None):
            eng.run([a])
        return a

    def test_un_oracle_recoit_le_debit_par_les_DEUX_portes(self):
        for kind in ("access_control.idor", "sqli.probe"):
            with self.subTest(kind=kind):
                self.assertEqual(self._via_campagne(kind).params.get("rate"), 5)
                self.assertEqual(self._via_run(kind).params.get("rate"), 5,
                                 "`forge run --actions` tirait sans lissage par-action")

    def test_un_outil_HTTP_recoit_son_drapeau_par_les_DEUX_portes(self):
        for kind in ("recon.feroxbuster", "recon.katana"):
            with self.subTest(kind=kind):
                self.assertEqual(self._via_campagne(kind).params.get("rate"), 5)
                self.assertEqual(self._via_run(kind).params.get("rate"), 5)

    def test_les_derivees_de_DELAI_suivent_aussi(self):
        a = self._via_run("access_control.idor")
        self.assertEqual(a.params.get("rate_delay_s"), "0.200")
        self.assertEqual(a.params.get("rate_delay_ms"), "200")
        self.assertEqual(a.params.get("rate_delay_dur"), "200ms")

    def test_la_politique_d_opt_in_est_LA_MEME_des_deux_cotes(self):
        """Corriger la porte ne doit pas changer la politique : le scanner de PORTS reste en opt-in."""
        self.assertIsNone(self._via_campagne("recon.naabu").params.get("rate"))
        self.assertIsNone(self._via_run("recon.naabu").params.get("rate"))
        self.assertEqual(self._via_campagne("recon.naabu", rate_explicit=True).params.get("rate"), 5)
        self.assertEqual(self._via_run("recon.naabu", rate_explicit=True).params.get("rate"), 5)


class InjectionIsIdempotent(unittest.TestCase):

    def test_une_action_de_campagne_qui_repasse_par_run_est_inchangee(self):
        """Les deux chemins se composent : `campaign` prépare puis appelle `run`."""
        eng = Engine(_scope())
        a = eng._prepare([Action("access_control.idor", "app.test")], None, {}, {})[0]
        avant = dict(a.params)
        with mock.patch.object(Engine, "_run_serial", lambda _self, acts, *_a, **_k: list(acts)), \
             mock.patch.object(Engine, "_say_run_cap", lambda _self: None):
            eng.run([a])
        self.assertEqual(a.params, avant)

    def test_un_debit_pose_par_l_appelant_n_est_JAMAIS_ecrase(self):
        eng = Engine(_scope())
        a = Action("access_control.idor", "app.test")
        a.params["rate"] = 99
        with mock.patch.object(Engine, "_run_serial", lambda _self, acts, *_a, **_k: list(acts)), \
             mock.patch.object(Engine, "_say_run_cap", lambda _self: None):
            eng.run([a])
        self.assertEqual(a.params["rate"], 99)


if __name__ == "__main__":
    unittest.main()

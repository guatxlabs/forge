# SPDX-License-Identifier: AGPL-3.0-or-later
"""Les modules qui ouvrent leur PROPRE socket honorent-ils le débit ?

Le plafond de débit du run est lié autour de `fire()` et honoré par `Oracle._http`, le chokepoint
HTTP des oracles. `RequestSmuggling._timed` n'y passe pas : il ouvre un raw socket pour mesurer un
délai de réponse. Il échappait donc AUX DEUX étages — mesuré sous un plafond actif à 5 req/s :
**10 requêtes en 5 ms** avant que la cadence à 0,200 s ne s'installe.

Un plafond que l'on contourne en ouvrant sa propre socket n'est pas un plafond. Et le contournement
ne se voit pas : le run reste « bridé » dans le ledger.

DEUX PROPRIÉTÉS, et la seconde est la moins évidente :
  1. l'attente A LIEU (le module consulte le contexte de débit) ;
  2. elle a lieu **AVANT** la fenêtre mesurée. Ce module mesure le délai jusqu'à la première
     réponse, et un délai anormal EST son signal de désynchronisation : dormir dans la fenêtre
     mesurée ferait rendre « désync confirmée » sur son propre frein.
"""
from __future__ import annotations

import unittest
from unittest import mock

from forge import throttle
from forge.modules import httpflow


class _Action:
    def __init__(self, target="http://127.0.0.1:8080/"):
        self.target = target
        self.params = {}


class _SpyBucket(throttle.RunCap):
    """Seau qui ne dort pas vraiment : il NOTE qu'on lui a demandé d'attendre, et FAIT AVANCER
    L'HORLOGE VIRTUELLE du temps qu'il aurait dormi.

    Hérite de `RunCap` et NON de `Bucket` : `using()` n'accepte un plafond de run que par
    `isinstance(run, RunCap)`. Un espion qui héritait de `Bucket` était silencieusement ignoré —
    le contexte se liait à None, et le test passait pour une absence de frein.

    L'AVANCE D'HORLOGE EST CE QUI DONNE SON POUVOIR AU TEST D'ORDRE, et elle manquait : un espion
    qui se contente de RENDRE `sleep_for` sans faire avancer le temps rend la position de l'attente
    (avant ou après `t0`) INOBSERVABLE. La mutation « déplacer l'attente dans la fenêtre mesurée »
    restait alors verte — constat sur le test, pas succès du code."""

    def __init__(self, clock, sleep_for=0.0):
        super().__init__(0)
        self.calls = 0
        self._clock = clock
        self._sleep_for = sleep_for

    def wait(self):
        self.calls += 1
        self._clock["t"] += self._sleep_for       # le frein CONSOMME du temps, comme un vrai sommeil
        return self._sleep_for


class RawSocketHonorsThrottle(unittest.TestCase):

    def _run_timed(self, bucket, elapsed_of_socket=0.0):
        """Joue `_timed` avec un socket factice, sous le contexte de débit `bucket`.
        Rend (elapsed, status) tel que le module les mesure."""
        clock = bucket._clock

        def fake_connect(*_a, **_k):
            clock["t"] += elapsed_of_socket           # le RÉSEAU coûte ceci, et rien d'autre
            return mock.MagicMock(recv=lambda *_: b"HTTP/1.1 200 OK")

        with mock.patch.object(httpflow.socket, "create_connection", fake_connect), \
             mock.patch.object(httpflow.time, "monotonic", lambda: clock["t"]):
            with throttle.using(0, run=bucket):
                return httpflow.RequestSmugglingProbe._timed(_Action(), "baseline", 5)

    def test_le_raw_socket_consulte_le_debit(self):
        b = _SpyBucket({"t": 0.0})
        self._run_timed(b)
        self.assertEqual(b.calls, 1, "le raw socket a tiré sans consulter le débit")

    def test_chaque_variante_paie_son_creneau(self):
        """Une seule attente pour dix tirs ne borne rien : c'est PAR REQUÊTE."""
        b = _SpyBucket({"t": 0.0})
        for variant in ("baseline", "clte", "tecl", "baseline", "clte"):
            self._run_timed(b)
        self.assertEqual(b.calls, 5)

    def test_l_attente_est_HORS_de_la_fenetre_mesuree(self):
        """LA PROPRIÉTÉ SUBTILE, ET CELLE QU'UN TEST NAÏF NE VOIT PAS. Le frein consomme 3 s
        d'horloge ; le réseau, lui, 10 ms. Le délai MESURÉ doit rester celui du RÉSEAU — sinon
        l'oracle lit son propre throttle comme un hang et rend « désynchronisation confirmée »
        sur un frein.

        Pour que ce test ait un pouvoir, il faut que l'attente FASSE AVANCER l'horloge virtuelle
        (cf. `_SpyBucket`) : sans cela, déplacer l'attente dans la fenêtre mesurée ne change rien
        d'observable et la mutation reste verte."""
        b = _SpyBucket({"t": 0.0}, sleep_for=3.0)
        elapsed, status = self._run_timed(b, elapsed_of_socket=0.01)
        self.assertEqual(b.calls, 1)
        self.assertAlmostEqual(elapsed, 0.01, places=6,
                               msg=f"l'attente du frein (3 s) a contaminé le délai mesuré : {elapsed}")
        self.assertEqual(status, "ok")

    def test_hors_contexte_rien_ne_change(self):
        """Aucun plafond lié (test unitaire, script hors moteur) -> `current()` rend None -> no-op."""
        self.assertIsNone(throttle.current())
        clock = {"t": 0.0}
        with mock.patch.object(httpflow.socket, "create_connection",
                               lambda *a, **k: mock.MagicMock(recv=lambda *_: b"HTTP/1.1 200 OK")), \
             mock.patch.object(httpflow.time, "monotonic", lambda: clock["t"]):
            elapsed, status = httpflow.RequestSmugglingProbe._timed(_Action(), "baseline", 5)
        self.assertEqual(status, "ok")


if __name__ == "__main__":
    unittest.main()

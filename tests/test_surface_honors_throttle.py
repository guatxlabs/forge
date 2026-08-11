# SPDX-License-Identifier: AGPL-3.0-or-later
"""La recon de surface honore-t-elle le débit ? — et les DEUX autres candidats, pourquoi non.

`PassiveSurface._http_get` ne passe pas par `Oracle._http`, le chokepoint qui honore les deux étages
de débit. Toute la recon de surface (`recon.js_endpoints`, `recon.tech`, `recon.urls`,
`recon.subdomains`…) y échappait donc — même trou que celui mesuré dans `httpflow` (10 requêtes en
5 ms sous un plafond actif de 5 req/s), et un plafond qu'on contourne en ouvrant sa propre connexion
n'est pas un plafond.

TROIS MODULES AVAIENT ÉTÉ SIGNALÉS COMME « MÊMES CANDIDATS » ; LA MESURE EN SÉPARE UN SEUL :

  · `recon_surface.PassiveSurface._http_get` -> frappe **la cible** (et crt.sh / Wayback) : CORRIGÉ ;
  · `burp._req`      -> parle à l'**API REST de Burp**, c'est-à-dire au service DE L'OPÉRATEUR ;
  · `msf._rpc_call`  -> parle à **msfrpcd**, également au service DE L'OPÉRATEUR.

Brider les deux derniers serait une FAUTE, pas une prudence : on compterait le trafic de plan de
contrôle de l'opérateur contre le budget de requêtes de la cible, et on ralentirait son outillage
sans rien protéger. Ce test fige cette distinction pour qu'un futur « uniformisons » ne l'efface pas.

LIMITE CONNUE, écrite ici plutôt que tue : le SCANNER de Burp, lui, frappe bien la cible — mais ce
trafic est émis par Burp, pas par forge, et `throttle` ne peut rien pour lui. Le brider demanderait
de passer un débit dans la configuration de scan de Burp.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import throttle                                                     # noqa: E402
from forge.modules import recon_surface                                        # noqa: E402


class _SpyCap(throttle.RunCap):
    def __init__(self):
        super().__init__(0)
        self.calls = 0

    def wait(self):
        self.calls += 1
        return 0.0


class _Resp:
    status = 200
    headers = {"Content-Type": "text/html"}

    def read(self, *_a):
        return b"<html>ok</html>"

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class SurfaceFetchHonorsTheCap(unittest.TestCase):

    def _get(self, cap, url="http://app.test/"):
        with mock.patch.object(recon_surface.urllib.request, "urlopen", lambda *a, **k: _Resp()), \
             mock.patch.object(recon_surface._pin, "ip_for", lambda _u: None):
            with throttle.using(0, run=cap):
                return recon_surface.PassiveSurface._http_get(url)

    def test_la_recon_de_surface_consulte_le_debit(self):
        cap = _SpyCap()
        self._get(cap)
        self.assertEqual(cap.calls, 1, "la recon de surface a tiré sans consulter le débit")

    def test_c_est_PAR_REQUETE_pas_une_fois_pour_toutes(self):
        cap = _SpyCap()
        for _ in range(5):
            self._get(cap)
        self.assertEqual(cap.calls, 5)

    def test_le_TIERS_est_bride_lui_aussi(self):
        """Un plafond déclaré borne ce que FORGE émet, pas seulement ce que la cible reçoit."""
        cap = _SpyCap()
        self._get(cap, "https://crt.sh/?q=app.test&output=json")
        self.assertEqual(cap.calls, 1)

    def test_hors_contexte_rien_ne_change(self):
        """Aucun plafond lié (test unitaire, script hors moteur) -> no-op, byte-identique."""
        self.assertIsNone(throttle.current())
        with mock.patch.object(recon_surface.urllib.request, "urlopen", lambda *a, **k: _Resp()), \
             mock.patch.object(recon_surface._pin, "ip_for", lambda _u: None):
            status, body, _h = recon_surface.PassiveSurface._http_get("http://app.test/")
        self.assertEqual(status, 200)
        self.assertIn("ok", body)


class TheOperatorsOwnServicesAreNotThrottled(unittest.TestCase):
    """La distinction qui empêche un futur « uniformisons » de faire une faute."""

    def test_burp_parle_au_service_de_l_operateur(self):
        from forge.modules import burp
        cfg = {"url": "http://127.0.0.1:1337", "key": "k"}
        self.assertTrue(burp._base(cfg).startswith(cfg["url"]),
                        "l'URL de Burp vient de la CONFIG de l'opérateur, pas de la cible")
        self.assertNotIn("throttle", burp._req.__doc__ or "",
                         "brider le plan de contrôle compterait le trafic de l'opérateur "
                         "contre le budget de la cible")

    def test_msf_parle_au_service_de_l_operateur(self):
        from forge.modules import msf
        cfg = {"host": "127.0.0.1", "port": 55553, "ssl": False}
        self.assertIn("127.0.0.1:55553", msf._rpc_url(cfg),
                      "l'URL de msfrpcd vient de la CONFIG de l'opérateur, pas de la cible")


if __name__ == "__main__":
    unittest.main()

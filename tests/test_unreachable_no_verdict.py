# SPDX-License-Identifier: AGPL-3.0-or-later
"""CIBLE INJOIGNABLE => AUCUN VERDICT — contrat transverse des oracles à preuve.

Défaut de CLASSE trouvé le 2026-08-05 : quand le réseau ne répond pas, les conjonctions de preuve
s'effondrent toutes à False, et `proof(proven=False, ...)` estampille `status='tested'` avec un titre
qui AFFIRME l'absence de vulnérabilité. Un test qui n'a jamais eu lieu devenait indiscernable d'un
test propre — sur IDOR, ATO, privesc et SSRF, c'est-à-dire les classes les plus graves du catalogue.

Ce que le contrat exige :
  - réseau MUET  -> `status='skipped'`, titre disant « injoignable », JAMAIS un verdict ;
  - réponse RÉELLE sans signal -> `status='tested'` (vrai négatif) — sinon on aurait échangé un faux
    négatif contre un aveuglement généralisé.

Le second point est le contrôle négatif : sans lui, un oracle qui refuserait TOUJOURS de conclure
passerait ce fichier haut la main.

HERMÉTIQUE : `_fetch` est monkeypatché, zéro réseau.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                  # noqa: E402
from forge.modules.access_control import IdorDifferential, PrivEsc   # noqa: E402
from forge.modules.auth import AuthTakeover                   # noqa: E402

URL = "http://cible.test/objet/1"
TGT = "http://cible.test/objet/1"


def _patch(cls, fn):
    orig = cls._fetch
    cls._fetch = staticmethod(fn)
    return lambda: setattr(cls, "_fetch", orig)


def _fire(cls, action, resp):
    """Tire `action` avec un `_fetch` qui rend toujours `resp` (signature tolérante aux appelants)."""
    restore = _patch(cls, lambda *a, **k: resp)
    try:
        return cls().fire(action)
    finally:
        restore()


# (status, body, content_type) — la forme rendue par `_ContentTypedOracle._fetch` et par auth.
MUET = (None, "", None)
REPOND = (404, "", "text/plain")


class TestIdorRead(unittest.TestCase):
    ACCOUNTS = [{"headers": {"Authorization": "A"}}, {"headers": {"Authorization": "B"}}]

    def _action(self):
        return Action("access_control.idor", TGT,
                      params={"accounts": self.ACCOUNTS, "urls": [URL], "method": "GET"})

    def test_unreachable_is_skipped(self):
        f = _fire(IdorDifferential, self._action(), MUET)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignable", f[0].title)

    def test_real_response_still_yields_a_verdict(self):
        """CONTRÔLE NÉGATIF : un 404 réel est une réponse — l'oracle doit conclure, pas se dérober."""
        f = _fire(IdorDifferential, self._action(), REPOND)
        self.assertEqual(f[0].status, "tested")
        self.assertNotIn("injoignable", f[0].title)


class TestIdorWrite(unittest.TestCase):
    """Chemin CRITICAL : un « IDOR write non confirmé » certifierait une écriture jamais tentée."""

    def _action(self):
        a = Action("access_control.idor", TGT,
                   params={"accounts": [{"headers": {"Authorization": "A"}},
                                        {"headers": {"Authorization": "B"}}],
                           "urls": [URL], "method": "PUT", "body": "{}"})
        a.destructive = True          # capacité write explicitement autorisée par le ROE
        return a

    def test_unreachable_is_skipped(self):
        f = _fire(IdorDifferential, self._action(), MUET)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignable", f[0].title)


class TestPrivEsc(unittest.TestCase):
    def _action(self):
        return Action("access_control.privesc", TGT,
                      params={"accounts": [{"headers": {"Authorization": "low"}},
                                           {"headers": {"Authorization": "admin"}}],
                              "urls": [URL], "method": "GET"})

    def test_unreachable_is_skipped(self):
        f = _fire(PrivEsc, self._action(), MUET)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignable", f[0].title)


class TestAuthTakeoverConfigPath(unittest.TestCase):
    def test_whoami_unreachable_is_skipped(self):
        f = _fire(AuthTakeover, Action("auth.takeover", TGT,
                                       params={"whoami_url": URL, "victim_marker": "victime",
                                               "session_headers": {"Cookie": "s=1"}}), MUET)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignable", f[0].title)

    def test_bypass_step_unreachable_is_skipped(self):
        """La PRÉMISSE compte : si l'étape de bypass n'est jamais partie, le whoami qui suit ne prouve
        rien. Son statut était jeté — une garde sur le seul whoami ne l'aurait pas vu."""
        f = _fire(AuthTakeover, Action("auth.takeover", TGT,
                                       params={"whoami_url": URL, "victim_marker": "victime",
                                               "session_headers": {"Cookie": "s=1"},
                                               "bypass": {"url": "http://cible.test/reset",
                                                          "method": "POST", "body": {"a": "1"}}}), MUET)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("injoignable", f[0].title)


if __name__ == "__main__":
    unittest.main()

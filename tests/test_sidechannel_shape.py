# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests hermétiques de `sidechannel.shape` — canal auxiliaire par forme de réponse (XS-Leak/length).

Zéro réseau : on monkeypatche le seam `_fetch_full` (renvoie status, en-têtes, corps). Les fakes
distinguent PRÉSENT d'ABSENT par la valeur injectée dans l'URL. Chaque test nomme la propriété de
preuve qu'il verrouille — la preuve est une CONJONCTION (présent STABLE et != absent), et le double
tir du présent est la mesure du plancher de bruit sans laquelle une variance passerait pour une fuite.
"""
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action  # noqa: E402
from forge.modules.sidechannel import SideChannelShape  # noqa: E402


def _patch_full(fn):
    """Installe SideChannelShape._fetch_full (staticmethod) et restaure (l'attribut n'existe pas
    par défaut -> delattr)."""
    had = "_fetch_full" in SideChannelShape.__dict__
    orig = SideChannelShape.__dict__.get("_fetch_full")
    SideChannelShape._fetch_full = staticmethod(fn)

    def restore():
        if had:
            SideChannelShape._fetch_full = orig
        else:
            del SideChannelShape._fetch_full
    return restore


def _boom(*a, **k):
    raise AssertionError("aucun réseau ne doit partir (hors périmètre / config manquante)")


def _is_present(url):
    return "userB" in urllib.parse.unquote_plus(url)


class TestSideChannelShape(unittest.TestCase):
    TGT = "https://app.test/resource"
    BASE = {"param": "id", "present_value": "userB", "absent_value": "ghost404", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _patch_full(fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return SideChannelShape().fire(Action("sidechannel.shape", self.TGT, params=p))
        finally:
            restore()

    # --- PREUVES ------------------------------------------------------------------------------
    def test_proven_status_and_etag_channel(self):
        """Présent -> 200 + ETag ; absent -> 404. Forme stable et différente -> fuite MEDIUM."""
        def fake(url, headers=None, method="GET", data=None):
            if _is_present(url):
                return (200, {"ETag": '"abc"'}, "<div>ressource</div>")
            return (404, {}, "not found")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "MEDIUM")
        self.assertEqual(f[0].cwe, "CWE-203")
        self.assertIn("CONFIRMÉ", f[0].title)

    def test_proven_length_channel(self):
        """Même statut, mais longueur du présent >> absent (au-delà du bucket) -> fuite par longueur."""
        def fake(url, headers=None, method="GET", data=None):
            return (200, {}, "X" * 500) if _is_present(url) else (200, {}, "X" * 10)
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")

    def test_proven_etag_presence_channel(self):
        """Statut et longueur identiques, mais l'ETag n'est présent que sur le présent -> fuite."""
        def fake(url, headers=None, method="GET", data=None):
            body = "body12345"
            return (200, {"etag": '"z"'}, body) if _is_present(url) else (200, {}, body)
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")

    # --- NON-PREUVES : le différentiel et le plancher de bruit doivent tenir -------------------
    def test_tested_when_present_is_noisy(self):
        """Le présent n'est pas stable entre deux tirs (contenu dynamique) -> canal bruité, pas de verdict."""
        state = {"n": 0}
        def fake(url, headers=None, method="GET", data=None):
            if _is_present(url):
                state["n"] += 1
                return (200, {}, "A" * (10 if state["n"] == 1 else 400))   # présent#1 vs #2 très différents
            return (404, {}, "nf")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("bruité", f[0].title)

    def test_tested_when_no_leak(self):
        """Présent et absent de même forme -> aucun oracle observable -> tested."""
        def fake(url, headers=None, method="GET", data=None):
            return (200, {}, "identique")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucune fuite", f[0].title)

    def test_tested_when_length_within_bucket(self):
        """Une micro-variance de longueur (<= bucket), même statut/ETag, n'est PAS une fuite."""
        def fake(url, headers=None, method="GET", data=None):
            return (200, {}, "X" * 100) if _is_present(url) else (200, {}, "X" * 120)   # delta 20 <= 48
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucune fuite", f[0].title)

    # --- GARDES -------------------------------------------------------------------------------
    def test_scope_guard_out_of_scope(self):
        restore = _patch_full(_boom)
        try:
            f = SideChannelShape().fire(Action("sidechannel.shape", "https://evil.example/x",
                                               params=dict(self.BASE)))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        restore = _patch_full(_boom)
        try:
            f = SideChannelShape().fire(Action("sidechannel.shape", self.TGT,
                                               params={"param": "id", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("config manquante", f[0].title)

    def test_network_down_is_degraded(self):
        def fake(url, headers=None, method="GET", data=None):
            return (None, {}, None)
        f = self._fire(fake)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)

    # --- discipline ---------------------------------------------------------------------------
    def test_oracle_is_read_only_and_non_destructive(self):
        self.assertFalse(SideChannelShape.exploit)
        self.assertFalse(SideChannelShape.destructive)


if __name__ == "__main__":
    unittest.main(verbosity=2)

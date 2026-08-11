# SPDX-License-Identifier: AGPL-3.0-or-later
"""D7 — une ERREUR DU SERVICE NAVIGATEUR ne produit plus de verdict.

LE DÉFAUT MESURÉ. `xss.stored` gardait son verdict par `if rst is None or not dom:` — le SUCCÈS de la
navigation n'était jamais vérifié. Un 500 du service navigateur rend `(500, "Internal Server Error")` :
`dom` est NON VIDE, la garde passe, et l'oracle conclut « XSS stored non confirmé — pas de reflet
exécutable non échappé dans le DOM rendu ». Une PANNE D'INFRASTRUCTURE devenait un verdict d'ABSENCE
de vulnérabilité, avec une evidence qui affirme « module NAVIGATEUR utilisé pour le rendu DOM ».

L'oracle frère `xss.execution` faisait déjà le bon choix (`if not _ok(gst): return False`) : ces tests
verrouillent la parité entre les deux, plus les deux étages du correctif :
  - le SEAM (`_browser_render`) vérifie le statut du `goto` AVANT de lire le DOM ;
  - la GARDE de `fire()` exige un 2xx — c'est elle qui protège quand le seam est stubé/patché,
    c'est-à-dire exactement le chemin par lequel le défaut a été reproduit.

Hermétique : les deux seams navigateur et le `_fetch` de persistance sont monkeypatchés — aucun
service n'est contacté, aucun octet n'est émis.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                          # noqa: E402
from forge.modules.clientflow import XssStored, _browser_ok           # noqa: E402


def _set(cls, name, fn):
    """Pose un staticmethod et rend le restaurateur (descripteur restauré, ou attribut retiré)."""
    had = name in cls.__dict__
    orig = cls.__dict__.get(name)
    setattr(cls, name, staticmethod(fn))

    def restore():
        if had:
            setattr(cls, name, orig)
        else:
            delattr(cls, name)
    return restore


def _boom(*a, **k):
    raise AssertionError("I/O émis alors qu'aucun ne devait l'être")


class TestBrowserOkPredicate(unittest.TestCase):
    """`browser_client` rend `status=0` sur erreur RÉSEAU et le CODE HTTP du service sinon."""

    def test_only_2xx_is_ok(self):
        for st in (200, 201, 204, 299):
            self.assertTrue(_browser_ok(st), st)
        for st in (None, 0, 300, 302, 400, 404, 500, 502, 503):
            self.assertFalse(_browser_ok(st), st)


class TestStoredXssRefusesToConcludeOnServiceError(unittest.TestCase):
    TGT = "https://app.test/comment"
    BASE = {"param": "comment", "store_url": "https://app.test/comment",
            "view_url": "https://app.test/thread", "in_scope": ["app.test"]}

    def _fire(self, render, persist=(200, "", [])):
        r_av = _set(XssStored, "_browser_available", lambda: True)
        r_rd = _set(XssStored, "_browser_render", render)
        r_ft = _set(XssStored, "_fetch", lambda *a, **k: persist)
        try:
            return XssStored().fire(Action("xss.stored", self.TGT, params=dict(self.BASE)))
        finally:
            r_ft(); r_rd(); r_av()

    def test_500_with_a_non_empty_body_no_longer_yields_a_verdict(self):
        """LE cas exact du banc : `(500, "Internal Server Error")` — corps NON VIDE."""
        f = self._fire(lambda url, tab="forge": (500, "Internal Server Error"))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "skipped",
                         "une erreur du service navigateur ne doit produire AUCUN verdict")
        self.assertIn("rendu navigateur indisponible", f[0].title)
        # et surtout : le titre ne doit PAS affirmer l'absence de vulnérabilité.
        self.assertNotIn("non confirmé", f[0].title)
        self.assertIn("500", f[0].evidence)

    def test_any_non_2xx_service_status_abstains(self):
        for st in (0, 400, 403, 404, 500, 502, 503):
            with self.subTest(status=st):
                f = self._fire(lambda url, tab="forge", _s=st: (_s, "<html>Service Unavailable</html>"))
                self.assertEqual(f[0].status, "skipped", st)

    def test_a_redirect_page_is_not_a_rendered_dom(self):
        """Un 302 du service (« la navigation n'a pas abouti ») porte aussi un corps."""
        f = self._fire(lambda url, tab="forge": (302, "<html>Found</html>"))
        self.assertEqual(f[0].status, "skipped")

    def test_true_negative_is_preserved(self):
        """CONTRE-ÉPREUVE — un 2xx avec un DOM réel conclut EXACTEMENT comme avant : le correctif
        n'échange pas un verdict fabriqué contre une abstention systématique."""
        marker = XssStored._marker(self.BASE["store_url"], "comment", "storedxss")
        f = self._fire(lambda url, tab="forge":
                       (200, f"<div>posted: {marker}&lt;&gt; thanks</div>"))
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)

    def test_true_positive_is_preserved(self):
        marker = XssStored._marker(self.BASE["store_url"], "comment", "storedxss")
        f = self._fire(lambda url, tab="forge":
                       (200, f'<script>var c="{marker}<>";</script>'))
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")

    def test_empty_dom_on_2xx_still_abstains(self):
        f = self._fire(lambda url, tab="forge": (200, ""))
        self.assertEqual(f[0].status, "skipped")


class TestBrowserRenderSeamChecksNavigation(unittest.TestCase):
    """Second étage : le SEAM lui-même ne lit plus le DOM d'une navigation ratée. Sans cette borne,
    `content()` rendrait la page PRÉCÉDENTE (ou celle d'erreur) et le DOM serait crédible."""

    def test_failed_goto_short_circuits_content(self):
        import forge.modules.clientflow as cf
        calls = {"goto": 0, "content": 0}

        class _Bc:
            DEFAULT_TAB = "forge"

            @staticmethod
            def goto(url, tab="forge", **kw):
                calls["goto"] += 1
                return 500, "Internal Server Error"

            @staticmethod
            def content(tab="forge", **kw):
                calls["content"] += 1
                return 200, "<html>page PRÉCÉDENTE, encore chargée</html>"

        orig = cf.bc
        cf.bc = _Bc
        try:
            st, dom = XssStored._browser_render("https://app.test/thread")
        finally:
            cf.bc = orig
        self.assertIsNone(st)
        self.assertEqual(dom, "")
        self.assertEqual(calls["goto"], 1)
        self.assertEqual(calls["content"], 0, "le DOM a été lu malgré une navigation en échec")

    def test_successful_goto_reads_the_dom(self):
        import forge.modules.clientflow as cf

        class _Bc:
            DEFAULT_TAB = "forge"

            @staticmethod
            def goto(url, tab="forge", **kw):
                return 200, {"ok": True}

            @staticmethod
            def content(tab="forge", **kw):
                return 200, {"content": "<html>rendu</html>"}

        orig = cf.bc
        cf.bc = _Bc
        try:
            st, dom = XssStored._browser_render("https://app.test/thread")
        finally:
            cf.bc = orig
        self.assertEqual(st, 200)
        self.assertEqual(dom, "<html>rendu</html>")


class TestParityWithXssExecution(unittest.TestCase):
    """Les deux oracles navigateur doivent s'abstenir sur la MÊME condition. C'est la divergence
    qu'on ferme : l'un le faisait, l'autre pas."""

    def test_same_predicate(self):
        from forge.modules.xssexec import _ok as exec_ok
        for st in (None, 0, 200, 204, 302, 400, 500, 503):
            with self.subTest(status=st):
                self.assertEqual(bool(_browser_ok(st)), bool(exec_ok(st)), st)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests hermétiques de `ssti.errors` — SSTI aveugle par le canal d'erreur (« Successful Errors »).

Zéro réseau : le seam `_fetch` est monkeypatché. Chaque fake distingue les trois sondes par le
contenu de l'URL injectée (décodée) : le TEST porte `/0`, le CONTRÔLE porte des délimiteurs autour
du marqueur inerte, le TÉMOIN porte le marqueur inerte nu.

Chaque test nomme la propriété de preuve qu'il verrouille — la preuve est une CONJONCTION (erreur
arithmétique test-only), et aucun test ne doit pouvoir passer sur une observation isolée.
"""
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action  # noqa: E402
from forge.modules.ssti_errors import SstiErrors  # noqa: E402


def _patch(cls, fn):
    """Remplace cls._fetch par un staticmethod et restaure proprement (cf. test_injection_oracles)."""
    had = "_fetch" in cls.__dict__
    orig = cls.__dict__.get("_fetch")
    cls._fetch = staticmethod(fn)

    def restore():
        if had:
            cls._fetch = orig
        else:
            del cls._fetch
    return restore


def _boom(*a, **k):
    raise AssertionError("aucun réseau ne doit partir sur une cible hors périmètre / sans param")


# Délimiteurs qui trahissent une sonde de CONTRÔLE (marqueur inerte entre délimiteurs de template).
_DELIMS = ("{{", "${", "#{", "<%", "@(", "#set", "*{", "{")


def _kind_of(url):
    """'test' | 'control' | 'witness' — d'après l'URL injectée décodée."""
    u = urllib.parse.unquote_plus(url)
    if "/0" in u:
        return "test"
    if any(d in u for d in _DELIMS):
        return "control"
    return "witness"


class TestSstiErrors(unittest.TestCase):
    TGT = "https://app.test/render"
    BASE = {"param": "q", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _patch(SstiErrors, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return SstiErrors().fire(Action("ssti.errors", self.TGT, params=p))
        finally:
            restore()

    # --- PREUVE : erreur arithmétique test-only ------------------------------------------------
    def test_vulnerable_medium_when_arith_error_test_only(self):
        """Division par zéro ÉVALUÉE (erreur arith sur le test), absente du contrôle et du témoin,
        SANS fuite du produit -> vulnerable MEDIUM."""
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if _kind_of(url) == "test":
                return (500, "Traceback: ZeroDivisionError: division by zero")
            return (200, "<h1>page normale, aucune erreur</h1>")   # témoin + contrôle propres
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "MEDIUM")
        self.assertEqual(f[0].cwe, "CWE-1336")
        self.assertEqual(f[0].mitre, "T1190")
        self.assertIn("CONFIRMÉE", f[0].title)

    def test_vulnerable_high_when_product_leaks_in_error(self):
        """Le produit N*M apparaît dans le corps d'erreur du test (et pas ailleurs) -> HIGH."""
        n, m, product, _inert = SstiErrors._marker(self.TGT, "q")
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if _kind_of(url) == "test":
                return (500, f"ArithmeticException: / by zero (value was {product})")
            return (200, "clean")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertIn(str(product), f[0].evidence)
        self.assertIn("divulgué", f[0].title)

    # --- NON-PREUVE : le différentiel doit tenir ----------------------------------------------
    def test_tested_when_control_also_errors(self):
        """Si les DÉLIMITEURS SEULS (contrôle inerte) produisent déjà l'erreur arithmétique, le test
        n'est pas concluant — c'est le parse des délimiteurs, pas l'évaluation de N*M/0."""
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            k = _kind_of(url)
            if k in ("test", "control"):
                return (500, "ZeroDivisionError")     # le contrôle erre AUSSI
            return (200, "clean")                     # témoin propre
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non confirmée", f[0].title)

    def test_tested_when_witness_already_errors(self):
        """Une page qui montre TOUJOURS une erreur arithmétique (témoin compris) ne prouve rien :
        le différentiel est neutralisé, verdict tested."""
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (500, "division by zero partout, page d'erreur permanente")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmée", f[0].title)

    def test_tested_when_no_error_at_all(self):
        """Aucune erreur arithmétique nulle part -> pas d'évaluation démontrée -> tested."""
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "réponse normale, le payload est ignoré ou échappé")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")

    def test_non_arith_error_does_not_count(self):
        """Une erreur NON arithmétique (UndefinedError, 500 générique) sur le test ne prouve pas
        l'évaluation d'une division — seule une signature ARITHMÉTIQUE compte."""
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            if _kind_of(url) == "test":
                return (500, "jinja2.exceptions.UndefinedError: 'x' is undefined")
            return (200, "clean")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")

    # --- GARDES ------------------------------------------------------------------------------
    def test_scope_guard_out_of_scope(self):
        restore = _patch(SstiErrors, _boom)
        try:
            f = SstiErrors().fire(Action("ssti.errors", "https://evil.example/x",
                                         params={"param": "q", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_param_is_skip(self):
        restore = _patch(SstiErrors, _boom)
        try:
            f = SstiErrors().fire(Action("ssti.errors", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("config manquante", f[0].title)

    def test_network_down_is_degraded(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (None, None)
        f = self._fire(fake)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)

    # --- marqueur ----------------------------------------------------------------------------
    def test_marker_deterministic_and_distinctive(self):
        a = SstiErrors._marker(self.TGT, "q")
        b = SstiErrors._marker(self.TGT, "q")
        c = SstiErrors._marker(self.TGT, "other")
        self.assertEqual(a, b)                                 # rejouable
        self.assertNotEqual(a[2], c[2])                        # produit distinct par paramètre
        self.assertGreater(a[2], 10 ** 9)                      # produit à ~11-12 chiffres
        self.assertTrue(a[3].startswith("forgeInert"))         # marqueur inerte

    def test_benign_payload_is_only_division_never_code_exec(self):
        """Garde-fou de bénignité : aucune sonde ne porte de primitive d'exécution/lecture — seulement
        un produit arithmétique suivi d'une division par zéro."""
        from forge.modules.ssti_errors import _TEST_TEMPLATES
        joined = " ".join(_TEST_TEMPLATES).lower()
        for banned in ("system", "popen", "exec", "import", "open(", "cat ", "/etc/", "subprocess",
                       "runtime", "process", "read"):
            self.assertNotIn(banned, joined)
        self.assertTrue(all("/0" in t for t in _TEST_TEMPLATES))   # toutes des divisions par zéro


if __name__ == "__main__":
    unittest.main(verbosity=2)

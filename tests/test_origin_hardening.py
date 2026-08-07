# SPDX-License-Identifier: AGPL-3.0-or-later
"""origin.find — DEUX corrections DISTINCTES, prouvées séparément.

Régression d'un run RÉEL (ledger `gxrun`, seq 5605) : sur 1573 tirs, `origin.find` a été la SEULE
exception remontée brute —

    UnicodeEncodeError('idna', 'https://guatx.com/cdn-cgi/challenge-platform/…', 14, 189,
                       'label too long')

…parce que le module passait l'URL ENTIÈRE là où un NOM D'HÔTE est attendu (`subfinder -d`,
`socket.gethostbyname`, en-tête `Host:`), et que l'IDNA refuse tout label > 63 octets.

(1) EXTRACTION DE L'HÔTE — `origin.find` énumère un DOMAINE. Une cible CHAÎNÉE depuis un endpoint
    découvert arrive sous forme d'URL : on en extrait l'hôte AVANT toute résolution.
(2) GARDE GÉNÉRIQUE — une exception au tir devient un `skipped` NOMMÉ, jamais une remontée brute.
    Indépendante de (1) : (1) supprime CETTE cause, (2) couvre la classe entière. La preuve par
    mutation les distingue — retirer l'une SANS l'autre doit faire rougir SON test, pas l'autre.

RACINE DU TROU : la boucle de résolution ne rattrapait qu'`OSError`, et `UnicodeEncodeError` n'en est
pas une (cf. `test_unicode_error_is_not_an_oserror`) — le `except OSError` était donc aveugle à ce cas.

Hermétique : `runner.tool` et `socket.gethostbyname` sont des seams monkeypatchés ; zéro réseau.
"""
import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import runner                                      # noqa: E402
from forge.engine import Engine                               # noqa: E402
from forge.roe import Action, Scope                           # noqa: E402
from forge.modules import origin as origin_mod                # noqa: E402
from forge.modules.origin import OriginFind                   # noqa: E402

# L'URL EXACTE qui a fait planter le module sur le run réel.
CF_CHALLENGE_URL = (
    "https://guatx.com/cdn-cgi/challenge-platform/h/b/fo/56157302:1786104021:"
    "CSa7tAN08690_xntt1UxTwNjsX0zja0eJpSVtxNsQwI/a2766b4c7995e1c5/"
    "k9HCseD3GpB3VMNZDlvo5_Cy_5MGDV9l7j_0BZFUW4s-1786107153-1.2.1.1-"
    "cGYoPBTKon6lgw0q8jkze6TDlPp51_Frx7xk51.3Qso9UX6LxHFHyj5jvUIc65BA")


def _idna_error(value):
    """L'exception EXACTE que lève `socket.gethostbyname` sur un label > 63 octets (reproduit le
    comportement de la stdlib sans toucher au réseau)."""
    return UnicodeEncodeError("idna", str(value), 14, 189, "label too long")


class _Seams:
    """Remplace les deux seams de `origin.find` : le runner d'outils et la résolution DNS.

    `resolver` par défaut REPRODUIT la stdlib : tout ce qui n'est pas un nom d'hôte (contient `://`
    ou `/`) lève l'IDNA `label too long`, exactement comme sur le run réel."""

    def __init__(self, test, *, tool=None, resolver=None):
        self.calls = []
        self.resolved = []
        self._tool = tool or (lambda *a, **k: (0, "", ""))
        self._resolver = resolver or self._stdlib_like
        orig_tool, orig_gethost = runner.tool, socket.gethostbyname

        def tool(*a, **k):
            self.calls.append((a, k))
            return self._tool(*a, **k)

        def gethostbyname(name):
            self.resolved.append(name)
            return self._resolver(name)

        runner.tool = tool
        origin_mod.socket.gethostbyname = gethostbyname
        test.addCleanup(lambda: (setattr(runner, "tool", orig_tool),
                                 setattr(origin_mod.socket, "gethostbyname", orig_gethost)))

    @staticmethod
    def _stdlib_like(name):
        if "://" in name or "/" in name:
            raise _idna_error(name)
        raise OSError("hôte inconnu (test hermétique)")        # aucune candidate ne résout


class TestRootCause(unittest.TestCase):
    def test_unicode_error_is_not_an_oserror(self):
        """Pourquoi le `except OSError` de la boucle de résolution était aveugle à ce cas."""
        self.assertFalse(issubclass(UnicodeEncodeError, OSError))


# --- CORRECTION (1) : extraction de l'hôte --------------------------------------------------------
class TestHostExtraction(unittest.TestCase):
    def test_domain_of_extracts_the_host_from_the_crashing_url(self):
        self.assertEqual(OriginFind._domain_of(CF_CHALLENGE_URL), "guatx.com")

    def test_domain_of_handles_ports_userinfo_and_bare_hosts(self):
        for target, host in ((("https://user@app.test:8443/x?y=1"), "app.test"),
                             ("app.test:8080", "app.test"),
                             ("app.test", "app.test"),
                             ("http://[::1]:7100/a", "::1")):
            self.assertEqual(OriginFind._domain_of(target), host, target)

    def test_resolution_only_ever_sees_hostnames(self):
        """LA preuve de (1), ISOLÉE : aucune résolution ne reçoit une URL. Assertion vérifiée AVANT
        toute autre (une mutation qui casse (1) fait rougir CE test, pas un autre)."""
        seams = _Seams(self)
        OriginFind().fire(Action("origin.find", CF_CHALLENGE_URL))
        self.assertTrue(seams.resolved, "aucune résolution tentée — le test ne prouverait rien")
        bad = [n for n in seams.resolved if "://" in n or "/" in n]
        self.assertEqual(bad, [], "une URL a été passée à la résolution DNS au lieu d'un hôte")

    def test_subfinder_is_given_the_host_not_the_url(self):
        seams = _Seams(self)
        OriginFind().fire(Action("origin.find", CF_CHALLENGE_URL))
        argvs = [a[2] for a, _k in seams.calls if len(a) > 2]
        self.assertTrue(argvs, "subfinder n'a pas été invoqué — le test ne prouverait rien")
        self.assertIn("guatx.com", argvs[0])
        self.assertNotIn(CF_CHALLENGE_URL, argvs[0])

    def test_dry_run_describes_the_host_not_the_url(self):
        s = OriginFind().dry(Action("origin.find", CF_CHALLENGE_URL))
        self.assertIn("subfinder -d guatx.com", s)
        self.assertNotIn("cdn-cgi", s)

    def test_bare_host_target_is_byte_identical(self):
        seams = _Seams(self)
        OriginFind().fire(Action("origin.find", "app.test"))
        self.assertEqual(seams.calls[0][0][2][:3], ["-d", "app.test", "-silent"])

    def test_target_without_a_resolvable_host_is_skipped_without_firing_anything(self):
        seams = _Seams(self)
        out = OriginFind().fire(Action("origin.find", "///"))
        self.assertEqual(seams.calls, [], "un processus a été lancé sur une cible sans hôte")
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("sans hôte résoluble", out[0].title)


# --- CORRECTION (2) : garde générique -------------------------------------------------------------
class TestGenericGuard(unittest.TestCase):
    def _boom(self, exc):
        def tool(*_a, **_k):
            raise exc
        return tool

    def test_an_exception_at_fire_becomes_a_named_skipped(self):
        """LA preuve de (2), ISOLÉE : la cause du crash est RETIRÉE de l'équation (cible = hôte nu),
        et l'exception vient d'ailleurs — donc seule la garde générique peut la rattraper."""
        _Seams(self, tool=self._boom(RuntimeError("boom sous-jacent")))
        out = OriginFind().fire(Action("origin.find", "app.test"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].status, "skipped",
                         "'skipped' = je n'ai pas pu vérifier ; jamais 'tested' (rien trouvé)")
        self.assertIn("RuntimeError", out[0].title)            # NOMMÉE
        self.assertIn("boom sous-jacent", out[0].evidence)     # la cause n'est pas perdue
        self.assertEqual(out[0].category, "origin-exposure")

    def test_guard_covers_non_oserror_families_too(self):
        for exc in (_idna_error("x"), ValueError("v"), KeyError("k"), MemoryError()):
            with self.subTest(exc=type(exc).__name__):
                _Seams(self, tool=self._boom(exc))
                out = OriginFind().fire(Action("origin.find", "app.test"))
                self.assertEqual(out[0].status, "skipped")
                self.assertIn(type(exc).__name__, out[0].title)

    def test_idna_from_the_resolver_is_still_absorbed(self):
        """Ceinture ET bretelles : même si (1) régressait, (2) empêche la remontée brute."""
        _Seams(self, resolver=lambda name: (_ for _ in ()).throw(_idna_error(name)))
        out = OriginFind().fire(Action("origin.find", CF_CHALLENGE_URL))
        self.assertTrue(all(f.status in ("skipped", "tested") for f in out))


# --- bout-en-bout : le moteur ne voit plus d'ERROR ------------------------------------------------
class TestThroughEngine(unittest.TestCase):
    def test_engine_gets_a_skipped_finding_not_an_error_verdict(self):
        _Seams(self, tool=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        orig_avail = OriginFind.available
        OriginFind.available = True                            # neutralise la sonde d'outils
        self.addCleanup(lambda: setattr(OriginFind, "available", orig_avail))
        eng = Engine(Scope({"mode": "grey", "in_scope": ["app.test"]}))
        eng.arm()
        a = Action("origin.find", "app.test")
        eng.approve(a.id)
        res = eng.execute(a)
        self.assertNotEqual(res["verdict"], "ERROR",
                            "l'exception remonte encore brute jusqu'au moteur")
        self.assertEqual(res["verdict"], "FIRE")
        self.assertEqual([f.status for f in eng.findings], ["skipped"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

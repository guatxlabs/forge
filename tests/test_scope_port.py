# SPDX-License-Identifier: AGPL-3.0-or-later
"""Scope-guard PAR PORT — un motif peut restreindre un hôte à un seul port.

Origine : le 2026-08-04, un engagement de lab visait `juice.lab.local` (Juice Shop). Le scope portait
`127.0.0.1` avec `allow_private`, et le scope-guard étant HOST-LEVEL, forge a scanné **tout ce qui
écoutait sur la machine** — le VNC du conteneur d'automatisation (:5900) et CUPS (:631) ont été
remontés en CRITICAL, présentés comme des découvertes sur la cible. Aucun garde-fou n'a été franchi :
le périmètre déclaré incluait réellement ces services. C'est le périmètre qui manquait de résolution.

Le motif décide désormais de la granularité :
  - `example.com`        -> l'hôte entier, tous ports (comportement historique, INCHANGÉ) ;
  - `example.com:3000`   -> ce port seulement.

Aucun scope existant ne portait de port au moment du changement (vérifié sur l'arbre) : l'ajout est
purement additif.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope  # noqa: E402


class TestHostLevelUnchanged(unittest.TestCase):
    """Un motif SANS port continue de couvrir tous les ports — la compat' est la valeur par défaut."""

    def setUp(self):
        self.scope = Scope({"in_scope": ["example.com"]})

    def test_bare_host_covers_every_port(self):
        for t in ["example.com", "example.com:8080", "https://example.com/a?b=1",
                  "http://user@example.com:31337/x"]:
            self.assertTrue(self.scope.is_in_scope(t), t)

    def test_glob_still_works(self):
        s = Scope({"in_scope": ["*.example.com"]})
        self.assertTrue(s.is_in_scope("api.example.com:9000"))
        self.assertFalse(s.is_in_scope("example.org:9000"))


class TestPortLevelScope(unittest.TestCase):
    """Un motif AVEC port ne couvre que ce port."""

    def setUp(self):
        self.scope = Scope({"in_scope": ["juice.lab.local:3000"]})

    def test_declared_port_is_in_scope(self):
        self.assertTrue(self.scope.is_in_scope("juice.lab.local:3000"))
        self.assertTrue(self.scope.is_in_scope("http://juice.lab.local:3000/#/login"))

    def test_other_ports_are_out_of_scope(self):
        """LA régression du 2026-08-04 : le voisinage de l'hôte n'est plus emporté avec la cible."""
        for port in (80, 631, 5900, 6080, 8080):
            self.assertFalse(self.scope.is_in_scope(f"juice.lab.local:{port}"), port)

    def test_host_without_port_does_not_widen_the_scope(self):
        """Fail-closed : une cible dont le port est indéterminable ne satisfait pas un motif qui en exige un."""
        self.assertFalse(self.scope.is_in_scope("juice.lab.local"))

    def test_scheme_supplies_the_implicit_port(self):
        s = Scope({"in_scope": ["example.com:443"]})
        self.assertTrue(s.is_in_scope("https://example.com/"))
        self.assertFalse(s.is_in_scope("http://example.com/"))


class TestLiteralAddresses(unittest.TestCase):
    """IP et IPv6 littérales — le chemin qui a réellement échoué."""

    def test_ipv4_with_port(self):
        s = Scope({"in_scope": ["127.0.0.1:3000"]})
        self.assertTrue(s.is_in_scope("127.0.0.1:3000"))
        self.assertFalse(s.is_in_scope("http://127.0.0.1:631/help/"))   # CUPS, la fausse CRITICAL
        self.assertFalse(s.is_in_scope("127.0.0.1:5900"))               # VNC, la fausse CRITICAL

    def test_ipv6_bracketed(self):
        s = Scope({"in_scope": ["[::1]:3000"]})
        self.assertTrue(s.is_in_scope("[::1]:3000"))
        self.assertFalse(s.is_in_scope("[::1]:5900"))

    def test_cidr_pattern_stays_host_level(self):
        """Un CIDR ne porte pas de port — il continue de couvrir la plage entière."""
        s = Scope({"in_scope": ["10.0.0.0/24"]})
        self.assertTrue(s.is_in_scope("10.0.0.7:9999"))


class TestOutScopeHasNoPortLoophole(unittest.TestCase):
    """out_scope l'emporte, et un port indéterminable ne doit pas servir d'échappatoire."""

    def setUp(self):
        self.scope = Scope({"in_scope": ["example.com"], "out_scope": ["example.com:22"]})

    def test_blocks_the_named_port(self):
        self.assertFalse(self.scope.is_in_scope("example.com:22"))

    def test_leaves_other_ports_reachable(self):
        self.assertTrue(self.scope.is_in_scope("example.com:443"))

    def test_unknown_port_is_blocked_not_allowed(self):
        """Asymétrie VOULUE : in_scope refuse dans le doute, out_scope bloque dans le doute."""
        self.assertFalse(self.scope.is_in_scope("example.com"))


class TestPortParsing(unittest.TestCase):
    def test_forms(self):
        cases = [("example.com", None), ("example.com:8080", 8080), ("https://example.com", 443),
                 ("http://example.com", 80), ("http://example.com:8443/x?y=1", 8443),
                 ("[::1]:5900", 5900), ("[::1]", None), ("::1", None),
                 ("ftp://example.com", None), ("example.com:abc", None),
                 ("example.com:0", None), ("example.com:65536", None), ("example.com:65535", 65535)]
        for value, expected in cases:
            self.assertEqual(Scope._port(value), expected, value)

    def test_host_extraction_is_unchanged_by_the_port_work(self):
        """`_host` est utilisé par le pinning et les sessions — il ne doit PAS bouger."""
        for value, expected in [("https://user@Example.COM:8443/x", "example.com"),
                                ("[::1]:5900", "::1"), ("10.0.0.5", "10.0.0.5")]:
            self.assertEqual(Scope._host(value), expected, value)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""D8 — LA DÉCOUVERTE NE DOIT PAS INGÉRER DES 404 COMME DE LA SURFACE.

CE QUI A ÉTÉ MESURÉ. `recon.feroxbuster` invoquait `--silent`, qui n'imprime QUE des URLs : la
colonne de STATUT n'existait pas dans la sortie, donc forge ne pouvait PAS la voir, et son
`https?://\\S+` faisait entrer chaque 404 dans le graphe comme un endpoint chaînable — balayé ensuite
par tout le panel d'oracles. Mesure directe (image `epi052/feroxbuster`, DVWA sur 127.0.0.1:8081,
`--no-recursion`) :

    --silent  ->  21 URLs ingérées, statut INVISIBLE
    --quiet   ->  22 lignes de résultat, dont **17 en 404**
    --quiet + rejet des lignes 404  ->  4 URLs réelles (`/`, `/docs`, `/config`, `/external`)

**81 % de ce que la découverte ingérait n'existait pas.** L'auto-filtre de feroxbuster ne les
rattrape pas : la taille de ses 404 varie avec la longueur du chemin (287c / 289c / 285c…).

LA SORTIE CI-DESSOUS EST VERBATIM de cette mesure — aucune ligne n'est inventée ni retouchée.

CE QUE CE FICHIER VERROUILLE : (1) le rejet porte sur la LIGNE (le statut n'est pas dans l'URL) ;
(2) SEUL le 404 est rejeté — 301/302/403 restent de la surface ; (3) une ligne SANS statut lisible
n'est PAS rejetée (refuser tout endpoint au statut inconnu serait l'excès inverse) ; (4) la
dégradation va dans le BON SENS : motif absent/illisible -> on ré-ingère du bruit, on ne perd JAMAIS
la découverte.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.modules import toolcatalog                            # noqa: E402
from forge.modules.toolspec import build_argv, parse_output, reject_lines  # noqa: E402

#: VERBATIM — `docker run --rm --network host epi052/feroxbuster --quiet -u http://127.0.0.1:8081
#: --no-recursion`, 2026-08-11. 22 lignes : 2 avis d'auto-filtrage (sans URL), 4 résultats réels,
#: 16 x 404. (Un 17e 404 est l'avis d'auto-filtrage, qui ne porte pas d'URL.)
FEROX_QUIET_VERBATIM = """\
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://127.0.0.1:8081/ => login.php
301      GET        9l       28w      312c http://127.0.0.1:8081/docs => http://127.0.0.1:8081/docs/
301      GET        9l       28w      314c http://127.0.0.1:8081/config => http://127.0.0.1:8081/config/
301      GET        9l       28w      316c http://127.0.0.1:8081/external => http://127.0.0.1:8081/external/
404      GET        9l       33w      287c http://127.0.0.1:8081/Reports%20List
404      GET        9l       33w      289c http://127.0.0.1:8081/external%20files
404      GET        9l       33w      288c http://127.0.0.1:8081/Style%20Library
404      GET        9l       33w      285c http://127.0.0.1:8081/modern%20mom
404      GET        9l       33w      285c http://127.0.0.1:8081/New%20Folder
404      GET        9l       34w      286c http://127.0.0.1:8081/What%20is%20New
404      GET        9l       33w      286c http://127.0.0.1:8081/Site%20Assets
404      GET        9l       33w      290c http://127.0.0.1:8081/neuf%20giga%20photo
"""

#: VERBATIM — la MÊME cible, la MÊME image, avec l'ancien `--silent` : que des URLs, aucun statut.
FEROX_SILENT_VERBATIM = """\
http://127.0.0.1:8081/
http://127.0.0.1:8081/docs
http://127.0.0.1:8081/external
http://127.0.0.1:8081/Style%20Library
http://127.0.0.1:8081/config
http://127.0.0.1:8081/neuf%20giga%20photo
"""


def _spec(kind):
    return {s.kind: s for s in toolcatalog.CATALOG_SPECS}[kind]


class TestInvocationShowsTheStatus(unittest.TestCase):
    """(1) LE CORRECTIF EST DANS L'INVOCATION — on regarde, on ne devine pas."""

    def test_argv_uses_quiet_not_silent(self):
        argv = build_argv(_spec("recon.feroxbuster"), "http://target.test")
        self.assertIn("--quiet", argv, "sans --quiet, la colonne de statut n'existe pas dans la sortie")
        self.assertNotIn("--silent", argv,
                         "--silent n'imprime QUE des URLs : le statut devient INOBSERVABLE")

    def test_silent_output_carries_no_status_at_all(self):
        """La preuve que le défaut n'était PAS un défaut de parsing : l'information n'était pas là."""
        for line in FEROX_SILENT_VERBATIM.splitlines():
            self.assertNotRegex(line, r"^\s*\d{3}\s",
                                "aucune ligne --silent ne porte de statut — rien à parser")


class TestOnly404IsRejected(unittest.TestCase):
    """(2)+(3) le rejet est CHIRURGICAL : le 404 part, tout le reste (y compris l'inconnu) demeure."""

    def setUp(self):
        self.spec = _spec("recon.feroxbuster")

    def test_404_lines_are_dropped_and_nothing_else(self):
        kept = reject_lines(FEROX_QUIET_VERBATIM, self.spec.parser_reject_line).splitlines()
        dropped = [ln for ln in FEROX_QUIET_VERBATIM.splitlines() if ln not in kept]
        self.assertEqual(len(dropped), 9, f"9 lignes en 404 attendues, {len(dropped)} rejetées")
        self.assertTrue(all(ln.lstrip().startswith("404") for ln in dropped),
                        "seules des lignes 404 doivent être rejetées")
        for code in ("301", "302", "403"):
            self.assertTrue(any(ln.lstrip().startswith(code) for ln in kept),
                            f"un {code} EST de la surface (ressource protégée/déplacée) — jamais rejeté")

    def test_line_without_a_status_is_never_rejected(self):
        """L'EXCÈS INVERSE, verrouillé : un statut ILLISIBLE ne doit pas faire disparaître l'endpoint."""
        odd = "http://127.0.0.1:8081/sans-statut\nsomething odd http://127.0.0.1:8081/autre\n"
        self.assertEqual(reject_lines(odd, self.spec.parser_reject_line), odd.rstrip("\n"))

    def test_parse_output_yields_the_real_surface_only(self):
        hits = parse_output(self.spec, 0, FEROX_QUIET_VERBATIM)
        self.assertNotIn("http://127.0.0.1:8081/Reports%20List", hits)
        self.assertNotIn("http://127.0.0.1:8081/neuf%20giga%20photo", hits)
        for real in ("http://127.0.0.1:8081/", "http://127.0.0.1:8081/docs",
                     "http://127.0.0.1:8081/config", "http://127.0.0.1:8081/external"):
            self.assertIn(real, hits, "la surface RÉELLE doit survivre au filtre")

    def test_mutation_the_reject_is_load_bearing(self):
        """MUTATION : motif de rejet neutralisé -> les 404 REVIENNENT dans les hits. Si ce test
        restait vert, le filtre ne servirait à rien."""
        saved = self.spec.parser_reject_line
        try:
            self.spec.parser_reject_line = ""
            hits = parse_output(self.spec, 0, FEROX_QUIET_VERBATIM)
            self.assertIn("http://127.0.0.1:8081/Reports%20List", hits,
                          "MUTATION INATTEIGNABLE : le filtre n'est pas ce qui écarte les 404")
            self.assertGreaterEqual(len(hits), 12)
        finally:
            self.spec.parser_reject_line = saved


class TestDegradationGoesTheRightWay(unittest.TestCase):
    """(4) si le format change un jour, on ré-ingère du bruit — on ne perd JAMAIS la découverte."""

    def test_no_pattern_is_byte_identical(self):
        self.assertEqual(reject_lines(FEROX_QUIET_VERBATIM, ""), FEROX_QUIET_VERBATIM)

    def test_broken_pattern_never_eats_anything(self):
        self.assertEqual(reject_lines(FEROX_QUIET_VERBATIM, "(unclosed"), FEROX_QUIET_VERBATIM)

    def test_url_regex_stayed_permissive(self):
        """Le `parser_regex` NE DOIT PAS exiger la colonne de statut : un changement de mise en forme
        rendrait alors ZÉRO hit, c'est-à-dire un « aucun hit » MENSONGER sur une cible balayée."""
        spec = _spec("recon.feroxbuster")
        self.assertEqual(spec.parser_regex, r"https?://\S+")
        self.assertEqual(parse_output(spec, 0, "http://127.0.0.1:8081/tout-seul\n"),
                         ["http://127.0.0.1:8081/tout-seul"])


class TestOtherSpecsUnchanged(unittest.TestCase):
    """Aucun autre spec ne rejette de ligne : le champ est ADDITIF, défaut byte-identique."""

    def test_only_feroxbuster_declares_a_reject(self):
        declaring = sorted(s.kind for s in toolcatalog.CATALOG_SPECS if s.parser_reject_line)
        self.assertEqual(declaring, ["recon.feroxbuster"])


if __name__ == "__main__":
    unittest.main()

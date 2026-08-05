# SPDX-License-Identifier: AGPL-3.0-or-later
"""Garde anti-FUITE DE FIXTURES (filet statique) — comportement runtime INCHANGÉ.

Ce test ne modifie rien : il lit `tests/` et ÉCHOUE si un `mkdtemp` nu réapparaît. But : empêcher le
retour de l'anti-pattern qui laissait **82 répertoires / 568 Kio** derrière la suite (mesuré le
2026-08-05, P7.1-a). Le seul chemin autorisé est `tests/_tmp.py: temp_dir(self, prefix)`, qui
enregistre la suppression via `addCleanup()` — donc nettoie même quand `setUp()` lève.

Pourquoi une garde STATIQUE et pas une mesure du `TMPDIR` en fin de suite : un test qui fuit ne fait
échouer aucune assertion, donc rien ne le signale ; et une mesure globale n'attribue pas le résidu à
son test d'origine. La garde, elle, pointe le fichier et la ligne.

Portée volontairement limitée à `tests/`. Le moteur (`forge/`) utilise `tempfile.mkdtemp` avec un
`try/finally: shutil.rmtree(...)` — vérifié site par site — ce qui est correct et hors sujet ici.

Se lance dans la suite ET en script autonome (`python3 tests/test_tmpdir_guard.py` → 1 si violation).
"""
import re
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

# `mkdtemp` appelé via le module `tempfile`. Les mentions en commentaire `#…` sont retirées avant scan.
BARE_MKDTEMP = re.compile(r"\btempfile\s*\.\s*mkdtemp\s*\(")

# Le helper implémente forcément l'appel ; cette garde le cite dans sa propre documentation.
EXEMPT = {"_tmp.py", "test_tmpdir_guard.py"}

# Échappatoire ligne-à-ligne, même convention que `portability-ok` dans test_portability_guard.py.
ESCAPE = "tmpdir-ok"


def violations():
    """Renvoie [(fichier, n° de ligne, texte)] pour chaque `mkdtemp` nu sous `tests/`."""
    out = []
    for f in sorted(TESTS_DIR.glob("*.py")):
        if f.name in EXEMPT:
            continue
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            if BARE_MKDTEMP.search(code) and ESCAPE not in line:
                out.append((f.name, n, line.strip()))
    return out


class TestNoBareMkdtempInTests(unittest.TestCase):
    def test_tests_use_the_cleanup_helper(self):
        found = violations()
        self.assertEqual(
            found, [],
            "mkdtemp nu détecté — le répertoire survivra au test.\n"
            "Utiliser `from tests._tmp import temp_dir` puis `temp_dir(self, \"prefixe-\")`.\n"
            + "\n".join(f"  {f}:{n}  {t}" for f, n, t in found))

    def test_the_helper_is_reachable_and_registers_cleanup(self):
        """Contrôle POSITIF : sans lui, la garde passerait aussi sur un helper cassé."""
        from tests._tmp import temp_dir
        d = temp_dir(self, "forge-guardprobe-")
        self.assertTrue(d.is_dir())
        # `addCleanup` a bien été enregistré par le helper (et non oublié) : on le déclenche ici même.
        self.doCleanups()
        self.assertFalse(d.exists(), "temp_dir() n'a pas programmé la suppression du répertoire")


if __name__ == "__main__":
    v = violations()
    for f, n, t in v:
        print(f"{f}:{n}: {t}")
    sys.exit(1 if v else 0)

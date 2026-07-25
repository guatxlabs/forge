"""Source de vérité UNIQUE de la version : `forge.__version__` == fichier `VERSION` (racine).

Garde-fou anti-dérive entre le fichier VERSION et le fallback codé en dur dans forge/__init__.py.
Vérifie aussi que la CLI `forge --version` imprime bien cette même version. `python -m unittest`
(stdlib, zéro dépendance, zéro réseau).
"""
import io
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import forge  # noqa: E402
from forge import cli  # noqa: E402


class TestVersion(unittest.TestCase):
    def test_version_matches_version_file(self):
        vfile = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertTrue(vfile, "fichier VERSION vide")
        self.assertEqual(forge.__version__, vfile)

    def test_version_is_semverish(self):
        self.assertRegex(forge.__version__, r"^\d+\.\d+\.\d+")

    def test_cli_version_flag_prints_version(self):
        # `argparse` action='version' imprime sur stdout puis lève SystemExit(0), même avec un
        # sous-parseur requis (l'action sort avant la validation du sous-parseur).
        buf = io.StringIO()
        with self.assertRaises(SystemExit) as cm, redirect_stdout(buf):
            cli.main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(forge.__version__, buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)

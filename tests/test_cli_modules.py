"""CLI `forge modules --json` — le catalogue machine-lisible exposé à la console/UI.

Couvre le RÉSIDU web_allowed : chaque row doit porter `web_allowed`, dérivé comme côté console
(`not (exploit or destructive)`) quand le module ne le déclare pas explicitement, et égal à la
valeur déclarée sinon. Cohérence avec la dérivation console qui pilote le plancher web du planner.

Hermétique : aucune sortie réseau (cmd_modules lit le REGISTRY + `.available` en lecture seule).
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import cli                                       # noqa: E402
from forge import modules as mods                           # noqa: E402


class _Args:
    """Stand-in pour argparse.Namespace : seul `json` est lu par cmd_modules."""
    def __init__(self, json=False):
        self.json = json


def _rows():
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.cmd_modules(_Args(json=True))
    assert rc == 0
    return json.loads(buf.getvalue())


class TestModulesJsonWebAllowed(unittest.TestCase):
    def test_every_row_carries_web_allowed_bool(self):
        rows = _rows()
        self.assertTrue(rows)
        for r in rows:
            self.assertIn("web_allowed", r, f"{r.get('kind')} sans web_allowed")
            self.assertIsInstance(r["web_allowed"], bool)

    def test_web_allowed_matches_declared_or_derived(self):
        # source de vérité : la valeur déclarée par le module si présente, sinon la dérivation
        # console `not (exploit or destructive)`. La row JSON DOIT refléter exactement cela.
        by_kind = {r["kind"]: r for r in _rows()}
        for k in mods.kinds():
            m = mods.get(k)
            expected = bool(getattr(m, "web_allowed", not (m.exploit or m.destructive)))
            self.assertEqual(by_kind[k]["web_allowed"], expected, f"web_allowed incohérent pour {k}")

    def test_known_module_values(self):
        # ancrage explicite : recon (scan pur) = web ; msf (exploit, opt-in opérateur) = non-web ;
        # idor (exploit mais déclaré web_allowed=True) suit la DÉCLARATION, pas la dérivation.
        by_kind = {r["kind"]: r for r in _rows()}
        self.assertTrue(by_kind["recon.httpx"]["web_allowed"])
        self.assertFalse(by_kind["msf.module"]["web_allowed"])
        self.assertTrue(by_kind["access_control.idor"]["web_allowed"])  # déclaré explicitement
        self.assertTrue(by_kind["burp.scan"]["web_allowed"])            # déclaré explicitement


if __name__ == "__main__":
    unittest.main(verbosity=2)

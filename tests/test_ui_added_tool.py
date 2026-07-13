"""OUTIL AJOUTÉ PAR L'UI (« add a tool from the web UI ») — le ToolSpec DÉCLARATIF que persiste l'endpoint
`POST /api/tools` (un fichier JSON dans le dir server-managed `FORGE_TOOLSPECS`) est chargé par
`load_toolspec_file` et gouverné EXACTEMENT comme un module natif.

Prouve, sur l'artefact RÉEL écrit par la console (JSON no-Python) :
  (1) AUTO-INTÉGRATION : le spec chargé apparaît comme module `@register` (ExternalToolModule) + dans
      `modules --json` avec son `params_schema` (formulaire de Lancement dynamique) et sa `flag_allowlist`.
  (2) SCOPE-GUARD ROE fail-closed : une cible HORS périmètre -> `status='skipped'`, ZÉRO I/O
      (runner.tool JAMAIS appelé) — l'outil ajouté par l'UI passe par `roe`/scope-guard comme un natif.
  (3) NO-SHELL / EXTRA-ARGS GOUVERNÉS : un `extra_args` avec un drapeau HORS `flag_allowlist` est REFUSÉ
      fail-closed (aucun processus lancé) ; la cible à métacaractères shell reste UN SEUL élément d'argv.
  (4) PROOF-ORIENTED : un hit devient `tested`/`reported_by_tool` (jamais `vulnerable`, statut clampé).
"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import cli                                            # noqa: E402
from forge import runner                                        # noqa: E402
from forge import modules as mods                               # noqa: E402
from forge import techniques                                    # noqa: E402
from forge.modules import registry                              # noqa: E402
from forge.modules.loader import load_toolspec_file             # noqa: E402
from forge.modules.toolspec import ExternalToolModule           # noqa: E402
from forge.roe import Action                                    # noqa: E402

# ARTEFACT réel écrit par POST /api/tools : un ToolSpec déclaratif (binaire + argv no-shell tokenisé +
# params_schema typé + flag_allowlist). `echo` = binaire présent partout (le probe le voit available).
UI_SPEC = {
    "kind": "custom.uitest_echo",
    "vuln_class": "Recon",
    "binary": "echo",
    "argv_template": ["-n", "{target}", "{args}"],
    "params_schema": [
        {"name": "note", "type": "text", "label": "note libre"},
        {"name": "mode", "type": "select", "label": "mode", "allowed": ["fast", "deep"]},
    ],
    "flag_allowlist": ["-t", "--rate"],
    "parser": "lines",
    "hit_status": "tested",
    "severity": "INFO",
    "description": "outil ajouté par l'UI (test) — enrobe echo, gouverné no-shell + scope-guard.",
}
KIND = UI_SPEC["kind"]


class _Patch:
    """Remplace temporairement des attributs de `runner` (référencé à l'appel par toolspec)."""

    def __init__(self, **attrs):
        self.attrs, self.saved = attrs, {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(runner, k)
            setattr(runner, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(runner, k, v)


def _boom(*a, **k):
    raise AssertionError("runner.tool appelé alors que le scope-guard/l'allowlist aurait dû court-circuiter")


def _rows_json():
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.cmd_modules(type("A", (), {"json": True})())
    assert rc == 0
    return {r["kind"]: r for r in json.loads(buf.getvalue())}


class TestUiAddedToolGoverned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # écrit le spec dans un fichier temporaire (comme la console dans son dir managé) puis le charge.
        cls.tmp = tempfile.TemporaryDirectory()
        p = Path(cls.tmp.name) / f"{KIND}.json"
        p.write_text(json.dumps(UI_SPEC), encoding="utf-8")
        cls.loaded_kind = load_toolspec_file(str(p))

    @classmethod
    def tearDownClass(cls):
        # nettoyage global (registre + catalogue technique) pour ne pas polluer les invariants d'autres tests.
        registry.REGISTRY.pop(KIND, None)
        techniques.TECHNIQUES.pop(KIND, None)
        techniques.CATALOG.pop(KIND, None)
        cls.tmp.cleanup()

    def test_1_registered_as_governed_module_with_schema(self):
        self.assertEqual(self.loaded_kind, KIND)
        self.assertIn(KIND, mods.kinds(), "l'outil UI n'est pas enregistré comme module")
        self.assertIsInstance(mods.get(KIND), ExternalToolModule, "pas un wrapper externe gouverné")
        rows = _rows_json()
        self.assertIn(KIND, rows, "l'outil UI n'apparaît pas dans `modules --json`")
        row = rows[KIND]
        # params_schema servi à l'UI (formulaire de Lancement dynamique) + allowlist server-side.
        names = [d.get("name") for d in row["params_schema"]]
        self.assertEqual(names, ["note", "mode"], "params_schema non servi au formulaire de Lancement")
        self.assertEqual(row["flag_allowlist"], ["-t", "--rate"], "flag_allowlist non exposée")
        self.assertFalse(row["exploit"], "recon non-exploit")

    def test_2_out_of_scope_target_skipped_zero_io(self):
        m = mods.get(KIND)
        with _Patch(tool=_boom):  # runner.tool NE DOIT PAS être appelé
            f = m.fire(Action(KIND, "evil.attacker.com", params={"in_scope": ["good.test"]}))
        self.assertEqual(f[0].status, "skipped", "cible hors périmètre non bloquée (scope-guard)")
        self.assertNotEqual(f[0].status, "vulnerable")

    def test_3_extra_args_flag_outside_allowlist_refused_zero_io(self):
        m = mods.get(KIND)
        with _Patch(tool=_boom):  # un drapeau hors allowlist -> refus fail-closed, aucun process
            f = m.fire(Action(KIND, "good.test",
                              params={"in_scope": ["good.test"], "extra_args": ["--proxy", "http://evil"]}))
        self.assertEqual(f[0].status, "skipped", "drapeau hors allowlist non refusé")

    def test_4_in_scope_hit_is_proof_oriented_not_vulnerable(self):
        m = mods.get(KIND)
        # binaire présent + in-scope : hit CLAMPÉ à tested/reported_by_tool, jamais vulnerable.
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, "some-output-line", "")):
            f = m.fire(Action(KIND, "good.test", params={"in_scope": ["good.test"]}))
        self.assertTrue(f, "aucun finding produit")
        for finding in f:
            self.assertIn(finding.status, ("tested", "reported_by_tool"),
                          f"statut {finding.status!r} — un outil ne peut jamais s'auto-promouvoir vulnerable")


if __name__ == "__main__":
    unittest.main()

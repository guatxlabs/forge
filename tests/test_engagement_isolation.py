"""Isolation PAR ENGAGEMENT au niveau du MOTEUR — le socle sur lequel repose la concurrence des runs
côté console.

La console lance chaque run avec `forge campaign --scope <scope de l'engagement> --ledger <ledger dédié
de l'engagement>`. Plusieurs engagements peuvent tourner EN MÊME TEMPS : chaque processus moteur reçoit
un `Scope` et un `Ledger` PROPRES à SON engagement. Ces tests prouvent, au niveau du moteur (stdlib, zéro
dépendance), que cette paramétrisation par chemin garantit l'isolation fail-closed :

  1. deux `Scope` chargés depuis deux fichiers scope.json DISTINCTS n'appliquent QUE leur propre
     périmètre — un run pour A ne peut PAS tirer contre une cible qui n'est que dans le scope de B
     (VETO dur), et réciproquement ;
  2. deux `Ledger` à deux chemins DISTINCTS n'écrivent QUE leur propre fichier — l'acte d'un run pour A
     n'apparaît JAMAIS dans le ledger de B, et chaque chaîne SHA-256 se vérifie indépendamment.

Ensemble : deux runs concurrents (un par engagement) sont isolés PAR CONSTRUCTION — chacun porte SON
scope-guard et SON ledger, jamais ceux d'un autre.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Roe, Action, VETO, DRY_RUN  # noqa: E402
from forge.ledger import Ledger  # noqa: E402


def write_scope(dirpath, name, in_scope):
    """Écrit un scope.json d'engagement (comme le fait run_create côté console) et renvoie son chemin."""
    p = Path(dirpath) / f"{name}.json"
    p.write_text(json.dumps({"mode": "grey", "in_scope": list(in_scope), "out_scope": []}),
                 encoding="utf-8")
    return str(p)


class TestPerEngagementScopeIsolation(unittest.TestCase):
    def test_each_scope_enforces_only_its_own_perimeter(self):
        with tempfile.TemporaryDirectory() as d:
            scope_a = Scope.load(write_scope(d, "engA", ["a.example.com"]))
            scope_b = Scope.load(write_scope(d, "engB", ["b.example.com"]))
            # A ne connaît QUE a.example.com ; B ne connaît QUE b.example.com.
            self.assertTrue(scope_a.is_in_scope("a.example.com"))
            self.assertFalse(scope_a.is_in_scope("b.example.com"),
                             "la cible de B n'est PAS dans le scope de A (isolation)")
            self.assertTrue(scope_b.is_in_scope("b.example.com"))
            self.assertFalse(scope_b.is_in_scope("a.example.com"),
                             "la cible de A n'est PAS dans le scope de B (isolation)")

    def test_roe_of_a_vetoes_target_only_in_b_scope(self):
        """PROBE : un run pour A (gate ROE construite sur le scope de A) ne peut PAS FIRER contre une
        cible qui n'existe que dans le scope de B — le scope-guard la VETO, même armé/approuvé."""
        with tempfile.TemporaryDirectory() as d:
            scope_a = Scope.load(write_scope(d, "engA", ["a.example.com"]))
            roe_a = Roe(scope_a)
            roe_a.arm()
            probe = Action("recon.http", "b.example.com")   # cible du SEUL scope de B
            roe_a.approve(probe.id)
            self.assertEqual(roe_a.decide(probe).verdict, VETO,
                             "A ne tire JAMAIS contre le périmètre de B (VETO dur)")
            # ... alors que sa PROPRE cible passe le scope-guard (DRY_RUN faute d'exploit — mais non VETO).
            own = Action("recon.http", "a.example.com")
            self.assertEqual(roe_a.decide(own).verdict, DRY_RUN,
                             "la cible de A passe SON scope-guard")


class TestPerEngagementLedgerIsolation(unittest.TestCase):
    def test_two_ledgers_write_only_their_own_file(self):
        with tempfile.TemporaryDirectory() as d:
            path_a = str(Path(d) / "engagement-A.jsonl")
            path_b = str(Path(d) / "engagement-B.jsonl")
            led_a = Ledger(path_a)
            led_b = Ledger(path_b)

            # Chaque run journalise dans SON ledger uniquement.
            led_a.append("run.start", {"engagement": "A", "run_id": "run-A-1"})
            led_a.append("run.end", {"engagement": "A", "run_id": "run-A-1"})
            led_b.append("run.start", {"engagement": "B", "run_id": "run-B-1"})

            txt_a = Path(path_a).read_text(encoding="utf-8")
            txt_b = Path(path_b).read_text(encoding="utf-8")

            # Isolation stricte : rien de A dans le fichier de B, et réciproquement.
            self.assertIn("run-A-1", txt_a)
            self.assertNotIn("run-A-1", txt_b, "l'acte de A n'apparaît JAMAIS dans le ledger de B")
            self.assertIn("run-B-1", txt_b)
            self.assertNotIn("run-B-1", txt_a, "l'acte de B n'apparaît JAMAIS dans le ledger de A")

            # Chaque chaîne SHA-256 se vérifie INDÉPENDAMMENT (tamper-evident, longueurs distinctes).
            va, vb = led_a.verify(), led_b.verify()
            self.assertTrue(va["ok"] and vb["ok"], "les deux chaînes de ledger sont intègres")
            self.assertEqual(va["entries"], 2, "le ledger de A a exactement SES 2 entrées")
            self.assertEqual(vb["entries"], 1, "le ledger de B a exactement SON entrée")

    def test_fresh_ledger_reopened_by_path_continues_its_own_chain(self):
        """Réouvrir un ledger PAR SON CHEMIN (comme un nouveau processus moteur au run suivant du MÊME
        engagement) reprend SA chaîne — sans jamais toucher celle d'un autre engagement."""
        with tempfile.TemporaryDirectory() as d:
            path_a = str(Path(d) / "engagement-A.jsonl")
            path_b = str(Path(d) / "engagement-B.jsonl")
            Ledger(path_a).append("run.start", {"engagement": "A"})
            Ledger(path_b).append("run.start", {"engagement": "B"})
            # 2e "processus" pour A : rouvre par chemin, ajoute, la chaîne reste valide et à 2 entrées.
            Ledger(path_a).append("run.end", {"engagement": "A"})
            va = Ledger(path_a).verify()
            vb = Ledger(path_b).verify()
            self.assertTrue(va["ok"] and vb["ok"])
            self.assertEqual(va["entries"], 2, "A a poursuivi SA chaîne (2 entrées)")
            self.assertEqual(vb["entries"], 1, "B est resté intact (1 entrée) pendant les runs de A")


if __name__ == "__main__":
    unittest.main()

"""Mémoire sémantique — dedup floue Jaccard (même cible + titre similaire) + fabrique make_memory."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.memory import Memory, JaccardMemory, make_memory  # noqa: E402
from forge.schema import Finding  # noqa: E402


def f(target, title, sev="HIGH"):
    return Finding(target=target, title=title, severity=sev)


class TestJaccard(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="forge-jac-"))

    def test_near_duplicate_same_target_deduped(self):
        m = JaccardMemory(self.dir / "m.jsonl", threshold=0.8)
        self.assertTrue(m.store(f("api.test/x", "SSRF in url parameter")))
        self.assertFalse(m.store(f("api.test/x", "SSRF in url parameter.")))   # reformulation -> fusionné
        self.assertEqual(m.stats()["records"], 1)

    def test_different_target_not_merged(self):
        m = JaccardMemory(self.dir / "m.jsonl")
        self.assertTrue(m.store(f("api.test/orders/1", "IDOR sur la commande")))
        self.assertTrue(m.store(f("api.test/orders/2", "IDOR sur la commande")))  # cible distincte -> gardé
        self.assertEqual(m.stats()["records"], 2)

    def test_same_target_different_class_not_merged(self):
        m = JaccardMemory(self.dir / "m.jsonl")
        self.assertTrue(m.store(f("api.test/x", "SSRF in url parameter")))
        self.assertTrue(m.store(f("api.test/x", "SQL injection in login")))      # autre vuln -> gardé
        self.assertEqual(m.stats()["records"], 2)

    def test_persists_signatures(self):
        JaccardMemory(self.dir / "m.jsonl").store(f("t", "XXE via DOCTYPE"))
        m2 = JaccardMemory(self.dir / "m.jsonl")                                 # recharge depuis disque
        self.assertFalse(m2.store(f("t", "XXE via DOCTYPE !")))                   # index reconstruit -> dedup


class TestMakeMemory(unittest.TestCase):
    def test_modes(self):
        self.assertIsInstance(make_memory(mode="exact"), Memory)
        self.assertIsInstance(make_memory(mode="jaccard"), JaccardMemory)
        # faiss indisponible dans l'env système -> repli Jaccard (dégradation propre)
        mem = make_memory(mode="faiss")
        self.assertTrue(hasattr(mem, "store") and hasattr(mem, "seen"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

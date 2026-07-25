"""P2 (fin) — graphe d'engagement (world-model) + module origin.find. Hermétique."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                       # noqa: E402
from forge.engine import Engine                           # noqa: E402
from forge.graph import EngagementGraph                   # noqa: E402
from forge.schema import Finding, Target                  # noqa: E402
from forge.modules.origin import OriginFind, _in_cf       # noqa: E402
from forge import modules as mods                         # noqa: E402


class TestGraph(unittest.TestCase):
    def test_service_creates_node_and_edge(self):
        g = EngagementGraph()
        g.add_service("app.test", 443, name="https")
        self.assertEqual(g.summary()["service"], 1)
        self.assertEqual(g.summary()["host"], 1)                 # host auto-créé
        self.assertTrue(any(t == "exposes" for (_, t, _) in g.edges))

    def test_finding_linked_to_host(self):
        g = EngagementGraph()
        g.add_finding(Finding(target="app.test", title="IDOR", severity="HIGH"))
        self.assertEqual(g.summary()["finding"], 1)
        self.assertEqual(len(g.findings_for("app.test")), 1)
        self.assertIn("app.test", g.hosts())

    def test_to_dict_roundtrips_shape(self):
        g = EngagementGraph(); g.add_service("h", 80)
        d = g.to_dict()
        self.assertIn("nodes", d); self.assertIn("edges", d)
        self.assertTrue(any(n["kind"] == "service" for n in d["nodes"]))


class TestEngineGraph(unittest.TestCase):
    def test_fire_populates_graph(self):
        eng = Engine(Scope({"mode": "grey", "in_scope": ["app.test"]})); eng.arm()
        a = Action("demo.fingerprint", "app.test"); eng.approve(a.id)
        eng.execute(a)
        self.assertGreaterEqual(eng.graph.summary()["finding"], 1)
        self.assertIn("app.test", eng.graph.hosts())


class TestOrigin(unittest.TestCase):
    def test_registered_and_not_exploit(self):
        self.assertIn("origin.find", mods.kinds())
        self.assertFalse(mods.get("origin.find").exploit)

    def test_cf_range_detection(self):
        self.assertTrue(_in_cf("104.16.1.1"))                   # Cloudflare
        self.assertFalse(_in_cf("8.8.8.8"))                     # pas Cloudflare
        self.assertFalse(_in_cf("not-an-ip"))

    def test_dry_describes_pipeline(self):
        s = OriginFind().dry(Action("origin.find", "exemple.test"))
        self.assertIn("subfinder", s)
        self.assertIn("Host:", s)

    def test_available_is_bool(self):
        self.assertIsInstance(OriginFind().available, bool)     # reflète présence subfinder/httpx


if __name__ == "__main__":
    unittest.main(verbosity=2)

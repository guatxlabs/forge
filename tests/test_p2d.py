"""P3 — client console (payload). Hermétique (pas de réseau ; l'ingest live est testé à part)."""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import console_client                          # noqa: E402
from forge.schema import Finding                          # noqa: E402


class TestConsoleClient(unittest.TestCase):
    def test_build_payload_converts_findings(self):
        p = console_client.build_payload(
            "camp1",
            [Finding(target="1.2.3.4", title="Origine exposée", severity="HIGH", mitre="T1590.005")],
            [{"target": "app.test", "kind": "origin.find", "mitre": "T1590.005", "fired": True}])
        self.assertEqual(p["campaign"], "camp1")
        self.assertEqual(p["findings"][0]["target"], "1.2.3.4")
        self.assertEqual(p["findings"][0]["mitre"], "T1590.005")
        self.assertEqual(p["run_records"][0]["kind"], "origin.find")

    def test_build_payload_defaults_empty(self):
        p = console_client.build_payload(None, None, None)
        self.assertEqual(p["campaign"], "default")
        self.assertEqual(p["findings"], [])
        self.assertEqual(p["run_records"], [])

    def test_base_url_env(self):
        os.environ["FORGE_CONSOLE_URL"] = "http://example.test:9999/"
        try:
            self.assertEqual(console_client.base_url(), "http://example.test:9999")
        finally:
            del os.environ["FORGE_CONSOLE_URL"]


if __name__ == "__main__":
    unittest.main(verbosity=2)

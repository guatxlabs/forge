"""mock_plume (DEMO FIXTURE stub of the Plume SOC detections API) — hermetic, stdlib only.

Boots the stub on an ephemeral localhost port in a background thread and drives the SAME contract
the Forge console consumes (`GET /api/coverage/detections?since=...`). Proves:
  - the response is well-formed JSON with a `detections` array of MITRE-tagged objects
    ({mitre, count, first_ts}) — the field names the console's fetch_purple_coverage() reads ;
  - the `since` window filters out older detections (matches a real SOC windowed query) ;
  - the stub is clearly labelled a demo fixture (`_demo`, `_warning`) — never mistaken for a real SOC ;
  - `load_detections` parses the bundled reference-engagement seed and rejects malformed lines.
No real network target, no real SOC — a localhost thread the test tears down.
"""
import json
import sys
import threading
import unittest
import urllib.request
from pathlib import Path

# le stub vit dans tools/ (pas un package) -> on ajoute tools/ au path pour l'importer nu.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mock_plume  # noqa: E402

REF_DIR = Path(__file__).resolve().parents[1] / "examples" / "reference-engagement"
SEED = REF_DIR / "detections.jsonl"


class _StubServer:
    """Context manager : démarre make_server sur un port éphémère (0) dans un thread, expose l'URL."""

    def __init__(self, detections):
        self.detections = detections
        self.httpd = None
        self.thread = None

    def __enter__(self):
        self.httpd = mock_plume.make_server("127.0.0.1", 0, self.detections, quiet=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def get(self, path):
        url = f"http://127.0.0.1:{self.port}{path}"
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, json.loads(r.read().decode("utf-8"))

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class TestLoadDetections(unittest.TestCase):
    def test_parses_bundled_seed(self):
        dets = mock_plume.load_detections(SEED)
        self.assertTrue(dets, "le seed d'engagement de référence doit contenir des détections")
        for d in dets:
            self.assertRegex(d["mitre"], r"^T\d{4}(\.\d{3})?$", "chaque détection est taggée MITRE ATT&CK")
            self.assertIsInstance(d["count"], int)
            self.assertIsInstance(d["first_ts"], int)

    def test_rejects_line_without_mitre(self):
        bad = Path(self.__class__.__name__ + "_bad.jsonl")
        bad.write_text('{"count":1,"first_ts":1}\n', encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                mock_plume.load_detections(bad)
        finally:
            bad.unlink()


class TestStubResponds(unittest.TestCase):
    def test_serves_mitre_tagged_detections(self):
        seed = mock_plume.load_detections(SEED)
        with _StubServer(seed) as srv:
            status, body = srv.get("/api/coverage/detections?since=0")
        self.assertEqual(status, 200)
        self.assertIn("detections", body)
        self.assertEqual(len(body["detections"]), len(seed))
        # contrat lu par la console : chaque détection porte mitre / count / first_ts.
        mitres = {d["mitre"] for d in body["detections"]}
        self.assertIn("T1595", mitres)
        for d in body["detections"]:
            self.assertRegex(d["mitre"], r"^T\d{4}(\.\d{3})?$")
            self.assertIn("count", d)
            self.assertIn("first_ts", d)

    def test_labelled_as_demo_fixture(self):
        with _StubServer(mock_plume.load_detections(SEED)) as srv:
            _, body = srv.get("/api/coverage/detections?since=0")
        self.assertTrue(body.get("_demo"), "la réponse doit se déclarer DEMO FIXTURE")
        self.assertIn("NOT a real SOC", body.get("_warning", ""))

    def test_since_window_filters_older(self):
        seed = mock_plume.load_detections(SEED)
        cutoff = max(d["first_ts"] for d in seed)  # ne garde QUE la détection la plus récente
        with _StubServer(seed) as srv:
            _, body = srv.get(f"/api/coverage/detections?since={cutoff}")
        self.assertEqual(len(body["detections"]), 1)
        self.assertEqual(body["detections"][0]["first_ts"], cutoff)

    def test_health_ok(self):
        with _StubServer([]) as srv:
            status, body = srv.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertTrue(body.get("_demo"))


if __name__ == "__main__":
    unittest.main()

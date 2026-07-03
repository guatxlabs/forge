"""Tests du collecteur de détections infra-agnostique (forge/detections.py + `forge.cli detections`).

Couvre : normalisation `[{mitre,count,first_ts}]`, agrégation (count sommé, first_ts=min), mapping de
champs natifs (records/mitre/ts/count), file_jsonl, exec (no-shell), syslog (règles regex), fail-open
sur mauvaise config, et RÉDACTION du secret dans les messages d'erreur.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from forge import detections as det

PKG_DIR = Path(__file__).resolve().parent.parent


def _run_cli(source_json, since=0):
    """Lance `forge.cli detections` avec la source passée par env (comme la console Rust)."""
    env = dict(os.environ, FORGE_DETECTION_SOURCE=source_json)
    p = subprocess.run(
        [sys.executable, "-m", "forge.cli", "detections", "--since", str(since),
         "--source", "env:FORGE_DETECTION_SOURCE"],
        capture_output=True, cwd=str(PKG_DIR), env=env, text=True,
    )
    return p


class TestAggregate(unittest.TestCase):
    def test_aggregate_sums_count_and_min_ts(self):
        """count sommé par mitre, first_ts = min ; enregistrement sans mitre ignoré ; tri stable."""
        records = [
            {"mitre": "T1110", "first_ts": 1000},
            {"mitre": "T1110", "first_ts": 900},
            {"mitre": "T1046", "first_ts": 2000},
            {"first_ts": 5},  # pas de mitre -> ignoré
        ]
        rows = det._aggregate(records, {})
        self.assertEqual(rows, [
            {"mitre": "T1046", "count": 1, "first_ts": 2000},
            {"mitre": "T1110", "count": 2, "first_ts": 900},
        ])

    def test_mapping_fields_and_explicit_count(self):
        """mitre/ts/count remappés sur des champs natifs ; count explicite sommé (pas +1)."""
        records = [
            {"tech": "T1190", "seen": 1500, "hits": 4},
            {"tech": "T1190", "seen": 1200, "hits": 3},
        ]
        rows = det._aggregate(records, {"mitre": "tech", "ts": "seen", "count": "hits"})
        self.assertEqual(rows, [{"mitre": "T1190", "count": 7, "first_ts": 1200}])

    def test_ts_iso_and_ms_normalised(self):
        """ISO-8601 et epoch-ms sont ramenés à l'epoch s."""
        self.assertEqual(det._to_epoch("1970-01-01T00:00:42Z"), 42)
        self.assertEqual(det._to_epoch(1000_000_000_000 * 2), 2_000_000_000)  # ms -> s
        self.assertEqual(det._to_epoch("bogus"), 0)


class TestFileJsonl(unittest.TestCase):
    def test_file_jsonl_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "det.jsonl"
            f.write_text('{"tech":"T1110","when":1000}\n\n'
                         '{"tech":"T1110","when":900}\n'
                         'not-json-ignored\n'
                         '{"tech":"T1046","when":2000}\n', encoding="utf-8")
            source = {"kind": "file_jsonl", "endpoint": str(f),
                      "mapping": {"mitre": "tech", "ts": "when"}}
            rows = det.collect(source, 0)
            self.assertEqual(rows, [
                {"mitre": "T1046", "count": 1, "first_ts": 2000},
                {"mitre": "T1110", "count": 2, "first_ts": 900},
            ])


class TestExec(unittest.TestCase):
    def test_exec_stdout_json_mapped(self):
        payload = json.dumps({"results": [{"mitre": "T1190", "first_ts": 1500, "count": 4}]})
        source = {"kind": "exec", "cmd": ["printf", "%s", payload],
                  "mapping": {"records": "results", "count": "count"}}
        rows = det.collect(source, 0)
        self.assertEqual(rows, [{"mitre": "T1190", "count": 4, "first_ts": 1500}])

    def test_exec_nonzero_raises(self):
        source = {"kind": "exec", "cmd": ["false"]}
        with self.assertRaises(ValueError):
            det.collect(source, 0)


class TestSyslog(unittest.TestCase):
    def test_syslog_rules_count_and_ts_group(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "fw.log"
            f.write_text(
                "ts=100 attack=bruteforce user=x\n"
                "ts=50 attack=bruteforce\n"
                "ts=300 msg=failed password for root\n"
                "benign line\n", encoding="utf-8")
            source = {"kind": "fortigate_syslog", "endpoint": str(f), "mapping": {"rules": [
                {"match": r"attack=bruteforce.*?ts=(?P<ts>\d+)|ts=(?P<ts2>\d+).*?attack=bruteforce", "mitre": "T1110"},
                {"match": r"ts=(?P<ts>\d+).*failed password", "mitre": "T1078"},
            ]}}
            rows = det.collect(source, 0)
            by = {r["mitre"]: r for r in rows}
            self.assertEqual(by["T1110"]["count"], 2, "deux lignes bruteforce")
            self.assertEqual(by["T1078"]["count"], 1)
            self.assertEqual(by["T1078"]["first_ts"], 300)

    def test_syslog_requires_rules(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "fw.log"
            f.write_text("x\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                det.collect({"kind": "pfsense", "endpoint": str(f)}, 0)


class TestFailOpenAndSecret(unittest.TestCase):
    def test_bad_kind_cli_exit_nonzero_stdout_empty(self):
        p = _run_cli(json.dumps({"kind": "nope"}))
        self.assertNotEqual(p.returncode, 0, "kind non supporté -> code non nul (fail-open)")
        self.assertEqual(p.stdout.strip(), "", "stdout vide -> pas de couverture inventée")

    def test_secret_never_leaks_in_error(self):
        """Une source http injoignable AVEC secret : le message d'erreur (stderr) ne contient JAMAIS le
        secret (rédaction). Port 1 -> connexion refusée immédiate."""
        secret = "SUPERSECRETTOKEN123456"
        source = {"kind": "generic_http", "endpoint": "http://127.0.0.1:1/x",
                  "auth": {"type": "bearer", "secret": secret}}
        # safe_error direct
        try:
            det.collect(source, 0)
            self.fail("attendu: exception (source injoignable)")
        except Exception as e:  # noqa: BLE001
            self.assertNotIn(secret, det.safe_error(e, source))
        # bout-en-bout via la CLI : ni stdout ni stderr ne contiennent le secret.
        p = _run_cli(json.dumps(source))
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn(secret, p.stdout)
        self.assertNotIn(secret, p.stderr)

    def test_load_source_env_and_literal(self):
        os.environ["FORGE_TEST_DS"] = json.dumps({"kind": "none"})
        try:
            self.assertEqual(det.load_source("env:FORGE_TEST_DS")["kind"], "none")
        finally:
            del os.environ["FORGE_TEST_DS"]
        self.assertEqual(det.load_source('{"kind":"exec"}')["kind"], "exec")
        with self.assertRaises(ValueError):
            det.load_source("[1,2,3]")  # non-objet


if __name__ == "__main__":
    unittest.main()

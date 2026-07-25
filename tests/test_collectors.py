"""Tests du paquet `forge.collectors` — collecteurs de détection infra-agnostiques (une classe par
`kind`) + sous-commande `forge.cli detections`.

Couvre, pour chaque collecteur : NORMALISATION d'un payload natif représentatif via `mapping` en
`[{mitre,count,first_ts}]` ; contrat NE-LÈVE-JAMAIS (`fetch()` -> `[]` + `doctor()` ok=False sur
erreur) ; distinction « joignable mais vide » (reachable=True) vs « injoignable » (reachable=False) ;
sécurité `exec` (no-shell + timeout + pas d'injection d'env/secret) ; round-trip CLI ; rédaction du
secret. Réseau/subprocess/fichier mockés ou pointés sur des cibles inertes.
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import collectors                       # noqa: E402
from forge.collectors import base                  # noqa: E402
from forge import cli                              # noqa: E402

PKG_DIR = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------------------------------
# Faux transport HTTP (un seul point de patch : forge.collectors.base.urllib.request.urlopen)
# --------------------------------------------------------------------------------------------------
class _Resp:
    def __init__(self, body):
        self._b = body.encode("utf-8") if isinstance(body, str) else body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urlopen(body, captured=None):
    def _open(req, timeout=None, context=None):
        if captured is not None:
            captured.append(req)
        return _Resp(body)
    return _open


def _raise_urlopen(*_a, **_k):
    raise urllib.error.URLError("connexion refusée (test)")


class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _run_cli(source_json, since=0):
    """Spawne `forge.cli detections` comme la console Rust (config via env, jamais argv)."""
    env = dict(os.environ, FORGE_DETECTION_SOURCE=source_json)
    return subprocess.run(
        [sys.executable, "-m", "forge.cli", "detections", "--since", str(since),
         "--source", "env:FORGE_DETECTION_SOURCE"],
        capture_output=True, cwd=str(PKG_DIR), env=env, text=True,
    )


# --------------------------------------------------------------------------------------------------
# Registre / dispatch
# --------------------------------------------------------------------------------------------------
class TestRegistry(unittest.TestCase):
    def test_all_expected_kinds_registered(self):
        for k in ("plume", "generic_http", "crowdsec", "elastic", "opensearch",
                  "fortigate_syslog", "pfsense", "opnsense", "file_jsonl", "exec"):
            self.assertIn(k, collectors.kinds(), k)
            self.assertIsNotNone(collectors.get_collector({"kind": k}), k)

    def test_unknown_kind_returns_none(self):
        self.assertIsNone(collectors.get_collector({"kind": "nope"}))
        self.assertIsNone(collectors.get_collector("not-a-dict"))


# --------------------------------------------------------------------------------------------------
# generic_http + plume (transport mocké)
# --------------------------------------------------------------------------------------------------
class TestGenericHttp(unittest.TestCase):
    def test_native_signature_table_normalised(self):
        payload = [
            {"sig": "waf-sqli", "ts": 1500}, {"sig": "waf-sqli", "ts": 1200},
            {"sig": "waf-scan", "ts": 2000}, {"sig": "unmapped", "ts": 5},
        ]
        source = {"kind": "generic_http", "endpoint": "http://fw.local/api?fmt=json",
                  "query": "since={since}",
                  "mapping": {"field": "sig", "ts": "ts",
                              "table": {"waf-sqli": "T1190", "waf-scan": "T1046"}}}
        cap = []
        with mock.patch.object(base.urllib.request, "urlopen", _fake_urlopen(json.dumps(payload), cap)):
            rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "T1046", "count": 1, "first_ts": 2000},
                                {"mitre": "T1190", "count": 2, "first_ts": 1200}])
        self.assertIn("since=0", cap[0].full_url)   # {since} substitué dans la query

    def test_bearer_auth_header_set(self):
        source = {"kind": "generic_http", "endpoint": "http://x/y",
                  "auth": {"type": "bearer", "secret": "TKN"}, "mapping": {"records": "detections"}}
        cap = []
        with mock.patch.object(base.urllib.request, "urlopen",
                               _fake_urlopen('{"detections":[]}', cap)):
            collectors.get_collector(source).fetch(0)
        self.assertTrue(any(v == "Bearer TKN" for _, v in cap[0].header_items()))

    def test_plume_preset_identity_mapping(self):
        payload = {"detections": [{"mitre": "T1110", "count": 3, "first_ts": 42}]}
        source = {"kind": "plume", "endpoint": "http://plume.local",
                  "auth": {"type": "basic", "secret": "dXNlcjpwYXNz"}}
        cap = []
        with mock.patch.object(base.urllib.request, "urlopen", _fake_urlopen(json.dumps(payload), cap)):
            rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "T1110", "count": 3, "first_ts": 42}])
        self.assertIn("/api/coverage/detections?since=0", cap[0].full_url)

    def test_unreachable_returns_empty_not_raise(self):
        source = {"kind": "generic_http", "endpoint": "http://x/y",
                  "auth": {"type": "bearer", "secret": "SECRETVALUE1234"}}
        col = collectors.get_collector(source)
        with mock.patch.object(base.urllib.request, "urlopen", _raise_urlopen):
            rows = col.fetch(0)
            d = col.doctor()
        self.assertEqual(rows, [])
        self.assertFalse(col.reachable)
        self.assertFalse(d["ok"])
        self.assertNotIn("SECRETVALUE1234", d["detail"])   # secret rédigé

    def test_missing_endpoint_config_error(self):
        col = collectors.get_collector({"kind": "generic_http"})
        self.assertIsNotNone(col.config_error())
        self.assertEqual(col.fetch(0), [])
        self.assertFalse(col.reachable)


# --------------------------------------------------------------------------------------------------
# crowdsec (LAPI, X-Api-Key, scénario -> MITRE)
# --------------------------------------------------------------------------------------------------
class TestCrowdSec(unittest.TestCase):
    def test_scenario_table_and_apikey_header(self):
        payload = [
            {"scenario": "crowdsecurity/ssh-bf", "created_at": "1970-01-01T00:00:10Z"},
            {"scenario": "crowdsecurity/ssh-bf", "created_at": "1970-01-01T00:00:05Z"},
            {"scenario": "crowdsecurity/http-probing", "created_at": "1970-01-01T00:00:20Z"},
            {"scenario": "crowdsecurity/unknown", "created_at": "1970-01-01T00:00:01Z"},
        ]
        source = {"kind": "crowdsec", "endpoint": "http://127.0.0.1:8080",
                  "auth": {"type": "api_key_header", "secret": "LAPIKEY"},
                  "mapping": {"table": {"crowdsecurity/ssh-bf": "T1110",
                                        "crowdsecurity/http-probing": "T1595"}}}
        cap = []
        with mock.patch.object(base.urllib.request, "urlopen", _fake_urlopen(json.dumps(payload), cap)):
            rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "T1110", "count": 2, "first_ts": 5},
                                {"mitre": "T1595", "count": 1, "first_ts": 20}])
        self.assertIn("/v1/decisions", cap[0].full_url)     # chemin LAPI par défaut
        items = {k.lower(): v for k, v in cap[0].header_items()}
        self.assertEqual(items.get("x-api-key"), "LAPIKEY")

    def test_missing_table_is_config_error_no_guess(self):
        source = {"kind": "crowdsec", "endpoint": "http://127.0.0.1:8080"}
        col = collectors.get_collector(source)
        self.assertIn("mapping.table", col.config_error())
        self.assertEqual(col.fetch(0), [])
        self.assertFalse(col.doctor()["ok"])


# --------------------------------------------------------------------------------------------------
# elastic / opensearch (POST, hits.hits, chemins _source)
# --------------------------------------------------------------------------------------------------
class TestElastic(unittest.TestCase):
    def _payload(self):
        return {"hits": {"hits": [
            {"_source": {"rule": {"name": "SSH Brute Force"}, "@timestamp": "1970-01-01T00:00:10Z"}},
            {"_source": {"rule": {"name": "SSH Brute Force"}, "@timestamp": "1970-01-01T00:00:05Z"}},
            {"_source": {"rule": {"name": "Port Scan"}, "@timestamp": "1970-01-01T00:00:20Z"}},
        ]}}

    def test_elastic_hits_mapped_via_source_paths(self):
        source = {"kind": "elastic", "endpoint": "http://es.local:9200/detections/_search",
                  "mapping": {"field": "_source.rule.name", "ts": "_source.@timestamp",
                              "table": {"SSH Brute Force": "T1110", "Port Scan": "T1046"}}}
        cap = []
        with mock.patch.object(base.urllib.request, "urlopen", _fake_urlopen(json.dumps(self._payload()), cap)):
            rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "T1046", "count": 1, "first_ts": 20},
                                {"mitre": "T1110", "count": 2, "first_ts": 5}])
        self.assertEqual(cap[0].get_method(), "POST")
        self.assertIsNotNone(cap[0].data)              # corps de requête ES envoyé

    def test_opensearch_same_dialect(self):
        source = {"kind": "opensearch", "endpoint": "http://os.local:9200/d/_search",
                  "mapping": {"field": "_source.rule.name", "ts": "_source.@timestamp",
                              "table": {"Port Scan": "T1046"}}}
        with mock.patch.object(base.urllib.request, "urlopen", _fake_urlopen(json.dumps(self._payload()))):
            rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "T1046", "count": 1, "first_ts": 20}])


# --------------------------------------------------------------------------------------------------
# syslog : fortigate_syslog + pfsense/opnsense (filterlog fichier + REST)
# --------------------------------------------------------------------------------------------------
class TestSyslog(unittest.TestCase):
    def test_fortigate_regex_rules(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "fw.log"
            f.write_text("attackname=bruteforce ts=100\nattackname=bruteforce ts=50\n"
                         "action=deny ts=300 msg=port scan\nbenign\n", encoding="utf-8")
            source = {"kind": "fortigate_syslog", "endpoint": str(f), "mapping": {"rules": [
                {"match": r"attackname=bruteforce ts=(?P<ts>\d+)", "mitre": "T1110"},
                {"match": r"ts=(?P<ts>\d+).*port scan", "mitre": "T1046"},
            ]}}
            rows = {r["mitre"]: r for r in collectors.get_collector(source).fetch(0)}
        self.assertEqual(rows["T1110"]["count"], 2)
        self.assertEqual(rows["T1110"]["first_ts"], 50)
        self.assertEqual(rows["T1046"]["count"], 1)
        self.assertEqual(rows["T1046"]["first_ts"], 300)

    def test_pfsense_file_requires_rules(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "filter.log"
            f.write_text("x\n", encoding="utf-8")
            col = collectors.get_collector({"kind": "pfsense", "endpoint": str(f)})
            self.assertIn("mapping.rules", col.config_error())
            self.assertEqual(col.fetch(0), [])
            self.assertFalse(col.reachable)

    def test_opnsense_rest_mode(self):
        payload = [{"sig": "block", "ts": 111}, {"sig": "block", "ts": 90}]
        source = {"kind": "opnsense", "endpoint": "http://opn.local/api/diag/log",
                  "mapping": {"field": "sig", "ts": "ts", "table": {"block": "T1595"}}}
        with mock.patch.object(base.urllib.request, "urlopen", _fake_urlopen(json.dumps(payload))):
            rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "T1595", "count": 2, "first_ts": 90}])


# --------------------------------------------------------------------------------------------------
# file_jsonl
# --------------------------------------------------------------------------------------------------
class TestFileJsonl(unittest.TestCase):
    def test_jsonl_mapped(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "e.jsonl"
            f.write_text('{"tech":"T1078","when":30}\n\nnot-json\n{"tech":"T1078","when":10}\n',
                         encoding="utf-8")
            source = {"kind": "file_jsonl", "endpoint": str(f), "mapping": {"mitre": "tech", "ts": "when"}}
            rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "T1078", "count": 2, "first_ts": 10}])

    def test_missing_file_empty_not_raise(self):
        col = collectors.get_collector({"kind": "file_jsonl", "endpoint": "/nope/does/not/exist.jsonl"})
        self.assertEqual(col.fetch(0), [])
        self.assertFalse(col.reachable)

    def test_empty_but_readable_is_reachable(self):
        # « joignable mais vide » (SOC frais) : reachable=True, [] légitime (PAS injoignable).
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "empty.jsonl"
            f.write_text("", encoding="utf-8")
            col = collectors.get_collector({"kind": "file_jsonl", "endpoint": str(f)})
            rows = col.fetch(0)
        self.assertEqual(rows, [])
        self.assertTrue(col.reachable)
        self.assertTrue(col.doctor()["ok"])


# --------------------------------------------------------------------------------------------------
# exec — no-shell, timeout, pas d'injection d'env/secret
# --------------------------------------------------------------------------------------------------
class TestExec(unittest.TestCase):
    def test_exec_stdout_json_mapped(self):
        payload = json.dumps({"results": [{"mitre": "T1190", "first_ts": 1500, "count": 4}]})
        source = {"kind": "exec", "cmd": [sys.executable, "-c",
                                          f"import sys;sys.stdout.write({payload!r})"],
                  "mapping": {"records": "results", "count": "count"}}
        rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "T1190", "count": 4, "first_ts": 1500}])

    def test_exec_no_shell(self):
        # subprocess.run DOIT être appelé avec un argv liste + shell=False (jamais une string shell).
        captured = {}

        def _fake_run(argv, **kw):
            captured["argv"] = argv
            captured["kw"] = kw
            return subprocess.CompletedProcess(argv, 0, stdout=b'[{"mitre":"T1","first_ts":0}]', stderr=b"")

        source = {"kind": "exec", "cmd": ["mytool", "--since", "{since}"]}
        with mock.patch("forge.collectors.exec_cmd.subprocess.run", _fake_run):
            collectors.get_collector(source).fetch(7)
        self.assertIsInstance(captured["argv"], list)
        self.assertEqual(captured["argv"], ["mytool", "--since", "7"])   # {since} substitué, argv fixe
        self.assertFalse(captured["kw"].get("shell", False))             # NO-SHELL

    def test_exec_shell_metachars_not_interpreted(self):
        # un argument à métacaractères shell est passé LITTÉRALEMENT (pas d'expansion).
        source = {"kind": "exec", "cmd": [
            sys.executable, "-c",
            "import sys,json;print(json.dumps([{'mitre':sys.argv[1],'first_ts':0}]))",
            "T1190;echo pwned"]}
        rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "T1190;echo pwned", "count": 1, "first_ts": 0}])

    def test_exec_timeout_returns_empty(self):
        source = {"kind": "exec", "cmd": [sys.executable, "-c", "import time;time.sleep(5)"],
                  "timeout": 0.3}
        col = collectors.get_collector(source)
        rows = col.fetch(0)                 # doit revenir en ~0.3 s, pas 5 s, et ne pas lever
        self.assertEqual(rows, [])
        self.assertFalse(col.reachable)
        self.assertFalse(col.doctor()["ok"])

    def test_exec_no_env_injection_of_secret(self):
        # le secret de détection (FORGE_DETECTION_SOURCE) NE DOIT PAS fuiter dans l'env de l'enfant.
        child = ("import os,json;"
                 "m='LEAK' if os.environ.get('FORGE_DETECTION_SOURCE') else 'CLEAN';"
                 "print(json.dumps([{'mitre':m,'first_ts':1}]))")
        source = {"kind": "exec", "cmd": [sys.executable, "-c", child]}
        with mock.patch.dict(os.environ, {"FORGE_DETECTION_SOURCE": '{"kind":"exec","auth":{"secret":"x"}}'}):
            rows = collectors.get_collector(source).fetch(0)
        self.assertEqual(rows, [{"mitre": "CLEAN", "count": 1, "first_ts": 1}])

    def test_exec_nonzero_empty_not_raise(self):
        col = collectors.get_collector({"kind": "exec", "cmd": [sys.executable, "-c", "import sys;sys.exit(3)"]})
        self.assertEqual(col.fetch(0), [])
        self.assertFalse(col.reachable)


# --------------------------------------------------------------------------------------------------
# CLI round-trip (contrat fail-open lisible que la console spawne)
# --------------------------------------------------------------------------------------------------
class TestCliRoundTrip(unittest.TestCase):
    def test_file_jsonl_roundtrip_exit0(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "e.jsonl"
            f.write_text('{"mitre":"T1046","first_ts":9}\n', encoding="utf-8")
            src = json.dumps({"kind": "file_jsonl", "endpoint": str(f)})
            p = _run_cli(src)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), {"detections": [{"mitre": "T1046", "count": 1, "first_ts": 9}]})

    def test_empty_reachable_exit0_empty_detections(self):
        # joignable mais vide -> code 0 + {"detections":[]} (PAS un fail-open injoignable).
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "empty.jsonl"
            f.write_text("", encoding="utf-8")
            p = _run_cli(json.dumps({"kind": "file_jsonl", "endpoint": str(f)}))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), {"detections": []})

    def test_unreachable_exit_nonzero_stdout_empty(self):
        p = _run_cli(json.dumps({"kind": "file_jsonl", "endpoint": "/nope/x.jsonl"}))
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout.strip(), "")

    def test_unknown_kind_exit_nonzero(self):
        p = _run_cli(json.dumps({"kind": "totally-unknown"}))
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout.strip(), "")

    def test_secret_redacted_in_cli_error(self):
        secret = "SUPERSECRETTOKEN99887766"
        src = {"kind": "generic_http", "endpoint": "http://127.0.0.1:1/x",
               "auth": {"type": "bearer", "secret": secret}}
        p = _run_cli(json.dumps(src))
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn(secret, p.stdout)
        self.assertNotIn(secret, p.stderr)


# --------------------------------------------------------------------------------------------------
# doctor / doctor --purple généralisés à la source configurée
# --------------------------------------------------------------------------------------------------
class TestDoctorGeneralised(unittest.TestCase):
    def _capture(self, fn, args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = fn(args)
        return rc, buf.getvalue()

    def test_plain_doctor_shows_detection_source_row(self):
        # source non configurée -> ligne detection.source INERTE (available False), jamais de crash.
        env = {k: os.environ[k] for k in os.environ}
        env.pop("FORGE_DETECTION_SOURCE", None)
        env.pop("PLUME_URL", None)
        with mock.patch.dict(os.environ, env, clear=True):
            rc, out = self._capture(cli.cmd_doctor, _Args(purple=False, json=False))
        self.assertEqual(rc, 0)
        self.assertIn("detection.source", out)
        self.assertIn("INERTE", out)

    def test_doctor_json_appends_detection_row(self):
        env = {k: os.environ[k] for k in os.environ}
        env.pop("FORGE_DETECTION_SOURCE", None)
        env.pop("PLUME_URL", None)
        with mock.patch.dict(os.environ, env, clear=True):
            rc, out = self._capture(cli.cmd_doctor, _Args(purple=False, json=True))
        payload = json.loads(out)
        self.assertTrue(any(r.get("kind") == "detection.source" for r in payload))

    def test_purple_preflight_generalised_to_configured_source(self):
        # source file_jsonl JOIGNABLE + console injoignable -> source-reachable OK, rc=1 (console down).
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "e.jsonl"
            f.write_text('{"mitre":"T1046","first_ts":9}\n', encoding="utf-8")
            src = json.dumps({"kind": "file_jsonl", "endpoint": str(f)})
            with mock.patch.dict(os.environ, {"FORGE_DETECTION_SOURCE": src,
                                              "FORGE_CONSOLE_URL": "http://127.0.0.1:1"}):
                rc, out = self._capture(cli.cmd_doctor, _Args(purple=True, json=False, timeout=1.0))
        self.assertEqual(rc, 1)                       # console injoignable = critique
        self.assertIn("source-configured", out)
        self.assertIn("source-reachable", out)
        self.assertIn("OK", out)                      # la source, elle, est joignable


if __name__ == "__main__":
    unittest.main()

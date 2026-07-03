# SPDX-License-Identifier: AGPL-3.0-only
"""LOT MIGRATION — importateurs de scans (`forge/importers/`) : ingérer les sorties d'outils EXISTANTS
(nmap/nuclei/burp/httpx/ffuf/subfinder-amass/generic-json/generic-csv) en findings Forge SOUS la
gouvernance.

Garanties vérifiées :
  (A) ORIENTÉ PREUVE — chaque parseur transforme un échantillon représentatif en findings dont le
      `status` est {tested | reported_by_tool} et JAMAIS `vulnerable` (un import ne confirme rien) ;
      scanner à auto-déclaration -> reported_by_tool ; recon/découverte -> tested. CWE/ATT&CK dérivés.
  (B) AUTO-DÉTECTION — `detect_format` reconnaît chaque format depuis le contenu.
  (C) RÉDACTION — un secret présent dans le fichier n'entre JAMAIS dans un finding.
  (D) DURCISSEMENT XML — XXE / billion-laughs refusés ; XML légitime (DOCTYPE nmap nu) accepté.
  (E) SCOPE-GUARD — les findings hors périmètre sont JETÉS (défaut) ou MARQUÉS (flag, status=skipped).
  (F) CLI — `forge import --json` produit l'enveloppe {format, counts, findings}.
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import importers as I                     # noqa: E402
from forge.importers import _base                    # noqa: E402
from forge.roe import Scope                           # noqa: E402
from forge import cli                                 # noqa: E402

# --- échantillons représentatifs (petits mais réalistes) -------------------------------------------
NMAP = ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap">'
        '<host><address addr="93.184.216.34" addrtype="ipv4"/>'
        '<hostnames><hostname name="example.com" type="user"/></hostnames>'
        '<ports>'
        '<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx"/></port>'
        '<port protocol="tcp" portid="8080"><state state="closed"/></port>'
        '</ports></host></nmaprun>')

# nuclei JSONL avec un SECRET dans l'URL matched-at (doit être rédigé)
NUCLEI = ('{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"high",'
          '"classification":{"cwe-id":["CWE-78"],"cve-id":["CVE-2021-1234"]}},'
          '"host":"https://example.com","matched-at":"https://example.com/api?token=SUPERSECRET123456"}')

BURP = ('<issues burpVersion="2023.1"><issue>'
        '<name>SQL injection</name><host ip="93.184.216.34">https://example.com</host>'
        '<path>/search</path><severity>High</severity><confidence>Certain</confidence>'
        '<vulnerabilityClassifications>CWE-89: SQL Injection</vulnerabilityClassifications>'
        '<issueDetail>The &lt;b&gt;q&lt;/b&gt; parameter is injectable. Authorization: Bearer LEAKTOKEN99</issueDetail>'
        '</issue></issues>')

HTTPX = ('{"url":"https://example.com","host":"example.com","status_code":200,'
         '"webserver":"nginx","tech":["Nginx","PHP"],"title":"Home"}\n'
         '{"url":"https://api.example.com","host":"api.example.com","status_code":403}')

FFUF = ('{"commandline":"ffuf -w wl -u https://example.com/FUZZ","config":{"rate":0},'
        '"results":[{"input":{"FUZZ":"admin"},"position":1,"status":200,"length":42,'
        '"words":5,"url":"https://example.com/admin","host":"example.com"}]}')

HOSTS_TEXT = "api.example.com\nwww.example.com\n# a comment\nmail.example.com,crtsh\n"
HOSTS_JSONL = ('{"host":"a.example.com","input":"example.com","source":"crtsh"}\n'
               '{"host":"b.example.com","input":"example.com","source":"dns"}')

GENERIC_JSON = ('{"findings":[{"host":"c.example.com","name":"Weak TLS","severity":"medium","cwe":"CWE-326",'
                '"description":"TLS 1.0 enabled; api_key=SECRETKEY0001 seen"}]}')
GENERIC_CSV = ("target,name,severity,cwe,evidence\r\n"
               "d.example.com,Directory listing,low,CWE-548,index of /backup password=HUNTER2xx\r\n")


class TestProofOriented(unittest.TestCase):
    """(A) chaque parseur -> findings orientés preuve (jamais `vulnerable`), tool + taxonomie corrects."""

    def _no_vulnerable(self, findings):
        for f in findings:
            self.assertIn(f.status, ("tested", "reported_by_tool", "skipped"),
                          f"import ne doit jamais produire un statut hors preuve: {f.status}")
            self.assertNotEqual(f.status, "vulnerable", "un import ne CONFIRME jamais (pas de vulnerable)")

    def test_nmap_recon_tested(self):
        f = I.parse("nmap", NMAP)
        self.assertEqual(len(f), 1, "un finding par port OUVERT (le port fermé est ignoré)")
        self._no_vulnerable(f)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].tool, "nmap")
        self.assertEqual(f[0].target, "example.com")
        self.assertEqual(f[0].mitre, "T1046")

    def test_nuclei_reported_by_tool_with_cwe_and_mitre(self):
        f = I.parse("nuclei", NUCLEI)
        self.assertEqual(len(f), 1)
        self._no_vulnerable(f)
        self.assertEqual(f[0].status, "reported_by_tool", "un scanner s'auto-déclare -> reported_by_tool")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-78")
        self.assertTrue(f[0].mitre, "ATT&CK dérivé du CWE via la table unique")
        self.assertEqual(f[0].tool, "nuclei")

    def test_burp_reported_by_tool(self):
        f = I.parse("burp", BURP)
        self.assertEqual(len(f), 1)
        self._no_vulnerable(f)
        self.assertEqual(f[0].status, "reported_by_tool")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-89")
        self.assertEqual(f[0].target, "example.com")

    def test_httpx_recon_tested(self):
        f = I.parse("httpx", HTTPX)
        self.assertEqual(len(f), 2)
        self._no_vulnerable(f)
        self.assertTrue(all(x.status == "tested" and x.tool == "httpx" for x in f))
        self.assertEqual(f[0].target, "example.com")

    def test_ffuf_recon_tested(self):
        f = I.parse("ffuf", FFUF)
        self.assertEqual(len(f), 1)
        self._no_vulnerable(f)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].tool, "ffuf")
        self.assertEqual(f[0].target, "example.com")

    def test_hosts_text_and_jsonl(self):
        ft = I.parse("hosts", HOSTS_TEXT)
        self.assertEqual({x.target for x in ft}, {"api.example.com", "www.example.com", "mail.example.com"})
        self.assertTrue(all(x.status == "tested" and x.mitre == "T1590" for x in ft))
        fj = I.parse("hosts", HOSTS_JSONL)
        self.assertEqual({x.target for x in fj}, {"a.example.com", "b.example.com"})
        self._no_vulnerable(ft + fj)

    def test_generic_json_and_csv(self):
        fj = I.parse("generic-json", GENERIC_JSON)
        self.assertEqual(len(fj), 1)
        self.assertEqual(fj[0].status, "reported_by_tool", "sévérité>INFO ou CWE -> reported_by_tool")
        self.assertEqual(fj[0].cwe, "CWE-326")
        self.assertEqual(fj[0].target, "c.example.com")
        fc = I.parse("generic-csv", GENERIC_CSV)
        self.assertEqual(len(fc), 1)
        self.assertEqual(fc[0].cwe, "CWE-548")
        self.assertEqual(fc[0].target, "d.example.com")
        self._no_vulnerable(fj + fc)

    def test_generic_mapping_override(self):
        rows = '[{"asset_url":"e.example.com","check":"Cookie flags","risk":"low"}]'
        f = I.parse("generic-json", rows, mapping={"target": "asset_url", "title": "check", "severity": "risk"})
        self.assertEqual(f[0].target, "e.example.com")
        self.assertEqual(f[0].title, "Cookie flags")
        self.assertEqual(f[0].severity, "LOW")


class TestAutoDetect(unittest.TestCase):
    """(B) auto-détection du format depuis le contenu."""

    def test_detects_all(self):
        self.assertEqual(_base.detect_format(NMAP), "nmap")
        self.assertEqual(_base.detect_format(NUCLEI), "nuclei")
        self.assertEqual(_base.detect_format(BURP), "burp")
        self.assertEqual(_base.detect_format(HTTPX), "httpx")
        self.assertEqual(_base.detect_format(FFUF), "ffuf")
        self.assertEqual(_base.detect_format(HOSTS_TEXT), "hosts")
        self.assertEqual(_base.detect_format(HOSTS_JSONL), "hosts")
        self.assertEqual(_base.detect_format(GENERIC_CSV), "generic-csv")
        self.assertEqual(_base.detect_format(GENERIC_JSON), "generic-json")

    def test_parse_auto_returns_format(self):
        fmt, findings = I.parse_auto(NMAP)
        self.assertEqual(fmt, "nmap")
        self.assertTrue(findings)

    def test_undetectable_raises(self):
        self.assertIsNone(_base.detect_format("just some prose that is not a scan output"))
        with self.assertRaises(ValueError):
            I.parse_auto("random text")


class TestRedaction(unittest.TestCase):
    """(C) aucun secret du fichier n'entre dans un finding (Bearer, token, api_key, password)."""

    def test_nuclei_url_token_redacted(self):
        f = I.parse("nuclei", NUCLEI)
        blob = f[0].evidence + f[0].poc + f[0].title
        self.assertNotIn("SUPERSECRET123456", blob, "le token de l'URL doit être rédigé")

    def test_burp_bearer_redacted(self):
        f = I.parse("burp", BURP)
        self.assertNotIn("LEAKTOKEN99", f[0].evidence, "le Bearer du détail Burp doit être rédigé")

    def test_generic_secrets_redacted(self):
        fj = I.parse("generic-json", GENERIC_JSON)
        fc = I.parse("generic-csv", GENERIC_CSV)
        self.assertNotIn("SECRETKEY0001", fj[0].evidence)
        self.assertNotIn("HUNTER2xx", fc[0].evidence)

    def test_redact_common_patterns(self):
        self.assertNotIn("abcdef123456", _base.redact("Authorization: Bearer abcdef123456"))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", _base.redact("key AKIAIOSFODNN7EXAMPLE here"))


class TestXmlHardening(unittest.TestCase):
    """(D) XXE / billion-laughs refusés ; XML légitime accepté (le DOCTYPE nmap nu passe)."""

    def test_billion_laughs_blocked(self):
        bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
                '<!ENTITY lol2 "&lol;&lol;">]><nmaprun>&lol2;</nmaprun>')
        with self.assertRaises(ValueError):
            I.parse("nmap", bomb)

    def test_external_xxe_blocked(self):
        for x in ('<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://evil/x.dtd"><nmaprun></nmaprun>',
                  '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>'):
            with self.assertRaises(ValueError):
                I.parse("nmap", x)

    def test_legit_doctype_allowed(self):
        # nmap émet réellement `<!DOCTYPE nmaprun>` (sans entité) — il DOIT rester parsable.
        self.assertEqual(len(I.parse("nmap", NMAP)), 1)

    def test_body_cdata_entity_literal_not_false_positive(self):
        burp = ('<issues burpVersion="2"><issue><name>Doc</name><host>https://example.com</host>'
                '<path>/</path><severity>Low</severity>'
                '<issueDetail><![CDATA[text mentioning <!ENTITY in prose]]></issueDetail></issue></issues>')
        self.assertEqual(len(I.parse("burp", burp)), 1)


class TestScopeGuard(unittest.TestCase):
    """(E) scope-guard sur les findings importés : hors périmètre -> jeté (défaut) ou marqué (flag)."""

    SCOPE = Scope({"mode": "grey", "in_scope": ["*.example.com", "example.com"], "out_scope": []})

    def _findings(self):
        return (I.parse("nmap", NMAP)
                + I.parse("hosts", "api.example.com\nevil.attacker.test\n"))

    def test_out_of_scope_dropped_by_default(self):
        kept, counts = I.scope_filter(self._findings(), self.SCOPE)
        self.assertEqual(counts["out_of_scope"], 1, "evil.attacker.test est hors scope")
        self.assertTrue(all(self.SCOPE.is_in_scope(f.target) for f in kept), "les jetés sont exclus")
        self.assertNotIn("evil.attacker.test", {f.target for f in kept})

    def test_out_of_scope_flagged_when_requested(self):
        kept, counts = I.scope_filter(self._findings(), self.SCOPE, flag_out_of_scope=True)
        self.assertEqual(counts["emitted"], counts["parsed"], "flag conserve tout")
        flagged = [f for f in kept if f.target == "evil.attacker.test"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].status, "skipped", "hors-scope marqué -> neutralisé (skipped)")
        self.assertTrue(flagged[0].title.startswith("[HORS-SCOPE]"))

    def test_fail_closed_empty_scope_drops_all(self):
        empty = Scope({"mode": "grey", "in_scope": [], "out_scope": []})
        kept, counts = I.scope_filter(self._findings(), empty)
        self.assertEqual(kept, [], "scope in_scope vide => rien n'est en scope (fail-closed)")
        self.assertEqual(counts["in_scope"], 0)


class TestCli(unittest.TestCase):
    """(F) `forge import --json` -> enveloppe {format, counts, findings} ; --scope filtre."""

    def _run_json(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(argv)
        self.assertEqual(rc, 0)
        return json.loads(buf.getvalue())

    def test_import_json_envelope(self):
        p = Path(self.tmp) / "scan.xml"
        p.write_text(NMAP, encoding="utf-8")
        env = self._run_json(["import", "--file", str(p), "--format", "auto", "--json"])
        self.assertEqual(env["format"], "nmap")
        self.assertEqual(env["counts"]["parsed"], 1)
        self.assertEqual(len(env["findings"]), 1)
        self.assertEqual(env["findings"][0]["status"], "tested")

    def test_import_scope_drops_out_of_scope(self):
        scan = Path(self.tmp) / "hosts.txt"
        scan.write_text("api.example.com\nevil.test\n", encoding="utf-8")
        scope = Path(self.tmp) / "scope.json"
        scope.write_text(json.dumps({"mode": "grey", "in_scope": ["*.example.com"], "out_scope": []}), encoding="utf-8")
        env = self._run_json(["import", "--file", str(scan), "--scope", str(scope), "--json"])
        self.assertEqual(env["counts"]["out_of_scope"], 1)
        self.assertEqual(env["counts"]["emitted"], 1)
        self.assertEqual(env["findings"][0]["target"], "api.example.com")

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory(prefix="forge-import-test-")
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()


if __name__ == "__main__":
    unittest.main()

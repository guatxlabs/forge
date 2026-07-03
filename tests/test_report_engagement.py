# SPDX-License-Identifier: AGPL-3.0-only
"""Tests du générateur de rapport d'engagement agrégé (livrable client, forge/report_engagement.py).

Couvre : ISOLATION (le rapport de l'engagement A ne contient QUE des findings de A) · RÉDACTION des
secrets dans HTML/CSV/JSON/DOCX · round-trip CSV/JSON · DOCX = ZIP OOXML VALIDE (parts présentes,
document lisible) · dégradation gracieuse du PDF quand aucun moteur n'est présent · couverture ATT&CK
et annexe custody rendues · CLI stdin->stdout (chemin de délégation DOCX de la console Rust). Stdlib only.
"""
import csv
import io
import json
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import report_engagement as R  # noqa: E402

SECRET_AWS = "AKIAABCDEFGHIJKLMNOP"
SECRET_PWD = "Sup3rSecretValue123"
SECRET_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKLmnop"
SECRETS = [SECRET_AWS, SECRET_PWD, SECRET_JWT]


def finding(eid, sev="HIGH", title="IDOR sur /orders", target="a.example.com",
            vuln_class="idor", cwe="CWE-639", evidence="", poc="", fix="Contrôle d'accès par ressource.",
            status="vulnerable", mitre="T1190", tool="oracle.idor"):
    return {
        "engagement_id": eid, "severity": sev, "title": title, "target": target,
        "vuln_class": vuln_class, "category": vuln_class, "cwe": cwe, "mitre": mitre,
        "cvss_vector": "", "cvss_score": 0.0, "status": status, "tool": tool,
        "evidence": evidence, "poc": poc, "fix": fix, "campaign": "camp", "ts": "2026-07-03T00:00:00Z",
    }


def sample_data(engagement_id=1, findings=None):
    return {
        "branding": {"customer_name": "ACME Corp", "logo": "", "vendor": "GuatX Forge"},
        "engagement": {"id": engagement_id, "name": "ACME webapp Q3", "mode": "grey",
                       "status": "active", "scope_in": ["a.example.com"], "scope_out": []},
        "findings": findings if findings is not None else [],
        "runs": [{"run_id": "run-1", "campaign": "camp", "mode": "propose", "status": "done",
                  "started_by": "alice", "fired": 3, "dry_run": 1, "vetoed": 0, "errors": 0}],
        "attack": {"techniques": [{"mitre": "T1190", "kinds": ["oracle.idor"], "targets": ["a.example.com"],
                                   "fires": 2}],
                   "detection_source_configured": False},
        "custody": {"ledger_path": "/data/engagement-1.jsonl", "entries": 5,
                    "head": "abc123", "alg": "ed25519", "chain_ok": True,
                    "pubkey": "aa" * 32, "actor": "alice"},
    }


class TestRedaction(unittest.TestCase):
    def test_redacts_known_secret_shapes(self):
        text = (f"key {SECRET_AWS} pass password={SECRET_PWD} hdr Authorization: Bearer {SECRET_JWT}")
        red = R.redact_secrets(text)
        for s in SECRETS:
            self.assertNotIn(s, red, f"secret non rédigé: {s}")
        self.assertIn(R.REDACT, red)
        # idempotent
        self.assertEqual(R.redact_secrets(red), red)

    def test_non_string_passthrough(self):
        self.assertEqual(R.redact_secrets(None), None)
        self.assertEqual(R.redact_secrets(42), 42)


class TestIsolation(unittest.TestCase):
    def test_filter_selects_only_target_engagement(self):
        all_f = [finding(1, title="A-one"), finding(2, title="B-one"), finding(1, title="A-two")]
        a = R.filter_findings_for_engagement(all_f, 1)
        self.assertEqual({f["title"] for f in a}, {"A-one", "A-two"})
        b = R.filter_findings_for_engagement(all_f, 2)
        self.assertEqual({f["title"] for f in b}, {"B-one"})

    def test_report_contains_only_given_findings(self):
        # rapport de A : construit à partir des SEULS findings de A -> B n'apparaît nulle part.
        all_f = [finding(1, title="A-secretname", target="a.example.com"),
                 finding(2, title="B-secretname", target="b.example.com")]
        data = sample_data(1, R.filter_findings_for_engagement(all_f, 1))
        html = R.build_html(data)
        js = R.build_json(data)
        csv_out = R.build_csv(data)
        for blob in (html, js, csv_out):
            self.assertIn("A-secretname", blob)
            self.assertNotIn("B-secretname", blob, "fuite d'un finding d'un AUTRE engagement (isolation cassée)")
            self.assertNotIn("b.example.com", blob)


class TestRedactionInFormats(unittest.TestCase):
    def setUp(self):
        f = finding(1, evidence=f"leak {SECRET_AWS} and password={SECRET_PWD}",
                    poc=f"curl -H 'Authorization: Bearer {SECRET_JWT}' https://a.example.com")
        self.data = sample_data(1, [f])

    def _assert_clean(self, blob, label):
        for s in SECRETS:
            self.assertNotIn(s, blob, f"{label}: secret '{s}' non rédigé")
        self.assertIn(R.REDACT, blob, f"{label}: marqueur de rédaction absent")

    def test_html_redacted(self):
        self._assert_clean(R.build_html(self.data), "HTML")

    def test_csv_redacted(self):
        self._assert_clean(R.build_csv(self.data), "CSV")

    def test_json_redacted(self):
        self._assert_clean(R.build_json(self.data), "JSON")

    def test_docx_redacted(self):
        docx = R.build_docx(self.data)
        doc = zipfile.ZipFile(io.BytesIO(docx)).read("word/document.xml").decode("utf-8")
        self._assert_clean(doc, "DOCX")


class TestRoundTrip(unittest.TestCase):
    def test_csv_round_trip(self):
        f = finding(1, title="XSS stocké", evidence="param q reflété", status="vulnerable")
        data = sample_data(1, [f])
        rows = list(csv.reader(io.StringIO(R.build_csv(data))))
        self.assertEqual(rows[0], R._CSV_COLS, "en-tête CSV stable")
        self.assertEqual(len(rows), 2, "en-tête + 1 finding")
        rec = dict(zip(rows[0], rows[1]))
        self.assertEqual(rec["title"], "XSS stocké")
        self.assertEqual(rec["severity"], "HIGH")
        self.assertEqual(rec["vuln_class"], "idor")
        self.assertEqual(rec["status"], "vulnerable")

    def test_json_round_trip(self):
        f = finding(1, title="SSRF")
        data = sample_data(1, [f])
        parsed = json.loads(R.build_json(data))
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertEqual(parsed["findings"][0]["title"], "SSRF")
        self.assertEqual(parsed["summary"]["total"], 1)
        self.assertEqual(parsed["summary"]["by_severity"]["HIGH"], 1)
        self.assertIn("T1190", json.dumps(parsed["attack"]))


class TestSummary(unittest.TestCase):
    def test_counts_by_severity_class_status(self):
        fs = [finding(1, sev="CRITICAL", vuln_class="rce", status="vulnerable"),
              finding(1, sev="HIGH", vuln_class="idor", status="vulnerable"),
              finding(1, sev="HIGH", vuln_class="idor", status="tested")]
        s = R.summarize(fs)
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["by_severity"]["HIGH"], 2)
        self.assertEqual(s["by_severity"]["CRITICAL"], 1)
        self.assertEqual(s["by_vuln_class"]["idor"], 2)
        self.assertEqual(s["by_status"]["vulnerable"], 2)

    def test_group_orders_severity_desc(self):
        fs = [finding(1, sev="LOW"), finding(1, sev="CRITICAL")]
        grouped = R.group_findings(fs)
        self.assertEqual(grouped[0][0], "CRITICAL")
        self.assertEqual(grouped[1][0], "LOW")


class TestDocxValidity(unittest.TestCase):
    def test_docx_is_valid_zip_with_ooxml_parts(self):
        data = sample_data(1, [finding(1)])
        docx = R.build_docx(data)
        z = zipfile.ZipFile(io.BytesIO(docx))
        self.assertIsNone(z.testzip(), "archive ZIP corrompue")
        names = set(z.namelist())
        self.assertIn("[Content_Types].xml", names)
        self.assertIn("_rels/.rels", names)
        self.assertIn("word/document.xml", names)
        doc = z.read("word/document.xml").decode("utf-8")
        self.assertIn("ACME Corp", doc)
        self.assertIn("w:document", doc)


class TestPdfDegrade(unittest.TestCase):
    def test_pdf_degrades_without_engine(self):
        orig = R.shutil.which
        R.shutil.which = lambda _name: None  # aucun moteur -> dégradation
        try:
            pdf, note = R.build_pdf("<html><body>x</body></html>")
        finally:
            R.shutil.which = orig
        self.assertIsNone(pdf, "sans moteur, aucun octet PDF")
        self.assertTrue(note and "Imprimer" in note, "note d'impression fournie")

    def test_render_pdf_degrades_to_html(self):
        orig = R.shutil.which
        R.shutil.which = lambda _name: None
        try:
            content, ctype, note = R.render(sample_data(1, [finding(1)]), "pdf")
        finally:
            R.shutil.which = orig
        # dégradé : renvoie le HTML imprimable + note (status, pas de crash).
        self.assertIn("text/html", ctype)
        self.assertTrue(note)
        self.assertIn("<html", content)


class TestAttackAndCustody(unittest.TestCase):
    def test_html_renders_attack_and_custody(self):
        html = R.build_html(sample_data(1, [finding(1)]))
        self.assertIn("Couverture ATT&amp;CK", html)
        self.assertIn("T1190", html)
        self.assertIn("chaîne de custody", html)
        self.assertIn("aa" * 32, html)  # pubkey Ed25519 rendue
        self.assertIn("autonome", html.lower())  # source de détection absente -> note autonome


class TestCli(unittest.TestCase):
    def test_cli_stdin_docx_roundtrip(self):
        """Chemin de délégation de la console Rust : JSON sur stdin -> DOCX (octets) sur stdout."""
        data = sample_data(1, [finding(1, evidence=f"leak password={SECRET_PWD}")])
        out = subprocess.run(
            [sys.executable, "-m", "forge.report_engagement", "--format", "docx", "--stdin"],
            input=json.dumps(data).encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(Path(__file__).resolve().parents[1]), check=False,
        )
        self.assertEqual(out.returncode, 0, out.stderr.decode("utf-8", "replace"))
        z = zipfile.ZipFile(io.BytesIO(out.stdout))
        self.assertIn("word/document.xml", z.namelist())
        doc = z.read("word/document.xml").decode("utf-8")
        self.assertNotIn(SECRET_PWD, doc, "secret non rédigé dans le DOCX généré via CLI")

    def test_cli_stdin_csv(self):
        data = sample_data(1, [finding(1, title="CLI-finding")])
        out = subprocess.run(
            [sys.executable, "-m", "forge.report_engagement", "--format", "csv"],
            input=json.dumps(data).encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(Path(__file__).resolve().parents[1]), check=False,
        )
        self.assertEqual(out.returncode, 0, out.stderr.decode("utf-8", "replace"))
        self.assertIn("CLI-finding", out.stdout.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()

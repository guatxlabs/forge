# SPDX-License-Identifier: AGPL-3.0-or-later
"""Le DOCX d'engagement doit pouvoir dire qu'un engagement est PARTIEL.

RUPTURE CORRIGÉE — md/HTML/JSON de la console annoncent depuis le lot précédent qu'un engagement
dont un run n'est pas allé au bout ne porte PAS un verdict complet. Le DOCX, lui, ne le disait pas —
et c'est le format que le COMMANDITAIRE ouvre. Un rapport tronqué qui se présente comme complet fait
lire « aucun risque critique » comme un verdict, alors qu'une partie du plan n'a jamais tourné.

Deux pièges que ces tests épinglent explicitement :
  1. `normalize()` reconstruit sa sortie depuis une LISTE FERMÉE de clefs : la clef `partial` que la
     console pose dans la Value du rapport y était JETÉE. Transmettre `partial` NE SUFFIT PAS — la
     partialité est DÉRIVÉE de `runs[*].status`, qui survit à `normalize()`.
  2. La table des statuts interrompus doit rester le MIROIR de
     `console/src/report_render/view.rs::partial_cause`. Un test lit la source Rust et compare : si
     l'une des deux tables bouge seule, le DOCX et le HTML de la MÊME donnée se contrediraient.

Chaque assertion porteuse vit dans SON test : une assertion antérieure qui échoue ne doit pas
empêcher la suivante de s'exécuter (sinon une mutation « verte » ne prouverait rien).
"""
import re
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import report_engagement as R  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
VIEW_RS = REPO / "console" / "src" / "report_render" / "view.rs"


def _data(run_status="done", run_id="run-1", extra_runs=()):
    """Value de rapport minimale — le contrat d'entrée documenté en tête de report_engagement."""
    runs = [{"run_id": run_id, "campaign": "camp", "mode": "propose", "status": run_status,
             "started_by": "alice", "fired": 3, "dry_run": 1, "vetoed": 0, "errors": 0}]
    runs.extend(extra_runs)
    return {
        "branding": {"customer_name": "ACME Corp", "vendor": "GuatX Forge"},
        "engagement": {"id": 1, "name": "ACME webapp Q3", "mode": "grey", "status": "active",
                       "scope_in": ["a.example.com"], "scope_out": []},
        "findings": [],
        "runs": runs,
        "attack": {"techniques": [], "detection_source_configured": False},
        "custody": {},
    }


def _docx_text(data):
    """word/document.xml du DOCX généré (le texte que Word affichera)."""
    import io
    raw = R.build_docx(data)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return z.read("word/document.xml").decode("utf-8")


class TestDocxPartiality(unittest.TestCase):
    def test_docx_announces_a_partial_engagement(self):
        xml = _docx_text(_data(run_status="timeout"))
        self.assertIn("ENGAGEMENT PARTIEL", xml,
                      "le DOCX ne dit PAS qu'un engagement dont un run a expiré est partiel")

    def test_docx_names_the_interrupted_run(self):
        # un COMPTE seul ne permet pas de retrouver ce qui manque : le run doit être NOMMÉ.
        xml = _docx_text(_data(run_status="timeout", run_id="run-cut"))
        self.assertIn("run-cut", xml, "le run interrompu doit être nommé dans le DOCX")

    def test_docx_says_the_cause(self):
        xml = _docx_text(_data(run_status="timeout"))
        self.assertIn("budget dépassé (timeout)", xml, "la cause de l'interruption doit être dite")

    def test_docx_banner_precedes_the_executive_summary(self):
        # la bannière BORNE le résumé exécutif : lue APRÈS, elle ne borne plus rien.
        xml = _docx_text(_data(run_status="cancelled"))
        self.assertLess(xml.index("ENGAGEMENT PARTIEL"), xml.index("Résumé exécutif"),
                        "la bannière doit précéder le résumé exécutif qu'elle borne")

    def test_docx_banner_forbids_reading_absence_as_a_clean_bill(self):
        xml = _docx_text(_data(run_status="failed"))
        self.assertIn("une absence de finding", xml)
        self.assertIn("PAS une absence de vulnérabilité", xml)

    def test_docx_complete_engagement_carries_no_banner(self):
        xml = _docx_text(_data(run_status="done"))
        self.assertNotIn("ENGAGEMENT PARTIEL", xml,
                         "un engagement dont tous les runs sont terminés ne doit pas s'annoncer partiel")

    def test_docx_counts_only_the_interrupted_runs(self):
        data = _data(run_status="done", run_id="ok-1", extra_runs=[
            {"run_id": "cut-1", "status": "timeout"},
            {"run_id": "cut-2", "status": "cancelled"},
        ])
        xml = _docx_text(data)
        self.assertIn("2 run(s) sur 3", xml, "le compte doit être « interrompus / total », pas un total")

    def test_docx_is_still_a_valid_ooxml_zip_with_the_banner(self):
        import io
        raw = R.build_docx(_data(run_status="timeout"))
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            self.assertEqual(z.testzip(), None)
            self.assertIn("word/document.xml", z.namelist())
            self.assertIn("[Content_Types].xml", z.namelist())


class TestHtmlPartiality(unittest.TestCase):
    """Le HTML du MÊME générateur (chemin CLI `--format html`) porte la MÊME phrase — sinon deux
    livrables issus de la même donnée diraient deux choses différentes."""

    def test_html_announces_a_partial_engagement(self):
        html = R.build_html(_data(run_status="timeout"))
        self.assertIn("ENGAGEMENT PARTIEL", html)

    def test_html_banner_precedes_the_executive_summary(self):
        html = R.build_html(_data(run_status="timeout"))
        self.assertLess(html.index("ENGAGEMENT PARTIEL"), html.index("Résumé exécutif"))

    def test_html_complete_engagement_carries_no_banner(self):
        self.assertNotIn("ENGAGEMENT PARTIEL", R.build_html(_data(run_status="done")))


class TestDerivationNotTheDroppedKey(unittest.TestCase):
    """Le piège #1, épinglé : `normalize()` JETTE `partial`. La partialité ne peut donc PAS en venir."""

    def test_normalize_still_drops_the_partial_key(self):
        # constat sur le code tel qu'il est : si un jour `normalize` préserve `partial`, ce test
        # rougit et on saura que la dérivation peut être simplifiée (au lieu de la découvrir en prod).
        norm = R.normalize({"partial": {"is_partial": True, "runs": [{"run_id": "x", "status": "timeout"}]},
                            "runs": [], "findings": []})
        self.assertNotIn("partial", norm, "normalize() préserve maintenant `partial` — revoir la dérivation")

    def test_partial_key_alone_does_not_produce_a_banner(self):
        # une clef `partial` posée par l'appelant, avec des runs TOUS terminés -> aucune bannière :
        # preuve que la source est bien `runs[*].status` et non la clef.
        data = _data(run_status="done")
        data["partial"] = {"is_partial": True, "runs_total": 1, "runs_interrupted": 1,
                           "runs": [{"run_id": "ghost", "status": "timeout", "why": "budget"}]}
        self.assertNotIn("ENGAGEMENT PARTIEL", _docx_text(data))

    def test_runs_status_alone_produces_the_banner(self):
        # et sans AUCUNE clef `partial`, un run coupé suffit.
        data = _data(run_status="timeout")
        self.assertNotIn("partial", data)
        self.assertIn("ENGAGEMENT PARTIEL", _docx_text(data))


class TestMirrorsConsolePartialCause(unittest.TestCase):
    """La table Python doit rester le miroir de `view.rs::partial_cause` (source Rust LUE, pas
    recopiée de mémoire). Une divergence ferait dire au DOCX autre chose qu'au rapport de run."""

    def _rust_table(self):
        src = VIEW_RS.read_text(encoding="utf-8")
        m = re.search(r"pub\(crate\) fn partial_cause\(status: &str\) -> Option<&'static str> \{(.*?)\n\}",
                      src, re.S)
        self.assertIsNotNone(m, "partial_cause introuvable dans view.rs")
        table = {}
        for arm in re.finditer(r'((?:"[a-z]+"\s*\|\s*)*"[a-z]+")\s*=>\s*Some\("([^"]*)"\)', m.group(1)):
            for key in re.findall(r'"([a-z]+)"', arm.group(1)):
                table[key] = arm.group(2)
        return table

    def test_same_statuses(self):
        self.assertEqual(set(R.INTERRUPTED_RUN_STATUS), set(self._rust_table()),
                         "la liste des statuts interrompus a divergé entre Python et Rust")

    def test_same_causes(self):
        self.assertEqual(R.INTERRUPTED_RUN_STATUS, self._rust_table(),
                         "une cause d'interruption est formulée différemment entre Python et Rust")


class TestPartialitySentence(unittest.TestCase):
    def test_no_runs_no_sentence(self):
        self.assertEqual(R.partiality_sentence(None), "")
        self.assertEqual(R.partiality_sentence([]), "")

    def test_status_is_case_and_space_insensitive(self):
        self.assertNotEqual(R.partiality_sentence([{"run_id": "r", "status": " TimeOut "}]), "")

    def test_unknown_status_is_not_treated_as_interrupted(self):
        self.assertEqual(R.partiality_sentence([{"run_id": "r", "status": "done"}]), "")
        self.assertEqual(R.partiality_sentence([{"run_id": "r", "status": ""}]), "")

    def test_malformed_run_entries_do_not_raise(self):
        self.assertEqual(R.partiality_sentence([None, {}, {"status": None}]), "")

    def test_run_without_id_is_still_reported(self):
        s = R.partiality_sentence([{"status": "failed"}])
        self.assertIn("?", s, "un run coupé sans identifiant doit quand même être compté et signalé")


if __name__ == "__main__":
    unittest.main()

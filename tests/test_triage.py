# SPDX-License-Identifier: AGPL-3.0-only
"""Tests du triage NATIF des findings (forge/triage.py) — dédup / cluster-bruit / score / rang.

Garanties prouvées (miroir des principes gouvernés de Forge) :
  · COVERAGE-SAFE : `count(in) == count(out)`, AUCUN finding perdu (le bruit est classé, jamais supprimé) ;
  · le bruit à haute cardinalité (gau, « config manquante ») est REGROUPÉ en quelques clusters ;
  · les vrais MEDIUM remontent EN TÊTE du rang, le noise-score ordonne correctement ;
  · DÉFAUT SÛR : auto_hide OFF ; un changement de seuil est HONORÉ ;
  · DÉTERMINISME : même entrée -> même triage (deux passes identiques) ;
  · le rapport SURFACE le triage (section synthèse + annotation par finding), sans rien masquer.
Stdlib only, zéro réseau.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.schema import Finding                       # noqa: E402
from forge import triage as T                          # noqa: E402
from forge.roe import Scope                             # noqa: E402
from forge.engine import Engine                         # noqa: E402
from forge.report import build_report                   # noqa: E402


def _noisy_set():
    """200 URLs d'archive gau (INFO, même gabarit) + 12 « config manquante » (INFO dégradé, 2 gabarits)
    + 4 vrais MEDIUM (uniques, preuve réelle). Total = 216. Reproduit la distribution T24/T27."""
    findings = []
    # 200 gau-junk : même titre-gabarit `Endpoint in-scope : <url>`, preuve IDENTIQUE, endpoints distincts.
    for i in range(200):
        u = f"http://a.example.com/archive/path{i}?id={i}"
        findings.append(Finding(
            target=u, title=f"Endpoint in-scope : {u}", severity="INFO",
            category="Recon", status="tested", tool="recon.gau",
            evidence="Endpoint in-scope découvert par gau — nouvelle surface chaînable."))
    # 12 « config manquante » : 7 RCE + 5 ATO (2 gabarits dégradés).
    for i in range(7):
        findings.append(Finding(
            target=f"svc{i}.example.com", title="RCE non testé — config manquante", severity="INFO",
            category="CWE-78", status="tested", tool="rce",
            evidence="Aucune configuration fournie (config manquante)."))
    for i in range(5):
        findings.append(Finding(
            target=f"svc{i}.example.com", title="ATO non testé — config manquante", severity="INFO",
            category="CWE-287", status="tested", tool="auth",
            evidence="Aucune configuration fournie (config manquante)."))
    # 4 vrais MEDIUM : uniques, preuve réelle, endpoints distincts.
    reals = [
        ("IDOR sur /orders/{id}", "b.example.com/orders/42", "CWE-639",
         "GET /orders/42 avec le compte A renvoie la commande du compte B (montant 189€)."),
        ("CORS credentials wildcard", "api.example.com/me", "CWE-942",
         "ACAO reflète Origin arbitraire avec ACAC:true — vol de session cross-origin confirmé."),
        ("Open redirect chaîné vers OAuth", "login.example.com/cb", "CWE-601",
         "redirect_uri=//evil casse la validation ; token OAuth exfiltré."),
        ("Stored XSS dans le champ profil", "app.example.com/profile", "CWE-79",
         "payload <img src=x onerror=fetch(...)> persisté et rejoué côté victime."),
    ]
    for title, tgt, cwe, ev in reals:
        findings.append(Finding(target=tgt, title=title, severity="MEDIUM",
                                category=cwe, status="tested", tool="oracle", evidence=ev))
    return findings


class TestNoDrop(unittest.TestCase):
    def test_count_in_equals_count_out_and_no_finding_dropped(self):
        """CRITIQUE : chaque finding d'entrée est TOUJOURS présent en sortie (rien supprimé)."""
        findings = _noisy_set()
        self.assertEqual(len(findings), 216)
        res = T.triage(findings)
        # count in == count out
        self.assertEqual(len(res.ranked), len(findings))
        self.assertEqual(res.summary["total"], len(findings))
        # ensemble EXACT (par identité) : la vue classée contient TOUS les objets d'entrée, aucun en plus.
        self.assertEqual({id(f) for f in res.ranked}, {id(f) for f in findings})
        # chaque finding a exactement UNE annotation.
        self.assertEqual(len(res.annotations), len(findings))
        for f in findings:
            self.assertIn(id(f), res.by_id)


class TestClusterAndRank(unittest.TestCase):
    def test_noise_clustered_and_real_findings_rank_top(self):
        findings = _noisy_set()
        res = T.triage(findings)
        # (1) le bruit gau (200) forme UN cluster à haute cardinalité.
        sizes = sorted((c["size"] for c in res.summary["clusters"]), reverse=True)
        self.assertGreaterEqual(sizes[0], 200)
        # (2) les 216 findings sont regroupés en un PETIT nombre de clusters-bruit (pas 212 lignes).
        self.assertLessEqual(res.summary["num_clusters"], 5)
        # (3) les 4 MEDIUM remontent EN TÊTE du rang.
        top4 = res.ranked[:4]
        self.assertTrue(all(f.severity == "MEDIUM" for f in top4),
                        [f.severity for f in top4])
        # (4) actionnables == 4 (les MEDIUM) ; le reste est classé bruit.
        self.assertEqual(res.summary["actionable"], 4)
        self.assertGreaterEqual(res.summary["noise"], 210)
        # (5) aucun MEDIUM n'est jamais marqué bruit (plancher de sécurité).
        for f in findings:
            if f.severity == "MEDIUM":
                self.assertFalse(res.by_id[id(f)]["likely_noise"])

    def test_noise_score_orders_correctly(self):
        """Le noise-score ordonne : dégradé+cluster (config manquante) > gau-cluster > MEDIUM unique."""
        findings = _noisy_set()
        res = T.triage(findings)
        gau = next(f for f in findings if f.tool == "recon.gau")
        cfg = next(f for f in findings if f.title.startswith("RCE non testé"))
        med = next(f for f in findings if f.severity == "MEDIUM")
        s_gau = res.by_id[id(gau)]["score"]
        s_cfg = res.by_id[id(cfg)]["score"]
        s_med = res.by_id[id(med)]["score"]
        self.assertGreater(s_cfg, s_gau)
        self.assertGreater(s_gau, s_med)
        self.assertLessEqual(s_med, T._ACTIONABLE_SCORE_CAP)


class TestDedup(unittest.TestCase):
    def test_pure_repeats_marked_duplicate_never_deleted(self):
        # deux findings STRICTEMENT identiques -> l'un représentant, l'autre dup (mais TOUJOURS présent).
        f1 = Finding(target="x.example.com", title="Missing header CSP", severity="LOW",
                     category="CWE-693", tool="security_headers", evidence="CSP absent")
        f2 = Finding(target="x.example.com", title="Missing header CSP", severity="LOW",
                     category="CWE-693", tool="security_headers", evidence="CSP absent")
        res = T.triage([f1, f2])
        self.assertEqual(len(res.ranked), 2)                     # rien supprimé
        self.assertTrue(res.by_id[id(f2)]["is_duplicate"])       # le 2e est un dup
        self.assertFalse(res.by_id[id(f1)]["is_duplicate"])      # le 1er est le représentant


class TestConfigAndDefaults(unittest.TestCase):
    def test_auto_hide_off_by_default(self):
        res = T.triage(_noisy_set())
        self.assertFalse(res.config.auto_hide)
        self.assertFalse(res.summary["auto_hide"])

    def test_threshold_change_is_honored(self):
        findings = _noisy_set()
        base = T.triage(findings)
        # config STRICTE : pas de cluster-bruit (min_size énorme), pas de quasi-dup (Jaccard=1.0), seuil
        # quasi-max -> le bruit gau/config n'atteint plus le seuil -> STRICTEMENT moins de findings « bruit ».
        strict = T.triage(findings, {"cluster_min_size": 99999, "dup_jaccard": 1.0,
                                     "noise_threshold": 0.99})
        self.assertLess(strict.summary["noise"], base.summary["noise"])

    def test_disabled_is_transparent_passthrough(self):
        findings = _noisy_set()
        res = T.triage(findings, {"enabled": False})
        self.assertEqual(len(res.ranked), len(findings))         # rien supprimé
        self.assertEqual(res.ranked, findings)                   # ordre d'origine préservé
        self.assertEqual(res.summary["noise"], 0)                # aucun classement
        self.assertFalse(res.summary["enabled"])

    def test_from_dict_tolerates_garbage(self):
        for bad in (None, "nope", 42, [], {"noise_threshold": "x", "cluster_min_size": -5}):
            cfg = T.TriageConfig.from_dict(bad)
            self.assertTrue(0.0 <= cfg.noise_threshold <= 1.0)
            self.assertGreaterEqual(cfg.cluster_min_size, 2)


class TestDeterminism(unittest.TestCase):
    def test_same_input_same_triage(self):
        f1 = _noisy_set()
        f2 = _noisy_set()
        r1 = T.triage(f1)
        r2 = T.triage(f2)
        self.assertEqual(r1.summary, r2.summary)                 # synthèse identique
        self.assertEqual(r1.annotations, r2.annotations)         # annotations (ordre d'entrée) identiques
        # rang identique (par (severity, title, target) — comparaison stable indépendante de l'identité).
        self.assertEqual([(f.severity, f.title, f.target) for f in r1.ranked],
                         [(f.severity, f.title, f.target) for f in r2.ranked])


class TestReportSurfaces(unittest.TestCase):
    def _engine(self, findings, triage_cfg=None):
        data = {"in_scope": ["*.example.com"], "mode": "grey"}
        if triage_cfg is not None:
            data["triage"] = triage_cfg
        eng = Engine(Scope(data))
        eng.findings = list(findings)
        return eng

    def test_report_emits_triage_summary_and_all_findings(self):
        findings = _noisy_set()
        rep = build_report(self._engine(findings))
        # la section triage est présente (transparence : le triage a TOURNÉ).
        self.assertIn("## Triage des findings", rep)
        self.assertIn("actionnables", rep)
        # TOUS les findings sont rendus (aucun masqué) : 216 blocs `### [`.
        self.assertEqual(rep.count("### ["), len(findings))
        # les 4 vrais MEDIUM sont visibles.
        for title in ("IDOR sur /orders", "CORS credentials wildcard",
                      "Open redirect chaîné", "Stored XSS dans le champ profil"):
            self.assertIn(title, rep)
        # le drapeau BRUIT probable apparaît (annotation par finding).
        self.assertIn("BRUIT probable", rep)

    def test_report_respects_disabled_config(self):
        findings = _noisy_set()
        rep = build_report(self._engine(findings, {"enabled": False}))
        self.assertIn("Triage désactivé", rep)
        self.assertEqual(rep.count("### ["), len(findings))      # toujours tous rendus


if __name__ == "__main__":
    unittest.main()

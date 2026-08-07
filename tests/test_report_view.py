# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests de la VUE actionnable-d'abord du rapport (forge/report_view.py + forge/report.py).

Le corpus de référence `_real_shaped_corpus()` REPRODUIT LA DISTRIBUTION EXACTE de l'évaluation réelle
qui a motivé ce lot (ledger `gxrun`, 5646 événements) : **2410 findings — 2404 INFO / 6 LOW / 0 ≥ MEDIUM,
2263 `tested` / 147 `skipped`**, dominés par des gabarits à haute cardinalité (`… non testé — config
manquante` ×28, `Endpoint in-scope : <url>` ×63, `nuclei: RDAP WHOIS` ×33). Un rapport éprouvé sur trois
findings de fixture ne prouve rien sur ce cas-là. (Le ledger RÉEL est en plus rejouable via
`$FORGE_TEST_LEDGER` — cf. `TestRealLedger`.)

Garanties prouvées ici :
  · **RIEN N'EST MASQUÉ EN SILENCE** — `rendered ∪ repliés` est une PARTITION EXACTE de l'entrée, les
    compteurs IMPRIMÉS dans le rapport se referment (rendus + repliés == total), et la garde est
    FAIL-LOUD (une comptabilité cassée est RENDUE, jamais rattrapée) ;
  · les **`skipped`** (trous de couverture) REMONTENT — seau dédié, section propre, AVANT l'annexe ;
  · **zéro fabrication d'impact** — un corpus sans MEDIUM+ produit « rien d'actionnable trouvé », les
    compteurs par sévérité du rapport égalent ceux de l'entrée, un statut non prouvé le DIT ;
  · **deux publics, un corpus** — la tête du rapport est BYTE-IDENTIQUE entre les vues ; seule l'annexe
    change ;
  · la **forme attendue par un triager** est présente pour chaque item actionnable (endpoint + méthode,
    reproduction, commande rejouable, CWE/CVSS, correctif).
Stdlib only, zéro réseau.
"""
import json
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.schema import Finding                        # noqa: E402
from forge.roe import Scope                             # noqa: E402
from forge.engine import Engine                         # noqa: E402
from forge.report import build_report                   # noqa: E402
from forge import report_view as V                      # noqa: E402
from forge import triage as T                           # noqa: E402


# --------------------------------------------------------------------------------------------------
# Corpus de référence — distribution EXACTE de l'évaluation réelle (2410 / 2404 INFO / 6 LOW / 147 skipped)
# --------------------------------------------------------------------------------------------------
_MISSING_CONFIG = [
    "IDOR", "SSRF", "CORS", "Command-Injection", "CSRF", "GraphQL access", "JWT", "SearchInjection",
    "NoSQLi", "OAuth flow", "Path Traversal", "Prototype-Pollution", "Race/TOCTOU", "Open Redirect",
    "RFI", "SQLi", "SSRF cloud-metadata", "XSPA", "SSTI", "XXE", "LFI", "XSS", "Deserialization",
    "Mass-Assignment", "Web-Cache-Deception", "CRLF", "Host-Header", "Subdomain-Takeover",
]
_SKIP_SHAPE = [
    ("recon.secrets", "recon.secrets non exécuté — aucun scanner (trufflehog/gitleaks) (dégradation)", 28),
    ("wfuzz", "fuzz.wfuzz non exécuté — outil indisponible (dégradation gracieuse)", 26),
    ("recon.content", "recon.content non exécuté — ffuf indisponible (dégradation)", 22),
    ("recon.dns", "recon.dns non concluant — résolution indisponible", 19),
    ("framework.exposure", "framework.exposure non testé — réseau indisponible (dégradation gracieuse)", 10),
    ("cache_poisoning.probe", "Cache-Poisoning non testé — réseau indisponible (dégradation gracieuse)", 6),
    ("header_injection.probe", "Header-Injection non testé — réseau indisponible (dégradation gracieuse)", 6),
    ("recon.tech", "recon.tech non concluant — cible injoignable et httpx indisponible", 6),
    ("recon.waf", "recon.waf non concluant — cible injoignable et wafw00f indisponible", 6),
    ("web.security_headers", "web.security_headers non testé — réponse HTTP indisponible", 6),
    ("request_smuggling.probe", "Request-Smuggling non testé — réseau indisponible (dégradation gracieuse)", 5),
    ("recon.urls", "recon.urls non concluant — archives injoignables", 3),
    ("recon.js_endpoints", "recon.js_endpoints non concluant — page injoignable", 2),
    ("recon.subdomains", "recon.subdomains non concluant — sources passives injoignables", 2),
]                                                          # somme == 147, comme le run réel


def _real_shaped_corpus():
    """2410 findings à la distribution du run réel. Déterministe, sans réseau."""
    out = []
    # (a) 6 LOW clickjacking sur 6 endpoints (1 seul gabarit) — le SEUL signal du run réel.
    for host in ("www.guatx.com", "guatx.com:8443", "www.guatx.com:8443",
                 "www.guatx.com:443", "https://www.guatx.com", "https://www.guatx.com/"):
        out.append(Finding(
            target=host, title="Clickjacking — X-Frame-Options absent (et pas de CSP frame-ancestors)",
            severity="LOW", category="CWE-1021", status="tested",
            tool="forge/modules/security_headers.py:web.security_headers", mitre="T1595.002",
            evidence="X-Frame-Options absent et CSP ne contient pas 'frame-ancestors' (HTTP 301) : "
                     "la page peut être enframée (clickjacking).",
            poc=f"curl -sSI 'https://{host.split('://')[-1]}'  # lire les en-têtes de sécurité"))
    # (b) 147 `skipped` — trous de couverture, répartis comme dans le run réel.
    for kind, title, n in _SKIP_SHAPE:
        for i in range(n):
            out.append(Finding(target=f"h{i}.guatx.com", title=title, severity="INFO",
                               status="skipped", tool=f"forge/modules/x.py:{kind}",
                               evidence="dégradation gracieuse — module non exécuté"))
    # (c) 28 gabarits « … non testé — config manquante » × 28 cibles = 784 INFO.
    for tech in _MISSING_CONFIG:
        for i in range(28):
            out.append(Finding(target=f"h{i}.guatx.com", title=f"{tech} non testé — config manquante",
                               severity="INFO", status="tested", tool=tech.lower(),
                               evidence="Aucune configuration fournie (config manquante)."))
    # (d) le reste en bruit de recon à haute cardinalité, jusqu'à 2410 pile.
    i = 0
    while len(out) < 2410:
        u = f"http://guatx.com/archive/p{i}?id={i}"
        out.append(Finding(target=u, title=f"Endpoint in-scope : {u}", severity="INFO",
                           status="tested", tool="recon.gau", category="recon",
                           evidence="Endpoint in-scope découvert — nouvelle surface chaînable.",
                           poc=f"curl -s '{u}'"))
        i += 1
    assert len(out) == 2410, len(out)
    return out


def _engine(findings, scope_extra=None):
    data = {"in_scope": ["guatx.com", "*.guatx.com"], "mode": "grey"}
    data.update(scope_extra or {})
    eng = Engine(Scope(data))
    eng.findings = list(findings)
    return eng


_ACCOUNTING_RX = re.compile(r"\*\*(\d+) finding\(s\) rendus(?: ici)?, (\d+) repliés\*\*"
                            r"\s*\(= (\d+) émis")


def _printed_accounting(report_text):
    """(rendus, repliés, total) tels qu'IMPRIMÉS dans le rapport — lus dans le markdown, pas dans les
    objets. C'est ce que le lecteur voit ; c'est donc ça qui doit se refermer."""
    m = _ACCOUNTING_RX.search(report_text)
    assert m, "ligne de comptabilité de l'annexe ABSENTE du rapport"
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


# ==================================================================================================
class TestBucketPartition(unittest.TestCase):
    """Les quatre seaux forment une PARTITION : aucun finding n'est compté deux fois ni oublié."""

    def test_buckets_partition_the_corpus(self):
        f = _real_shaped_corpus()
        b = V.bucket_findings(f, T.triage(f))
        allidx = [i for k in ("exploitable", "qualify", "unverified", "recon") for i in b[k]]
        self.assertEqual(len(allidx), len(set(allidx)), "un finding est tombé dans deux seaux")
        self.assertEqual(set(allidx), set(range(len(f))), "des findings n'ont AUCUN seau")

    def test_real_shaped_counts(self):
        f = _real_shaped_corpus()
        b = V.bucket_findings(f, T.triage(f))
        self.assertEqual(len(b["exploitable"]), 0)          # 0 ≥ MEDIUM, 0 prouvé (comme le run réel)
        self.assertEqual(len(b["qualify"]), 6)              # les 6 LOW
        self.assertEqual(len(b["unverified"]), 147)         # les 147 `skipped`
        self.assertEqual(len(b["recon"]), 2410 - 6 - 147)


class TestSkippedAreCoverageHolesNotNoise(unittest.TestCase):
    """Les 147 `skipped` MONTENT. Dans le rapport d'origine ils étaient pénalisés par le poids
    `degraded` du noise-score et enterrés (rangs 458 → 2387) : c'est l'inversion que ce lot corrige."""

    def test_skipped_never_land_in_recon_bucket(self):
        f = _real_shaped_corpus()
        b = V.bucket_findings(f, T.triage(f))
        for i in b["recon"]:
            self.assertNotEqual(f[i].status, "skipped")
        self.assertEqual({f[i].status for i in b["unverified"]}, {"skipped"})

    def test_skipped_are_noise_for_triage_but_promoted_by_the_view(self):
        # Constat sur l'ANCIEN comportement : le triage natif les classe TOUS `likely_noise`…
        f = _real_shaped_corpus()
        tr = T.triage(f)
        skipped = [x for x in f if x.status == "skipped"]
        self.assertEqual(len(skipped), 147)
        self.assertTrue(all(tr.annotation_for(x)["likely_noise"] for x in skipped),
                        "prémisse du bug : le triage classe les skipped en bruit")
        # …et pourtant la vue les PROMEUT (le seau ne dépend PAS du noise-score).
        for x in skipped:
            self.assertEqual(V.bucket_of(x, tr.annotation_for(x)), "unverified")

    def test_report_puts_unverified_before_the_annex_and_counts_them(self):
        rep = build_report(_engine(_real_shaped_corpus()))
        self.assertIn("## Couverture NON vérifiée", rep)
        self.assertIn("**147 finding(s) `skipped`**", rep)
        self.assertIn("14 module(s) n'ont PAS pu conclure", rep)
        self.assertLess(rep.index("## Couverture NON vérifiée"), rep.index("## Findings — annexe"),
                        "les trous de couverture doivent précéder le bruit, pas le suivre")
        # chaque module en échec est NOMMÉ avec son compte (pas un agrégat opaque).
        for kind, _title, n in _SKIP_SHAPE:
            self.assertIn(f"| `{kind}` | {n} |", rep)


class TestNothingHiddenSilently(unittest.TestCase):
    """LA contrainte dure : compter, dire combien, dire où les retrouver."""

    def test_pentest_view_folds_nothing(self):
        f = _real_shaped_corpus()
        tr = T.triage(f)
        plan = V.annex_plan(f, tr, V.VIEW_PENTEST)
        self.assertEqual(len(plan.rendered), len(f))
        self.assertEqual(plan.folded, 0)
        self.assertTrue(plan.check()[0], plan.check()[1])

    def test_bounty_view_partitions_exactly(self):
        f = _real_shaped_corpus()
        tr = T.triage(f)
        keep = V.bucket_findings(f, tr)
        keep = keep["exploitable"] + keep["qualify"] + keep["unverified"]
        plan = V.annex_plan(f, tr, V.VIEW_BOUNTY, keep_idxs=keep)
        ok, why = plan.check()
        self.assertTrue(ok, why)
        self.assertGreater(plan.folded, 0, "la vue bounty doit effectivement replier du bruit")
        # PARTITION EXACTE au niveau des INDICES (pas seulement des comptes).
        folded_idx = {m for g in plan.folded_groups for m in g["members"]}
        self.assertEqual(set(plan.rendered) | folded_idx, set(range(len(f))))
        self.assertEqual(set(plan.rendered) & folded_idx, set())
        self.assertEqual(len(plan.rendered) + plan.folded, len(f))

    def test_printed_counters_close_in_both_views(self):
        """LE compteur du rapport (celui qu'un lecteur voit) se referme : rendus + repliés == total."""
        f = _real_shaped_corpus()
        for view in (V.VIEW_PENTEST, V.VIEW_BOUNTY):
            with self.subTest(view=view):
                rep = build_report(_engine(f), view=view)
                rendered, folded, total = _printed_accounting(rep)
                self.assertEqual(total, len(f))
                self.assertEqual(rendered + folded, total,
                                 f"vue {view} : {rendered}+{folded} != {total} — masquage silencieux")
                # le compteur imprimé correspond aux blocs RÉELLEMENT rendus dans l'annexe.
                self.assertEqual(rep.count("### ["), rendered)

    def test_bounty_names_every_folded_template_and_says_how_to_get_them_back(self):
        f = _real_shaped_corpus()
        rep = build_report(_engine(f), view=V.VIEW_BOUNTY)
        tr = T.triage(f)
        keep = V.bucket_findings(f, tr)
        plan = V.annex_plan(f, tr, V.VIEW_BOUNTY,
                            keep_idxs=keep["exploitable"] + keep["qualify"] + keep["unverified"])
        self.assertIn("aucun n'est supprimé", rep)
        self.assertIn("--view pentest", rep)                       # où les retrouver
        self.assertIn("ledger signé", rep)                          # et l'autre source de vérité
        for g in plan.folded_groups:                                # chaque gabarit replié est NOMMÉ + compté
            self.assertIn(f"| {str(g['label'])[:70]} |", rep)
            self.assertIn(f"| {g['size']} |", rep)

    def test_every_input_finding_is_rendered_or_named_in_a_folded_group(self):
        """Au niveau du TEXTE : chaque finding est soit rendu, soit membre d'un gabarit listé."""
        f = _real_shaped_corpus()
        rep = build_report(_engine(f), view=V.VIEW_BOUNTY)
        body = rep.split("## Findings — annexe")[1]
        labels = {ln.split("|")[1].strip() for ln in body.splitlines()
                  if ln.startswith("|") and ln.count("|") >= 5}
        missing = []
        for x in f:
            head = f"### [{x.severity}] {x.title} — `{x.target}`"
            if head in body:
                continue
            if T.normalize_title(x.title)[:70] in labels:
                continue
            missing.append(head)
        self.assertEqual(missing, [], f"{len(missing)} finding(s) ni rendus ni nommés dans un repli")

    def test_broken_accounting_is_rendered_loudly_never_swallowed(self):
        """GARDE FAIL-LOUD : un plan qui perd un finding est DÉNONCÉ dans le rapport."""
        plan = V.AnnexPlan(rendered=[0, 1], folded_groups=[], total=5, view=V.VIEW_BOUNTY)
        ok, why = plan.check()
        self.assertFalse(ok)
        self.assertIn("disparus en silence", why)
        txt = "\n".join(V.render_annex_accounting(plan))
        self.assertIn("COMPTABILITÉ DE L'ANNEXE CASSÉE", txt)
        self.assertIn("ledger", txt)                                # renvoie vers la source de vérité

    def test_check_catches_double_count_and_declared_size_drift(self):
        # (a) un finding à la fois rendu ET replié -> compté deux fois.
        p = V.AnnexPlan(rendered=[0, 1], folded_groups=[{"members": [1], "size": 1}], total=2)
        self.assertFalse(p.check()[0])
        self.assertIn("deux fois", p.check()[1])
        # (b) taille DÉCLARÉE d'un groupe != membres réellement listés (dérive du bookkeeping).
        p = V.AnnexPlan(rendered=[0], folded_groups=[{"members": [1], "size": 7}], total=2)
        self.assertFalse(p.check()[0])
        self.assertIn("CASSÉE", p.check()[1])
        # (c) doublon dans `rendered`.
        p = V.AnnexPlan(rendered=[0, 0], folded_groups=[], total=1)
        self.assertFalse(p.check()[0])
        self.assertIn("double", p.check()[1])


class TestNoFabricatedImpact(unittest.TestCase):
    """La sévérité vient du finding, jamais du rapport."""

    def test_zero_actionable_says_so_in_one_line(self):
        rep = build_report(_engine(_real_shaped_corpus()))
        self.assertIn("**Rien d'actionnable trouvé.**", rep)
        self.assertIn("- **Actionnable** (≥ MEDIUM ou prouvé) : **0**", rep)
        # le verdict est en TÊTE : avant la synthèse, avant le triage, avant l'annexe.
        for later in ("## Synthèse", "## Triage des findings", "## Findings — annexe"):
            self.assertLess(rep.index("## Verdict"), rep.index(later))

    def test_report_severity_counts_equal_input_counts(self):
        f = _real_shaped_corpus()
        rep = build_report(_engine(f))
        self.assertIn("| LOW | 6 |", rep)
        self.assertIn("| INFO | 2404 |", rep)
        self.assertIn("| MEDIUM | 0 |", rep)
        self.assertIn("| HIGH | 0 |", rep)
        self.assertIn("| CRITICAL | 0 |", rep)

    def test_unproven_status_is_labelled_unproven(self):
        rep = build_report(_engine(_real_shaped_corpus()))
        self.assertIn("**Impact** : **non démontré**", rep)
        self.assertNotIn("exploitabilité DÉMONTRÉE", rep)

    def test_a_real_medium_leads_the_verdict_and_is_named(self):
        f = _real_shaped_corpus()
        f.append(Finding(target="api.guatx.com/orders/42", title="IDOR sur /orders/{id}",
                         severity="MEDIUM", category="CWE-639", status="tested", tool="oracle",
                         evidence="GET /orders/42 avec le compte A renvoie la commande du compte B.",
                         poc="curl -s -H 'Cookie: a' 'https://api.guatx.com/orders/42'"))
        rep = build_report(_engine(f))
        self.assertIn("**1 finding(s) actionnable(s)**", rep)
        self.assertIn("IDOR sur /orders/{id}", rep)
        self.assertIn("## Actionnable — à reporter", rep)
        self.assertNotIn("**Rien d'actionnable trouvé.**", rep)

    def test_proven_status_is_the_only_one_claiming_demonstrated_impact(self):
        from forge.modules.registry import Module           # chemin de PREUVE SANCTIONNÉ (_proven=True)
        f = Module.finding(_proven=True, target="api.guatx.com/orders/42", title="IDOR prouvé",
                           severity="HIGH", status="vulnerable",
                           evidence="La commande du compte B est lue depuis le compte A.",
                           poc="curl -s -H 'Cookie: a' 'https://api.guatx.com/orders/42'")
        self.assertEqual(f.status, "vulnerable")            # la sentinelle de preuve a bien été posée
        rep = build_report(_engine([f]))
        self.assertIn("exploitabilité DÉMONTRÉE", rep)
        self.assertNotIn("**Impact** : **non démontré**", rep)
        # …et un finding IDENTIQUE construit SANS le chemin de preuve est rabattu -> impact non démontré.
        forged = Finding(target="api.guatx.com/orders/42", title="IDOR prouvé", severity="HIGH",
                         status="vulnerable", evidence="idem", poc="curl -s x")
        self.assertEqual(forged.status, "tested")
        self.assertIn("**Impact** : **non démontré**", build_report(_engine([forged])))


class TestTriagerForm(unittest.TestCase):
    """Forme attendue par un triager, assemblée depuis les champs DÉJÀ produits par le dépôt."""

    def test_actionable_block_carries_everything_a_triager_asks_for(self):
        rep = build_report(_engine(_real_shaped_corpus()))
        block = rep.split("## Signal à qualifier")[1].split("## Couverture NON vérifiée")[0]
        for needed in ("| **Sévérité** | LOW |", "| **CWE** | CWE-1021 |", "**CVSS (base, indicatif)**",
                       "| **ATT&CK** | T1595.002 |", "| **Cible** |", "| **Requête** |",
                       "**Reproduction**", "**Commande rejouable**", "```bash",
                       "**Observation (preuve brute)**", "**Impact**", "**Correctif suggéré**"):
            self.assertIn(needed, block, f"champ triager manquant : {needed}")
        self.assertIn("curl -sSI", block)                            # la commande est REJOUABLE
        self.assertIn("6 occurrence(s)", block)                      # 1 vuln × N endpoints

    def test_http_method_is_derived_only_when_unambiguous(self):
        self.assertEqual(V.http_method_from_poc("curl -sSI 'https://a/'"), "HEAD")
        self.assertEqual(V.http_method_from_poc("curl -s 'https://a/'"), "GET")
        self.assertEqual(V.http_method_from_poc("curl -s -d 'x=1' 'https://a/'"), "POST")
        self.assertEqual(V.http_method_from_poc("curl -X PUT 'https://a/'"), "PUT")
        self.assertEqual(V.http_method_from_poc("docker run nuclei -u https://a/"), "",
                         "aucune méthode ne doit être INVENTÉE pour un outil non-curl")
        self.assertEqual(V.http_method_from_poc(""), "")
        # pas d'URL déductible -> pas de ligne « Requête » fabriquée
        self.assertEqual(V.request_line(Finding(target="h", title="t", poc="nmap -p80 h")), "")

    def test_occurrence_list_is_bounded_but_the_count_is_never_hidden(self):
        f = [Finding(target=f"h{i}.guatx.com", title="Clickjacking", severity="LOW",
                     category="CWE-1021", evidence="e", poc="curl -sSI 'https://h/'")
             for i in range(30)]
        rep = build_report(_engine(f))
        self.assertIn("30 occurrence(s) sur 30 cible(s) distincte(s)", rep)   # total EXACT
        self.assertIn(f"**+{30 - V.MAX_OCCURRENCE_EXAMPLES} autre(s)**", rep)  # reste COMPTÉ


class TestTwoViewsOneCorpus(unittest.TestCase):
    def test_lead_is_byte_identical_across_views(self):
        """Même corpus, deux rendus : la TÊTE (verdict + actionnables + trous de couverture) est
        IDENTIQUE — à l'unique exception du NOM DE VUE, qui doit être annoncé (une vue tue serait un
        masquage silencieux). Seule l'ANNEXE distingue les deux publics."""
        f = _real_shaped_corpus()
        head_p = build_report(_engine(f), view=V.VIEW_PENTEST).split("## Synthèse")[0]
        head_b = build_report(_engine(f), view=V.VIEW_BOUNTY).split("## Synthèse")[0]
        self.assertIn("(vue `pentest`)", head_p)                  # la vue est ANNONCÉE dans le verdict…
        self.assertIn("(vue `bounty`)", head_b)
        self.assertEqual(head_p.replace("(vue `pentest`)", "<V>"),
                         head_b.replace("(vue `bounty`)", "<V>"),
                         "hors nom de vue, la tête du rapport ne doit pas dépendre du public")

    def test_bounty_is_dramatically_shorter_without_losing_the_lead(self):
        f = _real_shaped_corpus()
        p = build_report(_engine(f), view=V.VIEW_PENTEST)
        b = build_report(_engine(f), view=V.VIEW_BOUNTY)
        self.assertLess(len(b.splitlines()), len(p.splitlines()) // 3)
        for kept in ("## Verdict", "## Couverture NON vérifiée", "**Commande rejouable**"):
            self.assertIn(kept, b)

    def test_view_resolution_precedence(self):
        env = os.environ.pop(V.ENV_VIEW, None)
        try:
            self.assertEqual(V.resolve_view(None, None), V.VIEW_PENTEST)          # défaut sûr
            self.assertEqual(V.resolve_view("bounty", None), V.VIEW_BOUNTY)       # explicite
            self.assertEqual(V.resolve_view(None, {"view": "bounty"}), V.VIEW_BOUNTY)
            # `auto_hide` — knob AUTREFOIS MORT, désormais raccordé à la vue repliée.
            self.assertEqual(V.resolve_view(None, {"auto_hide": True}), V.VIEW_BOUNTY)
            self.assertEqual(V.resolve_view(None, {"auto_hide": False}), V.VIEW_PENTEST)
            # valeurs folles ignorées (repli sur le niveau suivant), jamais d'exception
            self.assertEqual(V.resolve_view("zzz", {"view": "bounty"}), V.VIEW_BOUNTY)
            self.assertEqual(V.resolve_view(None, "pas-un-dict"), V.VIEW_PENTEST)
            os.environ[V.ENV_VIEW] = "bounty"
            self.assertEqual(V.resolve_view(None, {"view": "pentest"}), V.VIEW_BOUNTY)  # env > scope
            self.assertEqual(V.resolve_view("pentest", None), V.VIEW_PENTEST)           # explicite > env
        finally:
            os.environ.pop(V.ENV_VIEW, None)
            if env is not None:
                os.environ[V.ENV_VIEW] = env

    def test_auto_hide_true_folds_and_still_accounts(self):
        f = _real_shaped_corpus()
        rep = build_report(_engine(f, {"triage": {"auto_hide": True}}))
        rendered, folded, total = _printed_accounting(rep)
        self.assertGreater(folded, 0, "`auto_hide=true` doit enfin AVOIR un effet")
        self.assertEqual(rendered + folded, total)
        self.assertIn("Auto-masquage** : ACTIVÉ", rep)


class TestDeterminismAndSafety(unittest.TestCase):
    def test_same_corpus_same_report(self):
        f1, f2 = _real_shaped_corpus(), _real_shaped_corpus()
        self.assertEqual(build_report(_engine(f1), view=V.VIEW_BOUNTY),
                         build_report(_engine(f2), view=V.VIEW_BOUNTY))

    def test_empty_corpus_does_not_crash_and_says_nothing_found(self):
        rep = build_report(_engine([]))
        self.assertIn("**Rien d'actionnable trouvé.**", rep)
        self.assertIn("_Aucun finding._", rep)
        self.assertIn("Aucun module n'a échoué à s'exécuter", rep)
        rendered, folded, total = _printed_accounting(rep)
        self.assertEqual((rendered, folded, total), (0, 0, 0))

    def test_secrets_are_redacted_in_the_actionable_lead(self):
        f = [Finding(target="api.guatx.com", title="fuite", severity="LOW", category="CWE-200",
                     evidence="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aaaaaaaa.bbbbbbbb",
                     poc="curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aaaaaaaa.bbbbbbbb' https://api.guatx.com")]
        rep = build_report(_engine(f))
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9.aaaaaaaa.bbbbbbbb", rep)
        self.assertIn("[REDACTED]", rep)


class TestRealLedger(unittest.TestCase):
    """Rejoue le LEDGER RÉEL quand `$FORGE_TEST_LEDGER` le désigne (le fichier de 5 Mo n'est pas
    versionné). Les mêmes invariants doivent tenir sur les données qui ont motivé le lot."""

    def test_real_ledger_invariants(self):
        path = os.environ.get("FORGE_TEST_LEDGER", "")
        if not path or not Path(path).is_file():
            self.skipTest("FORGE_TEST_LEDGER non fourni (corpus réel non versionné)")
        findings = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("kind") != "finding":
                continue
            d = e["detail"]
            findings.append(Finding(
                target=d.get("target", ""), title=d.get("title", ""),
                severity=d.get("severity", "INFO"), category=d.get("category", ""),
                cwe=d.get("cwe", ""), mitre=d.get("mitre", ""), status=d.get("status", "tested"),
                evidence=d.get("evidence", ""), fix=d.get("fix", ""),
                cvss_vector=d.get("cvss_vector", ""), cvss_score=d.get("cvss_score", 0.0),
                tool=d.get("tool", ""), poc=d.get("poc", "")))
        self.assertTrue(findings, "ledger sans finding")
        for view in (V.VIEW_PENTEST, V.VIEW_BOUNTY):
            with self.subTest(view=view):
                rep = build_report(_engine(findings), view=view)
                rendered, folded, total = _printed_accounting(rep)
                self.assertEqual(total, len(findings))
                self.assertEqual(rendered + folded, total)
                self.assertEqual(rep.count("### ["), rendered)
        n_skipped = sum(1 for x in findings if x.status == "skipped")
        if n_skipped:
            self.assertIn(f"**{n_skipped} finding(s) `skipped`**", build_report(_engine(findings)))


if __name__ == "__main__":
    unittest.main()

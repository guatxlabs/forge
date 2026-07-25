"""LOT REGISTRY — `forge/techniques.py` comme REGISTRE DÉCLARATIF UNIQUE des techniques + le GARDE-FOU
qui rend la taxonomie SCALABLE : une nouvelle technique = UN module @register + UNE entrée de table,
et elle apparaît AUTOMATIQUEMENT dans le catalogue (groupé par catégorie), le pipeline pentest ordonné,
la sélection par-scope et les bons profils — sans câblage par-technique ailleurs.

Trois familles de garanties :
  (A) COMPLÉTUDE DU REGISTRE (le garde-fou anti-dérive) — CHAQUE kind du registre `forge.modules` a une
      entrée avec une `vuln_class` NON VIDE et des flags de profil COHÉRENTS. C'est ce test qui interdit
      qu'un nouveau module reste silencieusement NON CLASSÉ.
  (B) VUES DÉRIVÉES BIEN FORMÉES — by_vuln_class / profile_set / pipeline_ordered / techniques_for.
  (C) RÉTRO-COMPAT — les vues historiques (QUALIFYING/DEFAULT_CHECKLIST/DEFAULT_FIXES/mitre_by_kind)
      restent inchangées : ajouter la taxonomie de consolidation ne DÉRIVE aucune sortie existante.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import techniques, planner, schema, purple           # noqa: E402
from forge import modules as mods                                # noqa: E402


class TestRegistryCompleteness(unittest.TestCase):
    """(A) Le garde-fou : aucun module enregistré ne peut rester non classé / incohérent."""

    def test_every_registered_kind_has_entry_with_vuln_class(self):
        for k in mods.kinds():
            t = techniques.technique_for(k)
            self.assertIsNotNone(t, f"kind {k} enregistré mais ABSENT de la table techniques.py")
            self.assertTrue(t.vuln_class, f"kind {k} sans vuln_class (technique non classée)")

    def test_registered_set_equals_technique_kinds(self):
        # le registre de modules == l'ensemble des kinds-techniques du catalogue (pas de trou, pas de
        # placeholder de surface qui se ferait passer pour un module livré).
        self.assertEqual(set(mods.kinds()), set(techniques.technique_kinds()))

    def test_profile_flags_are_coherent(self):
        for k in mods.kinds():
            t = techniques.technique_for(k)
            # exactement UN de {bug_bounty_eligible, pentest_only} est vrai.
            self.assertNotEqual(t.bug_bounty_eligible, t.pentest_only,
                                f"{k} : bug_bounty_eligible et pentest_only incohérents")
            # default_profiles : pentest TOUJOURS présent ; bug_bounty ssi éligible.
            self.assertIn("pentest", t.default_profiles, f"{k} devrait tourner en pentest")
            self.assertEqual("bug_bounty" in t.default_profiles, t.bug_bounty_eligible,
                             f"{k} : default_profiles incohérent avec bug_bounty_eligible")

    def test_stage_equals_phase(self):
        for k in mods.kinds():
            t = techniques.technique_for(k)
            self.assertEqual(t.stage, t.phase, f"{k} : stage de pipeline != phase")

    def test_tools_nonempty_and_reference_registered_kinds(self):
        registered = set(mods.kinds())
        for k in mods.kinds():
            t = techniques.technique_for(k)
            self.assertTrue(t.tools, f"{k} sans `tools`")
            for dep in t.tools:
                self.assertIn(dep, registered, f"{k}: tool {dep} n'est pas un module enregistré")

    def test_depends_on_reference_registered_kinds(self):
        registered = set(mods.kinds())
        for k in mods.kinds():
            t = techniques.technique_for(k)
            for dep in t.depends_on:
                self.assertIn(dep, registered, f"{k}: depends_on {dep} n'est pas un module enregistré")

    def test_pipeline_property_shape(self):
        for k in mods.kinds():
            p = techniques.technique_for(k).pipeline
            self.assertIsInstance(p, dict, k)
            self.assertEqual(set(p), {"stage", "depends_on"}, k)
            self.assertIsInstance(p["depends_on"], list, k)


class TestConsolidationMapping(unittest.TestCase):
    """La liste qualifiante de la tâche est bien consolidée (catégorie + éligibilité BB par kind)."""

    QUALIFYING_BB = {
        "sqli.probe": "SQLi", "xss.reflected": "XSS", "access_control.idor": "IDOR",
        "auth.takeover": "Auth", "jwt.weakness": "Auth", "path.traversal": "LFI",
        "ssrf.callback": "SSRF", "cors.credentials": "CORS", "csrf.state_change": "CSRF",
        "redirect.open": "OpenRedirect", "recon.secrets": "ExposedSecrets",
        "ssti.eval": "RCE", "graphql.access": "IDOR",
    }

    def test_qualifying_list_categorised_and_bb_eligible(self):
        for kind, cls in self.QUALIFYING_BB.items():
            t = techniques.technique_for(kind)
            self.assertEqual(t.vuln_class, cls, f"{kind} mal catégorisé")
            self.assertTrue(t.bug_bounty_eligible, f"{kind} devrait être bug_bounty_eligible")

    def test_recon_and_connectors_are_pentest_only(self):
        # recon.* (sauf recon.secrets) + scanners/connecteurs -> pentest_only, non BB.
        for kind in ("recon.httpx", "recon.nmap", "recon.subdomains", "recon.dns",
                     "recon.js_endpoints", "recon.urls", "recon.tech", "recon.content",
                     "recon.waf", "demo.fingerprint", "origin.find",
                     "web.nuclei", "burp.scan", "msf.module",
                     "evasion.xhr", "evasion.turnstile", "evasion.discover", "evasion.idor_intercept"):
            t = techniques.technique_for(kind)
            self.assertTrue(t.pentest_only, f"{kind} devrait être pentest_only")
            self.assertFalse(t.bug_bounty_eligible, f"{kind} ne devrait pas être bug_bounty_eligible")

    def test_connectors_now_in_table(self):
        # burp.scan / msf.module : jadis absents de la table, désormais consolidés (leur mitre == module).
        self.assertEqual(techniques.technique_for("burp.scan").mitre, mods.get("burp.scan").mitre)
        self.assertEqual(techniques.technique_for("msf.module").mitre, mods.get("msf.module").mitre)


class TestDerivedViewsWellFormed(unittest.TestCase):
    """(B) by_vuln_class / profile_set / pipeline_ordered / techniques_for."""

    def test_by_vuln_class_partitions_all_kinds(self):
        bvc = techniques.by_vuln_class()
        # chaque catégorie -> liste triée non vide ; l'union == tous les kinds-techniques.
        flat = []
        for cls, ks in bvc.items():
            self.assertTrue(cls, "catégorie vide")
            self.assertTrue(ks, f"catégorie {cls} sans kind")
            self.assertEqual(ks, sorted(ks), f"{cls} non triée")
            flat.extend(ks)
        self.assertEqual(set(flat), set(techniques.technique_kinds()))
        self.assertEqual(len(flat), len(set(flat)), "un kind apparaît dans deux catégories")
        # ancrages de catégorie
        self.assertIn("sqli.probe", bvc["SQLi"])
        self.assertIn("access_control.idor", bvc["IDOR"])
        self.assertIn("graphql.access", bvc["IDOR"])

    def test_profile_set_bug_bounty_subset_of_pentest(self):
        pentest = techniques.profile_set("pentest")
        bb = techniques.profile_set("bug_bounty")
        self.assertEqual(pentest, set(techniques.technique_kinds()))
        self.assertTrue(bb < pentest, "bug_bounty devrait être un sous-ensemble STRICT de pentest")
        # bug_bounty == exactement les kinds bug_bounty_eligible.
        self.assertEqual(bb, {k for k in techniques.technique_kinds()
                              if techniques.technique_for(k).bug_bounty_eligible})
        # cohérence flag <-> default_profiles.
        self.assertEqual(bb, {k for k in techniques.technique_kinds()
                              if "bug_bounty" in techniques.technique_for(k).default_profiles})

    def test_profile_set_custom_and_direct_set(self):
        sel = {"sqli.probe", "xss.reflected"}
        self.assertEqual(techniques.profile_set("custom", custom=sel), sel)
        self.assertEqual(techniques.profile_set(sel), sel)              # ensemble passé directement
        self.assertEqual(techniques.profile_set("custom"), set())      # sans custom -> vide

    def test_pipeline_ordered_is_topological_and_phase_ranked(self):
        order = techniques.pipeline_ordered()
        self.assertEqual(set(order), set(techniques.technique_kinds()))
        self.assertEqual(len(order), len(set(order)), "doublon dans l'ordre du pipeline")
        pos = {k: i for i, k in enumerate(order)}
        rank = {"recon": 0, "access": 1, "exploit": 2, "": 3}
        # (1) topologie : toute dépendance PRÉSENTE précède son dépendant.
        for k in order:
            for dep in techniques.technique_for(k).depends_on:
                if dep in pos:
                    self.assertLess(pos[dep], pos[k], f"{dep} devrait précéder {k}")
        # (2) monotone par phase : recon avant access avant exploit.
        ranks = [rank[techniques.technique_for(k).phase] for k in order]
        self.assertEqual(ranks, sorted(ranks), "l'ordre des phases n'est pas monotone")

    def test_techniques_for_filters_and_orders(self):
        full = techniques.pipeline_ordered()
        # profil : sous-liste ordonnée de pipeline_ordered.
        bb = techniques.techniques_for("bug_bounty")
        self.assertEqual(bb, [k for k in full if k in techniques.profile_set("bug_bounty")])
        # ensemble explicite (sélection par-scope) : filtré + ordonné, ordre du pipeline préservé.
        sel = {"xss.reflected", "recon.httpx", "sqli.probe"}
        got = techniques.techniques_for(sel)
        self.assertEqual(set(got), sel)
        self.assertEqual(got, [k for k in full if k in sel])
        # recon.httpx (recon) doit précéder les oracles access.
        self.assertLess(got.index("recon.httpx"), got.index("sqli.probe"))

    def test_new_module_auto_appears_everywhere(self):
        # SIMULATION du contrat « derive-everywhere » : une entrée ajoutée à la volée apparaît dans
        # TOUTES les vues dérivées sans autre câblage. On restaure la table ensuite (hermétique).
        from forge.techniques import Technique, TECHNIQUES, CATALOG
        key = "xxe.parse"
        saved_t = dict(TECHNIQUES)
        saved_c = dict(CATALOG)
        try:
            rec = Technique(key=key, vuln_class="XXE", bug_bounty_eligible=True, pentest_only=False,
                            phase="access", capability="active", stage="access",
                            depends_on=("recon.js_endpoints",), tools=(key,),
                            default_profiles=("bug_bounty", "pentest"), mitre="T1190")
            TECHNIQUES[key] = rec
            CATALOG[key] = rec
            self.assertIn(key, techniques.by_vuln_class().get("XXE", []))   # catalogue groupé
            self.assertIn(key, techniques.profile_set("bug_bounty"))        # profil
            self.assertIn(key, techniques.pipeline_ordered())               # pipeline
            self.assertIn(key, techniques.techniques_for("pentest"))        # sélection
            self.assertEqual(techniques.mitre_for(key), "T1190")            # résolveur
        finally:
            TECHNIQUES.clear(); TECHNIQUES.update(saved_t)
            CATALOG.clear(); CATALOG.update(saved_c)
        self.assertNotIn(key, techniques.technique_kinds())                 # bien restauré


class TestBackwardCompatUnchanged(unittest.TestCase):
    """(C) La consolidation ne DÉRIVE aucune vue historique."""

    def test_qualifying_and_checklist_unchanged(self):
        self.assertEqual(set(planner.QUALIFYING), techniques.qualifying_classes())
        self.assertEqual(planner.DEFAULT_CHECKLIST, list(techniques.DEFAULT_CHECKLIST))
        # les jetons qualifiants restent des ALIAS non-phasés (pas de vuln_class).
        for q in techniques.qualifying_classes():
            self.assertEqual(techniques.technique_for(q).vuln_class, "",
                             f"l'alias qualifiant {q} ne doit pas porter de vuln_class")

    def test_default_fixes_unchanged(self):
        self.assertEqual(schema.DEFAULT_FIXES, techniques.remediation_map())

    def test_mitre_by_kind_unchanged(self):
        self.assertEqual(purple.DEFAULT_MITRE_BY_KIND, techniques.mitre_by_kind())

    def test_surface_placeholders_excluded_from_technique_kinds(self):
        # les placeholders de surface (métadonnées, sans module) ne sont PAS des kinds-techniques.
        for k in techniques.SURFACE_KEYS:
            self.assertNotIn(k, techniques.technique_kinds(), f"{k} (surface) ne doit pas être livré")


if __name__ == "__main__":
    unittest.main(verbosity=2)

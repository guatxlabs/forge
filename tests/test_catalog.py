"""LOT SURFACE — catalogue ATT&CK structuré (`forge/techniques.py`).

Deux garanties :
  (A) les NOUVEAUX champs structurés (attck_tactic/phase/capability/proof_required) sont BIEN FORMÉS
      pour CHAQUE entrée du catalogue consolidé, et les entrées de surface sont complètes/cohérentes ;
  (B) les vues dérivées HISTORIQUES restent INCHANGÉES — aucune entrée de surface ne pollue
      remediation_map()/qualifying_classes()/mitre_by_kind() ni les constantes du planner/schema
      (snapshot pré-refactor + pins littéraux). C'est le garde-fou byte-à-byte de la rétro-compat.
"""
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import techniques, schema, planner, purple           # noqa: E402
from forge.techniques import Technique                           # noqa: E402

SNAP = Path(__file__).resolve().parent / "_snapshots"

# Valeurs autorisées des champs structurés (vide = alias non-phasé : classe/CWE, pas un kind de module).
PHASES = {"", "recon", "access", "exploit"}
CAPABILITIES = {"", "passive", "active", "exploit"}
# ATT&CK bien formé : Txxxx éventuellement suivi d'une sous-technique .xxx.
_ATTCK_RX = re.compile(r"^T\d{4}(\.\d{3})?$")

# Les 8 classes de surface d'attaque que les prochaines slices implémentent (métadonnées seules ici).
EXPECTED_SURFACE_KEYS = {
    "surface.subdomains", "dns.enum", "web.discover", "js.endpoints",
    "secrets.detect", "tech.fingerprint", "waf.identify", "surface.origin",
}


def _snap(name):
    return json.loads((SNAP / name).read_text(encoding="utf-8"))


# --- (A) champs structurés bien formés -------------------------------------------------------------
class TestStructuredFieldsWellFormed(unittest.TestCase):
    def test_every_catalog_entry_has_wellformed_new_fields(self):
        for key, t in techniques.CATALOG.items():
            self.assertIsInstance(t, Technique, key)
            self.assertIsInstance(t.attck_tactic, str, key)
            self.assertIn(t.phase, PHASES, f"phase invalide pour {key}: {t.phase!r}")
            self.assertIn(t.capability, CAPABILITIES, f"capability invalide pour {key}: {t.capability!r}")
            self.assertIsInstance(t.proof_required, bool, key)
            # un mitre présent doit être un ATT&CK bien formé
            if t.mitre:
                self.assertRegex(t.mitre, _ATTCK_RX, f"mitre mal formé pour {key}: {t.mitre!r}")
            # cohérence : une entrée phasée (kind de module) doit déclarer une capability, et inversement
            self.assertEqual(bool(t.phase), bool(t.capability),
                             f"phase/capability incohérents pour {key}")

    def test_phased_entries_carry_tactic_and_mitre(self):
        # tout ce qui est phasé (kind de module héritage OU surface) porte tactique + ATT&CK.
        for key, t in techniques.CATALOG.items():
            if t.phase:
                self.assertTrue(t.attck_tactic, f"{key} phasé sans attck_tactic")
                self.assertTrue(t.mitre, f"{key} phasé sans mitre")

    def test_class_and_cwe_aliases_stay_unphased(self):
        # les alias (jetons de classe simples, clés cwe-*) NE sont pas des techniques de module :
        # phase/capability vides. Sinon `not t.phase` cesserait de séparer alias vs kinds.
        for key, t in techniques.TECHNIQUES.items():
            if "." not in key:                       # alias : mot simple ou 'cwe-xxx'/'origin-exposure'
                self.assertEqual(t.phase, "", f"alias {key} ne devrait pas être phasé")
                self.assertEqual(t.capability, "", f"alias {key} ne devrait pas avoir de capability")


# --- (A) entrées de surface complètes et cohérentes ------------------------------------------------
class TestSurfaceCatalog(unittest.TestCase):
    def test_surface_keys_present(self):
        self.assertEqual(set(techniques.SURFACE), EXPECTED_SURFACE_KEYS)
        self.assertEqual(techniques.SURFACE_KEYS, frozenset(EXPECTED_SURFACE_KEYS))

    def test_surface_entries_are_recon_and_complete(self):
        for key, t in techniques.SURFACE.items():
            self.assertEqual(t.phase, "recon", f"{key} devrait être phase=recon")
            self.assertIn(t.capability, {"passive", "active"}, f"{key} capability={t.capability!r}")
            self.assertTrue(t.attck_tactic, f"{key} sans attck_tactic")
            self.assertRegex(t.mitre, _ATTCK_RX, f"{key} mitre={t.mitre!r}")
            self.assertTrue(t.remediation, f"{key} sans remédiation")
            self.assertIn(".", key, f"{key} devrait suivre la convention kind pointée")
            # métadonnées seules : jamais qualifiant, jamais exploit (recon non destructif)
            self.assertFalse(t.qualifying, f"{key} ne doit pas être qualifiant")
            self.assertFalse(t.exploit, f"{key} recon ne doit pas être exploit")

    def test_surface_expected_attck_mapping(self):
        # pin des ATT&CK demandés par la tâche (les slices modules s'y raccrocheront).
        want = {
            "dns.enum": "T1590.002", "web.discover": "T1595.003",
            "tech.fingerprint": "T1592.002", "surface.origin": "T1590.005",
        }
        for key, mitre in want.items():
            self.assertEqual(techniques.SURFACE[key].mitre, mitre, key)
        # exposed-secret detection (T1552) + origin discovery : preuve exigée.
        self.assertTrue(techniques.SURFACE["secrets.detect"].mitre.startswith("T1552"))
        self.assertTrue(techniques.SURFACE["secrets.detect"].proof_required)
        self.assertTrue(techniques.SURFACE["surface.origin"].proof_required)

    def test_catalog_is_union_and_disjoint(self):
        self.assertEqual(set(techniques.CATALOG), set(techniques.TECHNIQUES) | set(techniques.SURFACE))
        self.assertEqual(set(techniques.TECHNIQUES) & set(techniques.SURFACE), set(),
                         "collision de clés entre noyau hérité et surface")

    def test_resolvers_reach_surface_kinds(self):
        # le catalogue est le squelette d'enregistrement : les résolveurs voient les kinds surface.
        self.assertEqual(techniques.mitre_for("surface.origin"), "T1590.005")
        self.assertIsNotNone(techniques.technique_for("dns.enum"))
        self.assertIsNone(techniques.technique_for("kind.inexistant"))


# --- (A) vues by_phase / by_capability / by_tactic -------------------------------------------------
class TestCatalogViews(unittest.TestCase):
    def test_by_phase_groups_recon_and_exploit(self):
        recon = techniques.by_phase("recon")
        # les 8 entrées surface + les kinds recon hérités sont là ; aucun alias non-phasé.
        for k in EXPECTED_SURFACE_KEYS:
            self.assertIn(k, recon)
        for k in ("recon.httpx", "recon.nmap", "web.nuclei", "origin.find", "demo.fingerprint"):
            self.assertIn(k, recon)
        exploit = techniques.by_phase("exploit")
        for k in ("access_control.idor", "ssrf.callback", "auth.takeover", "cors.credentials"):
            self.assertIn(k, exploit)
        # aucun alias de classe/CWE (non phasé) ne fuite dans une vue phasée.
        self.assertNotIn("idor", recon)
        self.assertNotIn("cwe-639", recon)

    def test_by_capability_partitions(self):
        passive = techniques.by_capability("passive")
        active = techniques.by_capability("active")
        exploit = techniques.by_capability("exploit")
        self.assertIn("tech.fingerprint", passive)
        self.assertIn("dns.enum", active)
        self.assertIn("ssrf.callback", exploit)
        # partition stricte : pas de recouvrement entre capacités.
        self.assertEqual(set(passive) & set(active), set())
        self.assertEqual(set(active) & set(exploit), set())

    def test_by_tactic_reconnaissance_nonempty(self):
        recon_tactic = techniques.by_tactic("Reconnaissance")
        self.assertTrue(recon_tactic)
        self.assertIn("surface.subdomains", recon_tactic)
        self.assertIn("Initial Access", {t.attck_tactic for t in techniques.CATALOG.values()})


# --- (B) rétro-compat : vues dérivées historiques INCHANGÉES ---------------------------------------
class TestBackwardCompatViewsUnchanged(unittest.TestCase):
    def test_remediation_map_byte_identical_to_snapshot(self):
        before = _snap("default_fixes.json")
        self.assertEqual(techniques.remediation_map(), before)
        self.assertEqual(schema.DEFAULT_FIXES, before)

    def test_no_surface_key_leaks_into_derived_views(self):
        # AUCUNE clé de surface (qui porte pourtant une remédiation) ne pollue les vues héritées.
        for k in techniques.SURFACE_KEYS:
            self.assertNotIn(k, techniques.remediation_map(), f"{k} pollue remediation_map")
            self.assertNotIn(k, schema.DEFAULT_FIXES, f"{k} pollue DEFAULT_FIXES")
            self.assertNotIn(k, techniques.qualifying_classes(), f"{k} pollue QUALIFYING")
            self.assertNotIn(k, techniques.mitre_by_kind(), f"{k} pollue mitre_by_kind")

    def test_planner_and_purple_constants_match_snapshots(self):
        planner_snap = _snap("planner_const.json")
        self.assertEqual(sorted(planner.QUALIFYING), planner_snap["QUALIFYING"])
        self.assertEqual(planner.DEFAULT_CHECKLIST, planner_snap["DEFAULT_CHECKLIST"])
        self.assertEqual(purple.DEFAULT_MITRE_BY_KIND, _snap("mitre_by_kind.json"))

    def test_qualifying_derived_from_legacy_core(self):
        # qualifying_classes itère le noyau hérité (pas le catalogue) : ensemble figé.
        self.assertEqual(techniques.qualifying_classes(), set(planner.QUALIFYING))


if __name__ == "__main__":
    unittest.main(verbosity=2)

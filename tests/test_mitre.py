"""LOT FORGE-MITRE — boucle purple : tout tir porte un ATT&CK NON VIDE + run_id/campaign.

Valeur défensive (purple-team) : pour mesurer detected/missed/MTTD, Plume corrèle « technique T
tirée -> détection T ? ». Un tir SANS mitre = trou de couverture (impossible de savoir si la
détection manquait ou si l'attaque n'a jamais été taggée). Ces tests garantissent qu'aucun tir
n'échappe au tag : fallback par-kind (DEFAULT_MITRE_BY_KIND), le vrai mitre primant toujours.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                            # noqa: E402
from forge.engine import Engine                                # noqa: E402
from forge.modules.registry import register, Module, REGISTRY  # noqa: E402
from forge import purple                                       # noqa: E402


def scope(in_scope=("app.test",), exploit=False):
    return Scope({"mode": "grey", "in_scope": list(in_scope), "allow_exploit": exploit})


class TestDefaultMitreByKind(unittest.TestCase):
    def test_table_non_empty_per_known_kind(self):
        # Chaque kind de la table a un ATT&CK non vide (sinon le repli ne sert à rien).
        self.assertTrue(purple.DEFAULT_MITRE_BY_KIND)
        for kind, tech in purple.DEFAULT_MITRE_BY_KIND.items():
            self.assertTrue(tech, f"{kind} a un mitre de repli vide")

    def test_mitre_for_kind_known_and_unknown(self):
        self.assertEqual(purple.mitre_for_kind("recon.httpx"), "T1595")
        self.assertEqual(purple.mitre_for_kind("kind.inconnu"), "")   # inconnu -> vide (pas de KeyError)

    def test_fire_without_finding_on_empty_mitre_module_gets_fallback(self):
        # CONTRAT FORGE-MITRE : tir SANS finding sur un module mitre='' -> run-record mitre NON VIDE.
        kind = "recon.httpx"                                # présent dans DEFAULT_MITRE_BY_KIND (T1595)
        saved = REGISTRY.get(kind)
        try:
            @register(kind)
            class _Empty(Module):
                mitre = ""                                  # AUCUN mitre déclaré par le module
                available = True

                def dry(self, action):
                    return "noop"

                def fire(self, action):
                    return []                               # tir « rien trouvé » : zéro finding

            eng = Engine(scope())
            eng.arm()
            a = Action(kind, "app.test")                    # AUCUN params.mitre
            eng.approve(a.id)
            eng.execute(a)
            self.assertEqual(len(eng.run_records), 1)       # la technique a quand même été tirée
            self.assertEqual(eng.run_records[0]["mitre"], "T1595")   # repli par-kind appliqué
            self.assertNotEqual(eng.run_records[0]["mitre"], "")
        finally:
            if saved is not None:
                REGISTRY[kind] = saved                      # restaure le vrai module pour les autres tests

    def test_real_mitre_wins_over_fallback(self):
        # Le VRAI mitre prime : params.mitre l'emporte sur le repli par-kind.
        eng = Engine(scope())
        eng.arm()
        a = Action("demo.fingerprint", "app.test", params={"mitre": "T1190"})
        eng.approve(a.id)
        eng.execute(a)
        self.assertEqual(eng.run_records[0]["mitre"], "T1190")   # params.mitre, pas le repli T1595


class TestRunRecordRunIdCampaign(unittest.TestCase):
    def test_run_record_carries_run_id_and_campaign(self):
        rr = purple.run_record("app.test", "demo.fingerprint", "T1595",
                               run_id="run-42", campaign="camp-A")
        self.assertEqual(rr["run_id"], "run-42")
        self.assertEqual(rr["campaign"], "camp-A")

    def test_run_record_defaults_none_when_absent(self):
        rr = purple.run_record("app.test", "demo.fingerprint", "T1595")
        self.assertIsNone(rr["run_id"])
        self.assertIsNone(rr["campaign"])

    def test_engine_propagates_run_id_and_campaign_into_records(self):
        eng = Engine(scope(), campaign="camp-B", run_id="run-7")
        eng.arm()
        a = Action("demo.fingerprint", "app.test")
        eng.approve(a.id)
        eng.execute(a)
        self.assertEqual(eng.run_records[0]["run_id"], "run-7")
        self.assertEqual(eng.run_records[0]["campaign"], "camp-B")

    def test_demo_module_has_non_empty_default_mitre(self):
        # défaut mitre demo : le module porte désormais un ATT&CK (badge purple non vide).
        from forge.modules import demo
        self.assertTrue(demo.DemoFingerprint.mitre)


if __name__ == "__main__":
    unittest.main(verbosity=2)

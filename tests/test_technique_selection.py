"""SÉLECTION DE TECHNIQUES PAR-SCOPE + PROFILS + PENTEST AUTOMATISÉ — tout DÉRIVÉ de la table unique
(`forge/techniques.py`), sans câblage par-technique. Ce fichier PROUVE les 4 exigences :

  (1) MODÈLE — un scope porte `profile` (bug_bounty|pentest|custom) + toggles `techniques_enabled`/
      `categories_enabled` ; l'effective set en est RÉSOLU (profil ∪ activations − désactivations).
  (2) ENFORCEMENT fail-closed — une technique HORS de l'effective set n'est NI planifiée NI tirée,
      MÊME si son module est disponible et la cible in-scope (en plus du scope-guard ROE).
  (3) AUTO-PENTEST — `--auto-pentest` (AutoPentestBrain) balaie SEULEMENT l'ensemble activé.
  (4) CATALOGUE — `forge techniques --json` groupe par catégorie et reflète l'état activé du scope.

Tests HERMÉTIQUES : aucune I/O réseau (mode propose -> dry() sans effet ; ou stub `available` local).
"""
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import techniques                                    # noqa: E402
from forge import cli                                           # noqa: E402
from forge.roe import Scope, Action                             # noqa: E402
from forge.engine import Engine                                 # noqa: E402
from forge.brain import AutoPentestBrain, HeuristicBrain        # noqa: E402
from forge.planner import Planner                               # noqa: E402
from forge.schema import Target, Finding                        # noqa: E402
from forge.modules import registry                              # noqa: E402

SEL_REASON = "sélection profil/catégorie/technique"             # sous-chaîne de la raison du SKIP-sélection


class _PresentFiring(registry.Module):
    """Module PRÉSENT (available=True) qui TIRE un finding — sert à prouver qu'une technique DÉSACTIVÉE
    ne tire JAMAIS même quand son module est disponible et la cible in-scope."""
    available = True
    exploit = False
    web_allowed = True

    def dry(self, action):
        return f"# dry {self.kind} {action.target}"

    def fire(self, action):
        return [Finding(target=action.target, title=f"hit {self.kind}", severity="INFO",
                        category="recon", status="tested", tool=self.kind)]


class _stub_kind:
    """Context manager : substitue `_PresentFiring` à un KIND-technique réel, restaure le REGISTRY."""
    def __init__(self, kind):
        self.kind = kind
        self._saved = None

    def __enter__(self):
        self._saved = registry.REGISTRY.get(self.kind)
        registry.REGISTRY[self.kind] = type("Stub", (_PresentFiring,), {"kind": self.kind})
        return self

    def __exit__(self, *exc):
        if self._saved is None:
            registry.REGISTRY.pop(self.kind, None)
        else:
            registry.REGISTRY[self.kind] = self._saved
        return False


# =================================================================================================
class TestResolveEnabledKinds(unittest.TestCase):
    """(1) La résolution de l'effective set : profil de base + toggles add/remove, désactivation prime."""

    def test_bug_bounty_base_includes_bb_eligible_and_recon_excludes_pentest_only_vuln(self):
        en = techniques.resolve_enabled_kinds(profile="bug_bounty")
        self.assertIn("access_control.idor", en)        # bb-eligible
        self.assertIn("sqli.probe", en)                 # bb-eligible
        self.assertIn("recon.httpx", en)                # infra recon (toujours incluse)
        self.assertIn("recon.js_endpoints", en)         # infra recon
        self.assertNotIn("rce.probe", en)               # pentest-only (exploit)
        self.assertNotIn("business_logic.scan", en)     # pentest-only
        self.assertNotIn("msf.module", en)              # pentest-only (exploit connector, phase exploit)

    def test_pentest_is_all_kinds(self):
        self.assertEqual(techniques.resolve_enabled_kinds(profile="pentest"),
                         set(techniques.technique_kinds()))

    def test_custom_starts_empty_then_toggles_build(self):
        self.assertEqual(techniques.resolve_enabled_kinds(profile="custom"), set())
        en = techniques.resolve_enabled_kinds(profile="custom",
                                              techniques_enabled=["sqli.probe", "xss.reflected"])
        self.assertEqual(en, {"sqli.probe", "xss.reflected"})

    def test_category_enable_adds_all_its_kinds(self):
        # sur custom (base vide), activer la catégorie IDOR ajoute TOUS ses kinds.
        en = techniques.resolve_enabled_kinds(profile="custom", categories_enabled={"IDOR": True})
        self.assertEqual(en, set(techniques.by_vuln_class()["IDOR"]))
        self.assertIn("access_control.idor", en)
        self.assertIn("graphql.access", en)

    def test_category_disable_removes_all_its_kinds(self):
        # sur pentest (tout), désactiver la catégorie SQLi retire tous ses kinds.
        en = techniques.resolve_enabled_kinds(profile="pentest", categories_enabled={"SQLi": False})
        for k in techniques.by_vuln_class()["SQLi"]:
            self.assertNotIn(k, en, f"{k} (SQLi) aurait dû être retiré")
        self.assertIn("xss.reflected", en, "les autres catégories sont intactes")

    def test_disable_wins_over_enable_fail_closed(self):
        # même technique activée (catégorie) ET désactivée (technique) -> RETIRÉE (désactivation prime).
        en = techniques.resolve_enabled_kinds(
            profile="custom",
            categories_enabled={"SQLi": True},
            techniques_enabled={"sqli.probe": False})
        self.assertNotIn("sqli.probe", en, "la désactivation explicite prime (fail-closed)")

    def test_list_form_is_pure_enable(self):
        # forme itérable = ensemble d'activations (add), pas de désactivation.
        en = techniques.resolve_enabled_kinds(profile="bug_bounty",
                                              techniques_enabled=["rce.probe"])
        self.assertIn("rce.probe", en, "un toggle-liste active la technique par-dessus le profil")

    def test_only_real_kinds_survive(self):
        en = techniques.resolve_enabled_kinds(profile="custom",
                                              techniques_enabled=["not.a.kind", "sqli.probe"])
        self.assertEqual(en, {"sqli.probe"})


# =================================================================================================
class TestScopeModel(unittest.TestCase):
    """(1) Le scope porte la sélection ; effective_technique_kinds la résout (legacy => tout)."""

    def test_legacy_scope_unconfigured_means_all(self):
        sc = Scope({"in_scope": ["app.test"]})
        self.assertFalse(sc.technique_selection_configured())
        self.assertEqual(sc.effective_technique_kinds(), set(techniques.technique_kinds()))

    def test_profile_only_scope_is_configured(self):
        sc = Scope({"in_scope": ["app.test"], "profile": "bug_bounty"})
        self.assertTrue(sc.technique_selection_configured())
        self.assertNotIn("rce.probe", sc.effective_technique_kinds())

    def test_toggles_only_scope_defaults_bug_bounty(self):
        # toggles sans profil -> profil bug_bounty par défaut, puis toggles appliqués.
        sc = Scope({"in_scope": ["app.test"], "categories_enabled": {"SSRF": False}})
        self.assertTrue(sc.technique_selection_configured())
        en = sc.effective_technique_kinds()
        self.assertNotIn("ssrf.callback", en)
        self.assertIn("access_control.idor", en)        # base bug_bounty intacte ailleurs


# =================================================================================================
class TestEnforcementFailClosed(unittest.TestCase):
    """(2) Une technique hors effective set n'est NI planifiée NI tirée — même module dispo + in-scope."""

    def _armed_auto(self, scope):
        eng = Engine(scope, mode="auto")
        eng.arm("test sélection technique")
        return eng

    def test_disabled_technique_skipped_despite_available_module_and_in_scope(self):
        # sqli.probe stubé PRÉSENT (available=True), cible IN-SCOPE, moteur ARMÉ+auto -> il TIRERAIT.
        # Mais la catégorie SQLi est DÉSACTIVÉE au scope -> SKIP-sélection, ZÉRO finding (fail-closed).
        with _stub_kind("sqli.probe"):
            sc = Scope({"in_scope": ["app.test"], "profile": "pentest",
                        "categories_enabled": {"SQLi": False}})
            eng = self._armed_auto(sc)
            res = eng.execute(Action("sqli.probe", "https://app.test/x?q=1"))
        self.assertEqual(res["verdict"], "SKIP")
        self.assertIn(SEL_REASON, " ".join(res["reasons"]))
        self.assertEqual(eng.findings, [], "une technique désactivée ne tire AUCUN finding")

    def test_control_same_module_fires_when_enabled(self):
        # CONTRÔLE : le MÊME stub PRÉSENT, catégorie SQLi ACTIVE (pentest) -> FIRE (il aurait bien tiré).
        with _stub_kind("sqli.probe"):
            sc = Scope({"in_scope": ["app.test"], "profile": "pentest"})
            eng = self._armed_auto(sc)
            res = eng.execute(Action("sqli.probe", "https://app.test/x?q=1"))
        self.assertEqual(res["verdict"], "FIRE", "technique activée + module présent + in-scope -> FIRE")
        self.assertEqual(len(eng.findings), 1)

    def test_bug_bounty_profile_excludes_pentest_only_at_fire(self):
        # rce.probe / business_logic.scan sont PENTEST-ONLY : un scope bug_bounty les SKIP au tir.
        for kind in ("rce.probe", "business_logic.scan"):
            with _stub_kind(kind):
                sc = Scope({"in_scope": ["app.test"], "profile": "bug_bounty"})
                eng = self._armed_auto(sc)
                res = eng.execute(Action(kind, "https://app.test/x"))
            self.assertEqual(res["verdict"], "SKIP", f"{kind} pentest-only -> SKIP en bug_bounty")
            self.assertIn(SEL_REASON, " ".join(res["reasons"]))

    def test_enabled_technique_not_selection_skipped(self):
        # une technique ACTIVÉE (bb-eligible) n'est jamais SKIP par la SÉLECTION (elle passe le filtre) ;
        # access_control.idor est exploit -> VETO côté ROE, mais PAS le SKIP-sélection.
        sc = Scope({"in_scope": ["app.test"], "profile": "bug_bounty"})
        eng = Engine(sc)
        res = eng.execute(Action("access_control.idor", "https://app.test/x"))
        self.assertNotEqual(res["verdict"], "SKIP")
        self.assertNotIn(SEL_REASON, " ".join(res["reasons"]))

    def test_disabled_category_removes_all_its_techniques_from_pipeline(self):
        # PIPELINE (campaign, mode propose -> dry, aucune I/O) : désactiver la catégorie IDOR retire
        # TOUS ses kinds du plan (jamais planifiés). Les autres catégories restent balayées.
        sc = Scope({"in_scope": ["app.test"], "profile": "pentest",
                    "categories_enabled": {"IDOR": False}})
        eng = Engine(sc)                                 # NON armé -> dry (hermétique)
        eng.campaign([Target(host="app.test", kind="app")], HeuristicBrain(), Planner())
        attempted = {r["kind"] for r in eng.results}
        for k in techniques.by_vuln_class()["IDOR"]:
            self.assertNotIn(k, attempted, f"{k} (IDOR désactivée) ne doit JAMAIS être planifié")
        self.assertTrue(attempted, "d'autres techniques restent planifiées")
        self.assertLessEqual(attempted, sc.effective_technique_kinds(),
                             "rien hors de l'effective set n'est planifié")


# =================================================================================================
class TestAutoPentest(unittest.TestCase):
    """(3) --auto-pentest balaie SEULEMENT l'ensemble activé du scope, gouverné à l'identique."""

    def _run(self, scope):
        eng = Engine(scope)                              # mode propose (défaut) -> dry, aucune I/O réseau
        brain = AutoPentestBrain(scope.effective_technique_kinds())
        eng.campaign([Target(host="app.test", kind="app")], brain, Planner())
        return eng

    def test_auto_pentest_sweeps_only_enabled_set(self):
        sc = Scope({"in_scope": ["app.test"], "profile": "bug_bounty",
                    "categories_enabled": {"SQLi": False}})
        eng = self._run(sc)
        attempted = {r["kind"] for r in eng.results}
        enabled = sc.effective_technique_kinds()
        # (a) rien hors de l'ensemble activé.
        self.assertLessEqual(attempted, enabled, "auto-pentest ne balaie que l'ensemble activé")
        # (b) catégorie désactivée + pentest-only exclus.
        self.assertNotIn("sqli.probe", attempted, "SQLi désactivée -> jamais balayée")
        self.assertNotIn("rce.probe", attempted, "pentest-only -> hors bug_bounty")
        # (c) un vrai BALAYAGE : des techniques activées variées ont bien été tentées (au-delà des
        #     seules propositions heuristiques de base).
        for k in ("access_control.idor", "xss.reflected", "cors.credentials", "recon.httpx"):
            self.assertIn(k, attempted, f"{k} (activée) aurait dû être balayée par auto-pentest")

    def test_auto_pentest_pentest_profile_includes_high_impact_but_gated(self):
        # profil pentest : rce.probe/business_logic.scan SONT dans l'ensemble balayé (mais gatés ROE).
        sc = Scope({"in_scope": ["app.test"], "profile": "pentest"})
        eng = self._run(sc)
        attempted = {r["kind"] for r in eng.results}
        self.assertIn("rce.probe", attempted)
        self.assertIn("business_logic.scan", attempted)
        # gouverné : rce.probe (exploit) non armé -> VETO, jamais FIRE.
        rce = [r for r in eng.results if r["kind"] == "rce.probe"][0]
        self.assertEqual(rce["verdict"], "VETO", "exploit non armé -> VETO (plancher exploit tient)")


# =================================================================================================
class TestCatalogCLI(unittest.TestCase):
    """(4) `forge techniques --json` : catalogue groupé par catégorie + état activé du scope."""

    def _run(self, selection=None):
        buf = io.StringIO()
        args = type("A", (), {"json": True, "selection": selection})()
        with redirect_stdout(buf):
            rc = cli.cmd_techniques(args)
        self.assertEqual(rc, 0)
        return json.loads(buf.getvalue())

    def test_groups_by_category_and_covers_all_kinds(self):
        d = self._run()
        self.assertEqual(d["profile"], "bug_bounty")     # défaut
        flat = [row["kind"] for rows in d["groups"].values() for row in rows]
        self.assertEqual(set(flat), set(techniques.technique_kinds()))
        # chaque catégorie == by_vuln_class ; chaque ligne porte tools + éligibilité + état.
        for cat, rows in d["groups"].items():
            self.assertEqual({r["kind"] for r in rows}, set(techniques.by_vuln_class()[cat]))
            for r in rows:
                self.assertIn("tools", r)
                self.assertIn("bug_bounty_eligible", r)
                self.assertIn("pentest_only", r)
                self.assertIn("enabled_for_current_scope", r)

    def test_enabled_state_reflects_default_bug_bounty(self):
        d = self._run()
        state = {r["kind"]: r["enabled_for_current_scope"]
                 for rows in d["groups"].values() for r in rows}
        self.assertTrue(state["access_control.idor"])    # bb-eligible
        self.assertTrue(state["recon.httpx"])            # infra recon
        self.assertFalse(state["rce.probe"])             # pentest-only
        self.assertEqual(set(d["enabled"]),
                         techniques.resolve_enabled_kinds(profile="bug_bounty"))

    def test_enabled_state_reflects_selection(self):
        d = self._run(selection='{"profile":"pentest","categories":{"SQLi":false}}')
        self.assertEqual(d["profile"], "pentest")
        state = {r["kind"]: r["enabled_for_current_scope"]
                 for rows in d["groups"].values() for r in rows}
        self.assertFalse(state["sqli.probe"], "SQLi désactivée -> non activée pour ce scope")
        self.assertTrue(state["rce.probe"], "pentest -> rce.probe activée")

    def test_tools_reference_registered_kinds(self):
        d = self._run()
        registered = set(techniques.technique_kinds())
        for rows in d["groups"].values():
            for r in rows:
                for tool in r["tools"]:
                    self.assertIn(tool, registered, f"{r['kind']}: tool {tool} inconnu")


if __name__ == "__main__":
    unittest.main(verbosity=2)

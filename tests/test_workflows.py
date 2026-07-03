"""WORKFLOWS ÉDITABLES & SAUVEGARDÉS (pipelines composés sans code) — DÉRIVÉS du registre unique
(`forge/techniques.py`). Ce fichier PROUVE les exigences :

  (1) MODÈLE — un workflow = {name, description, steps:[{kind, params}]} validé/normalisé ; round-trip
      save/load/edit/delete via WorkflowStore ; workflows INTÉGRÉS dérivés du registre, NON supprimables.
  (2) FAIL-CLOSED (le cœur) — `resolve(workflow, enabled_kinds)` FILTRE les étapes par l'ensemble
      EFFECTIF activé du scope : une étape hors-scope/désactivée est LARGUÉE (dropped) ; un workflow
      ne peut que RESTREINDRE, jamais élargir.
  (3) EXÉCUTION — lancer un workflow ne TIRE que ses étapes in-scope ET activées pour le scope ; une
      étape désactivée/hors-scope est larguée (fail-closed), PROUVÉ au niveau de l'ENGINE (même module
      présent + cible in-scope ne tire pas si la technique est désactivée ; cible hors-scope -> VETO).

Tests HERMÉTIQUES : aucune I/O réseau (mode auto -> stubs firing locaux ; ou dry() sans effet).
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import techniques                                    # noqa: E402
from forge import workflows                                     # noqa: E402
from forge.roe import Scope, Action                             # noqa: E402
from forge.engine import Engine                                 # noqa: E402
from forge.brain import AutoPentestBrain                        # noqa: E402
from forge.planner import Planner                               # noqa: E402
from forge.schema import Target, Finding                        # noqa: E402
from forge.modules import registry                              # noqa: E402


class _PresentFiring(registry.Module):
    """Module PRÉSENT (available=True) qui TIRE un finding — prouve qu'une étape DÉSACTIVÉE / hors-scope
    ne tire JAMAIS même quand son module est disponible."""
    available = True
    exploit = False
    web_allowed = True

    def dry(self, action):
        return f"# dry {self.kind} {action.target}"

    def fire(self, action):
        return [Finding(target=action.target, title=f"hit {self.kind}", severity="INFO",
                        category="recon", status="tested", tool=self.kind)]


class _stub_kinds:
    """Context manager : substitue `_PresentFiring` à des KINDS réels, restaure le REGISTRY."""
    def __init__(self, *kinds):
        self.kinds = kinds
        self._saved = {}

    def __enter__(self):
        for k in self.kinds:
            self._saved[k] = registry.REGISTRY.get(k)
            registry.REGISTRY[k] = type("Stub", (_PresentFiring,), {"kind": k})
        return self

    def __exit__(self, *exc):
        for k in self.kinds:
            if self._saved[k] is None:
                registry.REGISTRY.pop(k, None)
            else:
                registry.REGISTRY[k] = self._saved[k]
        return False


# =================================================================================================
class TestValidateWorkflow(unittest.TestCase):
    """(1) validate_workflow : grammaire du nom, étapes {kind, params}, défauts, entrées hostiles."""

    def test_minimal_normalizes(self):
        v = workflows.validate_workflow({"name": "wf1", "steps": [{"kind": "recon.httpx"}]})
        self.assertEqual(v["name"], "wf1")
        self.assertEqual(v["description"], "")
        self.assertFalse(v["builtin"], "un workflow utilisateur n'est jamais builtin")
        self.assertEqual(v["steps"], [{"kind": "recon.httpx", "params": {}}])

    def test_name_from_arg_overrides(self):
        v = workflows.validate_workflow({"steps": []}, name="from-url")
        self.assertEqual(v["name"], "from-url")

    def test_bad_names_rejected(self):
        for bad in (None, "", "-x", "a b", "évil", "x" * 65, "a/b"):
            with self.assertRaises(workflows.WorkflowError):
                workflows.validate_workflow({"name": bad, "steps": []})

    def test_bad_steps_rejected(self):
        with self.assertRaises(workflows.WorkflowError):
            workflows.validate_workflow({"name": "w", "steps": "nope"})
        with self.assertRaises(workflows.WorkflowError):
            workflows.validate_workflow({"name": "w", "steps": [{"kind": "bad kind"}]})
        with self.assertRaises(workflows.WorkflowError):
            workflows.validate_workflow({"name": "w", "steps": [{"kind": "recon.httpx", "params": []}]})
        with self.assertRaises(workflows.WorkflowError):
            workflows.validate_workflow({"name": "w", "steps": [{} for _ in range(workflows.MAX_STEPS + 1)]})

    def test_unknown_kind_tolerated_but_dropped_by_resolve(self):
        # un kind inconnu du registre est TOLÉRÉ à la validation (comme la sélection) mais LARGUÉ par
        # resolve (∩ technique_kinds) -> jamais une capacité fabriquée.
        v = workflows.validate_workflow({"name": "w", "steps": [{"kind": "not.a.real.kind"}]})
        kept, dropped = workflows.resolve(v, set(techniques.technique_kinds()))
        self.assertEqual(kept, [])
        self.assertEqual([s["kind"] for s in dropped], ["not.a.real.kind"])

    def test_description_truncated(self):
        v = workflows.validate_workflow({"name": "w", "description": "x" * 999, "steps": []})
        self.assertLessEqual(len(v["description"]), workflows.MAX_DESC)


# =================================================================================================
class TestStoreRoundTrip(unittest.TestCase):
    """(1) WorkflowStore : round-trip save/load, édition, suppression ; builtins non supprimables."""

    def test_put_get_list_delete_round_trip(self):
        st = workflows.WorkflowStore()
        st.put({"name": "my-wf", "description": "d", "steps": [{"kind": "recon.httpx"}]})
        self.assertIsNotNone(st.get("my-wf"))
        self.assertIn("my-wf", st.list())
        # édition : re-put remplace (pas de doublon).
        st.put({"name": "my-wf", "steps": [{"kind": "web.nuclei"}, {"kind": "recon.httpx"}]})
        self.assertEqual(workflows.step_kinds(st.get("my-wf")), ["web.nuclei", "recon.httpx"])
        self.assertTrue(st.delete("my-wf"))
        self.assertIsNone(st.get("my-wf"))
        self.assertFalse(st.delete("my-wf"), "supprimer un inconnu -> False (pas d'exception)")

    def test_file_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "wf.json"
            st = workflows.WorkflowStore()
            st.put({"name": "disk-wf", "steps": [{"kind": "sqli.probe", "params": {"param": "q"}}]})
            st.save(p)
            st2 = workflows.WorkflowStore.load(p)
            got = st2.get("disk-wf")
            self.assertIsNotNone(got)
            self.assertEqual(workflows.workflow_module_params(got), {"sqli.probe": {"param": "q"}})

    def test_missing_file_is_builtins_only(self):
        st = workflows.WorkflowStore.load("/nonexistent/path/wf.json")
        self.assertEqual(st.user, {})
        self.assertEqual(set(st.list()), workflows.BUILTIN_NAMES | set(st.user))

    def test_builtins_protected(self):
        st = workflows.WorkflowStore()
        for name in workflows.BUILTIN_NAMES:
            with self.assertRaises(workflows.WorkflowError):
                st.delete(name)                          # suppression d'un builtin refusée (fail-closed)
            with self.assertRaises(workflows.WorkflowError):
                st.put({"name": name, "steps": []})      # écrasement d'un nom réservé refusé
        # un fichier ne peut pas shadow un builtin.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "wf.json"
            p.write_text(json.dumps({"full-pentest": {"name": "full-pentest", "steps": []}}), encoding="utf-8")
            st2 = workflows.WorkflowStore.load(p)
            self.assertNotIn("full-pentest", st2.user, "un builtin n'est pas fantômisable par un fichier")
            self.assertTrue(st2.get("full-pentest")["builtin"], "get renvoie le builtin dérivé")


# =================================================================================================
class TestBuiltinsDerived(unittest.TestCase):
    """(1) Les workflows INTÉGRÉS DÉRIVENT du registre (auto-à-jour) et pointent des kinds RÉELS."""

    def test_builtins_reference_real_kinds_and_are_ordered(self):
        b = workflows.builtin_workflows()
        self.assertEqual(set(b), workflows.BUILTIN_NAMES)
        real = set(techniques.technique_kinds())
        order = techniques.pipeline_ordered()
        for name, wf in b.items():
            self.assertTrue(wf["builtin"])
            kinds = workflows.step_kinds(wf)
            self.assertTrue(kinds, f"{name} non vide")
            for k in kinds:
                self.assertIn(k, real, f"{name}: kind {k} inconnu du registre")
            # l'ordre des étapes suit le pipeline topologique (recon < access < exploit).
            idx = [order.index(k) for k in kinds]
            self.assertEqual(idx, sorted(idx), f"{name}: étapes ordonnées topologiquement")

    def test_full_pentest_covers_all_kinds(self):
        wf = workflows.builtin_workflows()["full-pentest"]
        self.assertEqual(set(workflows.step_kinds(wf)), set(techniques.technique_kinds()))

    def test_bug_bounty_web_excludes_pentest_only(self):
        wf = workflows.builtin_workflows()["bug-bounty-web"]
        kinds = set(workflows.step_kinds(wf))
        self.assertIn("access_control.idor", kinds)      # bb-eligible
        self.assertNotIn("rce.probe", kinds)             # pentest-only -> exclu du profil bug_bounty
        self.assertNotIn("msf.module", kinds)


# =================================================================================================
class TestResolveFailClosed(unittest.TestCase):
    """(2) resolve() : intersection PROPOSITION ∩ ensemble activé — une étape hors ensemble est LARGUÉE."""

    def test_disabled_step_dropped(self):
        wf = workflows.validate_workflow({"name": "w", "steps": [
            {"kind": "xss.reflected"}, {"kind": "sqli.probe"}, {"kind": "recon.httpx"}]})
        sc = Scope({"in_scope": ["app.test"], "profile": "pentest",
                    "categories_enabled": {"SQLi": False}})
        kept, dropped = workflows.resolve(wf, sc.effective_technique_kinds())
        self.assertIn("xss.reflected", [s["kind"] for s in kept])
        self.assertIn("recon.httpx", [s["kind"] for s in kept])
        self.assertEqual([s["kind"] for s in dropped], ["sqli.probe"], "SQLi désactivée -> larguée")

    def test_resolve_cannot_widen_beyond_enabled(self):
        # un workflow qui propose une pentest-only sous un scope bug_bounty NE peut PAS l'activer.
        wf = workflows.validate_workflow({"name": "w", "steps": [
            {"kind": "rce.probe"}, {"kind": "access_control.idor"}]})
        sc = Scope({"in_scope": ["app.test"], "profile": "bug_bounty"})
        kept, dropped = workflows.resolve(wf, sc.effective_technique_kinds())
        self.assertEqual([s["kind"] for s in kept], ["access_control.idor"])
        self.assertEqual([s["kind"] for s in dropped], ["rce.probe"], "pentest-only larguée sous bug_bounty")

    def test_dedup_preserves_first(self):
        wf = {"steps": [{"kind": "recon.httpx", "params": {"a": 1}},
                        {"kind": "recon.httpx", "params": {"b": 2}}]}
        kept, _ = workflows.resolve(wf, {"recon.httpx"})
        self.assertEqual(len(kept), 1, "dédupliqué (1re occurrence)")


# =================================================================================================
class TestWorkflowRunFailClosed(unittest.TestCase):
    """(3) LANCER un workflow ne TIRE que ses étapes in-scope ET activées — PROUVÉ au niveau ENGINE.

    Reproduit ce que fait `forge campaign --workflow` : modules = étapes du workflow (la PROPOSITION),
    brain = AutoPentestBrain(effective set), mode auto + armé, modules PRÉSENTS+firing. On PROUVE :
      - une étape ACTIVÉE + in-scope TIRE (FIRE) ;
      - une étape DÉSACTIVÉE au scope ne tire JAMAIS (larguée, même module présent) ;
      - une cible HORS-SCOPE -> VETO (jamais tirée)."""

    def _campaign(self, scope, wf, targets):
        eng = Engine(scope, mode="auto")
        eng.arm("test workflow")
        modules = workflows.step_kinds(wf)               # la PROPOSITION brute (l'engine larguera)
        brain = AutoPentestBrain(scope.effective_technique_kinds())
        eng.campaign(targets, brain, Planner(),
                     modules=modules, module_params=workflows.workflow_module_params(wf))
        return eng

    def test_only_enabled_in_scope_steps_fire(self):
        wf = workflows.validate_workflow({"name": "w", "steps": [
            {"kind": "xss.reflected"}, {"kind": "sqli.probe"}]})
        # SQLi désactivée au scope ; XSS activée. app.test in-scope ; evil.test HORS scope.
        sc = Scope({"in_scope": ["app.test"], "profile": "pentest",
                    "categories_enabled": {"SQLi": False}})
        with _stub_kinds("xss.reflected", "sqli.probe"):
            eng = self._campaign(sc, wf, [Target(host="app.test", kind="app"),
                                          Target(host="evil.test", kind="app")])
        fired = {(r["kind"], r["target"]) for r in eng.results if r["verdict"] == "FIRE"}
        # (a) l'étape ACTIVÉE + in-scope a bien tiré.
        self.assertIn(("xss.reflected", "app.test"), fired, "étape activée + in-scope -> FIRE")
        # (b) l'étape DÉSACTIVÉE ne tire JAMAIS (nulle part), malgré un module présent+firing.
        self.assertFalse(any(k == "sqli.probe" for k, _ in fired),
                         "étape désactivée au scope -> jamais tirée (fail-closed)")
        # (c) rien n'a tiré sur la cible HORS-SCOPE.
        self.assertFalse(any(t == "evil.test" for _, t in fired), "cible hors-scope -> jamais tirée")
        # et l'unique finding vient de app.test (l'étape activée in-scope).
        self.assertTrue(eng.findings)
        for f in eng.findings:
            self.assertEqual(f.target, "app.test")

    def test_out_of_scope_target_is_vetoed(self):
        wf = workflows.validate_workflow({"name": "w", "steps": [{"kind": "xss.reflected"}]})
        sc = Scope({"in_scope": ["app.test"], "profile": "pentest"})
        with _stub_kinds("xss.reflected"):
            eng = self._campaign(sc, wf, [Target(host="evil.test", kind="app")])
        verdicts = {r["verdict"] for r in eng.results}
        self.assertIn("VETO", verdicts, "cible hors-scope -> VETO")
        self.assertNotIn("FIRE", verdicts, "aucune action ne tire hors-scope")
        self.assertEqual(eng.findings, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

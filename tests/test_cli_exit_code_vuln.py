# SPDX-License-Identifier: AGPL-3.0-or-later
"""D11 — le code de sortie DOCUMENTÉ (« 1 = vuln trouvée ») est désormais PRODUIT.

LE DÉFAUT MESURÉ. `docs/CLI.md` annonce « `0` OK, `1` échec/vuln trouvée » ; `cmd_run` et
`cmd_campaign` faisaient `return 0` INCONDITIONNELLEMENT. Tous les runs du banc de détection ayant
produit des findings `HIGH`/`vulnerable` sortaient en `rc=0` : **une CI qui gate sur le code de sortie
ne pouvait pas voir une vulnérabilité**, et c'est le seul signal qu'une CI lit.

CE QUE CES TESTS VERROUILLENT, y compris la borne qu'il ne faut PAS casser :

  1. `run` et `campaign` sortent en **1** quand au moins un finding porte `status=vulnerable` ;
  2. ils sortent en **0** quand aucun ne le porte (INFO/tested/reported_by_tool ne suffisent pas) ;
  3. un run **INTERROMPU** (échéance de budget) sort toujours en **0** — décision DÉLIBÉRÉE :
     l'honnêteté d'un run partiel est portée par le rapport, pas par un code d'échec ;
  4. mais une vuln trouvée AVANT la coupure sort quand même en **1** : c'est « vuln trouvée » qui
     doit se voir, pas « run interrompu » ;
  5. le critère est la PREUVE, pas la sévérité : un `CRITICAL` non prouvé (`tested`) ne fait pas
     basculer le code — sinon on rejugerait la preuve une seconde fois, ailleurs.

Hermétique : cerveau et registre de modules stubés, aucun réseau (NXDOMAIN forcé par `tests._dns`),
et l'échéance de budget est prouvée en INJECTANT l'horloge, jamais en dormant.
"""
import json
import sys
import unittest
import unittest.mock as _mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                    # noqa: E402
from forge.schema import Finding                                # noqa: E402
from forge.modules import registry                              # noqa: E402
from forge.cli import build_parser                              # noqa: E402
from forge.cli import engine as cli_engine                      # noqa: E402
from forge.cli.engine import EXIT_VULN, _exit_code              # noqa: E402
from forge.interrupt import Budget                              # noqa: E402
from tests._tmp import temp_dir                                 # noqa: E402
from tests._dns import setUpModule, tearDownModule  # noqa: F401,E402


class FakeClock:
    """Horloge monotone factice : chaque lecture avance de `step` (déterministe, instantanée)."""

    def __init__(self, step=1.0):
        self.t, self.step = 0.0, step

    def __call__(self):
        self.t += self.step
        return self.t


# --- stubs moteur (même discipline que tests/test_run_budget.py : zéro réseau) ----------------------
class _StubModule(registry.Module):
    exploit = False
    web_allowed = True
    mitre = "T9999"
    _findings = []

    def dry(self, action):
        return f"# stub dry {self.kind} {action.target}"

    def fire(self, action):
        f = self._findings
        return list(f(action)) if callable(f) else list(f)


class _swap_registry:
    def __init__(self, mapping):
        self.mapping, self._saved = mapping, {}

    def __enter__(self):
        for kind, findings in self.mapping.items():
            self._saved[kind] = registry.REGISTRY.get(kind)
            registry.REGISTRY[kind] = type(
                f"Stub_{kind.replace('.', '_')}", (_StubModule,),
                {"kind": kind, "_findings": staticmethod(findings)})
        return self

    def __exit__(self, *exc):
        for kind, prev in self._saved.items():
            if prev is None:
                registry.REGISTRY.pop(kind, None)
            else:
                registry.REGISTRY[kind] = prev
        return False


class _WaveBrain:
    """Cerveau déterministe : la vague i à chaque appel, puis [] (point fixe)."""

    def __init__(self, waves):
        self._waves, self._i = list(waves), 0

    def propose(self, graph_state):
        if self._i < len(self._waves):
            acts = self._waves[self._i]
            self._i += 1
            return acts
        return []


# --- émetteurs de findings : la PREUVE passe par le chemin sanctionné (`finding(_proven=True)`) -----
def _proven_vuln(action):
    return [registry.Module.finding(
        _proven=True, target=action.target, status="vulnerable", severity="HIGH",
        title=f"vuln prouvée sur {action.target}", category="CWE-89",
        evidence="preuve concrète (stub de test)")]


def _tested_only(action):
    return [registry.Module.finding(
        target=action.target, status="tested", severity="INFO",
        title=f"rien trouvé sur {action.target}", category="demo")]


def _critical_but_unproven(action):
    """Sévérité maximale, AUCUNE preuve : le schéma rabat `vulnerable` -> `tested`. Le code de sortie
    ne doit PAS basculer — sinon la sévérité redeviendrait un second juge de la preuve."""
    return [registry.Module.finding(
        target=action.target, status="vulnerable", severity="CRITICAL",
        title=f"réclamation non prouvée sur {action.target}", category="demo")]


class _Harness(unittest.TestCase):
    HOSTS = ("h0.exit.test", "h1.exit.test", "h2.exit.test")

    def setUp(self):
        self.dir = temp_dir(self, "forge-exit-")
        self.scope = self.dir / "scope.json"
        self.targets = self.dir / "targets.json"
        self.actions = self.dir / "actions.json"
        self.report = self.dir / "report.md"
        self.scope.write_text(json.dumps({
            "mode": "grey", "in_scope": list(self.HOSTS),
            "allow_exploit": True, "allow_destructive": False}), encoding="utf-8")
        self.targets.write_text(json.dumps([{"host": self.HOSTS[0]}]), encoding="utf-8")
        self.actions.write_text(json.dumps(
            [{"kind": "demo.probe", "target": h} for h in self.HOSTS]), encoding="utf-8")

    def _run(self, emitter):
        args = build_parser().parse_args(
            ["run", "--scope", str(self.scope), "--actions", str(self.actions),
             "--arm", "--mode", "auto", "--report", str(self.report)])
        with _swap_registry({"demo.probe": emitter}):
            return cli_engine.cmd_run(args)

    def _campaign(self, emitter, budget_secs=None, clock_step=1.0, waves=None):
        args = build_parser().parse_args(
            ["campaign", "--scope", str(self.scope), "--targets", str(self.targets),
             "--arm", "--mode", "auto", "--report", str(self.report)])
        brain = _WaveBrain(waves if waves is not None
                           else [[Action("demo.probe", h) for h in self.HOSTS]])
        patches = [_mock.patch.object(cli_engine, "HeuristicBrain", lambda *a, **k: brain),
                   _mock.patch.object(cli_engine, "AutoPentestBrain", lambda *a, **k: brain)]
        if budget_secs is not None:
            clock = FakeClock(step=clock_step)
            patches.append(_mock.patch.object(
                cli_engine, "Budget", lambda secs, clock=clock: Budget(secs, clock=clock)))
            args.run_timeout = budget_secs
        started = []
        try:
            for p in patches:
                p.start()
                started.append(p)
            with _swap_registry({"demo.probe": emitter}):
                return cli_engine.cmd_campaign(args)
        finally:
            for p in reversed(started):
                p.stop()


class TestExitCodePredicate(unittest.TestCase):
    """Le prédicat, isolé : la PREUVE et rien d'autre."""

    class _E:
        def __init__(self, findings):
            self.findings = findings

    def test_only_vulnerable_status_triggers(self):
        self.assertEqual(_exit_code(self._E([])), 0)
        self.assertEqual(_exit_code(self._E([
            Finding(target="t", title="a", status="tested", severity="CRITICAL")])), 0)
        self.assertEqual(_exit_code(self._E([
            Finding(target="t", title="a", status="skipped", severity="HIGH")])), 0)
        self.assertEqual(_exit_code(self._E([
            Finding(target="t", title="a", status="reported_by_tool", severity="HIGH")])), 0)

    def test_a_proven_finding_triggers_regardless_of_severity(self):
        f = registry.Module.finding(_proven=True, target="t", title="v", status="vulnerable",
                                    severity="LOW", category="CWE-89")
        self.assertEqual(f.status, "vulnerable")
        self.assertEqual(_exit_code(self._E([f])), EXIT_VULN)

    def test_interruption_alone_does_not_change_the_code(self):
        self.assertEqual(_exit_code(self._E([]), {"cause": "budget", "label": "budget"}), 0)

    def test_engine_without_findings_attribute_is_tolerated(self):
        self.assertEqual(_exit_code(object()), 0)


class TestRunExitCode(_Harness):
    def test_proven_vuln_exits_1(self):
        self.assertEqual(self._run(_proven_vuln), EXIT_VULN)

    def test_no_vuln_exits_0(self):
        self.assertEqual(self._run(_tested_only), 0)

    def test_unproven_critical_exits_0(self):
        self.assertEqual(self._run(_critical_but_unproven), 0)


class TestCampaignExitCode(_Harness):
    def test_proven_vuln_exits_1(self):
        self.assertEqual(self._campaign(_proven_vuln), EXIT_VULN)

    def test_no_vuln_exits_0(self):
        self.assertEqual(self._campaign(_tested_only), 0)


class TestInterruptedRunStaysZero(_Harness):
    """LA BORNE À NE PAS CASSER. Une décision récente a rendu `exit 0` VOLONTAIRE sur interruption
    budget/signal : l'honnêteté est portée par le RAPPORT (« RAPPORT PARTIEL — RUN INTERROMPU »)."""

    MANY = tuple(f"h{i}.exit.test" for i in range(20))

    def setUp(self):
        super().setUp()
        self.scope.write_text(json.dumps({
            "mode": "grey", "in_scope": list(self.MANY),
            "allow_exploit": True, "allow_destructive": False}), encoding="utf-8")
        self.targets.write_text(json.dumps([{"host": self.MANY[0]}]), encoding="utf-8")

    def _waves(self):
        return [[Action("demo.probe", h) for h in self.MANY]]

    def test_budget_interruption_without_vuln_exits_0(self):
        rc = self._campaign(_tested_only, budget_secs=5, clock_step=1.0, waves=self._waves())
        self.assertEqual(rc, 0, "un run coupé par SON budget n'est pas un échec")
        rep = self.report.read_text(encoding="utf-8")
        self.assertIn("RAPPORT PARTIEL", rep, "l'honnêteté du partiel vit dans le rapport")

    def test_budget_interruption_WITH_a_vuln_exits_1(self):
        """La vuln trouvée AVANT la coupure doit rester VISIBLE : c'est « vuln trouvée » qui doit se
        voir, pas « run interrompu »."""
        rc = self._campaign(_proven_vuln, budget_secs=5, clock_step=1.0, waves=self._waves())
        self.assertEqual(rc, EXIT_VULN)
        rep = self.report.read_text(encoding="utf-8")
        self.assertIn("RAPPORT PARTIEL", rep, "le run reste ANNONCÉ partiel malgré l'exit 1")


class TestDocumentedContract(unittest.TestCase):
    """Le contrat est écrit dans `docs/CLI.md` : il doit décrire ce que le code fait maintenant."""

    def test_cli_doc_states_both_branches(self):
        doc = (Path(__file__).resolve().parents[1] / "docs" / "CLI.md").read_text(encoding="utf-8")
        self.assertIn("status=vulnerable", doc)
        self.assertIn("INTERROMPU", doc)


if __name__ == "__main__":
    unittest.main()

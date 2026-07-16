"""LOT ENGINE ITÉRATIF — campagne plan->observe->replan + cerveau qui lit le graphe (chaînage).

Preuves (toutes HERMÉTIQUES — modules stubés, ZÉRO réseau) :
  1. le cerveau lit l'ÉTAT du graphe : `propose(graph)` accepte un EngagementGraph (nouveau
     contrat) ET rétro-compat une `list[Target]` (ancien contrat) ;
  2. CHAÎNAGE : une 2e vague est proposée À PARTIR des findings de la 1re (origine hors-CDN
     découverte en vague 1 -> nuclei/idor/ssrf sur l'IP d'origine en vague 2) ;
  3. CRITÈRES D'ARRÊT : point fixe (plus de nouvelle action) ET garde-fou `max_waves` respectés ;
  4. IDEMPOTENCE : une action déjà jouée n'est jamais rejouée (id stable kind:target) ;
  5. GOUVERNANCE par vague : le ROE gate chaque vague (rien ne tire sans FIRE) ;
  6. coverage-safe préservée : skipped_budget accumulé (defer != delete), gaps recalculés.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action, FIRE                    # noqa: E402
from forge.engine import Engine                              # noqa: E402
from forge.brain import HeuristicBrain, Brain, _as_graph     # noqa: E402
from forge.planner import Planner                            # noqa: E402
from forge.graph import EngagementGraph                      # noqa: E402
from forge.schema import Target, Finding                     # noqa: E402
from forge.modules import registry                           # noqa: E402


def scope(in_scope=("app.test",), exploit=True, destructive=False):
    return Scope({"mode": "grey", "in_scope": list(in_scope),
                  "allow_exploit": exploit, "allow_destructive": destructive})


class _StubModule(registry.Module):
    """Module stub configurable : fire() renvoie des Finding fixés (zéro I/O).

    `_findings` peut être une liste statique OU un callable(action)->list[Finding] (utile pour
    refléter la cible réelle de l'action, ex: nuclei qui ne 'trouve' un hit que sur l'IP chaînée)."""
    exploit = False
    web_allowed = True
    mitre = "T9999"
    _findings = []                                            # surchargé par sous-classe

    def dry(self, action):
        return f"# stub dry {self.kind} {action.target}"

    def fire(self, action):
        f = self._findings
        return list(f(action)) if callable(f) else list(f)


class _swap_registry:
    """Context manager : remplace des kinds du REGISTRY par des stubs, restaure à la sortie.

    Permet de tester la BOUCLE (engine+brain) sans toucher les vrais modules réseau. On stube
    UNIQUEMENT les kinds passés ; les autres restent les vrais (mais ne tirent pas dans ces tests)."""
    def __init__(self, mapping):
        self.mapping = mapping                                # {kind: list[Finding]}
        self._saved = {}

    def __enter__(self):
        for kind, findings in self.mapping.items():
            self._saved[kind] = registry.REGISTRY.get(kind)
            # callable -> staticmethod (sinon il serait lié comme méthode et recevrait `self`).
            attr = staticmethod(findings) if callable(findings) else findings
            cls = type(f"Stub_{kind.replace('.', '_')}", (_StubModule,),
                       {"kind": kind, "_findings": attr})
            registry.REGISTRY[kind] = cls
        return self

    def __exit__(self, *exc):
        for kind, prev in self._saved.items():
            if prev is None:
                registry.REGISTRY.pop(kind, None)
            else:
                registry.REGISTRY[kind] = prev
        return False


def _armed_auto(sc):
    """Engine armé + mode auto (toutes actions in-scope/autorisées FIRENT sans approbation 1-à-1).
    Le ROE reste seul juge : une action hors-scope/exploit-non-autorisé est quand même refusée."""
    eng = Engine(sc, mode="auto")
    eng.arm("test")
    return eng


# ---------------------------------------------------------------------------
class TestBrainReadsGraph(unittest.TestCase):
    def test_propose_accepts_graph_state(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        actions = HeuristicBrain().propose(g)
        kinds = {a.kind for a in actions}
        self.assertIn("recon.httpx", kinds)
        self.assertIn("access_control.idor", kinds)           # qualifiant toujours proposé
        self.assertIn("ssrf.callback", kinds)                 # nouveaux oracles inclus
        self.assertIn("origin.find", kinds)                   # amorce du chaînage CDN->origine

    def test_propose_backward_compat_target_list(self):
        # ancien contrat : propose([Target(...)]) reste valide (converti en graphe éphémère)
        actions = HeuristicBrain().propose([Target("app.test", "url")])
        self.assertTrue(actions)
        self.assertIn("web.nuclei", {a.kind for a in actions})

    def test_as_graph_passthrough_and_conversion(self):
        g = EngagementGraph()
        self.assertIs(_as_graph(g), g)                        # graphe -> passthrough
        g2 = _as_graph([Target("h1", "url")])                 # liste -> graphe neuf
        self.assertIn("h1", g2.hosts())

    def test_chaining_on_origin_finding(self):
        # graphe avec un finding "origine hors-CDN vérifiée" sur une IP -> le cerveau CHAÎNE des
        # attaques sur l'IP (pas le domaine WAF).
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        g.add_finding(Finding(target="203.0.113.10", title="Origine exposée derrière CDN (VÉRIFIÉE) — bypass WAF",
                              status="vulnerable", severity="HIGH", category="origin-exposure"))
        actions = HeuristicBrain().propose(g)
        chained = [a for a in actions if a.target == "203.0.113.10"]
        kinds = {a.kind for a in chained}
        self.assertIn("web.nuclei", kinds)                    # nuclei sur l'origine (bypass WAF)
        self.assertIn("access_control.idor", kinds)
        self.assertIn("ssrf.callback", kinds)

    def test_chaining_on_discovered_http_service(self):
        # un service HTTP découvert (posé par nmap dans le graphe) -> le cerveau CHAÎNE un
        # fingerprint sur host:port (nouvelle cible), qui amorcera les oracles à la vague suivante.
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        g.add_service("app.test", 8080, name="http-alt")
        actions = HeuristicBrain().propose(g)
        self.assertTrue(any(a.kind == "recon.httpx" and a.target == "app.test:8080"
                            and "chaîné" in a.desc for a in actions))


# ---------------------------------------------------------------------------
class TestIterativeCampaign(unittest.TestCase):
    def test_second_wave_proposed_from_first_wave_findings(self):
        # VAGUE 1 : origin.find (stubé) découvre une origine hors-CDN sur 203.0.113.10 ->
        # VAGUE 2 : le cerveau CHAÎNE nuclei/idor/ssrf sur 203.0.113.10. Tous stubés (zéro réseau).
        ip = "203.0.113.10"
        origin_find = [Finding(target=ip, title="Origine exposée derrière CDN (VÉRIFIÉE) — bypass WAF",
                               status="vulnerable", severity="HIGH", category="origin-exposure",
                               mitre="T1590.005")]
        # nuclei ne 'trouve' un hit QUE sur l'IP d'origine (chaînée en vague 2), pas sur le domaine WAF :
        # ainsi un finding nuclei sur l'IP PROUVE que la chaîne a réellement tiré sur l'origine.
        def nuclei_only_on_ip(action):
            if action.target == ip:
                return [Finding(target=ip, title="nuclei: hit sur origine", status="reported_by_tool",
                                severity="HIGH", category="nuclei")]
            return []
        stubs = {
            "origin.find": origin_find,
            "recon.httpx": [], "web.nuclei": nuclei_only_on_ip, "access_control.idor": [],
            "ssrf.callback": [], "auth.takeover": [], "cors.credentials": [], "recon.nmap": [],
            # seeds de découverte semés d'office par le cerveau (auto-alimentation) -> stub inerte (zéro réseau)
            "recon.subdomains": [], "recon.js_endpoints": [], "recon.urls": [],
        }
        # le 2e tour cible l'IP -> nuclei sur l'IP doit FIRER -> l'IP doit être in-scope.
        sc = scope(in_scope=("app.test", ip), exploit=True)
        with _swap_registry(stubs):
            eng = _armed_auto(sc)
            eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), max_waves=4)

        # la campagne a fait AU MOINS 2 vagues (chaînage : la 2e dérive des findings de la 1re)
        self.assertGreaterEqual(eng.waves, 2)
        # une action a CIBLÉ l'IP d'origine -> c'est le chaînage (vague 2), pas le plan de base (vague 1)
        ip_actions = [r for r in eng.results if r["target"] == ip]
        self.assertTrue(ip_actions, "aucune action chaînée sur l'IP d'origine — pas de 2e vague dérivée")
        self.assertIn("web.nuclei", {r["kind"] for r in ip_actions})
        # toutes les actions sur l'IP ont été GATÉES (FIRE) — la gouvernance s'applique par vague
        self.assertTrue(all(r["verdict"] == FIRE for r in ip_actions))
        # un finding nuclei sur l'IP atteste que la chaîne a réellement tiré sur l'origine
        self.assertTrue(any(f.target == ip and "nuclei" in f.title for f in eng.findings))

    def test_stop_on_fixpoint_no_new_action(self):
        # cerveau qui propose TOUJOURS la même action unique : après la 1re vague, plus rien de neuf
        # -> arrêt par POINT FIXE (1 seule vague), bien avant max_waves.
        class FixedBrain(Brain):
            def propose(self, graph_state):
                return [Action("demo.fingerprint", "app.test")]
        eng = _armed_auto(scope())
        eng.campaign([Target("app.test", "url")], FixedBrain(), Planner(), max_waves=10)
        self.assertEqual(eng.waves, 1)                        # point fixe atteint après 1 vague
        # l'action n'a été jouée qu'UNE fois (idempotence inter-vagues)
        demo = [r for r in eng.results if r["kind"] == "demo.fingerprint"]
        self.assertEqual(len(demo), 1)

    def test_max_waves_cap_is_respected(self):
        # cerveau pathologique : propose une action NEUVE à chaque vague (jamais de point fixe) ->
        # le garde-fou max_waves DOIT borner la boucle.
        class GrowingBrain(Brain):
            def __init__(self):
                self.n = 0
            def propose(self, graph_state):
                self.n += 1
                # cible distincte à chaque appel -> id d'action toujours neuf (jamais dédupliqué)
                return [Action("demo.fingerprint", f"app.test", params={"i": self.n}, id=f"demo:{self.n}")]
        eng = _armed_auto(scope())
        eng.campaign([Target("app.test", "url")], GrowingBrain(), Planner(), max_waves=3)
        self.assertEqual(eng.waves, 3)                        # borné par max_waves (pas de boucle infinie)

    def test_governance_applies_each_wave_unarmed_fires_nothing(self):
        # campagne NON armée -> AUCUN tir, même sur plusieurs vagues proposées (ROE par vague).
        ip = "203.0.113.10"
        stubs = {"origin.find": [Finding(target=ip, title="Origine exposée derrière CDN (VÉRIFIÉE) — bypass WAF",
                                         status="vulnerable", severity="HIGH", category="origin-exposure")],
                 "recon.httpx": [], "web.nuclei": [], "access_control.idor": [],
                 "ssrf.callback": [], "auth.takeover": [], "cors.credentials": [], "recon.nmap": []}
        with _swap_registry(stubs):
            eng = Engine(scope(in_scope=("app.test", ip), exploit=True))   # in-scope mais NON armé
            eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner())
        self.assertEqual(len(eng.coverage()["fired"]), 0)     # rien tiré (tout DRY_RUN)
        self.assertEqual(len(eng.run_records), 0)

    def test_idempotence_no_duplicate_planning_across_waves(self):
        # même action proposée sur 2 vagues -> planifiée/exécutée une SEULE fois.
        ip = "203.0.113.10"
        stubs = {"origin.find": [Finding(target=ip, title="Origine exposée derrière CDN (VÉRIFIÉE) — bypass WAF",
                                         status="vulnerable", severity="HIGH", category="origin-exposure")],
                 "recon.httpx": [], "web.nuclei": [], "access_control.idor": [],
                 "ssrf.callback": [], "auth.takeover": [], "cors.credentials": [], "recon.nmap": [],
                 "recon.subdomains": [], "recon.js_endpoints": [], "recon.urls": []}
        with _swap_registry(stubs):
            eng = _armed_auto(scope(in_scope=("app.test", ip), exploit=True))
            eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(), max_waves=5)
        # aucun (kind, target) n'apparaît deux fois dans results (dedup inter-vagues garanti)
        seen = [(r["kind"], r["target"]) for r in eng.results]
        self.assertEqual(len(seen), len(set(seen)), f"action rejouée entre vagues: {seen}")

    def test_final_gaps_host_matching_is_delimited_not_prefix(self):
        # ANTI-FAUX-NÉGATIF de couverture : une action sur `app.testing` (autre host qui PARTAGE
        # un préfixe avec `app.test`) ne doit PAS être rattachée à `app.test` — sinon une classe
        # « jamais tentée » sur app.test serait masquée comme « tentée ». Un startswith naïf cassait
        # ça ; on exige host exact OU délimiteur franc (host:port / host/path).
        eng = Engine(scope(in_scope=("app.test", "app.testing")))
        eng.results = [
            # une seule classe access_control tentée, et seulement sur app.testing
            {"action": "x", "target": "app.testing", "kind": "access_control.idor",
             "verdict": FIRE, "reasons": [], "output": None},
            # une action sur host:port d'app.test -> DOIT compter pour app.test (délimiteur ':')
            {"action": "y", "target": "app.test:8080", "kind": "auth.takeover",
             "verdict": FIRE, "reasons": [], "output": None},
        ]
        gaps = eng._final_gaps(Planner(), ["app.test", "app.testing"])
        # app.test : auth tenté (via host:port), access_control PAS tenté (l'idor était sur app.testing)
        self.assertIn("app.test", gaps)
        self.assertIn("access_control", gaps["app.test"])     # lacune RÉELLE, non masquée
        self.assertNotIn("auth", gaps["app.test"])            # auth tenté via app.test:8080
        # app.testing : access_control tenté (sur lui-même), pas faussement crédité à app.test
        self.assertIn("app.testing", gaps)
        self.assertNotIn("access_control", gaps["app.testing"])

    def test_skipped_budget_accumulated_across_waves(self):
        # budget serré -> des non-qualifiantes sont déférées ; elles restent VISIBLES (defer != delete)
        # et ne sont JAMAIS perdues même sur une campagne multi-vagues.
        eng = _armed_auto(scope())
        eng.campaign([Target("app.test", "url")], HeuristicBrain(), Planner(budget=0.0), max_waves=2)
        # avec budget=0, les non-qualifiantes (recon/nuclei/origin) sont déférées, les qualifiantes gardées
        deferred_kinds = {a.kind for a in eng.skipped_budget}
        self.assertTrue(deferred_kinds, "budget=0 aurait dû déférer des actions non-qualifiantes")
        # une qualifiante (idor) n'est JAMAIS déférée (plancher coverage-safe préservé)
        self.assertNotIn("access_control.idor", deferred_kinds)


class TestFireExceptionRobustness(unittest.TestCase):
    """M6 — une exception LEVÉE par module.fire() devient un ExecResult(ERROR) TRAÇABLE ; la campagne
    (boucle run/execute) CONTINUE au lieu d'avorter (contrat « zéro lacune silencieuse »)."""

    def test_module_exception_becomes_error_record_and_run_continues(self):
        def boom(action):
            raise RuntimeError("module boom xyz")
        good = [Finding(target="app.test", title="hit", severity="LOW", mitre="T1")]
        # 1er kind explose au tir, 2e kind est sain -> on prouve que le 2e tire QUAND MÊME.
        with _swap_registry({"access_control.idor": boom, "web.nuclei": good}):
            eng = _armed_auto(scope())
            bad = Action(kind="access_control.idor", target="app.test")
            ok = Action(kind="web.nuclei", target="app.test")
            # run() enchaîne les deux : le 1er lève côté module, le 2e est sain. AUCUNE exception ne remonte.
            results = eng.run([bad, ok])
            self.assertEqual(len(results), 2, "run() n'a PAS avorté à l'exception du module")
            # (1) l'action qui explose -> ExecResult(ERROR) traçable, repr de l'exception dans les raisons.
            self.assertEqual(results[0]["verdict"], "ERROR")
            self.assertTrue(any("boom xyz" in r for r in results[0]["reasons"]),
                            "la raison porte le repr de l'exception levée")
            self.assertIsNone(results[0]["output"])
            # (2) l'action SUIVANTE (module sain) a bien tiré -> la campagne survit et produit son finding.
            self.assertEqual(results[1]["verdict"], FIRE)
            self.assertTrue(results[1]["output"], "le module sain produit un output APRÈS l'ERROR")
            # (3) l'ERROR est bucketé dans results (rapport anti-masquage), jamais perdu silencieusement.
            self.assertTrue(any(r["verdict"] == "ERROR" for r in eng.results))


if __name__ == "__main__":
    unittest.main(verbosity=2)

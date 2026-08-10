# SPDX-License-Identifier: AGPL-3.0-or-later
"""LA DÉCOUVERTE D'ABORD — étage structurel, frontière de replanification, part de budget par kind.

CE QUE CE FICHIER PROUVE, ET CE QU'IL REFUSE DE PROUVER
-------------------------------------------------------
Le dépôt portait DÉJÀ deux tests d'ordre (`test_engine_iterative.TestE3…`) et une intention d'ordre
DÉCLARÉE dans le cerveau — et la campagne réelle a quand même perdu 93 % de ses actions et 100 % de
sa surface. Un test « l'ordre est correct » ne prouve rien sur la PORTÉE. On prouve donc les deux :
  · les propriétés STRUCTURELLES (étage, frontière, part), une par une, avec leur MUTATION ;
  · la PORTÉE, en chiffres, sur le harnais qui rejoue la forme du run réel
    (`tests/bench_wave_reach.py` : 3 cibles, durées mesurées injectées, horloge virtuelle).

CHAQUE MUTATION EST VÉRIFIÉE ATTEIGNABLE. Une mutation qui reste VERTE est un constat sur le test,
pas un succès ; une mutation qu'on ne peut pas ATTEINDRE ne prouve rien non plus (le cas s'est produit
dans ce dépôt : une garde court-circuitait la boucle avant le prédicat muté, masquant le défaut au
lieu de prouver qu'il était corrigé). `_assert_mutation_kills` exige donc DEUX faits : la propriété
passe sur le code livré, ET elle ÉCHOUE sur le code muté — sans quoi le test échoue lui-même.
"""
from __future__ import annotations

import inspect
import re
import sys
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import planner as planner_mod                      # noqa: E402
from forge.brain import AutoPentestBrain, HeuristicBrain      # noqa: E402
from forge.engine import Engine                               # noqa: E402
from forge.graph import EngagementGraph                       # noqa: E402
from forge.interrupt import KindShare, resolve_kind_share     # noqa: E402
from forge.modules import registry                            # noqa: E402
from forge.planner import (Planner, STAGE_SURFACE, STAGE_VERIFY, is_endpoint_target,  # noqa: E402
                           is_floored, stage, surface_producers)
from forge.roe import Action, Scope                             # noqa: E402
from forge.schema import Finding                                # noqa: E402
from tests._dns import setUpModule, tearDownModule  # noqa: F401,E402

SKIP = "SKIP"                                    # `engine.Verdict.SKIP.value` — la chaîne sérialisée


def _assert_mutation_kills(case, check, patcher, label):
    """Preuve par MUTATION, en deux temps NON NÉGOCIABLES.

    1. ATTEIGNABILITÉ + VÉRITÉ : `check()` passe sur le code LIVRÉ (sinon le test est faux, pas le
       code) ;
    2. LÉTALITÉ : sous `patcher` (la mutation), `check()` DOIT lever `AssertionError`. S'il passe
       quand même, la mutation n'est pas atteinte par ce test — on le DIT, on ne s'en félicite pas.
    """
    check()                                                    # (1) le code livré satisfait la propriété
    with patcher:
        try:
            check()
        except AssertionError:
            return                                             # (2) la mutation TUE : c'est la preuve
    case.fail(f"MUTATION NON LÉTALE — « {label} » : la propriété passe encore une fois le correctif "
              f"retiré. Le test ne prouve donc RIEN sur ce point (soit il ne l'atteint pas, soit il "
              f"vérifie autre chose).")


def _legacy_rank_key(self, action):
    """MUTATION — `Planner.rank_key` d'avant le lot : l'EV seule, sans étage."""
    return (0, -self.ev(action))


def _legacy_split(ordered, wave_index):
    """MUTATION — `Engine._split_discovery_first` d'avant le lot : aucune coupe."""
    return list(ordered), []


# ---------------------------------------------------------------------------------------------
class TestNativeProducerList(unittest.TestCase):
    """`planner.NATIVE_SURFACE_PRODUCERS` est-elle une TAXONOMIE RECOPIÉE (qui dérivera) ou un fait
    VÉRIFIABLE ? On le vérifie contre le SOURCE des modules : un module natif est un producteur SI ET
    SEULEMENT SI il émet un finding de DÉCOUVERTE (marqueur `techniques.DISCOVERY_*` ou l'un des
    helpers `_discovery.*`). Équivalence EXACTE, aucune exception tolérée."""

    #: signatures d'ÉMISSION d'un asset découvert, telles qu'écrites dans les modules.
    _EMITS = re.compile(r"DISCOVERY_(SUBDOMAIN|ENDPOINT|HISTORICAL_URL|SERVICE)_MARKER"
                        r"|endpoint_discovery_findings|service_discovery_findings")

    @staticmethod
    def _native_kinds():
        """Kinds dont le module est NATIF (pas un wrapper `ToolSpec`, qui déclare `asset_hits`)."""
        return {k: m for k, m in registry.REGISTRY.items() if getattr(m, "spec", None) is None}

    def test_liste_native_equivaut_aux_emetteurs_de_decouverte(self):
        emitters = set()
        for kind, module in self._native_kinds().items():
            try:
                src = inspect.getsource(module)
            except (OSError, TypeError):                        # module sans source lisible -> ignoré
                continue
            if self._EMITS.search(src):
                emitters.add(kind)
        self.assertTrue(emitters, "aucun émetteur natif trouvé — le scan de source ne marche plus")
        self.assertEqual(
            emitters, set(planner_mod.NATIVE_SURFACE_PRODUCERS),
            "DÉRIVE : `NATIVE_SURFACE_PRODUCERS` ne coïncide plus avec les modules natifs qui émettent "
            "une découverte. Manquants (émettent mais non listés) : "
            f"{sorted(emitters - set(planner_mod.NATIVE_SURFACE_PRODUCERS))} ; en trop (listés mais "
            f"n'émettent rien) : {sorted(set(planner_mod.NATIVE_SURFACE_PRODUCERS) - emitters)}")

    def test_origin_find_nest_pas_un_producteur_de_surface(self):
        # Décision MESURÉE (cf. le commentaire de `NATIVE_SURFACE_PRODUCERS`) : `origin.find` publie une
        # ROUTE alternative vers la surface CONNUE, pas de la surface nouvelle — et il pèse 24 % du
        # travail du run de référence. Il reste PLANIFIÉ, simplement pas prioritaire.
        self.assertNotIn("origin.find", surface_producers())
        self.assertEqual(stage(Action("origin.find", "app.test")), STAGE_VERIFY)

    def test_les_outils_du_catalogue_sont_classes_par_leur_spec(self):
        """Les 8 outils de DÉCOUVERTE sont producteurs, les 11 SCANNERS ne le sont pas — et c'est le
        `ToolSpec` qui le dit (`asset_hits`), pas une liste tenue à la main."""
        producers = surface_producers()
        for kind in ("recon.katana", "recon.gau", "recon.subfinder", "recon.amass",
                     "recon.feroxbuster", "recon.naabu", "recon.dnsx", "recon.gobuster_dns"):
            self.assertIn(kind, producers, f"{kind} devrait produire de la surface")
        for kind in ("web.nikto", "web.testssl", "web.wpscan", "web.zap_baseline", "xss.dalfox",
                     "fuzz.wfuzz", "recon.whatweb", "recon.wafw00f", "sqli.sqlmap", "recon.curl",
                     "recon.dig"):
            self.assertNotIn(kind, producers, f"{kind} CONSOMME la surface, il ne la produit pas")


# ---------------------------------------------------------------------------------------------
class TestStageOrdering(unittest.TestCase):
    """L'ÉTAGE est structurel : il s'applique à TOUTE action, quelle que soit la voie qui l'a
    proposée — c'est précisément ce que l'intention d'ordre du cerveau ne pouvait pas faire (le
    balayage auto-pentest la contournait en proposant à l'EV par DÉFAUT)."""

    @staticmethod
    def _service_graph():
        g = EngagementGraph()
        g.add_host("127.0.0.1", kind="host")
        g.add_finding(Finding(target="127.0.0.1:8000", title="Service web in-scope : 127.0.0.1:8000",
                              status="tested", severity="INFO", category="recon"))
        return g

    def test_un_producteur_sous_note_passe_devant_un_consommateur_mieux_note(self):
        """Le cœur du lot, en deux actions : `recon.katana` (EV 0.08) DOIT passer devant
        `web.testssl` (EV 0.25, celle du balayage). C'est l'inversion exacte qu'aucune table d'EV
        n'avait obtenue."""
        katana = Action("recon.katana", "app.test", value=0.4, confidence=0.4, cost=2)    # EV 0.08
        testssl = Action("web.testssl", "app.test")                                       # EV 0.25

        def check():
            ordered, skipped = Planner().order([testssl, katana])
            self.assertEqual([a.kind for a in ordered], ["recon.katana", "web.testssl"])
            self.assertEqual(skipped, [], "un ré-ordonnancement ne DÉFÈRE rien")
            self.assertLess(Planner.ev(katana), Planner.ev(testssl),
                            "le test perd son sens si le producteur est mieux noté")

        _assert_mutation_kills(self, check, mock.patch.object(Planner, "rank_key", _legacy_rank_key),
                               "étage retiré du tri (retour à l'EV seule)")

    def test_le_balayage_auto_pentest_est_soumis_a_l_etage(self):
        """La voie de proposition qui CONTOURNAIT l'intention d'ordre du cerveau (EV par défaut 0.25
        pour tout kind balayé) est désormais ordonnée comme les autres."""
        actions = AutoPentestBrain().propose(self._service_graph())

        def check():
            ordered, _ = Planner().order(actions)
            kinds = [a.kind for a in ordered]
            last_producer = max(i for i, a in enumerate(ordered) if stage(a) == STAGE_SURFACE)
            first_consumer = min(i for i, a in enumerate(ordered) if stage(a) == STAGE_VERIFY)
            self.assertLess(last_producer, first_consumer,
                            "producteurs et consommateurs sont entrelacés — l'étage ne porte pas")
            for slow in ("web.testssl", "web.nikto", "xss.dalfox"):
                self.assertIn(slow, kinds, f"{slow} a été DROPPÉ (régression coverage-safe)")

        _assert_mutation_kills(self, check, mock.patch.object(Planner, "rank_key", _legacy_rank_key),
                               "étage retiré du tri (le balayage repasse devant la découverte)")

    def test_un_producteur_sur_un_ENDPOINT_nest_pas_un_producteur(self):
        """Mesuré : 224 « découvertes » sur des endpoints dérivés passaient devant tous les oracles et
        consommaient le budget sans rien découvrir (portée 2 000+ -> 32)."""
        self.assertEqual(stage(Action("recon.katana", "konghq.com")), STAGE_SURFACE)
        self.assertEqual(stage(Action("recon.katana", "https://konghq.com/a/b?x=1")), STAGE_VERIFY)
        self.assertTrue(is_endpoint_target("https://h.test/a"))
        self.assertFalse(is_endpoint_target("h.test"))
        self.assertFalse(is_endpoint_target("h.test:8000"))
        # SOURCE UNIQUE : le cerveau délègue au planner (pas de recopie du prédicat).
        for target in ("h.test", "h.test:8000", "https://h.test/a", "https://h.test/?q=1"):
            self.assertEqual(HeuristicBrain._is_endpoint(target), is_endpoint_target(target))

    def test_une_vague_homogene_garde_l_ordre_d_avant_le_lot(self):
        """Propriété de non-régression : sans producteur (ou sans consommateur), l'étage est un no-op
        et l'ordre est EXACTEMENT celui de l'EV — l'ordre historique, action par action."""
        consumers = [Action("web.testssl", "a.test", value=0.3, confidence=0.4, cost=3),
                     Action("web.nuclei", "a.test", value=0.9, confidence=0.8, cost=1),
                     Action("web.nikto", "a.test", value=0.35, confidence=0.4, cost=2)]
        legacy = sorted(consumers, key=Planner.ev, reverse=True)
        self.assertEqual(Planner().order(consumers)[0], legacy)


# ---------------------------------------------------------------------------------------------
class TestCoverageSafeUnchanged(unittest.TestCase):
    """LA LIGNE ROUGE : l'ordonnancement ne doit RIEN écarter en silence. Le plancher qualifiant, le
    `defer != delete` et les lacunes déclarées sont exactement ceux d'avant."""

    def test_lidor_sous_note_reste_planifie_meme_sous_budget_nul(self):
        idor = Action("access_control.idor", "app.test", cls="access_control",
                      value=0.1, confidence=0.1, cost=3)
        katana = Action("recon.katana", "app.test", value=0.4, confidence=0.4, cost=2)
        scan = Action("web.nuclei", "app.test", value=0.9, confidence=0.9, cost=1)
        ordered, skipped = Planner(budget=0.0).order([scan, idor, katana])
        self.assertIn(idor, ordered, "RÉGRESSION : la voie qualifiante a été affamée")
        self.assertNotIn(idor, skipped)
        self.assertEqual(len(ordered) + len(skipped), 3, "defer != delete : rien n'est jeté")

    def test_le_reordonnancement_est_une_permutation_exacte(self):
        """Aucune action ne disparaît, aucune n'apparaît : `ordered ∪ skipped` == l'entrée, à
        l'identité d'objet près."""
        actions = AutoPentestBrain().propose(_url_graph())
        ordered, skipped = Planner(budget=3.0).order(actions)
        self.assertEqual(sorted(id(a) for a in ordered + skipped), sorted(id(a) for a in actions))

    def test_exhaustive_reste_un_passe_droit_total(self):
        actions = AutoPentestBrain().propose(_url_graph())
        ordered, skipped = Planner(exhaustive=True).order(actions)
        self.assertEqual([id(a) for a in ordered], [id(a) for a in actions])
        self.assertEqual(skipped, [])


def _url_graph():
    g = EngagementGraph()
    g.add_host("app.test", kind="url")
    return g


# ---------------------------------------------------------------------------------------------
class TestKindShare(unittest.TestCase):
    """LA PART DE BUDGET PAR KIND — la clause CUMULATIVE qui manquait à la porte de budget."""

    def test_le_premier_tir_dun_kind_nest_jamais_refuse(self):
        """Anti « excès inverse » : un scanner lent doit TOUJOURS pouvoir tourner au moins une fois —
        `nikto` a produit les 16 seuls signaux qualifiables du run de référence."""
        ks = KindShare(share=1.0 / 3.0)
        ks.observe(1200.0)                                     # part = 400 s
        self.assertEqual(ks.refuse("web.testssl", 600.0), "", "le 1er tir a été refusé par la part")

    def test_la_repetition_est_bornee_et_le_refus_est_nomme(self):
        ks = KindShare(share=1.0 / 3.0)
        ks.observe(3600.0)                                     # part = 1200 s
        ks.record("web.testssl", 300.0)                        # cumul 300, moyenne 300
        self.assertEqual(ks.refuse("web.testssl", 600.0), "", "300 + ~300 <= 1200 : doit passer")
        ks.record("web.testssl", 600.0)                        # cumul 900, moyenne 450
        why = ks.refuse("web.testssl", 600.0)                  # 900 + 450 > 1200
        self.assertTrue(why, "la 3e répétition dépasse la part et doit être refusée")
        self.assertIn("part de budget du kind épuisée", why)
        self.assertIn("AUCUN verdict", why)

    def test_on_predit_par_la_MESURE_pas_par_la_borne(self):
        """`web.nuclei` déclare 600 s et consomme ~330 s : prédire la borne le refuserait à tort."""
        ks = KindShare(share=1.0 / 3.0)
        ks.observe(3600.0)                                     # part = 1200 s
        ks.record("web.nuclei", 280.0)
        ks.record("web.nuclei", 378.0)                         # cumul 658, moyenne 329
        self.assertEqual(ks.refuse("web.nuclei", 600.0), "",
                         "658 + 329 (mesuré) <= 1200 : le 3e nuclei DOIT passer")
        # sans la mesure (kind jamais tiré ici), on retombe sur la borne, et elle mord.
        ks2 = KindShare(share=1.0 / 3.0)
        ks2.observe(3600.0)
        ks2.record("web.nuclei", 900.0)                        # un seul tir, moyenne 900
        self.assertTrue(ks2.refuse("web.nuclei", 600.0))

    def test_un_kind_SANS_borne_declaree_est_quand_meme_borne(self):
        """`origin.find` (natif, aucune borne) pèse 1 864 s du run de référence : la clause absolue ne
        peut rien pour lui (fail-open), la part si — par la mesure."""
        ks = KindShare(share=1.0 / 3.0)
        ks.observe(3600.0)
        ks.record("origin.find", 1799.0)
        why = ks.refuse("origin.find", None)
        self.assertTrue(why, "un kind sans borne doit rester bornable par sa consommation observée")
        self.assertIn("aucune borne déclarée", why)

    def test_inerte_sans_budget_et_desactivable(self):
        self.assertEqual(KindShare(share=1.0 / 3.0).refuse("web.testssl", 600.0), "",
                         "aucun budget observé -> aucune part -> aucune gate")
        off = KindShare(share=0.0)
        off.observe(3600.0)
        off.record("web.testssl", 3000.0)
        self.assertEqual(off.refuse("web.testssl", 600.0), "", "share=0 doit désactiver la part")

    def test_la_part_par_defaut_respecte_le_cahier_des_charges(self):
        self.assertLess(resolve_kind_share(), 0.5,
                        "un kind ne doit pas pouvoir manger la MOITIÉ du budget")
        self.assertEqual(resolve_kind_share("0.25"), 0.25)
        self.assertEqual(resolve_kind_share("pas un nombre"), resolve_kind_share())


# ---------------------------------------------------------------------------------------------
class _Slow(registry.Module):
    """Module de test : borne déclarée 600 s, durée simulée injectée (aucun sommeil)."""
    kind = "share.slow"
    exploit = False
    web_allowed = True
    mitre = "T1595"
    secs = 600.0

    def max_runtime(self, action):
        return 600.0

    def dry(self, action):
        return "# dry"

    def fire(self, action):
        _CLOCK[0] += self.secs
        return [Finding(target=action.target, title="constat", status="tested",
                        severity="INFO", category="recon", mitre="T1595")]


class _Qualifying(_Slow):
    """Même profil, mais classe QUALIFIANTE (le plancher du planner s'y applique)."""
    kind = "access_control.idor"


_CLOCK = [0.0]


class TestKindShareInEngine(unittest.TestCase):
    """La part, BRANCHÉE dans la porte de budget du moteur : un SKIP nommé, aucun verdict."""

    def _engine(self, budget=1200.0, share="0.3333333333333333"):
        _CLOCK[0] = 0.0
        sc = Scope({"mode": "grey", "in_scope": ["app.test"], "allow_exploit": True,
                    "allow_destructive": False})
        eng = Engine(sc, mode="auto", remaining=lambda: budget - _CLOCK[0])
        eng.arm("test part de budget")
        return eng

    def _run(self, kind, n, **kw):
        import forge.engine as engine_mod

        class _Clk:
            @staticmethod
            def monotonic():
                return _CLOCK[0]

        eng = self._engine(**kw)
        with mock.patch.object(engine_mod, "time", _Clk), \
                mock.patch.dict(registry.REGISTRY, {"share.slow": _Slow,
                                                    "access_control.idor": _Qualifying}, clear=False), \
                mock.patch.dict("os.environ", {"FORGE_PARALLELISM": "1"}, clear=False):
            eng.run([Action(kind, f"app.test/{i}" if i else "app.test") for i in range(n)])
        return eng

    def test_le_refus_est_un_SKIP_nomme_sans_verdict_ni_finding(self):
        eng = self._run("share.slow", 3)                       # part = 400 s, borne 600 s
        skips = [r for r in eng.results if r["verdict"] == SKIP
                 and any("part de budget" in x for x in r["reasons"])]
        self.assertEqual(len(skips), 2, "le 1er tir passe, les suivants sont bornés par la part")
        self.assertEqual([r["output"] for r in skips], [None, None], "un SKIP ne porte AUCUN résultat")
        self.assertEqual(len(eng.findings), 1, "aucune action non démarrée n'a produit de finding")
        self.assertEqual(len(eng.run_records), 1, "aucune action non démarrée n'a produit de record")
        # VISIBLE AU RAPPORT : le seau `errors` de coverage() est celui que `report.py` rend en clair.
        errors = eng.coverage()["errors"]
        self.assertEqual(len(errors), 2)
        for row in errors:
            self.assertIn("non démarrée", " ".join(row["reasons"]))
            self.assertIn("pas « rien trouvé »", " ".join(row["reasons"]))

    def test_une_classe_QUALIFIANTE_nest_jamais_bornee_par_la_part(self):
        """La ligne rouge, dans la porte : une voie payable ne peut PAS être écartée par la part —
        c'est la règle que `Planner.order` applique déjà au budget de plan, lue depuis le planner."""
        eng = self._run("access_control.idor", 3)

        def check():
            skips = [r for r in eng.results if r["verdict"] == SKIP
                     and any("part de budget" in x for x in r["reasons"])]
            self.assertEqual(skips, [], "une classe qualifiante a été bornée par la part de budget")
            self.assertTrue(is_floored(Action("access_control.idor", "app.test")))

        _assert_mutation_kills(
            self, check, mock.patch.object(planner_mod, "_floored", lambda action: False),
            "exemption qualifiante retirée de la porte de part")

    def test_aucun_budget_aucune_part(self):
        _CLOCK[0] = 0.0
        sc = Scope({"mode": "grey", "in_scope": ["app.test"], "allow_exploit": True,
                    "allow_destructive": False})
        eng = Engine(sc, mode="auto")                          # AUCUN `remaining` -> aucune gate
        eng.arm("test")
        with mock.patch.dict(registry.REGISTRY, {"share.slow": _Slow}, clear=False):
            eng.run([Action("share.slow", f"app.test/{i}") for i in range(3)])
        self.assertIsNone(eng.kind_share)
        self.assertEqual([r["verdict"] for r in eng.results].count(SKIP), 0)


# ---------------------------------------------------------------------------------------------
class TestSplitDiscoveryFirst(unittest.TestCase):
    """LA FRONTIÈRE DE REPLANIFICATION — ce que l'ordre SEUL ne pouvait pas donner."""

    @staticmethod
    def _wave():
        return [Action("recon.katana", "app.test"), Action("recon.gau", "app.test"),
                Action("web.testssl", "app.test"), Action("web.nikto", "app.test")]

    def test_coupe_a_la_frontiere_producteur_consommateur(self):
        head, tail = Engine._split_discovery_first(self._wave(), 0)
        self.assertEqual([a.kind for a in head], ["recon.katana", "recon.gau"])
        self.assertEqual([a.kind for a in tail], ["web.testssl", "web.nikto"])

    def test_une_seule_coupe_par_campagne(self):
        """Couper à chaque vague reporterait les consommateurs NOUVELLEMENT chaînés derrière les
        anciens : mesuré, la portée retombe de 2 000+ actions à 32."""
        head, tail = Engine._split_discovery_first(self._wave(), 1)
        self.assertEqual(len(head), 4)
        self.assertEqual(tail, [], "aucune coupe hors 1re vague : sinon famine des nouveaux oracles")

    def test_noop_sur_une_vague_homogene(self):
        only_consumers = [Action("web.testssl", "app.test"), Action("web.nikto", "app.test")]
        head, tail = Engine._split_discovery_first(only_consumers, 0)
        self.assertEqual([id(a) for a in head], [id(a) for a in only_consumers])
        self.assertEqual(tail, [])
        only_producers = [Action("recon.katana", "app.test"), Action("recon.gau", "app.test")]
        self.assertEqual(Engine._split_discovery_first(only_producers, 0)[1], [])

    def test_les_reportees_restent_COMPTEES_et_LISTEES(self):
        """DEFER != DELETE, jusque dans l'accounting : une action reportée entre au dénominateur
        (`planned_total`) et, si le run s'arrête avant elle, sort en « planifiées jamais tentées » —
        JAMAIS en verdict négatif."""
        from tests.bench_wave_reach import run_config
        r = run_config("after", 2400.0, True, 1.0 / 3.0)
        eng = r["engine"]
        applied = {x["action"] for x in eng.results}
        pending = {a.id for a in eng.not_attempted}
        self.assertTrue(pending, "le run a été coupé : il DOIT rester des actions non tentées")
        self.assertEqual(applied & pending, set(), "une action ne peut pas être à la fois faite et non tentée")
        self.assertEqual(eng.planned_total, len(applied | pending),
                         "planifiées == appliquées + non tentées (aucune omission silencieuse)")
        for a in eng.not_attempted:                            # aucune n'a produit quoi que ce soit
            self.assertNotIn(a.id, applied)


# ---------------------------------------------------------------------------------------------
class TestReach(unittest.TestCase):
    """LA PORTÉE, EN CHIFFRES — le seul livrable qui compte. Harnais `bench_wave_reach` : 3 cibles,
    durées MESURÉES du run réel injectées, horloge virtuelle (aucun sommeil), budget ÉGAL."""

    #: budget SÉRIEL équivalent au run réel : 3 600 s de mur à `FORGE_PARALLELISM=4`, avec
    #: l'accélération MESURÉE de ce run (7 683 s de travail en 4 674 s de mur = 1,64x).
    BUDGET = 5918.0

    @classmethod
    def setUpClass(cls):
        from tests.bench_wave_reach import run_config
        cls.before = run_config("before", cls.BUDGET, staged=False, share=0.0)
        cls.after = run_config("after", cls.BUDGET, staged=True, share=1.0 / 3.0)

    def test_la_portee_augmente_a_budget_egal(self):
        # `before` EST la mutation : les DEUX mécanismes retirés (`rank_key` historique + aucune
        # coupe). Le chiffre ci-dessous est donc la preuve par mutation de la portée elle-même.
        self.assertGreater(self.after["actions"], 4 * self.before["actions"],
                           f"actions : {self.before['actions']} -> {self.after['actions']}")
        self.assertEqual(self.before["urls"], 0,
                         "le run de référence n'atteignait AUCUNE URL au-delà des 3 graines")
        self.assertGreaterEqual(self.after["urls"], 30,
                                f"URLs distinctes atteintes : {self.after['urls']}")
        self.assertEqual(self.before["waves"], 0, "aucune vague complétée avant le lot")
        self.assertGreaterEqual(self.after["waves"], 1, "la vague 1 doit désormais se terminer")

    def test_les_scanners_lents_tournent_TOUJOURS(self):
        """L'excès inverse est aussi grave que le défaut : à budget de référence, AUCUN kind tiré
        avant le lot ne doit avoir disparu après."""
        fired = {c: {r["kind"] for r in res["engine"].results if r["verdict"] == "FIRE"}
                 for c, res in (("before", self.before), ("after", self.after))}
        self.assertEqual(fired["before"] - fired["after"], set(),
                         "des kinds ne tirent plus du tout — c'est l'excès inverse")
        for slow in ("web.nikto", "web.testssl", "web.nuclei", "xss.dalfox", "web.zap_baseline"):
            self.assertIn(slow, fired["after"], f"{slow} ne tourne plus")

    def test_la_frontiere_de_replanification_est_PORTANTE_pas_decorative(self):
        """MUTATION ISOLÉE : on garde l'étage de tri et on retire la SEULE coupe. Si la portée ne
        retombe pas, la frontière ne sert à rien et il faut la supprimer — c'est la question que ce
        test pose, et la réponse est mesurée : sans elle, la vague 1 consomme tout le budget avant de
        replanifier, et la découverte (pourtant faite EN PREMIER) n'alimente jamais la suite."""
        from tests.bench_wave_reach import run_config

        def check():
            with mock.patch.object(Engine, "_split_discovery_first", staticmethod(_legacy_split)):
                muted = run_config("stage-sans-coupe", self.BUDGET, staged=True, share=1.0 / 3.0)
            self.assertGreaterEqual(muted["urls"], 30,
                                    f"URLs atteintes sans la coupe : {muted['urls']}")

        # la propriété (>=30 URLs) est VRAIE sur le code livré...
        self.assertGreaterEqual(self.after["urls"], 30)
        # ...et FAUSSE dès qu'on retire la coupe : la frontière est donc portante.
        with self.assertRaises(AssertionError):
            check()

    def test_les_scanners_lents_tournent_sur_une_surface_DECOUVERTE(self):
        """Le but n'est pas de les faire passer en dernier, c'est qu'ils travaillent sur ce que la
        découverte a trouvé : au moins un scanner doit viser une cible DÉRIVÉE."""
        seeds = {"konghq.com", "developer.konghq.com", "cloud.konghq.com"}
        derived = {r["target"] for r in self.after["engine"].results
                   if r["verdict"] == "FIRE" and r["target"] not in seeds}
        self.assertGreaterEqual(len(derived), 30)
        before_derived = {r["target"] for r in self.before["engine"].results
                          if r["target"] not in seeds}
        self.assertEqual(before_derived, set(), "avant le lot, aucune cible dérivée n'était atteinte")


if __name__ == "__main__":
    unittest.main()

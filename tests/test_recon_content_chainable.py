# SPDX-License-Identifier: AGPL-3.0-or-later
"""`recon.content` — SES ROUTES ÉTAIENT DES CULS-DE-SAC. OUBLI OU CHOIX ?

LE CONSTAT, MESURÉ AVANT TOUTE CORRECTION
------------------------------------------
Le module trouvait des routes et n'émettait QUE `DISCOVERY_CHALLENGE_MARKER` — jamais
`DISCOVERY_ENDPOINT_MARKER`. Or l'edge (e) du cerveau (`_chained_actions`) ne s'allume QUE sur ce
marqueur. Sur 12 routes rendues par un ffuf stubbé, l'état d'avant donnait :

    12 findings de route  ->  12 NŒUDS ajoutés au graphe  ->  **0 action proposée sur les 12**

VERDICT : OUBLI. Quatre faits, tous vérifiables, aucun n'exige d'interpréter une intention :
  1. le module PAYAIT DÉJÀ le prix de la chaînabilité — chaque route sort avec `target=<URL>`, et
     `graph.add_finding` en fait un NŒUD. 12 nœuds pour 0 action, c'est du coût pur. Un refus
     DÉLIBÉRÉ de chaîner aurait rattaché les routes à l'hôte, comme son propre finding de synthèse ;
  2. il est CÂBLÉ dans le pont challenge->évasion (edge (f)) : bloqué, il RÉCLAME `evasion.discover`
     pour aller chercher des endpoints. Ce pont n'a de sens que si sa sortie normale EST de la surface ;
  3. son jumeau spec-driven `recon.feroxbuster` (même technique, même T1595.003) est DÉJÀ producteur ;
  4. le titre était à un mot du marqueur : « Route in-scope » vs « Endpoint in-scope ».
Ni le source, ni les tests, ni l'historique du fichier ne formulent de réserve sur la QUALITÉ des
routes — l'hypothèse « choix » n'a aucun appui écrit.

CE QUE LA CORRECTION DONNE, EN CHIFFRES (`TestChainedSurface`)
---------------------------------------------------------------
    routes découvertes            12  ->  12      (inchangé : on ne découvre pas plus)
    routes recevant >= 1 action    0  ->  12
    actions proposées             11  ->  47      (+36 = 12 routes x idor/sqli/xss)

LE RISQUE INVERSE EST TRAITÉ SANS ÉCRIRE DE SECONDE CONTRE-MESURE (`TestFloodGuards`) : la
contre-mesure catch-all `Oracle.path_discrimination` couvre DÉJÀ le seul consommateur capable de
conclure de l'existence d'un chemin, et la sélection partagée (`_select_endpoints`) borne, filtre et
re-valide. Les routes au-delà du cap gardent leur constat et le DISENT.

Hermétique : ffuf est un seam (`_run_ffuf`), zéro sous-processus, zéro réseau.
"""
from __future__ import annotations

import json
import sys
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import planner as planner_mod                       # noqa: E402
from forge import techniques                                   # noqa: E402
from forge.brain import HeuristicBrain                          # noqa: E402
from forge.graph import EngagementGraph                         # noqa: E402
from forge.modules.exposure import FrameworkExposure            # noqa: E402
from forge.modules.recon_active import ContentDiscovery         # noqa: E402
from forge.planner import STAGE_SURFACE, STAGE_VERIFY, stage, surface_producers  # noqa: E402
from forge.roe import Action                                    # noqa: E402

HOST = "app.test"
MARKER = techniques.DISCOVERY_ENDPOINT_MARKER
#: 12 routes, 1 sur 3 en 403 (route qui EXISTE mais se referme) — la forme d'une sortie ffuf réelle.
PATHS = ["admin", "api", "api/v1", "graphql", "config.json", ".env", "backup",
         "swagger.json", "actuator/env", "metrics", "dashboard", "console"]
ROUTES = [{"url": f"https://{HOST}/{p}", "status": 403 if i % 3 == 0 else 200, "length": 100 + i}
          for i, p in enumerate(PATHS)]


def _assert_mutation_kills(case, check, patcher, label):
    """Preuve par MUTATION en deux temps (même contrat que `test_planner_discovery_first`) : la
    propriété passe sur le code LIVRÉ, et ÉCHOUE sous la mutation. Sinon le test ne prouve rien."""
    check()
    with patcher:
        try:
            check()
        except AssertionError:
            return
    case.fail(f"MUTATION NON LÉTALE — « {label} » : la propriété passe encore une fois le correctif "
              f"retiré. Le test ne prouve donc RIEN sur ce point.")


def _ffuf(routes):
    """Seam ffuf : rend l'objet JSON global que `_parse_ffuf` sait lire."""
    def run(url, wordlist, rate, threads, timeout, match_codes=None, extensions="", extra=()):
        return 0, json.dumps({"results": list(routes)}), ""
    return run


def _fire(routes=ROUTES, in_scope=(HOST,)):
    action = Action("recon.content", HOST)
    action.params.update({"in_scope": list(in_scope), "out_scope": []})
    with mock.patch.object(ContentDiscovery, "_tool_available", staticmethod(lambda: True)), \
         mock.patch.object(ContentDiscovery, "_run_ffuf", staticmethod(_ffuf(routes))):
        return ContentDiscovery().fire(action)


def _proposed(findings):
    """(actions proposées par le cerveau, cibles couvertes) après ingestion des findings au graphe."""
    g = EngagementGraph()
    g.add_host(HOST, kind="host")
    for f in findings:
        g.add_finding(f)
    actions = HeuristicBrain().propose(g)
    by_target = {}
    for a in actions:
        by_target.setdefault(a.target, []).append(a.kind)
    return actions, by_target


#: MUTATION — l'état d'AVANT ce lot : AUCUNE route n'est sélectionnée comme chaînable, donc aucune
#: ne porte le marqueur et toutes gardent le titre historique « Route in-scope ». C'est la mutation
#: EXACTE du correctif. (Muter `techniques.DISCOVERY_ENDPOINT_MARKER` ne marcherait PAS : le cerveau
#: lit la MÊME constante, la mutation resterait cohérente des deux côtés et donc VERTE — essayé.)
_NO_CHAINABLE = mock.patch.object(ContentDiscovery, "_by_probeability",
                                  staticmethod(lambda kept, target: []))


# ---------------------------------------------------------------------------------------------
class TestVerdictWasAnOversight(unittest.TestCase):
    """Les QUATRE faits qui font pencher « oubli » — assertions, pas interprétations."""

    def test_1_les_routes_creaient_deja_des_noeuds_du_graphe(self):
        """Le module payait DÉJÀ le prix de la chaînabilité : `target=<URL>` -> un nœud par route."""
        findings = _fire()
        routes = [f for f in findings if f.target != HOST]
        self.assertEqual(len(routes), len(ROUTES))
        g = EngagementGraph()
        g.add_host(HOST, kind="host")
        for f in findings:
            g.add_finding(f)
        self.assertEqual(len(g.hosts()), 1 + len(ROUTES),
                         "chaque route DEVIENT un nœud — le coût était déjà payé")

    def test_2_le_module_est_cable_dans_le_pont_challenge_evasion(self):
        """Bloqué, il RÉCLAME `evasion.discover` pour obtenir des endpoints : ce pont n'a de sens que
        si sa sortie normale est de la surface pour les oracles."""
        blocked = [{"url": f"https://{HOST}/{p}", "status": 403, "length": 0} for p in PATHS[:4]]
        findings = _fire(blocked)
        self.assertTrue(any(techniques.DISCOVERY_CHALLENGE_MARKER in f.title for f in findings))
        _actions, by_target = _proposed(findings)
        self.assertIn("evasion.discover", by_target.get(HOST, []),
                      "l'edge (f) doit s'allumer — c'est le câblage qui atteste l'intention")

    def test_3_son_jumeau_spec_driven_etait_deja_classe_producteur(self):
        """Même technique, même T1595.003 : `recon.feroxbuster` est classé producteur depuis toujours
        (`asset_hits`). L'asymétrie de classement entre deux modules qui font LE MÊME travail est le
        3e indice — et elle n'a jamais été justifiée nulle part."""
        self.assertIn("recon.feroxbuster", surface_producers())
        self.assertEqual(techniques.CATALOG["recon.content"].mitre,
                         techniques.CATALOG["recon.feroxbuster"].mitre)

    def test_3bis_feroxbuster_porte_LE_MEME_defaut_hors_perimetre(self):
        """NUANCE MESURÉE, et elle n'affaiblit pas le verdict — elle l'étend : `recon.feroxbuster` est
        était CLASSÉ producteur mais ne posait pas `emit_endpoint_discovery`, donc ses hits sortaient
        en culs-de-sac : 6 URLs -> 6 nœuds -> **0 action**. Le trou était le même, à deux endroits.
        BOUCHÉ le 2026-08-10 : ce test ne CONSIGNE plus, il VERROUILLE — un producteur déclaré doit
        émettre le marqueur, sinon il paie le coût du graphe sans rien chaîner."""
        from forge.modules import registry
        spec = registry.REGISTRY["recon.feroxbuster"].spec
        self.assertTrue(spec.asset_hits, "classé producteur")
        self.assertTrue(spec.emit_endpoint_discovery,
                        "un producteur DÉCLARÉ qui n'émet pas le marqueur produit des culs-de-sac")

    def test_4_le_titre_etait_a_un_mot_du_marqueur_partage(self):
        self.assertEqual(MARKER, "Endpoint in-scope")


# ---------------------------------------------------------------------------------------------
class TestChainedSurface(unittest.TestCase):
    """LE CHIFFRE : 0 -> 12 routes chaînées, 11 -> 47 actions. Avec sa mutation."""

    def test_les_routes_portent_le_marqueur_partage(self):
        findings = _fire()
        marked = [f for f in findings if f.title.startswith(f"{MARKER} : ")]
        self.assertEqual(len(marked), len(ROUTES))
        for f in marked:
            self.assertTrue(f.target.startswith(f"https://{HOST}/"))
            self.assertRegex(f.title, r"\[\d{3}\]$", "le STATUT réel reste dans le titre")
            self.assertIn("HTTP", f.evidence, "l'évidence reste celle de ffuf, pas un gabarit faux")

    def test_chaque_route_recoit_desormais_des_oracles(self):
        def check():
            findings = _fire()
            actions, by_target = _proposed(findings)
            covered = [r["url"] for r in ROUTES if by_target.get(r["url"])]
            self.assertEqual(len(covered), len(ROUTES),
                             f"routes chaînées : {len(covered)}/{len(ROUTES)} (0 = culs-de-sac)")
            self.assertEqual(len(actions), 47, "11 actions d'hôte + 12 routes x 3 oracles")
            self.assertEqual(sorted(set(by_target[covered[0]])),
                             ["access_control.idor", "sqli.probe", "xss.reflected"])

        # MUTATION = l'état d'AVANT : aucune route marquée -> l'edge (e) reste éteint.
        _assert_mutation_kills(self, check, _NO_CHAINABLE,
                               "aucune route sélectionnée comme chaînable (état d'avant ce lot)")

    def test_la_mutation_est_atteinte_avant_la_correction_zero_route_chainee(self):
        """ATTEIGNABILITÉ EXPLICITE, et c'est LA mesure « avant » : sans le marqueur, les 12 nœuds
        existent et ne reçoivent AUCUNE action."""
        with _NO_CHAINABLE:
            findings = _fire()
            actions, by_target = _proposed(findings)
        self.assertTrue(all(f.title.startswith("Route in-scope : ")
                            for f in findings if f.target != HOST), "titre historique restauré")
        self.assertEqual([r["url"] for r in ROUTES if by_target.get(r["url"])], [])
        self.assertEqual(len(actions), 11, "aucune action dérivée : 11 actions d'hôte, et c'est tout")

    def test_le_resume_annonce_combien_de_routes_sont_chainees(self):
        summary = next(f for f in _fire() if f.title.startswith("Routes découvertes"))
        self.assertIn(f"{len(ROUTES)} chaînée(s) vers les oracles", summary.evidence)


# ---------------------------------------------------------------------------------------------
class TestStageFollows(unittest.TestCase):
    """« Le classement d'étage doit suivre » — VÉRIFIÉ, pas supposé : il ne bascule PAS tout seul."""

    def test_recon_content_est_desormais_un_producteur_de_surface(self):
        self.assertIn("recon.content", surface_producers())
        self.assertEqual(stage(Action("recon.content", HOST)), STAGE_SURFACE)

    def test_un_producteur_sur_un_endpoint_derive_reste_un_consommateur(self):
        """La règle générale s'applique : ffuf sur une URL à chemin n'élargit rien."""
        self.assertEqual(stage(Action("recon.content", f"https://{HOST}/api/v1")), STAGE_VERIFY)

    def test_le_classement_NE_bascule_PAS_tout_seul(self):
        """`surface_producers()` n'auto-détecte que les modules à `ToolSpec` (`asset_hits`). Un module
        NATIF exige l'inscription explicite — c'est le test d'équivalence
        (`test_planner_discovery_first.TestNativeProducerList`) qui l'a EXIGÉE, suite rouge à l'appui.
        On le prouve ici : retirer l'inscription rend le module consommateur alors qu'il ÉMET."""
        without = frozenset(planner_mod.NATIVE_SURFACE_PRODUCERS - {"recon.content"})
        with mock.patch.object(planner_mod, "NATIVE_SURFACE_PRODUCERS", without):
            planner_mod.reset_surface_producers_cache()
            try:
                self.assertNotIn("recon.content", surface_producers())
                self.assertEqual(stage(Action("recon.content", HOST)), STAGE_VERIFY)
            finally:
                planner_mod.reset_surface_producers_cache()
        self.assertIn("recon.content", surface_producers(), "cache correctement réinitialisé")


# ---------------------------------------------------------------------------------------------
class TestFloodGuards(unittest.TestCase):
    """LE RISQUE INVERSE — inonder les oracles de cibles douteuses. Aucune contre-mesure NOUVELLE :
    on vérifie que celles du dépôt couvrent ce cas."""

    @staticmethod
    def _many(n):
        return [{"url": f"https://{HOST}/p{i}", "status": 200, "length": 10 + i} for i in range(n)]

    def test_le_cap_de_fan_out_sapplique_desormais_aux_routes(self):
        def check():
            findings = _fire(self._many(60))
            marked = [f for f in findings if f.title.startswith(f"{MARKER} : ")]
            plain = [f for f in findings if f.title.startswith("Route in-scope : ")]
            self.assertEqual(len(marked), ContentDiscovery.MAX_ENDPOINTS,
                             "le cap partagé `crawl_max_endpoints` doit borner les routes chaînées")
            self.assertEqual(len(marked) + len(plain), 60, "aucune route n'est PERDUE")
            for f in plain:
                self.assertIn("CONSIGNÉE, non chaînée", f.evidence, "la troncature doit se DIRE")

        # MUTATION : cap neutralisé -> les 60 routes deviennent chaînables (l'inondation).
        _assert_mutation_kills(
            self, check,
            mock.patch.object(ContentDiscovery, "MAX_ENDPOINTS", 10 ** 6),
            "cap de sélection d'endpoints neutralisé")

    def test_les_routes_interrogeables_passent_avant_les_routes_fermees(self):
        """Le cap ne doit pas sacrifier ce qu'un oracle peut questionner (200) au profit de 403 qui
        attestent une existence et referment la porte."""
        routes = ([{"url": f"https://{HOST}/closed{i}", "status": 403, "length": 0} for i in range(30)]
                  + [{"url": f"https://{HOST}/open{i}", "status": 200, "length": 9} for i in range(5)])
        marked = [f.target for f in _fire(routes) if f.title.startswith(f"{MARKER} : ")]
        for i in range(5):
            self.assertIn(f"https://{HOST}/open{i}", marked,
                          "une route SERVIE a été évincée par des 403")

    def test_les_non_cibles_dinfra_ne_sont_pas_chainees_et_le_constat_est_emis(self):
        routes = [{"url": f"https://{HOST}/cdn-cgi/challenge-platform/x", "status": 200, "length": 5},
                  {"url": f"https://{HOST}/api", "status": 200, "length": 5}]
        findings = _fire(routes)
        marked = [f.target for f in findings if f.title.startswith(f"{MARKER} : ")]
        self.assertEqual(marked, [f"https://{HOST}/api"])
        constat = [f for f in findings if "non-cible" in f.title.lower() or "écarté" in f.title]
        self.assertTrue(constat, "l'écart doit être NOMMÉ, jamais silencieux")
        self.assertEqual(constat[0].status, "skipped")

    def test_une_route_hors_perimetre_nest_jamais_chainee(self):
        routes = [{"url": "https://evil.example/admin", "status": 200, "length": 5},
                  {"url": f"https://{HOST}/api", "status": 200, "length": 5}]
        marked = [f.target for f in _fire(routes) if f.title.startswith(f"{MARKER} : ")]
        self.assertEqual(marked, [f"https://{HOST}/api"])

    def test_path_discrimination_couvre_DEJA_le_consommateur_qui_pourrait_conclure(self):
        """`framework.exposure` est le seul consommateur capable de tirer un verdict de l'EXISTENCE
        d'un chemin. Sur une cible catch-all (2xx sur des chemins de contrôle aléatoires), il rend
        `skipped` — la contre-mesure livrée couvre ce cas, inutile d'en écrire une seconde."""
        route = f"https://{HOST}/p0"
        with mock.patch.object(FrameworkExposure, "_fetch",
                               staticmethod(lambda url, timeout=15: (200, "<html>SPA</html>"))):
            findings = FrameworkExposure().fire(
                Action("framework.exposure", route, params={"in_scope": [HOST]}))
        self.assertTrue(findings)
        self.assertTrue(any(f.status == "skipped" and "catch-all" in f.title.lower() for f in findings),
                        f"attendu un skipped catch-all ; vu : {[(f.status, f.title) for f in findings]}")
        self.assertFalse([f for f in findings if f.status == "vulnerable"])

    def test_les_oracles_chaines_sur_une_route_sans_parametre_ne_concluent_rien(self):
        """Les 3 oracles que l'edge (e) chaîne sur une route SANS query ne peuvent RIEN conclure d'un
        chemin fantôme : SQLi/XSS dégradent (« config manquante »), IDOR est différentiel."""
        _actions, by_target = _proposed(_fire())
        chained = sorted(set(by_target[ROUTES[0]["url"]]))
        self.assertEqual(chained, ["access_control.idor", "sqli.probe", "xss.reflected"])
        from forge.modules import registry
        for kind in ("sqli.probe", "xss.reflected"):
            out = registry.get(kind).fire(Action(kind, ROUTES[0]["url"],
                                                 params={"in_scope": [HOST]}))
            self.assertTrue(all(f.status != "vulnerable" for f in out),
                            f"{kind} conclut sur une route sans paramètre")


if __name__ == "__main__":
    unittest.main()

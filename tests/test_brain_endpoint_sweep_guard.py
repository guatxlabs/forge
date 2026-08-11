# SPDX-License-Identifier: AGPL-3.0-or-later
"""D9 — LE BALAYAGE AUTO-PENTEST PASSE PAR LE MÊME GARDE HÔTE/ENDPOINT QUE LE PLAN DE BASE.

CE QUI A ÉTÉ MESURÉ. `brain._is_endpoint` dit depuis toujours qu'un endpoint est vérifié par les
oracles CIBLÉS du chaînage, « jamais par les actions de base (qui sèmeraient recon/nmap/origin sur
une URL) », et `_base_actions` l'applique. `AutoPentestBrain.propose`, lui, balayait CHAQUE technique
sur CHAQUE cible touchée — endpoints DÉRIVÉS compris — sans ce garde. Relevé dans les ledgers des
quatre campagnes du banc (2026-08-10), en comptant les décisions ROE `FIRE` dont la cible est une URL
à chemin :

    app        recon.nmap sur endpoint    total actions HÔTE-SCOPÉES sur endpoint
    juiceshop            15                            133
    dvwa                 26                            234
    vampi                16                            144
    dvga                 15                            133
                        ---                           -----
                         72                            644

Les findings correspondants portent `Nmap done: 0 IP addresses (0 hosts up) scanned` et sortent en
`status=tested`. nmap rend `rc=0` (« Unable to split netmask from target expression ») : la borne
`rc != 0` de `blindness.tool_did_not_run` ne PEUT pas voir ce silence. Une action qui n'a rien pu
regarder affirmait avoir vérifié.

CE QUE CE FICHIER VERROUILLE :
  1. plus AUCUNE action hôte-scopée n'est proposée sur un endpoint ;
  2. la couverture d'endpoint est INTACTE — tous les autres kinds y sont toujours balayés (l'excès
     inverse coûterait la surface qu'on vient de gagner) ;
  3. sur un HÔTE, rien ne change — l'ensemble des kinds proposés est IDENTIQUE ;
  4. l'ensemble hôte-scopé est DÉRIVÉ (producteurs de surface + specs qui ne parlent pas HTTP), donc
     un nouvel outil est couvert SANS qu'on tienne une liste ;
  5. MUTATION : garde neutralisé -> les tirs aveugles REVIENNENT (le garde est porteur).
"""
from __future__ import annotations

import collections
import sys
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import forge.modules  # noqa: F401,E402  (charge le registre : specs + natifs)
from forge import planner as planner_mod                          # noqa: E402
from forge import techniques                                      # noqa: E402
from forge.brain import AutoPentestBrain                          # noqa: E402
from forge.graph import EngagementGraph                           # noqa: E402
from forge.modules import registry                                # noqa: E402
from forge.planner import is_endpoint_target                      # noqa: E402

HOST = "127.0.0.1:3000"
#: les endpoints RÉELLEMENT découverts par la campagne juiceshop du banc (piste B).
ENDPOINTS = ["/media", "/api", "/assets", "/profile", "/redirect", "/assets/private", "/ftp",
             "/assets/public", "/ftp/suspicious_errors.yml", "/video", "/restricted", "/rest",
             "/promotion", "/restaurants", "/metrics"]


def _graph():
    """1 hôte web + 15 endpoints DÉCOUVERTS (marqueur de découverte) — la forme du run du banc."""
    g = EngagementGraph()
    g.add_host(HOST, kind="app", service="http")
    for path in ENDPOINTS:
        url = f"http://{HOST}{path}"
        g.add_host(url, kind="url")
        g.add_finding({"target": url, "status": "tested", "severity": "INFO",
                       "title": f"{techniques.DISCOVERY_ENDPOINT_MARKER} : {url}"})
    return g


def _by_target(actions):
    """{cible -> {kinds}} des actions proposées."""
    out = collections.defaultdict(set)
    for a in actions:
        out[a.target].add(a.kind)
    return out


class TestNoBlindHostScopedActionOnAnEndpoint(unittest.TestCase):

    def setUp(self):
        self.actions = AutoPentestBrain().propose(_graph())
        self.host_scoped = AutoPentestBrain._host_scoped_kinds()

    def test_nmap_is_never_proposed_on_an_endpoint(self):
        blind = [a for a in self.actions
                 if a.kind == "recon.nmap" and is_endpoint_target(a.target)]
        self.assertEqual(blind, [], "nmap sur une URL à chemin ne scanne AUCUN hôte (mesuré : 72 tirs)")

    def test_no_host_scoped_kind_at_all_on_an_endpoint(self):
        blind = [(a.kind, a.target) for a in self.actions
                 if a.kind in self.host_scoped and is_endpoint_target(a.target)]
        self.assertEqual(blind, [], f"{len(blind)} action(s) hôte-scopées sur un endpoint")

    def test_nmap_is_STILL_proposed_on_the_host(self):
        """Le garde retire des tirs AVEUGLES, pas la technique : sur l'hôte, nmap reste proposé."""
        on_host = [a for a in self.actions
                   if a.kind == "recon.nmap" and not is_endpoint_target(a.target)]
        self.assertTrue(on_host, "nmap doit continuer de tourner LÀ OÙ IL VOIT quelque chose")


class TestEndpointCoverageIsIntact(unittest.TestCase):
    """L'EXCÈS INVERSE — le garde ne doit RIEN retirer d'autre."""

    def setUp(self):
        self.after = _by_target(AutoPentestBrain().propose(_graph()))
        with mock.patch.object(AutoPentestBrain, "_host_scoped_kinds",
                               staticmethod(lambda: frozenset())):
            self.before = _by_target(AutoPentestBrain().propose(_graph()))
        self.host_scoped = AutoPentestBrain._host_scoped_kinds()

    def test_every_endpoint_keeps_every_non_host_scoped_kind(self):
        for target, kinds in self.before.items():
            if not is_endpoint_target(target):
                continue
            expected = kinds - self.host_scoped
            self.assertEqual(self.after.get(target, set()), expected,
                             f"la couverture de {target} a changé au-delà des kinds hôte-scopés")

    def test_the_qualifying_oracles_still_reach_every_endpoint(self):
        for target in self.before:
            if not is_endpoint_target(target):
                continue
            for kind in ("access_control.idor", "sqli.probe", "xss.reflected", "path.traversal",
                         "auth.takeover", "cors.credentials", "ssrf.callback", "jwt.weakness"):
                self.assertIn(kind, self.after[target], f"{kind} a disparu de {target}")

    def test_host_plan_is_byte_identical(self):
        for target, kinds in self.before.items():
            if is_endpoint_target(target):
                continue
            self.assertEqual(self.after[target], kinds,
                             "le plan sur un HÔTE ne doit pas bouger d'un kind")


class TestHostScopedSetIsDerivedNotCopied(unittest.TestCase):
    """L'ensemble hôte-scopé ne se TIENT pas à la main : il se DÉDUIT de ce que le dépôt déclare."""

    def test_contains_every_surface_producer(self):
        missing = planner_mod.surface_producers() - AutoPentestBrain._host_scoped_kinds()
        self.assertEqual(missing, set(),
                         "`planner.stage` dit déjà qu'un producteur n'en est un que sur un HÔTE")

    def test_contains_every_spec_that_does_not_speak_http(self):
        """Le discriminant est DANS L'ARGV : `{target_host}` -> l'outil reçoit un hôte NU."""
        host_scoped = AutoPentestBrain._host_scoped_kinds()
        checked = 0
        for kind, module in registry.REGISTRY.items():
            spec = getattr(module, "spec", None)
            if spec is not None and not spec.speaks_http:
                checked += 1
                self.assertIn(kind, host_scoped, f"{kind} est invoqué avec un hôte nu")
        self.assertGreater(checked, 4, "le registre doit contenir des outils à hôte nu")

    def test_a_new_host_scoped_tool_is_covered_without_touching_this_code(self):
        """Un outil AJOUTÉ au registre avec un spec à hôte nu entre AUTOMATIQUEMENT dans l'ensemble."""
        class _Spec:
            speaks_http = False
            asset_hits = False
            emit_endpoint_discovery = False
            emit_service_discovery = False

        class _Mod:
            kind = "recon.tout_neuf"
            spec = _Spec()

        registry.REGISTRY["recon.tout_neuf"] = _Mod()
        try:
            planner_mod.reset_surface_producers_cache()
            self.assertIn("recon.tout_neuf", AutoPentestBrain._host_scoped_kinds())
        finally:
            registry.REGISTRY.pop("recon.tout_neuf", None)
            planner_mod.reset_surface_producers_cache()

    def test_origin_find_is_in_the_set(self):
        """Le 3e nom de la phrase du garde existant (« recon/nmap/origin sur une URL »)."""
        self.assertIn("origin.find", AutoPentestBrain._host_scoped_kinds())

    def test_no_oracle_is_ever_classed_host_scoped(self):
        """Contre-borne : aucun oracle de vérification ne doit tomber dans l'ensemble."""
        host_scoped = AutoPentestBrain._host_scoped_kinds()
        for kind in ("access_control.idor", "sqli.probe", "xss.reflected", "ssrf.callback",
                     "auth.takeover", "cors.credentials", "rce.probe", "path.traversal",
                     "xxe.probe", "graphql.access", "jwt.weakness", "web.nuclei"):
            self.assertNotIn(kind, host_scoped, f"{kind} n'est PAS hôte-scopé")


class TestMutationTheGuardIsLoadBearing(unittest.TestCase):
    """MUTATION : garde neutralisé -> les 15 nmap aveugles (1 par endpoint) REVIENNENT."""

    def test_neutralising_the_guard_brings_the_blind_actions_back(self):
        with mock.patch.object(AutoPentestBrain, "_host_scoped_kinds",
                               staticmethod(lambda: frozenset())):
            actions = AutoPentestBrain().propose(_graph())
        blind = [a for a in actions if a.kind == "recon.nmap" and is_endpoint_target(a.target)]
        self.assertEqual(len(blind), len(ENDPOINTS),
                         "MUTATION INATTEIGNABLE : le garde n'est pas ce qui écarte ces actions")
        host_scoped = AutoPentestBrain._host_scoped_kinds()
        all_blind = [a for a in actions
                     if a.kind in host_scoped and is_endpoint_target(a.target)]
        self.assertEqual(len(all_blind), len(ENDPOINTS) * len(host_scoped))


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""D13 — UN TIR SUR UNE CIBLE MORTE NE PRODUIT AUCUN VERDICT.

CE QUE LE BANC A CONSTATÉ, ET CE QUE LA CONTRE-ÉPREUVE A CORRIGÉ
----------------------------------------------------------------
Le banc a conclu « le mode autonome TUE la cible » sur deux campagnes Juice Shop finies en
`Exited (139)` + `FATAL ERROR: Ineffective mark-compacts near heap limit`. **La mesure dit autre
chose** : `bkimminich/juice-shop:latest` (image du 2026-06-05), lancée SEULE et sans qu'un seul
paquet lui soit envoyé, monte de 121 MiB à 4,79 GiB et meurt **à 222 s** avec exactement la même
signature. La campagne n'était pas la CAUSE. On n'ajoute donc AUCUN throttle : aucune mesure ne le
justifie, et brider le balayage se paierait en couverture.

CE QUI RESTE VRAI EST LE VRAI DÉFAUT, et il est mesuré sur une campagne rejouée le 2026-08-11
(`--auto-pentest`, budget 420 s, périmètre `127.0.0.1:3000`), gate de liveness NEUTRALISÉE :

    mort du conteneur              t ~= 120 s
    décisions ROE APRÈS la mort    1175 FIRE
    tirs RÉELS après la mort       1099 run-records `fired=True`
    findings émis après la mort    1158, dont **178 `tested`**

178 fois « j'ai vérifié, rien trouvé » sur une cible qui n'existait plus. C'est ce que cette gate
supprime — et elle le fait EN AMONT : le module n'est PAS appelé, donc il n'y a ni finding, ni
run-record, ni verdict. Juste un SKIP NOMMÉ, compté dans `coverage()['errors']` et listé au rapport.

LES TROIS BORNES CONTRE L'EXCÈS INVERSE (chacune a son test ici)
----------------------------------------------------------------
  1. il faut un PORT EXPLICITE (ou un schéma dont il se déduit) : on ne devine pas de port ;
  2. il faut que la cible ait été JOINTE au moins une fois PENDANT le run : une cible jamais jointe
     (proxy, pare-feu, tunnel) reste `unknown` et n'est JAMAIS gatée ;
  3. la cible qui REVIENT débloque la campagne toute seule (re-sonde par fenêtre de TTL).

AUCUN RÉSEAU ICI : le seam `engine._tcp_reachable` est substitué dans tous les tests.
"""
from __future__ import annotations

import sys
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import engine as engine_mod                          # noqa: E402
from forge.engine import Engine, _target_endpoint                # noqa: E402
from forge.modules import registry                               # noqa: E402
from forge.roe import Action, Scope                              # noqa: E402
from forge.schema import Finding                                 # noqa: E402
from tests._dns import setUpModule, tearDownModule  # noqa: F401,E402

TARGET = "127.0.0.1:3000"
URL = "http://127.0.0.1:3000/rest/basket/1"


class _Spy(registry.Module):
    """Module stub qui COMPTE ses tirs et rend un finding `tested` (« j'ai vérifié, rien trouvé »).

    Le compteur est de CLASSE : le registre stocke des classes et `registry.get()` en instancie une
    NEUVE à chaque action — un compteur d'instance ne compterait jamais au-delà de 1."""

    kind = "spy.probe"
    exploit = False
    destructive = False
    available = True
    mitre = "T1190"
    fires = 0

    def dry(self, action):
        return "# dry"

    def fire(self, action):
        type(self).fires += 1
        return [Finding(target=action.target, title="spy — rien trouvé", status="tested",
                        severity="INFO", category="recon", mitre=self.mitre)]


class _Probe:
    """Sonde TCP substituée : scénario piloté + COMPTAGE des sondes réellement émises."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, host, port, timeout=None):
        self.calls.append((host, port))
        return self.answers[min(len(self.calls) - 1, len(self.answers) - 1)]


class _Base(unittest.TestCase):

    def setUp(self):
        _Spy.fires = 0
        self.spy = _Spy
        self._saved = registry.REGISTRY.get("spy.probe")
        registry.REGISTRY["spy.probe"] = _Spy
        self.scope = Scope({"mode": "grey", "in_scope": [TARGET], "out_scope": [],
                            "allow_exploit": False, "allow_destructive": False,
                            "allow_private": True})

    def tearDown(self):
        if self._saved is None:
            registry.REGISTRY.pop("spy.probe", None)
        else:
            registry.REGISTRY["spy.probe"] = self._saved

    def _engine(self):
        eng = Engine(self.scope, mode="auto")
        eng.arm("test")
        return eng

    @staticmethod
    def _act(target=TARGET, ident=""):
        a = Action("spy.probe", target)
        if ident:
            a.id = ident
        return a


class TestTargetThatDiedDuringTheRun(_Base):
    """LE CAS D13 : la cible a répondu, puis a cessé. Aucun tir, aucun verdict."""

    def test_no_fire_no_finding_no_verdict(self):
        probe = _Probe(True, False)                 # 1re sonde : vivante ; 2e : morte
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", probe), \
                mock.patch.object(engine_mod, "_LIVENESS_TTL", 0.0):
            first = eng.execute(self._act(ident="spy.probe:1"))
            second = eng.execute(self._act(ident="spy.probe:2"))
        self.assertEqual(first["verdict"], "FIRE", "la 1re action doit tirer normalement")
        self.assertEqual(self.spy.fires, 1, "le module n'a PAS été rappelé sur la cible morte")
        self.assertEqual(second["verdict"], "SKIP")
        self.assertIsNone(second["output"], "aucune sortie : le module n'a pas tourné")
        self.assertEqual(len(eng.findings), 1, "aucun finding n'est né de la cible morte")
        self.assertEqual(len(eng.run_records), 1, "aucun run-record sur la cible morte")

    def test_the_reason_names_it_and_refuses_to_conclude(self):
        probe = _Probe(True, False)
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", probe), \
                mock.patch.object(engine_mod, "_LIVENESS_TTL", 0.0):
            eng.execute(self._act(ident="spy.probe:1"))
            res = eng.execute(self._act(ident="spy.probe:2"))
        reason = " ".join(res["reasons"])
        self.assertIn("127.0.0.1:3000", reason)
        self.assertIn("AUCUN verdict", reason)
        self.assertIn("pas « rien trouvé »", reason,
                      "le vocabulaire du dépôt : « je n'ai pas vérifié » != « rien trouvé »")

    def test_the_constat_is_said_once_but_every_action_stays_a_named_skip(self):
        """Miroir exact de `_note_non_target` : reconnu != supprimé."""
        probe = _Probe(True, False)
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", probe), \
                mock.patch.object(engine_mod, "_LIVENESS_TTL", 0.0):
            eng.execute(self._act(ident="spy.probe:1"))
            skips = [eng.execute(self._act(ident=f"spy.probe:{i}")) for i in range(2, 6)]
        self.assertEqual([r["verdict"] for r in skips], ["SKIP"] * 4)
        self.assertEqual(list(eng.down_targets), ["127.0.0.1:3000"],
                         "le CONSTAT est unique par cible")
        for r in skips:
            self.assertTrue(r["reasons"][0], "chaque action garde sa raison nommée")

    def test_a_target_that_comes_back_unblocks_the_campaign(self):
        probe = _Probe(True, False, True)
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", probe), \
                mock.patch.object(engine_mod, "_LIVENESS_TTL", 0.0):
            eng.execute(self._act(ident="spy.probe:1"))
            dead = eng.execute(self._act(ident="spy.probe:2"))
            back = eng.execute(self._act(ident="spy.probe:3"))
        self.assertEqual(dead["verdict"], "SKIP")
        self.assertEqual(back["verdict"], "FIRE", "la cible est revenue : on reprend")
        self.assertEqual(self.spy.fires, 2)


class TestTheThreeBoundsAgainstOverreach(_Base):
    """Chaque borne empêche le moteur de décréter une mort qu'il n'a pas constatée."""

    def test_never_seen_alive_is_never_gated(self):
        """Une cible qu'on n'a JAMAIS jointe reste `unknown` — proxy/pare-feu/tunnel sont légitimes."""
        probe = _Probe(False)
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", probe), \
                mock.patch.object(engine_mod, "_LIVENESS_TTL", 0.0):
            results = [eng.execute(self._act(ident=f"spy.probe:{i}")) for i in range(3)]
        self.assertEqual([r["verdict"] for r in results], ["FIRE"] * 3,
                         "jamais jointe != morte : la gate doit rester muette")
        self.assertEqual(self.spy.fires, 3)

    def test_a_bare_host_is_never_probed(self):
        """Sans port explicite ni schéma, aucune sonde : on ne fabrique pas de port pour conclure."""
        self.scope = Scope({"mode": "grey", "in_scope": ["app.test"], "out_scope": [],
                            "allow_exploit": False, "allow_destructive": False})
        probe = _Probe(False)
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", probe):
            res = eng.execute(self._act(target="app.test"))
        self.assertEqual(res["verdict"], "FIRE")
        self.assertEqual(probe.calls, [], "aucune sonde ne doit partir sur un hôte nu")

    def test_endpoint_parsing_only_accepts_an_explicit_port(self):
        self.assertEqual(_target_endpoint("127.0.0.1:3000"), ("127.0.0.1", 3000))
        self.assertEqual(_target_endpoint("http://h.test/a?b=1"), ("h.test", 80))
        self.assertEqual(_target_endpoint("https://h.test:8443/x"), ("h.test", 8443))
        self.assertEqual(_target_endpoint("[::1]:8080"), ("::1", 8080))
        for bare in ("app.test", "", None, "h:notaport", "ftp://h.test/x"):
            self.assertIsNone(_target_endpoint(bare), f"{bare!r} n'a pas de port EXPLICITE")

    def test_the_probe_uses_the_pinned_ip_not_a_fresh_resolution(self):
        """La gate tourne APRÈS le ROE : re-résoudre le nom rouvrirait la fenêtre de rebinding que
        l'épinglage vient de fermer. On sonde l'IP ÉPINGLÉE."""
        probe = _Probe(True)
        eng = self._engine()
        # gate APPELÉE DIRECTEMENT : sur le chemin complet, le ROE ré-épingle lui-même (et une cible
        # littérale s'épingle sur elle-même), ce qui rendrait l'assertion indiscernable du repli.
        act = self._act(target="http://app.test:3000/x")
        act.params["_pinned_ips"] = ["10.9.9.9"]
        with mock.patch.object(engine_mod, "_tcp_reachable", probe):
            eng._liveness_gate(act)
        self.assertEqual(probe.calls, [("10.9.9.9", 3000)],
                         "la sonde doit partir vers l'IP ÉPINGLÉE, jamais vers une re-résolution")

    def test_without_a_pin_the_probe_falls_back_to_the_host(self):
        probe = _Probe(True)
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", probe):
            eng._liveness_gate(self._act(target="http://app.test:3000/x"))
        self.assertEqual(probe.calls, [("app.test", 3000)])

    def test_a_failing_probe_never_aborts_a_fire(self):
        """FAIL-OPEN STRICT : une sonde qui LÈVE ne doit pas empêcher le tir."""
        def boom(*a, **k):
            raise RuntimeError("socket cassé")
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", boom):
            res = eng.execute(self._act())
        self.assertEqual(res["verdict"], "FIRE")
        self.assertEqual(self.spy.fires, 1)


class TestProbeCost(_Base):
    """Le coût est borné : UNE sonde par host:port et par fenêtre, jamais par action."""

    def test_ttl_caches_the_probe(self):
        probe = _Probe(True)
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", probe), \
                mock.patch.object(engine_mod, "_LIVENESS_TTL", 3600.0):
            for i in range(25):
                eng.execute(self._act(ident=f"spy.probe:{i}"))
        self.assertEqual(len(probe.calls), 1, f"{len(probe.calls)} sondes pour 25 actions")
        self.assertEqual(self.spy.fires, 25)

    def test_endpoints_of_the_same_host_port_share_one_probe(self):
        probe = _Probe(True)
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", probe), \
                mock.patch.object(engine_mod, "_LIVENESS_TTL", 3600.0):
            eng.execute(self._act(target=TARGET, ident="a"))
            eng.execute(self._act(target=URL, ident="b"))
            eng.execute(self._act(target="http://127.0.0.1:3000/autre", ident="c"))
        self.assertEqual(len(probe.calls), 1, "le port est la même cible physique")


class TestMutationTheGateIsLoadBearing(_Base):
    """MUTATION : sonde toujours « vivante » -> le tir sur cadavre REVIENT, avec son `tested`."""

    def test_neutralising_the_probe_restores_the_verdict_on_a_corpse(self):
        eng = self._engine()
        with mock.patch.object(engine_mod, "_tcp_reachable", lambda *a, **k: True), \
                mock.patch.object(engine_mod, "_LIVENESS_TTL", 0.0):
            eng.execute(self._act(ident="spy.probe:1"))
            res = eng.execute(self._act(ident="spy.probe:2"))
        self.assertEqual(res["verdict"], "FIRE",
                         "MUTATION INATTEIGNABLE : la gate n'est pas ce qui arrête le tir")
        self.assertEqual(self.spy.fires, 2)
        self.assertEqual([f.status for f in eng.findings], ["tested", "tested"],
                         "c'est bien un verdict `tested` que la gate supprime")


if __name__ == "__main__":
    unittest.main()

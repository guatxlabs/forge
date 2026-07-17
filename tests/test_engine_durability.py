"""LOT DURABILITÉ — un run tué/timeout ne perd plus TOUT le travail accompli (fix D1).

Symptôme reproduit (live) : un run complet (43 modules -> 534 actions en vague 2) heurtait le watchdog
900s de la console (`kill group`) et était tué en pleine vague 2. Malgré 487 `[FIRE]` dans le log, les
tables `finding`/`runrecord`/`roe_decision` restaient VIDES et les compteurs à 0 : la finalisation était
« tout ou rien » (unique POST /api/ingest en fin de campagne) — tout le travail des vagues déjà terminées
était perdu.

Preuves (toutes HERMÉTIQUES — modules stubés, ZÉRO réseau ; une fausse console en mémoire mime la
sémantique d'idempotence de `POST /api/ingest` du store Rust : findings dédupliqués par
UNIQUE(campaign,target,title), run-records/décisions append, compteurs SET, statut 'running' tant que
`partial=True`) :

  1. DURABILITÉ PAR VAGUE : un run tué (watchdog SIGTERM -> `_Terminate`) APRÈS la vague 1 a bien
     PERSISTÉ les findings/run-records/décisions de la vague 1 (rien n'est perdu) ; les compteurs
     reflètent le travail fait (non nuls) ; le run_job reste 'running' (jamais faussement 'done' -> le
     superviseur console pourra le marquer 'timeout' honnêtement).
  2. DURABILITÉ INTRA-VAGUE : une vague unique de N actions tuée EN COURS a persisté les actions déjà
     exécutées (batch tous les `checkpoint_every`), pas seulement en fin de vague.
  3. PAS DE DOUBLE-COMPTAGE : un run COMPLET normal persiste tout EXACTEMENT une fois (offsets du sink)
     — findings/run-records/décisions comptés une seule fois, run_job marqué 'done' ; un re-flush à vide
     n'ajoute rien.
  4. ROBUSTESSE DU GARDE : le flush best-effort du moteur AVALE une erreur réseau ordinaire (le run
     continue) mais LAISSE PASSER l'arrêt gracieux (`_Terminate`, une BaseException) — sinon le `except
     Exception` du moteur (M6) l'engloutirait et on ne flusherait jamais le travail final.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action, FIRE                     # noqa: E402
from forge.engine import Engine                               # noqa: E402
from forge.brain import Brain                                 # noqa: E402
from forge.schema import Target, Finding                      # noqa: E402
from forge.modules import registry                            # noqa: E402
from forge.planner import Planner as _Planner                 # noqa: E402
from forge import console_client                              # noqa: E402
from forge.console_client import IncrementalIngest            # noqa: E402
from forge.cli.engine import _Terminate                       # noqa: E402  (arrêt gracieux réel du CLI)


# --- stubs moteur (repris de test_engine_iterative, zéro réseau) ------------------------------------
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
        self.mapping = mapping
        self._saved = {}

    def __enter__(self):
        for kind, findings in self.mapping.items():
            self._saved[kind] = registry.REGISTRY.get(kind)
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


class _WaveBrain(Brain):
    """Cerveau déterministe : renvoie la liste d'actions de la vague i à chaque appel, puis [] (point
    fixe). Chaque action a un id stable unique (kind:target) -> dédup inter-vagues respectée."""
    def __init__(self, waves):
        self._waves = waves
        self._i = 0

    def propose(self, graph_state):
        if self._i < len(self._waves):
            acts = self._waves[self._i]
            self._i += 1
            return acts
        return []


def _hit(action):
    # un finding par action, titre UNIQUE par cible -> compte exact (pas de dédup accidentelle).
    return [Finding(target=action.target, title=f"hit:{action.target}", status="reported_by_tool",
                    severity="LOW", category="demo", mitre="T1190")]


def _scope(hosts):
    return Scope({"mode": "grey", "in_scope": list(hosts),
                  "allow_exploit": True, "allow_destructive": False})


def _engine(hosts, run_id="run-test"):
    eng = Engine(_scope(hosts), mode="auto", campaign="camp", run_id=run_id)
    eng.arm("test durability")
    return eng


class FakeConsole:
    """Mime `POST /api/ingest` du store Rust (console/src/ingest.rs) SANS réseau : findings dédupliqués
    par UNIQUE(campaign,target,title) (ON CONFLICT IGNORE) ; run-records + décisions en append ; run_job
    compteurs SET, statut préservé 'running' si `partial` sinon 'done'. Sert de sender injecté au sink."""
    def __init__(self):
        self.findings = {}       # (campaign,target,title) -> dict
        self.run_records = []
        self.roe = []
        self.run_job = {}        # run_id -> {status, fired, dry_run, vetoed, errors}
        self.calls = 0

    def ingest(self, campaign, findings, run_records, url=None, token=None, run_id=None,
               roe_decisions=None, coverage=None, coverage_gaps=None, skipped_budget=None,
               not_planned=None, partial=False):
        self.calls += 1
        for f in (findings or []):
            d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            self.findings.setdefault((campaign, d.get("target"), d.get("title")), d)  # ON CONFLICT IGNORE
        for r in (run_records or []):
            self.run_records.append(dict(r))
        for d in (roe_decisions or []):
            self.roe.append(dict(d))
        if run_id:
            counts = console_client._coverage_counts(coverage)
            job = self.run_job.setdefault(run_id, {"status": "running", "fired": 0,
                                                    "dry_run": 0, "vetoed": 0, "errors": 0})
            job.update(counts)
            job["status"] = "running" if partial else "done"   # miroir de la branche partial du handler
        return 200, {"findings_ingested": len(findings or []),
                     "runrecords_ingested": len(run_records or []),
                     "roe_decisions_ingested": len(roe_decisions or [])}


def _sink(fake, run_id="run-test"):
    return IncrementalIngest("camp", run_id, url=None, token=None, sender=fake.ingest)


# ===================================================================================================
class TestPerWaveDurability(unittest.TestCase):
    def test_kill_after_wave1_preserves_wave1_work(self):
        # VAGUE 1 : 6 actions ; VAGUE 2 : 6 actions. Le watchdog tue le run À LA FRONTIÈRE de vague 1
        # (checkpoint par-vague), AVANT la vague 2. Le travail de la vague 1 DOIT être persisté.
        w1 = [f"h{i}.wave1.test" for i in range(6)]
        w2 = [f"h{i}.wave2.test" for i in range(6)]
        waves = [[Action("demo.probe", h) for h in w1],
                 [Action("demo.probe", h) for h in w2]]
        fake = FakeConsole()
        sink = _sink(fake)

        calls = {"n": 0}

        def checkpoint():
            sink.flush(eng, partial=True, coverage=eng.coverage(),
                       coverage_gaps=eng.coverage_gaps, skipped_budget=eng.skipped_budget,
                       not_planned=eng.not_planned)
            calls["n"] += 1
            if calls["n"] >= 1:               # simule le watchdog : SIGTERM juste après la vague 1
                raise _Terminate()

        with _swap_registry({"demo.probe": _hit}):
            eng = _engine(w1 + w2)
            terminated = False
            try:
                # checkpoint_every=0 -> flush UNIQUEMENT aux frontières de vague (prouve la durabilité par vague)
                eng.campaign([Target(w1[0], "url")], _WaveBrain(waves), _Planner(), max_waves=4,
                             checkpoint=checkpoint, checkpoint_every=0)
            except _Terminate:
                terminated = True
                sink.flush(eng, partial=True, coverage=eng.coverage(),   # flush final (chemin timeout du CLI)
                           coverage_gaps=eng.coverage_gaps, skipped_budget=eng.skipped_budget,
                           not_planned=eng.not_planned)

        self.assertTrue(terminated, "l'arrêt gracieux _Terminate aurait dû dérouler la campagne")
        # (1) le travail de la VAGUE 1 est PERSISTÉ dans la console (findings/run-records/décisions).
        persisted_targets = {t for (_c, t, _title) in fake.findings}
        for h in w1:
            self.assertIn(h, persisted_targets, f"finding vague 1 perdu : {h}")
        self.assertEqual(len(fake.findings), 6, "exactement les 6 findings de la vague 1 persistés")
        self.assertEqual(len(fake.run_records), 6, "run-records de la vague 1 persistés")
        self.assertEqual(len(fake.roe), 6, "décisions ROE de la vague 1 persistées")
        # (2) la VAGUE 2 n'a jamais tourné (tuée avant) -> aucun de ses findings.
        for h in w2:
            self.assertNotIn(h, persisted_targets)
        # (3) compteurs NON NULS reflétant le travail fait (le symptôme : fired=0 alors que 487 FIRE).
        self.assertEqual(fake.run_job["run-test"]["fired"], 6)
        # (4) HONNÊTETÉ DU STATUT : le run reste 'running' (jamais faussement 'done' sur un flush partiel)
        #     -> le superviseur console pourra le marquer 'timeout'. Pas un « 0 silencieux ».
        self.assertEqual(fake.run_job["run-test"]["status"], "running")


class TestIntraWaveDurability(unittest.TestCase):
    def test_kill_mid_wave_preserves_completed_actions(self):
        # UNE seule grande vague de 12 actions, checkpoint tous les 3 actions. Le watchdog tue APRÈS le
        # 2e checkpoint intra-vague (6 actions exécutées). Ces 6 actions DOIVENT être persistées — la
        # durabilité ne dépend PAS d'atteindre la fin de la vague (cas des 534 actions en une vague).
        hosts = [f"h{i}.big.test" for i in range(12)]
        waves = [[Action("demo.probe", h) for h in hosts]]
        fake = FakeConsole()
        sink = _sink(fake)
        calls = {"n": 0}

        def checkpoint():
            sink.flush(eng, partial=True, coverage=eng.coverage(),
                       coverage_gaps=eng.coverage_gaps, skipped_budget=eng.skipped_budget,
                       not_planned=eng.not_planned)
            calls["n"] += 1
            if calls["n"] == 2:               # tué au 2e batch intra-vague (après 6 actions)
                raise _Terminate()

        with _swap_registry({"demo.probe": _hit}):
            eng = _engine(hosts)
            terminated = False
            try:
                eng.campaign([Target(hosts[0], "url")], _WaveBrain(waves), _Planner(), max_waves=2,
                             checkpoint=checkpoint, checkpoint_every=3)
            except _Terminate:
                terminated = True

        self.assertTrue(terminated)
        # 6 actions exécutées avant le kill (2 batches de 3) -> 6 findings persistés, pas 0, pas 12.
        self.assertEqual(len(eng.findings), 6, "6 actions exécutées avant le kill mid-vague")
        self.assertEqual(len(fake.findings), 6, "les 6 findings pré-kill sont PERSISTÉS (pas perdus)")
        self.assertEqual(len(fake.run_records), 6)
        self.assertEqual(fake.run_job["run-test"]["fired"], 6)
        self.assertEqual(fake.run_job["run-test"]["status"], "running")


class TestNormalRunNoDoubleCount(unittest.TestCase):
    def test_full_run_persists_everything_exactly_once(self):
        # Run COMPLET normal (2 vagues, checkpoints intra + par-vague, PAS de kill) suivi d'un flush FINAL
        # (partial=False). Tout est persisté EXACTEMENT une fois (offsets) et le run_job est marqué 'done'.
        w1 = [f"h{i}.a.test" for i in range(5)]
        w2 = [f"h{i}.b.test" for i in range(5)]
        waves = [[Action("demo.probe", h) for h in w1],
                 [Action("demo.probe", h) for h in w2]]
        fake = FakeConsole()
        sink = _sink(fake)

        def checkpoint():
            sink.flush(eng, partial=True, coverage=eng.coverage(),
                       coverage_gaps=eng.coverage_gaps, skipped_budget=eng.skipped_budget,
                       not_planned=eng.not_planned)

        with _swap_registry({"demo.probe": _hit}):
            eng = _engine(w1 + w2)
            eng.campaign([Target(w1[0], "url")], _WaveBrain(waves), _Planner(), max_waves=4,
                         checkpoint=checkpoint, checkpoint_every=2)
            # flush FINAL (fin normale) : delta restant + marque 'done'.
            sink.flush(eng, partial=False, coverage=eng.coverage(),
                       coverage_gaps=eng.coverage_gaps, skipped_budget=eng.skipped_budget,
                       not_planned=eng.not_planned)

        # (1) TOUT persisté, chaque item UNE seule fois — pas de double-comptage malgré N checkpoints.
        self.assertEqual(len(fake.findings), len(eng.findings), "findings persistés = findings moteur")
        self.assertEqual(len(fake.findings), 10)
        self.assertEqual(len(fake.run_records), len(eng.run_records),
                         "run-records persistés EXACTEMENT une fois (pas de double-comptage)")
        self.assertEqual(len(fake.roe), len(eng.results),
                         "une décision ROE par résultat, exactement une fois")
        # (2) run marqué 'done', compteurs justes.
        self.assertEqual(fake.run_job["run-test"]["status"], "done")
        self.assertEqual(fake.run_job["run-test"]["fired"], len(eng.coverage()["fired"]))
        # (3) un re-flush à vide n'ajoute RIEN (idempotence des offsets) -> aucune régression de compteur.
        before = (len(fake.findings), len(fake.run_records), len(fake.roe))
        r = sink.flush(eng, partial=True, coverage=eng.coverage(),
                       coverage_gaps=eng.coverage_gaps, skipped_budget=eng.skipped_budget,
                       not_planned=eng.not_planned)
        self.assertIsNone(r, "un checkpoint partiel sans travail neuf ne poste rien")
        self.assertEqual((len(fake.findings), len(fake.run_records), len(fake.roe)), before)


class TestGuardSemantics(unittest.TestCase):
    """Le garde `_run_checkpoint` du moteur AVALE une erreur réseau ordinaire (Exception) mais LAISSE
    PASSER l'arrêt gracieux (`_Terminate`, BaseException). Sans ça, le `except Exception` M6 du tir
    engloutirait le signal et le flush final ne se ferait jamais (cause racine du symptôme 0-persisté)."""

    def test_ordinary_exception_in_checkpoint_is_swallowed_run_continues(self):
        boom = {"n": 0}

        def checkpoint():
            boom["n"] += 1
            raise RuntimeError("console injoignable (erreur réseau ordinaire)")

        with _swap_registry({"demo.probe": _hit}):
            eng = _engine(["a.test", "b.test", "c.test"])
            # checkpoint_every=1 : le flush lève à CHAQUE action, mais le run ne DOIT PAS avorter.
            res = eng.run([Action("demo.probe", h) for h in ("a.test", "b.test", "c.test")],
                          checkpoint=checkpoint, checkpoint_every=1)
        self.assertEqual(len(res), 3, "une erreur de flush ne doit pas interrompre le run")
        self.assertTrue(all(r["verdict"] == FIRE for r in res))
        self.assertGreaterEqual(boom["n"], 3, "le checkpoint a bien été appelé à chaque action")

    def test_terminate_baseexception_propagates_through_guard(self):
        def checkpoint():
            raise _Terminate()

        with _swap_registry({"demo.probe": _hit}):
            eng = _engine(["a.test", "b.test"])
            with self.assertRaises(_Terminate):     # NON avalé par `except Exception` -> propagation
                eng.run([Action("demo.probe", "a.test"), Action("demo.probe", "b.test")],
                        checkpoint=checkpoint, checkpoint_every=1)
            # tué au 1er checkpoint (après la 1re action) -> la 2e n'a pas tourné.
            self.assertEqual(len(eng.results), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

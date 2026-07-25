"""R4 — GARDE-FOU MÉMOIRE : BORNE LE NB DE SOUS-PROCESS OUTILS SIMULTANÉS.

`runner._PROC_GATE` (sémaphore borné à plafond DYNAMIQUE `max_concurrent_procs()`) enveloppe le
LANCEMENT réel d'un outil externe (`_spawn_and_wait` -> `Popen`). Preuves :

  (a) CAP QUI BINDE : plafond forcé à 1 + pool=4 -> le MAX de process vivants observés ne dépasse
      JAMAIS 1, et les 4 tirs se terminent (aucun deadlock, aucun travail perdu, sérialisés) ;
  (b) DÉFAUT INERTE : sans override, plafond=6 (balanced) >= pool -> le sémaphore PERMET >= pool
      process concurrents (aucun throttle vs aujourd'hui — comportement byte-identique) ;
  (c) PRÉCÉDENCE : `FORGE_MAX_CONCURRENT_PROCS=2` GAGNE sur le profil (full=16) ;
  (d) LIBÉRATION en `finally` : un tir qui LÈVE ou TIMEOUTE relâche quand même son slot (pas de fuite,
      pas de deadlock) -> les tirs suivants passent ;
  (e) le résolveur réutilise `resource_profile` (aucune valeur codée en dur) — override>profil>défaut.

Ces preuves sont HERMÉTIQUES : le vrai `subprocess.Popen` est monkeypatché par un FAUX process (aucun
process OS réel, zéro réseau), pour instrumenter la concurrence VIVANTE de façon déterministe.
"""
import os
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import runner              # noqa: E402
from forge import resource_profile as rp  # noqa: E402


class _EnvGuard:
    """Sauvegarde/restaure les variables d'env de ressources autour d'un test (isolation stricte)."""
    _VARS = ("FORGE_RESOURCE_PROFILE", "FORGE_MAX_CONCURRENT_PROCS", "FORGE_PARALLELISM")

    def __enter__(self):
        self._saved = {k: os.environ.get(k) for k in self._VARS}
        for k in self._VARS:
            os.environ.pop(k, None)
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


class _SleepProc:
    """FAUX Popen : compte les process VIVANTS (max observé) et « vit » un court instant dans communicate.

    Construction (== lancement) -> +1 vivant (sous verrou, max_live mis à jour). `communicate` dort puis
    -1. La fenêtre vivant est donc bornée par le sémaphore (acquis avant construction, relâché après
    communicate). Un plafond=1 SÉRIALISE -> max_live == 1 ; sans plafond effectif -> max_live monterait.
    """
    _lock = threading.Lock()
    live = 0
    max_live = 0
    _seq = 0
    HOLD = 0.05

    def __init__(self, cmd, **kwargs):
        with _SleepProc._lock:
            _SleepProc._seq += 1
            self.pid = 2147480000 + _SleepProc._seq   # pid factice, jamais un process réel
            _SleepProc.live += 1
            _SleepProc.max_live = max(_SleepProc.max_live, _SleepProc.live)
        self.returncode = 0

    def communicate(self, timeout=None):
        time.sleep(_SleepProc.HOLD)
        with _SleepProc._lock:
            _SleepProc.live -= 1
        return ("ok", "")

    @classmethod
    def reset(cls):
        with cls._lock:
            cls.live = 0
            cls.max_live = 0
            cls._seq = 0


class _BarrierProc:
    """FAUX Popen prouvant l'INERTIE : chaque communicate ATTEND une barrière de `parties` participants
    AVANT de rendre la main. Si le sémaphore autorise >= `parties` process concurrents, tous atteignent
    la barrière et passent ; s'il throttlait en dessous, la barrière TIMEOUTERAIT (deadlock détecté)."""
    _lock = threading.Lock()
    live = 0
    max_live = 0
    _seq = 0
    barrier = None

    def __init__(self, cmd, **kwargs):
        with _BarrierProc._lock:
            _BarrierProc._seq += 1
            self.pid = 2147481000 + _BarrierProc._seq
            _BarrierProc.live += 1
            _BarrierProc.max_live = max(_BarrierProc.max_live, _BarrierProc.live)
        self.returncode = 0

    def communicate(self, timeout=None):
        _BarrierProc.barrier.wait(timeout=5.0)     # exige la concurrence : lève BrokenBarrierError si throttlé
        with _BarrierProc._lock:
            _BarrierProc.live -= 1
        return ("ok", "")

    @classmethod
    def reset(cls, parties):
        with cls._lock:
            cls.live = 0
            cls.max_live = 0
            cls._seq = 0
        cls.barrier = threading.Barrier(parties)


def _run_pool(n_tasks, pool):
    """Lance `n_tasks` `_spawn_and_wait` via un pool de `pool` threads ; renvoie la liste des rc."""
    with ThreadPoolExecutor(max_workers=pool) as ex:
        futs = [ex.submit(runner._spawn_and_wait, ["fake-tool"], 10, None) for _ in range(n_tasks)]
        return [f.result()[0] for f in futs]


class TestProcGateResolver(unittest.TestCase):
    """(c)(e) le résolveur réutilise `resource_profile` : override > profil > défaut."""

    def test_precedence_override_beats_profile_beats_default(self):
        with _EnvGuard():
            self.assertEqual(runner._max_concurrent_procs(), 6)          # balanced (défaut-code)
            os.environ["FORGE_RESOURCE_PROFILE"] = "low"
            self.assertEqual(runner._max_concurrent_procs(), 2)          # profil low
            os.environ["FORGE_RESOURCE_PROFILE"] = "full"
            self.assertEqual(runner._max_concurrent_procs(), 16)         # profil full
            os.environ["FORGE_MAX_CONCURRENT_PROCS"] = "2"               # override GAGNE sur full(16)
            self.assertEqual(runner._max_concurrent_procs(), 2)
            os.environ["FORGE_MAX_CONCURRENT_PROCS"] = "garbage"         # fail-through -> profil
            self.assertEqual(runner._max_concurrent_procs(), 16)

    def test_default_cap_is_at_least_pool_for_every_profile(self):
        """NO-OP structurel : plafond >= parallelism pour CHAQUE profil -> sémaphore inerte sous défauts."""
        for prof in ("low", "balanced", "full"):
            cap = rp.PROFILES[prof]["max_concurrent_procs"]
            par = rp.PROFILES[prof]["parallelism"]
            self.assertGreaterEqual(cap, par, f"profil {prof}: cap {cap} < pool {par}")


class TestProcGateBinds(unittest.TestCase):
    """(a) plafond=1 + pool=4 -> max concurrent process == 1, tout se termine (pas de deadlock)."""

    def setUp(self):
        runner._LIVE_TOOL_PGIDS.clear()
        _SleepProc.reset()
        self._orig_popen = subprocess.Popen

    def tearDown(self):
        subprocess.Popen = self._orig_popen
        runner._LIVE_TOOL_PGIDS.clear()

    def test_cap_one_serializes_four_workers(self):
        subprocess.Popen = _SleepProc
        with _EnvGuard():
            os.environ["FORGE_MAX_CONCURRENT_PROCS"] = "1"       # plafond DUR à 1
            self.assertEqual(runner._max_concurrent_procs(), 1)
            rcs = _run_pool(n_tasks=8, pool=4)                   # pool 4 > cap 1
        self.assertEqual(rcs, [0] * 8, "les 8 tirs se terminent (aucun travail perdu, aucun deadlock)")
        self.assertEqual(_SleepProc.max_live, 1,
                         f"jamais plus de 1 process vivant à la fois (observé {_SleepProc.max_live})")
        self.assertEqual(runner._PROC_GATE._active, 0, "aucun slot de sémaphore fuité")

    def test_cap_two_binds_below_pool(self):
        subprocess.Popen = _SleepProc
        with _EnvGuard():
            os.environ["FORGE_MAX_CONCURRENT_PROCS"] = "2"
            rcs = _run_pool(n_tasks=8, pool=6)                   # pool 6 > cap 2
        self.assertEqual(rcs, [0] * 8)
        self.assertLessEqual(_SleepProc.max_live, 2,
                             f"le plafond 2 BINDE (observé {_SleepProc.max_live})")
        self.assertEqual(runner._PROC_GATE._active, 0)


class TestProcGateInertByDefault(unittest.TestCase):
    """(b) défaut (balanced, cap=6) -> sémaphore INERTE : >= pool process concurrents autorisés."""

    def setUp(self):
        runner._LIVE_TOOL_PGIDS.clear()
        _BarrierProc.reset(parties=4)
        self._orig_popen = subprocess.Popen

    def tearDown(self):
        subprocess.Popen = self._orig_popen
        runner._LIVE_TOOL_PGIDS.clear()

    def test_default_permits_full_pool_concurrency(self):
        subprocess.Popen = _BarrierProc
        with _EnvGuard():                                        # aucun override -> balanced cap=6
            self.assertEqual(runner._max_concurrent_procs(), 6)
            rcs = _run_pool(n_tasks=4, pool=4)                   # 4 tirs qui EXIGENT de se croiser
        self.assertEqual(rcs, [0] * 4, "les 4 franchissent la barrière -> concurrence >= pool (inerte)")
        self.assertEqual(_BarrierProc.max_live, 4,
                         "cap 6 >= pool 4 : les 4 process sont vivants EN MÊME TEMPS (aucun throttle)")
        self.assertEqual(runner._PROC_GATE._active, 0)


class _RaiseProc:
    """FAUX Popen dont communicate LÈVE : exerce le chemin exception de `_spawn_and_wait` (relâche en finally)."""
    def __init__(self, cmd, **kwargs):
        self.pid = 2147482001
        self.returncode = 1

    def communicate(self, timeout=None):
        raise RuntimeError("boom au tir")


class _TimeoutProc:
    """FAUX Popen dont communicate TIMEOUTE toujours : exerce le chemin timeout (kill de groupe + finally)."""
    def __init__(self, cmd, **kwargs):
        self.pid = 2147482002       # pid factice -> os.getpgid lève ProcessLookupError (avalé par _terminate_group)
        self.returncode = None

    def communicate(self, timeout=None):
        raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)


class TestProcGateReleasesOnFailure(unittest.TestCase):
    """(d) un tir qui LÈVE ou TIMEOUTE relâche quand même son slot (finally) -> les suivants passent."""

    def setUp(self):
        runner._LIVE_TOOL_PGIDS.clear()
        _SleepProc.reset()
        self._orig_popen = subprocess.Popen

    def tearDown(self):
        subprocess.Popen = self._orig_popen
        runner._LIVE_TOOL_PGIDS.clear()

    def test_exception_releases_slot(self):
        subprocess.Popen = _RaiseProc
        rc, _o, err = runner._spawn_and_wait(["boom"], 10, None)
        self.assertEqual(rc, 1)
        self.assertIn("boom", err)
        self.assertEqual(runner._PROC_GATE._active, 0, "slot relâché malgré l'exception (finally)")

    def test_timeout_releases_slot(self):
        subprocess.Popen = _TimeoutProc
        rc, _o, err = runner._spawn_and_wait(["hang"], 1, None)
        self.assertEqual(rc, 124)
        self.assertIn("timeout", err)
        self.assertEqual(runner._PROC_GATE._active, 0, "slot relâché malgré le timeout (finally)")

    def test_subsequent_tools_proceed_after_failure_under_cap_one(self):
        # Avec plafond=1, si un tir en échec NE relâchait PAS son slot, le suivant DEADLOCKERAIT.
        with _EnvGuard():
            os.environ["FORGE_MAX_CONCURRENT_PROCS"] = "1"
            subprocess.Popen = _RaiseProc
            runner._spawn_and_wait(["boom"], 10, None)           # échoue et DOIT relâcher
            subprocess.Popen = _SleepProc                        # le suivant doit passer, pas deadlocker
            rc, _o, _e = runner._spawn_and_wait(["ok"], 10, None)
        self.assertEqual(rc, 0, "un tir sain passe après un échec (slot bien relâché sous cap=1)")
        self.assertEqual(runner._PROC_GATE._active, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

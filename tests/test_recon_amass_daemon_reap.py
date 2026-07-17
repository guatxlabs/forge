"""E2 — `recon.amass` NE LAISSE PLUS de daemon `amass engine` fuité (pprof exposé sur :6060).

amass v4 `enum` démarre un daemon `amass engine` DÉTACHÉ qui SURVIT à la fin de l'enum et ÉCHAPPE au
reap par groupe de processus (host-networking -> pprof sur 0.0.0.0). Le correctif lance amass sous un
HOME privé + un marqueur unique (`FORGE_RUN_MARKER`) dans l'environnement de l'enfant ; tout survivant
portant CE marqueur est terminé (SIGTERM puis SIGKILL) APRÈS l'exécution — succès, timeout OU annulation.

Ces tests MOCKENT `runner.tool` par un stub qui SIMULE amass : il fork un vrai enfant DÉTACHÉ
(`start_new_session=True` -> nouvelle session/pgid, comme le daemon qui échappe au reap de groupe) en
lui passant l'`env` reçu (donc le marqueur), puis retourne comme si l'enum s'était terminé. On prouve
qu'APRÈS `fire()` l'enfant marqué est mort — sans jamais toucher un `amass` tiers (marqueur différent).
Zéro I/O réseau, aucun vrai binaire amass requis (subprocess = `sleep`, stdlib).
"""
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import runner                                        # noqa: E402
from forge import modules as mods                               # noqa: E402
from forge.roe import Action                                    # noqa: E402
from forge.modules import _daemon_reap                          # noqa: E402


def _alive(pid):
    """True si le process existe ET n'est pas un zombie (défunt = déjà reapé). Réutilise la sonde du
    reaper pour cohérence."""
    return _daemon_reap._alive(pid)


def _wait_gone(pid, timeout=3.0):
    """Attend (borné) que `pid` disparaisse/devienne zombie. True si mort dans le délai."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.02)
    return not _alive(pid)


class _PatchRunner:
    """Remplace temporairement `runner.tool` / `runner.available` (référencés à l'appel par toolspec)."""

    def __init__(self, **attrs):
        self.attrs, self.saved = attrs, {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(runner, k)
            setattr(runner, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(runner, k, v)


class ReconAmassDaemonReap(unittest.TestCase):
    """Prouve : un run `recon.amass` (normal / timeout / annulation) ne laisse AUCUN `amass engine`
    survivant, la terminaison est CIBLÉE (marqueur unique — n'atteint pas un amass tiers), et l'enum
    reste fonctionnel (les sous-domaines découverts deviennent des findings)."""

    def setUp(self):
        self._spawned = []          # (Popen) enfants à harvester en tearDown (évite les zombies de test)

    def tearDown(self):
        for p in self._spawned:
            try:
                if p.poll() is None:
                    p.kill()
                p.wait(timeout=2)
            except Exception:       # noqa: BLE001 — nettoyage best-effort
                pass

    # --- stub amass : fork un daemon DÉTACHÉ portant l'env (donc le marqueur) reçu de reaping_env ---
    def _fake_amass(self, holder, rc=0, out="sub.good.test\n", err="", raise_after=False):
        def fake_tool(binary, docker_image=None, args=None, prefer_docker=False, timeout=120, env=None):
            # simule `amass enum` qui démarre un `amass engine` détaché qui SURVIT à l'enum.
            p = subprocess.Popen(["sleep", "300"], env=env, start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._spawned.append(p)
            holder["pid"] = p.pid
            holder["env"] = env
            if raise_after:                       # simule une ANNULATION en plein run (post-spawn)
                raise KeyboardInterrupt("annulation simulée pendant l'enum")
            return (rc, out, err)
        return fake_tool

    def _fire(self, holder, **kw):
        m = mods.get("recon.amass")
        # in_scope inclut le sous-domaine découvert -> l'asset survit à la re-validation scope (fail-closed),
        # ce qui permet d'assert que l'enum reste FONCTIONNEL (produit un finding attribué).
        with _PatchRunner(available=lambda *a, **k: True, tool=self._fake_amass(holder, **kw)):
            return m.fire(Action("recon.amass", "good.test",
                                 params={"in_scope": ["good.test", "sub.good.test"]}))

    # (a) CHEMIN NORMAL — l'enum réussit, le daemon fuité est reapé, l'enum reste fonctionnel.
    def test_normal_run_leaves_no_surviving_engine(self):
        holder = {}
        findings = self._fire(holder)
        pid = holder["pid"]
        # le marqueur a bien été injecté dans l'env de l'enfant (HOME privé + FORGE_RUN_MARKER).
        self.assertIn("FORGE_RUN_MARKER", holder["env"])
        self.assertTrue(holder["env"]["HOME"].startswith(__import__("tempfile").gettempdir()))
        # APRÈS fire() : AUCUN survivant (le daemon détaché a été terminé de façon ciblée).
        self.assertTrue(_wait_gone(pid), "le daemon `amass engine` a SURVÉCU au run (fuite non corrigée)")
        # l'enum reste FONCTIONNEL : le sous-domaine découvert est devenu un finding attribué.
        assets = [f for f in findings if getattr(f, "target", None) == "sub.good.test"]
        self.assertTrue(assets, "recon.amass ne produit plus de finding (le correctif a cassé l'enum)")

    # (b) CHEMIN TIMEOUT (rc=124) — compose avec le timeout de D1 : le daemon est reapé quand même.
    def test_timeout_run_leaves_no_surviving_engine(self):
        holder = {}
        self._fire(holder, rc=124, out="", err="timeout")
        self.assertTrue(_wait_gone(holder["pid"]),
                        "le daemon a survécu après un TIMEOUT (le reap ne compose pas avec le timeout)")

    # (c) CHEMIN ANNULATION — une exception (SIGTERM/annulation D1) pendant le run : le `finally` reape.
    def test_cancelled_run_leaves_no_surviving_engine(self):
        holder = {}
        with self.assertRaises(KeyboardInterrupt):
            self._fire(holder, raise_after=True)
        self.assertTrue(_wait_gone(holder["pid"]),
                        "le daemon a survécu à une ANNULATION (le reap n'est pas dans un finally)")

    # (d) CIBLAGE — un `amass` TIERS (marqueur DIFFÉRENT) NE DOIT PAS être tué (pas de pkill aveugle).
    def test_reap_is_targeted_spares_unrelated_amass(self):
        # daemon tiers : même variable d'env mais TOKEN différent -> hors de notre run.
        other_env = dict(os.environ, FORGE_RUN_MARKER="unrelated-user-amass-token")
        other = subprocess.Popen(["sleep", "300"], env=other_env, start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._spawned.append(other)
        try:
            holder = {}
            self._fire(holder)
            self.assertTrue(_wait_gone(holder["pid"]), "notre daemon aurait dû être reapé")
            # le tiers, lui, est INTACT (marqueur non concordant) — ciblage prouvé.
            self.assertTrue(_alive(other.pid),
                            "un amass TIERS a été tué : la terminaison n'est PAS ciblée (pkill aveugle ?)")
        finally:
            try:
                os.kill(other.pid, signal.SIGKILL)
            except OSError:
                pass

    # (e) BYTE-IDENTIQUE — un outil SANS reap_daemon appelle runner.tool SANS env (chemin historique).
    def test_non_daemon_tool_runs_with_inherited_env(self):
        seen = {}

        def fake_tool(binary, docker_image=None, args=None, prefer_docker=False, timeout=120, env=None):
            seen["env"] = env
            return (0, "sub.good.test\n", "")

        m = mods.get("recon.subfinder")     # reap_daemon=False (défaut)
        with _PatchRunner(available=lambda *a, **k: True, tool=fake_tool):
            m.fire(Action("recon.subfinder", "good.test", params={"in_scope": ["good.test"]}))
        self.assertIsNone(seen["env"], "un outil sans reap_daemon ne doit PAS passer d'env (byte-identique)")

    def test_amass_spec_flags_daemon_reap(self):
        self.assertTrue(mods.get("recon.amass").spec.reap_daemon)
        self.assertFalse(mods.get("recon.subfinder").spec.reap_daemon)


if __name__ == "__main__":
    unittest.main()

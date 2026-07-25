"""E4 — UN CANCEL NE LAISSE AUCUN OUTIL ORPHELIN.

Symptôme (T29, live) : `POST /api/runs/<id>/cancel` marquait la base 'cancelled' mais le moteur Python
détaché continuait de tourner ET les outils qu'il avait lancés (nuclei &c.) — chacun dans sa PROPRE
session (`start_new_session=True`, cf. `runner._spawn_and_wait`) — SURVIVAIENT au SIGTERM du groupe
moteur (session séparée = jamais atteinte). Le testeur devait hard-kill le groupe à la main.

Fix : `runner` tient un registre des groupes d'outils EN VOL ; le handler SIGTERM du moteur
(`forge/cli/engine.py::_on_sigterm`) appelle `runner.terminate_live_tool_groups(force=True)` pour couper
EXPLICITEMENT ces sessions séparées. Ces preuves sont HERMÉTIQUES (processus locaux `python3`/`true`,
zéro réseau).

ISOLATION DE SUITE (impératif) : on ne `killpg` JAMAIS un PID déjà récolté (danger de RÉUTILISATION de PID
-> on tuerait le groupe d'un process innocent d'un autre test). On ne signale qu'un pgid CONFIRMÉ vivant
(et à nous), on récolte notre enfant DIRECT, et le nettoyage `finally` ne tue que si le leader vit encore.

  1. REAP RÉEL : un « outil » vivant (leader + enfant dans son groupe) enregistré est TUÉ par
     `terminate_live_tool_groups` — leader ET enfant morts, groupe entièrement éteint (aucun survivant).
  2. CYCLE DE VIE DU REGISTRE : `tool()` enregistre le pgid pendant l'exécution puis le RETIRE au retour
     (même sur timeout) -> pas de pgid fantôme qui ferait killpg un pid RÉUTILISÉ plus tard.
  3. FAIL-SAFE / IDEMPOTENT : reap d'un registre vide ou d'un pgid inexistant = no-op silencieux (ESRCH avalé).
"""
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import runner  # noqa: E402

# pgid sentinelle qui ne correspond à AUCUN process réel (bien au-dessus de tout PID vivant du test) ->
# exerce le swallow ESRCH de `terminate_live_tool_groups` SANS jamais viser une victime innocente.
_NONEXISTENT_PGID = 2147483000


def _group_gone(pgid):
    """True si le GROUPE `pgid` n'a plus aucun membre (killpg(pgid,0) -> ProcessLookupError)."""
    try:
        os.killpg(pgid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:  # membre existant mais non signalable -> considéré vivant
        return False


def _pid_gone(pid):
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:
        return False


def _wait_until(pred, timeout=5.0, step=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


@unittest.skipUnless(hasattr(os, "killpg") and hasattr(signal, "SIGKILL"), "POSIX process groups requis")
class TestCancelReapsTools(unittest.TestCase):
    def setUp(self):
        runner._LIVE_TOOL_PGIDS.clear()  # isolation inter-tests.

    def tearDown(self):
        runner._LIVE_TOOL_PGIDS.clear()

    def test_terminate_live_tool_groups_kills_leader_and_child_no_survivor(self):
        # Un « outil » = un leader (nouvelle session) qui fork un enfant ; les deux dorment 120s. C'est le
        # cas nuclei/`docker run` : un petit-enfant tient le sous-arbre. Le reap doit TOUT emporter.
        _fd, _pf = tempfile.mkstemp(prefix="e4-tool-child-", suffix=".pid")
        os.close(_fd)
        pidfile = Path(_pf)
        pidfile.unlink(missing_ok=True)  # part d'un fichier ABSENT -> preuve que l'enfant l'écrit vraiment.
        script = (
            "import os,sys,time\n"
            "pid=os.fork()\n"
            "if pid==0:\n"
            "    open(sys.argv[1],'w').write(str(os.getpid()))\n"
            "    time.sleep(120)\n"
            "else:\n"
            "    time.sleep(120)\n"
        )
        proc = subprocess.Popen([sys.executable, "-c", script, str(pidfile)], start_new_session=True)
        pgid = proc.pid  # start_new_session -> le leader EST le pgid.
        try:
            # attend la publication du pid de l'enfant (groupe bien établi : leader + enfant vivants).
            def _child_published():
                try:
                    return pidfile.read_text().strip().isdigit()
                except OSError:
                    return False
            self.assertTrue(_wait_until(_child_published), "l'enfant de l'outil doit publier son PID")
            child = int(pidfile.read_text().strip())
            self.assertFalse(_group_gone(pgid), "le groupe outil doit être vivant avant le reap")
            self.assertFalse(_pid_gone(child), "l'enfant doit être vivant avant le reap")

            # SIMULE le handler SIGTERM du moteur : l'outil est enregistré -> reap. `killpg` vise un pgid
            # CONFIRMÉ VIVANT (proc pas encore récolté) -> aucun risque de PID réutilisé.
            runner._register_tool_pgid(pgid)
            runner.terminate_live_tool_groups(force=True)
            proc.wait(timeout=5)  # récolte le leader (plus de zombie qui masquerait _group_gone).

            # AUCUN SURVIVANT : leader ET enfant morts, groupe éteint (l'enfant est récolté par init).
            self.assertTrue(_wait_until(lambda: _pid_gone(child)),
                            "l'enfant de l'outil doit être tué aussi (aucun orphelin — comme le hard-kill manuel)")
            self.assertTrue(_pid_gone(pgid), "le leader de l'outil doit être tué")
            self.assertTrue(_wait_until(lambda: _group_gone(pgid)), "le groupe outil est entièrement éteint")
        finally:
            # nettoyage SÛR : on ne tue que si le leader vit ENCORE (pid non récolté -> pas de réutilisation).
            if proc.poll() is None:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
                try:
                    proc.wait(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            pidfile.unlink(missing_ok=True)

    def test_registry_lifecycle_registers_then_unregisters(self):
        # Un outil réel (bref) via `runner.tool` doit être RETIRÉ APRÈS -> jamais de pgid fantôme au
        # registre (sinon un killpg futur viserait un PID réutilisé).
        rc, _out, _err = runner.tool("true", args=[], timeout=10)
        self.assertEqual(len(runner._LIVE_TOOL_PGIDS), 0, "le registre est vide après le retour de l'outil")
        self.assertIn(rc, (0, 127))  # 0 si `true` présent, 127 sinon — le point clé (registre vide) tient.

    def test_registry_cleared_even_on_timeout(self):
        # Un outil qui timeoute (per-action) est tué par _spawn_and_wait ET retiré du registre (finally).
        rc, _out, _err = runner.tool(sys.executable, args=["-c", "import time; time.sleep(30)"], timeout=1)
        self.assertEqual(rc, 124, "un outil qui dépasse son timeout rend 124")
        self.assertEqual(len(runner._LIVE_TOOL_PGIDS), 0, "registre vidé même sur timeout (finally)")

    def test_reap_empty_or_dead_registry_is_noop(self):
        # FAIL-SAFE : reap sans rien enregistré ne lève pas.
        runner.terminate_live_tool_groups(force=True)
        self.assertEqual(len(runner._LIVE_TOOL_PGIDS), 0)
        # reap d'un pgid INEXISTANT (sentinelle, jamais un pid réel) : ProcessLookupError avalé, pas de crash,
        # et AUCUNE victime innocente possible.
        runner._register_tool_pgid(_NONEXISTENT_PGID)
        runner.terminate_live_tool_groups(force=True)  # ESRCH avalé.
        runner._unregister_tool_pgid(_NONEXISTENT_PGID)
        self.assertEqual(len(runner._LIVE_TOOL_PGIDS), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

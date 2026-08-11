# SPDX-License-Identifier: AGPL-3.0-or-later
"""Un conteneur d'outil peut-il SURVIVRE au run qui l'a lancé ? (D21)

MESURÉ le 2026-08-11, preuve horodatée. Deux conteneurs feroxbuster encore VIVANTS des heures après
la fin de leurs campagnes :

    zealous_easley    démarré 12:57:34   `feroxbuster --quiet -u http://127.0.0.1:3000 --rate-limit 5`
    agitated_mestorf  démarré 13:50:09   `…                                        --rate-limit 20`

… toujours en train de crawler à 16:11. Ils ont pollué TROIS mesures successives — une cible « au
repos » relevée à 1,68 Gio, puis une cible MORTE (`Exited(139)`) avant même qu'aucune campagne n'ait
été tirée — avant qu'on ne comprenne que la charge ne venait pas du run en cours.

LE PIÈGE : `docker run` est un CLIENT ; le conteneur vit dans le DÉMON. `_terminate_group` tue le
sous-arbre local — le client meurt, le conteneur survit, et `--rm` (qui ne se déclenche qu'à la
SORTIE du conteneur) n'arrive donc jamais. Le SIGTERM est proxifié par le client et peut suffire ;
le SIGKILL, par construction, ne l'est pas. **Un timeout d'action = un orphelin.**

CE N'EST PAS UNE FUITE DE RESSOURCE, C'EST UNE FAILLE DE SÛRETÉ : en engagement réel, c'est un
crawler qui continue de marteler la cible du client APRÈS la fin du run — sans borne, sans budget,
et sans trace, puisque le ledger dit « run terminé ».

Aucun test ici n'appelle docker : `subprocess.Popen`/`subprocess.run` sont substitués et l'on
observe les argv.
"""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from forge import runner


class _FakeProc:
    """Process factice. `hang=True` -> `communicate` lève `TimeoutExpired` (le chemin qui orpheline)."""

    def __init__(self, hang=False):
        self.pid = 4242
        self.returncode = 0
        self._hang = hang
        self._calls = 0

    def communicate(self, timeout=None):
        self._calls += 1
        if self._hang and self._calls == 1:
            raise subprocess.TimeoutExpired("docker", timeout or 1)
        return ("out", "err")


class _Harness:
    """Substitue Popen + run, et NOTE tous les argv docker vus."""

    def __init__(self, hang=False):
        self.popen_argv = []
        self.run_argv = []
        self.hang = hang

    def popen(self, cmd, **_kw):
        self.popen_argv.append(list(cmd))
        return _FakeProc(hang=self.hang)

    def run(self, cmd, **_kw):
        self.run_argv.append(list(cmd))
        return mock.Mock(returncode=0, stdout="", stderr="")

    def rm_targets(self):
        return [c[-1] for c in self.run_argv if c[:3] == ["docker", "rm", "-f"]]


def _patched(h):
    return mock.patch.multiple(runner.subprocess, Popen=h.popen, run=h.run)


class ArgvCarriesAName(unittest.TestCase):

    def test_le_dry_run_reste_byte_identique(self):
        """Ce qu'on MONTRE à un humain doit rester copiable tel quel : pas de `--name` dans le PoC."""
        argv = runner._docker_argv("img", ["-u", "http://x"])
        self.assertEqual(argv, ["docker", "run", "--rm", "--network", "host", "img", "-u", "http://x"])

    def test_la_voie_d_execution_nomme_le_conteneur(self):
        argv = runner._docker_argv("img", ["-u", "http://x"], name="forge-tool-1-0")
        self.assertEqual(argv[:7], ["docker", "run", "--rm", "--network", "host",
                                    "--name", "forge-tool-1-0"])

    def test_le_nom_ne_se_repete_pas(self):
        """Deux tirs concurrents ne doivent pas se disputer un nom : docker REFUSERAIT le second."""
        noms = {runner._container_name() for _ in range(50)}
        self.assertEqual(len(noms), 50)
        self.assertTrue(all(n.startswith(runner.CONTAINER_PREFIX) for n in noms))


class ContainerIsRemovedOnEveryPath(unittest.TestCase):

    def _fire(self, hang):
        h = _Harness(hang=hang)
        with _patched(h), \
             mock.patch.object(runner.shutil, "which", lambda b: "/usr/bin/docker" if b == "docker" else None), \
             mock.patch.object(runner, "_terminate_group", lambda *a, **k: None):
            rc, _out, _err = runner.tool("feroxbuster", "epi052/feroxbuster",
                                         ["-u", "http://127.0.0.1:3000"],
                                         prefer_docker=True, timeout=1)
        return h, rc

    def test_retire_apres_un_retour_normal(self):
        h, rc = self._fire(hang=False)
        self.assertEqual(rc, 0)
        self.assertEqual(len(h.rm_targets()), 1, f"aucun retrait tenté : {h.run_argv}")

    def test_retire_apres_un_TIMEOUT_le_chemin_qui_orphelinait(self):
        """LE CHEMIN DU DÉFAUT. Au timeout, le groupe local est tué — et c'est précisément là que le
        conteneur survivait, parce qu'aucun signal local n'atteint le démon docker."""
        h, rc = self._fire(hang=True)
        self.assertEqual(rc, 124)
        self.assertEqual(len(h.rm_targets()), 1, "un timeout laisse le conteneur debout")

    def test_le_nom_retire_est_CELUI_qui_a_ete_lance(self):
        """Retirer *un* conteneur ne sert à rien : il faut retirer CELUI-LÀ."""
        h, _rc = self._fire(hang=True)
        lance = h.popen_argv[0]
        nom = lance[lance.index("--name") + 1]
        self.assertEqual(h.rm_targets(), [nom])

    def test_la_voie_LOCALE_ne_touche_pas_a_docker(self):
        """Un binaire local n'a pas de conteneur : aucun `docker rm` ne doit être tenté."""
        h = _Harness()
        with _patched(h), \
             mock.patch.object(runner.shutil, "which", lambda b: f"/usr/bin/{b}"):
            runner.tool("feroxbuster", "epi052/feroxbuster", ["-u", "http://x"], timeout=1)
        self.assertEqual(h.rm_targets(), [])


class WholeRunCancelSweepsContainers(unittest.TestCase):

    def test_le_cancel_balaye_aussi_les_conteneurs(self):
        """`terminate_live_tool_groups` promet « TOUS les groupes d'outils encore en vol ». Tuer les
        groupes de process LOCAUX n'en couvre que la moitié."""
        h = _Harness()
        vus = []
        with _patched(h), mock.patch.object(runner, "live_containers",
                                            lambda: ["forge-tool-1-0", "forge-tool-1-1"]):
            runner.terminate_live_tool_groups(force=True)
            vus = h.rm_targets()
        self.assertEqual(vus, ["forge-tool-1-0", "forge-tool-1-1"])

    def test_le_balayage_rend_ce_qu_il_a_trouve(self):
        """Un filet muet ne se distingue pas d'un filet inutile : il doit DIRE ce qu'il a ramassé."""
        h = _Harness()
        with _patched(h), mock.patch.object(runner, "live_containers", lambda: ["forge-tool-9-3"]):
            self.assertEqual(runner.terminate_live_containers(), ["forge-tool-9-3"])

    def test_docker_absent_ne_leve_pas(self):
        """Pas de docker sur la machine -> best-effort silencieux, jamais d'exception."""
        with mock.patch.object(runner.subprocess, "run", side_effect=FileNotFoundError("docker")):
            self.assertEqual(runner.live_containers(), [])
            runner._docker_rm("forge-tool-1-0")            # ne doit pas lever


if __name__ == "__main__":
    unittest.main()

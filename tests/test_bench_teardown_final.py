# SPDX-License-Identifier: AGPL-3.0-or-later
"""Le démontage du banc est-il FINAL ? (D19)

Le banc lève QUATRE applications délibérément vulnérables. Sa seule garantie de sûreté est
qu'elles ne vivent que le temps du banc. Le rejeu du 2026-08-11 a pris cette garantie en défaut :
`forge-bench-dvwa` écoutait encore sur 127.0.0.1:8081 APRÈS un `teardown()` réputé complet
(`RestartCount=0`, `RestartPolicy=no` — donc recréé, pas redémarré).

Le code portait TROIS chemins de fuite, et aucun n'était couvert par un test :

  1. `--teardown` était OPT-IN et placé APRÈS la boucle. Délai dépassé, exception, Ctrl-C : les
     applications restaient levées.
  2. `apps = up` (ligne 55) écrasait la liste demandée par celle qui A RÉPONDU. Un conteneur créé
     mais resté muet — `wait_up` rend False après 120 s — n'était PLUS dans la liste de démontage.
     Il était donc levé, vulnérable, et structurellement hors de portée du démontage.
  3. Le refus de périmètre (`verify_loopback_only` -> `return 2`) sortait SANS démonter : le garde
     qui refuse d'armer parce qu'une application vulnérable écoute hors de la boucle locale la
     laissait précisément écouter.

Même famille que le reste de la série : la garde existait et ne gardait rien.

Ces tests n'appellent JAMAIS docker : `sh()` est remplacé par un double qui tient l'état des
conteneurs. Ce qui est vérifié, c'est le CHEMIN DE CONTRÔLE — qui est retiré, et quand.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from bench.detection import provision, run_bench


class FakeDocker:
    """Double de `sh()` tenant l'état des conteneurs — assez pour répondre `docker ps` et
    `docker rm`, et pour enregistrer ce que le banc a tenté."""

    def __init__(self, present=(), listening=()):
        self.present = set(present)
        self.listening = list(listening)
        self.removed = []          # noms passés à `docker rm -f`, dans l'ordre

    def __call__(self, *args, check=False):
        argv = list(args)
        out = ""
        if argv[:2] == ["docker", "ps"]:
            out = "\n".join(sorted(self.present))
        elif argv[:3] == ["docker", "rm", "-f"]:
            names = argv[3:]
            self.removed.append(list(names))
            for n in names:
                self.present.discard(n)
                self.listening = [ln for ln in self.listening if n not in ln]
        elif argv[0] == "ss":
            out = "\n".join(self.listening)
        elif argv[:2] == ["docker", "run"]:
            # `-d --name forge-bench-X ...` : le conteneur EXISTE dès sa création, avant même
            # de répondre. C'est tout l'objet du chemin de fuite n°2.
            self.present.add(argv[argv.index("--name") + 1])
        return mock.Mock(returncode=0, stdout=out, stderr="")


class TeardownVerifiesItsOwnEffect(unittest.TestCase):
    """`teardown()` doit CONSTATER l'absence, pas la supposer."""

    def test_rend_ok_quand_plus_rien_ne_subsiste(self):
        fake = FakeDocker(present={"forge-bench-dvwa", "forge-bench-juiceshop"})
        with mock.patch.object(provision, "sh", fake):
            ok, restes = provision.teardown()
        self.assertTrue(ok)
        self.assertEqual(restes, [])

    def test_signale_le_conteneur_qui_survit(self):
        """MUTATION — si `teardown()` rend la main sans relire docker, ce test tombe."""
        fake = FakeDocker(present={"forge-bench-dvwa"})

        def rm_sans_effet(*args, check=False):
            if args[:3] == ("docker", "rm", "-f"):
                return mock.Mock(returncode=1, stdout="", stderr="permission denied")
            return fake(*args, check=check)

        with mock.patch.object(provision, "sh", rm_sans_effet):
            ok, restes = provision.teardown()
        self.assertFalse(ok, "un démontage qui échoue doit se DIRE incomplet")
        self.assertIn("forge-bench-dvwa", restes)

    def test_signale_le_socket_qui_reste_ouvert(self):
        """Un conteneur peut disparaître de `docker ps` et laisser un socket : on regarde les DEUX."""
        fake = FakeDocker(present=set(), listening=["LISTEN 0 4096 127.0.0.1:8081 0.0.0.0:*"])
        with mock.patch.object(provision, "sh", fake):
            ok, restes = provision.teardown(ports=["8081"])
        self.assertFalse(ok)
        self.assertTrue(any("8081" in r for r in restes))

    def test_le_port_ne_se_reconnait_pas_dans_un_port_plus_long(self):
        """`:3000` ne doit pas s'apparier à `:30000` — sinon le banc crie au faux reste."""
        fake = FakeDocker(present=set(), listening=["LISTEN 0 4096 127.0.0.1:30000 0.0.0.0:*"])
        with mock.patch.object(provision, "sh", fake):
            ok, restes = provision.teardown(ports=["3000"])
        self.assertTrue(ok, f"faux positif d'ancrage : {restes}")

    def test_n_accuse_pas_le_banc_du_socket_d_un_autre(self):
        """LE GARDE NE DOIT PAS CRIER AU LOUP. Mesuré le 2026-08-11 : `teardown()` a rendu
        `ok=False` en pointant `127.0.0.1:3000`, tenu par un conteneur `fjs` ÉTRANGER au banc, alors
        que le banc n'avait levé que DVWA (port 8081). Confondre « le port est occupé » avec « le
        banc n'a pas démonté », c'est le même geste que tout ce que cette série répare : ne pas
        demander PAR QUI. Un garde qui accuse à tort finit ignoré — donc inutile le jour où il a
        raison."""
        fake = FakeDocker(present={"forge-bench-dvwa"},
                          listening=["LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*"])
        with mock.patch.object(provision, "sh", fake):
            ok, restes = provision.teardown()          # ports DÉRIVÉS : dvwa -> 8081, pas 3000
        self.assertTrue(ok, f"socket étranger imputé au banc : {restes}")

    def test_accuse_bien_le_banc_du_socket_qu_il_tient(self):
        """L'excès inverse — le port de l'application RÉELLEMENT levée, lui, est bien vérifié."""
        fake = FakeDocker(present={"forge-bench-dvwa"},
                          listening=["LISTEN 0 4096 127.0.0.1:8081 0.0.0.0:*"])
        fake_rm = lambda *a, **k: (mock.Mock(returncode=0, stdout="", stderr="")
                                   if a[:3] == ("docker", "rm", "-f") else fake(*a, **k))
        with mock.patch.object(provision, "sh", fake_rm):     # retrait sans effet sur le socket
            ok, restes = provision.teardown()
        self.assertFalse(ok)
        self.assertTrue(any("8081" in r for r in restes), restes)

    def test_retire_ce_qui_porte_le_prefixe_sans_le_connaitre(self):
        """FUITE n°2, à la racine : le démontage est DÉRIVÉ de docker, pas d'une liste tenue à la
        main. Un conteneur du banc dont le nom n'est plus dans `APPS` doit quand même partir."""
        fake = FakeDocker(present={"forge-bench-application-oubliee"})
        with mock.patch.object(provision, "sh", fake):
            ok, _ = provision.teardown()
        self.assertTrue(ok)
        self.assertIn(["forge-bench-application-oubliee"], fake.removed)


class TeardownEstAtteintParTousLesChemins(unittest.TestCase):
    """Le démontage appartient au `finally`, pas au chemin heureux."""

    def _args(self, work, **kw):
        base = dict(workdir=str(work), apps="dvwa", track="a", budget=10,
                    no_bring_up=True, keep_up=False, teardown=False)
        base.update(kw)
        return mock.Mock(**base)

    def test_une_exception_en_cours_de_route_demonte_quand_meme(self):
        """FUITE n°1 : `--teardown` après la boucle ne survivait à aucune interruption."""
        fake = FakeDocker(present={"forge-bench-dvwa"})
        work = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        with mock.patch.object(provision, "sh", fake), \
             mock.patch.object(run_bench, "_run", side_effect=RuntimeError("délai dépassé")):
            with self.assertRaises(RuntimeError):
                run_bench.main([f"--workdir={work}", "--apps=dvwa", "--no-bring-up"])
        self.assertNotIn("forge-bench-dvwa", fake.present,
                         "une campagne interrompue laisse une application vulnérable levée")

    def test_le_refus_de_perimetre_demonte_avant_de_sortir(self):
        """FUITE n°3 : le garde qui refuse d'armer parce qu'une application écoute hors boucle
        locale la laissait écouter. C'est le pire des trois — le refus AGGRAVAIT l'exposition."""
        fake = FakeDocker(present={"forge-bench-dvwa"},
                          listening=["LISTEN 0 4096 0.0.0.0:8081 0.0.0.0:*"])
        work = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        with mock.patch.object(provision, "sh", fake):
            rc = run_bench.main([f"--workdir={work}", "--apps=dvwa", "--no-bring-up"])
        self.assertEqual(rc, 2, "le refus de périmètre doit rester un refus")
        self.assertNotIn("forge-bench-dvwa", fake.present,
                         "refuser d'armer sans démonter laisse la cible vulnérable exposée")

    def test_keep_up_reste_possible_et_explicite(self):
        """MUTATION inverse — si le démontage devenait inconditionnel, ce test tombe. L'opérateur
        doit pouvoir garder le banc debout pour enquêter ; simplement, ce n'est plus le défaut."""
        fake = FakeDocker(present={"forge-bench-dvwa"},
                          listening=["LISTEN 0 4096 0.0.0.0:8081 0.0.0.0:*"])
        work = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        with mock.patch.object(provision, "sh", fake):
            run_bench.main([f"--workdir={work}", "--apps=dvwa", "--no-bring-up", "--keep-up"])
        self.assertIn("forge-bench-dvwa", fake.present)

    def test_un_conteneur_leve_mais_muet_est_quand_meme_demonte(self):
        """FUITE n°2 en situation : `bring_up` CRÉE le conteneur, puis `wait_up` échoue ; l'ancien
        code réduisait la liste de démontage aux applications qui avaient RÉPONDU. Le conteneur
        existait, vulnérable, et n'était plus dans la liste de personne."""
        fake = FakeDocker()
        work = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        with mock.patch.object(provision, "sh", fake), \
             mock.patch.object(provision, "wait_up", return_value=False):
            run_bench.main([f"--workdir={work}", "--apps=dvwa"])
        self.assertTrue(fake.removed, "aucun démontage tenté")
        self.assertNotIn("forge-bench-dvwa", fake.present)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""Les variables des modules avancés s'appellent `FORGE_ADVANCED_*` ; l'ancien nom fait refuser.

Le renommage `FORGE_ENTERPRISE_<X>` -> `FORGE_ADVANCED_<X>` est fait SANS alias : l'ancien nom n'active
plus rien. L'ignorer en silence éteindrait le module de conformité (signeur du ledger hors hôte) chez
qui met à jour sans lire ; sa seule PRÉSENCE fait donc refuser la construction du signeur, avant tout
le reste. Trois témoins : ancien nom posé -> refus au message exact ; nouveau nom -> module actif ;
aucun des deux -> comportement d'avant (signeur local). Le même contrat côté console est tenu par
`console/src/flags.rs` (test `retired_env_gate_contract`).
"""
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import signing  # noqa: E402
from forge.ledger import Ledger  # noqa: E402
from tests._tmp import temp_dir  # noqa: E402

_REFUS_COMPLIANCE = (
    "variable(s) d'environnement retirée(s) encore posée(s) : "
    "FORGE_ENTERPRISE_COMPLIANCE -> renommer en FORGE_ADVANCED_COMPLIANCE. "
    "Les noms FORGE_ENTERPRISE_* ne sont plus lus (renommés FORGE_ADVANCED_*, sans alias) ; "
    "démarrage refusé plutôt qu'un module avancé éteint en silence. Voir docs/UPGRADE.fr.md §7."
)


class RetiredNameIsRefused(unittest.TestCase):
    def test_ancien_nom_pose_refus_au_message_exact(self):
        with self.assertRaises(signing.RetiredEnvNameError) as ctx:
            signing.make_ledger_signer("unused-base", env={"FORGE_ENTERPRISE_COMPLIANCE": "1"})
        self.assertEqual(str(ctx.exception), _REFUS_COMPLIANCE)

    def test_valeur_vide_ou_fausse_refusee_aussi(self):
        for valeur in ("", "0", "off"):
            with self.subTest(valeur=valeur):
                with self.assertRaises(signing.RetiredEnvNameError):
                    signing.make_ledger_signer("unused-base", env={"FORGE_ENTERPRISE_COMPLIANCE": valeur})

    def test_refus_meme_avec_le_nouveau_nom_pose_a_cote(self):
        env = {"FORGE_ENTERPRISE_COMPLIANCE": "1", signing.ENTERPRISE_COMPLIANCE_FLAG: "1"}
        with self.assertRaises(signing.RetiredEnvNameError):
            signing.make_ledger_signer("unused-base", env=env)

    def test_chaque_nom_retire_est_nomme_avec_son_successeur_et_aucune_valeur(self):
        env = {f"FORGE_ENTERPRISE_{s}": "valeur-secrete" for s in signing.RENAMED_ENV_SUFFIXES}
        env["FORGE_ENTERPRISE_INCONNU"] = "valeur-secrete"
        message = signing.retired_env_names_message(env.keys())
        for s in signing.RENAMED_ENV_SUFFIXES:
            self.assertIn(f"FORGE_ENTERPRISE_{s} -> renommer en FORGE_ADVANCED_{s}", message)
        self.assertIn("FORGE_ENTERPRISE_INCONNU -> aucun successeur, la retirer", message)
        self.assertNotIn("valeur-secrete", message)

    def test_le_ledger_refuse_depuis_l_environnement_du_processus(self):
        d = temp_dir(self, "forge-retired-env-")
        with mock.patch.dict(os.environ, {"FORGE_ENTERPRISE_COMPLIANCE": "1"}):
            with self.assertRaises(signing.RetiredEnvNameError):
                Ledger(d / "l.jsonl")


class TheCliShowsTheRefusalNotATraceback(unittest.TestCase):
    """Au point d'entrée réel (`python -m forge.cli`), le refus sort en UN message et un code non nul :
    une trace de pile ferait passer une erreur de configuration pour un défaut du programme."""

    def test_le_cli_affiche_le_seul_message_et_sort_en_code_2(self):
        d = temp_dir(self, "forge-retired-env-cli-")
        env = {k: v for k, v in os.environ.items() if not k.startswith(signing.RETIRED_ENV_PREFIX)}
        env["FORGE_ENTERPRISE_COMPLIANCE"] = "1"
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        proc = subprocess.run(
            [sys.executable, "-m", "forge.cli", "ledger", "verify", "--ledger", str(d / "l.jsonl")],
            env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stderr, f"forge: {_REFUS_COMPLIANCE}\n")
        self.assertNotIn("Traceback", proc.stderr)
        self.assertEqual(proc.stdout, "")


class NewNameEngagesTheModule(unittest.TestCase):
    def test_le_nouveau_nom_est_le_drapeau(self):
        self.assertEqual(signing.ENTERPRISE_COMPLIANCE_FLAG, "FORGE_ADVANCED_COMPLIANCE")
        self.assertTrue(signing.enterprise_signer_enabled({"FORGE_ADVANCED_COMPLIANCE": "1"}))

    def test_le_nouveau_nom_engage_le_signeur_distant(self):
        env = {
            "FORGE_ADVANCED_COMPLIANCE": "1",
            signing.LEDGER_SIGNER_ENV: "kms",
            "FORGE_LEDGER_SIGNER_ENDPOINT": "https://kms.example.internal/sign",
            "FORGE_LEDGER_SIGNER_PUBKEY": "ab" * 32,
        }
        self.assertIsInstance(signing.make_ledger_signer("unused-base", env=env), signing.RemoteSigner)

    def test_l_ancien_nom_n_est_pas_un_alias(self):
        self.assertFalse(signing.enterprise_signer_enabled({"FORGE_ENTERPRISE_COMPLIANCE": "1"}))


class NeitherNameKeepsTheDefault(unittest.TestCase):
    def test_aucun_des_deux_signeur_local_comme_avant(self):
        d = temp_dir(self, "forge-retired-env-")
        signer = signing.make_ledger_signer(d / "l", env={})
        self.assertNotIsInstance(signer, signing.RemoteSigner)
        self.assertIsNone(signing.retired_env_names_message({"FORGE_LEDGER_SIGNER": "local"}.keys()))

    def test_aucun_des_deux_le_distant_reste_refuse(self):
        with self.assertRaises(signing.RemoteSignerError):
            signing.make_ledger_signer("unused-base", env={signing.LEDGER_SIGNER_ENV: "kms"})


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: AGPL-3.0-or-later
"""Les textes servis disent « module avancé » et « build par défaut », pas une édition payante.

forge est entièrement open source : il n'a ni édition « community » ni édition « enterprise ». Des
messages servis à l'opérateur (refus d'API, erreur de migration, refus du signeur, vue de la console,
journal de build, sortie d'une garde) parlaient encore ainsi. Chaque texte est tenu ici par un témoin.

Ce qui NE change PAS, à dessein : les identifiants (`FORGE_ENTERPRISE_*`, `enterprise.*`, le code
d'erreur `enterprise_disabled`, les noms de champs) — leur renommage touche la configuration des
installations et attend sa propre décision. Le texte du refus de l'API de tenancy est aussi tenu
par le test Rust `tenant_crud_gated_and_ledgered`, sur la réponse réellement servie.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest

RACINE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE))

from forge import signing  # noqa: E402


def _lire(chemin):
    return (RACINE / chemin).read_text(encoding="utf-8")


class ServedTextsNameTheAdvancedModule(unittest.TestCase):

    def test_le_refus_du_signeur_distant_nomme_le_module_avance(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(signing.RemoteSignerError) as ctx:
                signing.make_ledger_signer(pathlib.Path(d) / "led.jsonl", config={"mode": "exec"}, env={})
        message = str(ctx.exception)
        self.assertIn("le module avancé COMPLIANCE n'est pas activé", message)
        self.assertIn(signing.ENTERPRISE_COMPLIANCE_FLAG, message, "le nom de la variable reste cité")
        for mot in ("open-core", "l'entreprise"):
            self.assertNotIn(mot, message)

    def test_la_note_du_perimetre_par_defaut_de_la_garde_openssl(self):
        spec = importlib.util.spec_from_file_location(
            "check_openssl_freedom", RACINE / "scripts" / "check_openssl_freedom.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.PERIMETRES["default"]["note"], "le binaire livré par défaut")

    def test_textes_servis_lus_a_la_source(self):
        """Textes qu'aucun essai ne peut atteindre à moindre coût (vue HTML, journal de build, erreur
        d'un chemin sous `store-postgres`) : lus là où ils sont écrits, présents et sans l'ancien mot."""
        cas = [
            ("console/web/index.html",
             "En build par défaut (module avancé éteint, flag OFF) : cette vue n'existe pas",
             "En build <b>community</b>"),
            ("Dockerfile", "pg_dump non installé (image par défaut inchangée)", "image community"),
            ("console/src/cli/migrate_store.rs",
             "aucun schéma connu — build par défaut ou module avancé — ne les crée", "base ou enterprise"),
            ("console/src/tenancy/admin_api.rs",
             "module avancé multi-tenancy non activé", "multi-tenancy enterprise non activée"),
        ]
        for chemin, present, absent in cas:
            with self.subTest(fichier=chemin):
                texte = _lire(chemin)
                self.assertIn(present, texte)
                self.assertNotIn(absent, texte)


class TheConsoleHelpCitesTheFrenchDocuments(unittest.TestCase):
    """La console est en français : l'aide (`help.js`, champ `doc:`) et les renvois visibles
    d'`index.html` (`<code>docs/…</code>`) citent la version française de chaque document, et
    chaque document cité existe."""

    def _cites(self, chemin, motif):
        import re
        return re.findall(motif, _lire(chemin))

    def test_chaque_document_cite_est_la_version_francaise_et_existe(self):
        cites = (self._cites("console/web/js/core/help.js", r"doc: '(docs/[^']+)'")
                 + self._cites("console/web/index.html", r"<code>(docs/[^<]+\.md)</code>"))
        self.assertGreaterEqual(len(cites), 21, f"renvois trouvés : {len(cites)}")
        for doc in cites:
            with self.subTest(doc=doc):
                self.assertTrue(doc.endswith(".fr.md"), f"{doc} : version anglaise citée par la console")
                self.assertTrue((RACINE / doc).is_file(), f"{doc} : document absent")


if __name__ == "__main__":
    unittest.main()

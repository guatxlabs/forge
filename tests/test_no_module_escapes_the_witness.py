# SPDX-License-Identifier: AGPL-3.0-or-later
"""Quel module peut encore CONCLURE sur un mur de défi ? (dette « 2 553 findings hors Oracle »)

La roadmap portait, depuis la campagne du 2026-08-09, un reste chiffré : « 2 553 findings hors
`Oracle` (curl, nuclei, zap-baseline, naabu, recon_surface, pentest, evasion) ne passent pas par
`_http` : l'abstention ne les couvre donc PAS, et ils concluent toujours sur des réponses de mur ».

**Ce chiffre est PÉRIMÉ.** Le témoin de cécité a atteint depuis `toolspec`, `recon`, `recon_surface`,
`web`, `clientflow` et `evasion` — la dette a été payée par morceaux et la roadmap ne l'a jamais
rattrapée. Ce fichier remplace un chiffre mort par une LISTE DÉRIVÉE et maintenue : plus jamais de
« reste » qu'on récite sans le mesurer.

CE QUI RESTE HORS TÉMOIN — et pourquoi chaque cas est LÉGITIME :
  · `burp.scan`, `msf.module` : parlent au service DE L'OPÉRATEUR (API REST de Burp, msfrpcd), pas à
    la cible. Un défi Cloudflare n'a aucun sens sur un plan de contrôle qu'on héberge soi-même ;
  · `mobile.apk`, `network.ftp/smb/ssh` : surfaces NON-HTTP. Un interstitiel web ne s'y produit pas ;
  · `demo.fingerprint` : module de démonstration, aucun réseau réel.

Un module qui touche une CIBLE en HTTP et n'alimente pas le témoin doit faire ÉCHOUER ce test : il
conclurait « j'ai vérifié, rien trouvé » sur une page de challenge, ce qui est le mensonge exact que
toute cette série a passé son temps à supprimer.
"""
from __future__ import annotations

import inspect
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from forge import modules as mods                                              # noqa: E402

#: Exceptions ADMISES, avec leur raison. Toute autre entrée doit faire échouer le test.
HORS_TEMOIN_ADMIS = {
    "burp.scan": "plan de contrôle de l'opérateur (API REST de Burp), pas la cible",
    "msf.module": "plan de contrôle de l'opérateur (msfrpcd), pas la cible",
    "demo.fingerprint": "module de démonstration, aucun réseau réel",
    "mobile.apk": "analyse d'archive locale — surface non-HTTP",
    "network.ftp": "surface non-HTTP",
    "network.smb": "surface non-HTTP",
    "network.ssh": "surface non-HTTP",
}


def _fichiers_qui_alimentent_le_temoin():
    """DÉRIVÉ du source, jamais tenu à la main : un fichier qui parle au témoin le NOMME."""
    out = set()
    for f in pathlib.Path("forge/modules").glob("*.py"):
        s = f.read_text(encoding="utf-8")
        if "_blind" in s or "blindness" in s or "looks_like_challenge" in s:
            out.add(f.name)
    return out


def _hors_temoin():
    """Kinds dont NI la classe NI aucune de ses bases ne touche le témoin, ET qui n'appellent pas
    `Oracle._http` (le câblage partagé qui l'alimente pour tout le monde)."""
    couverts = _fichiers_qui_alimentent_le_temoin()
    out = {}
    for kind in sorted(mods.kinds()):
        cls = type(mods.get(kind))
        bases = set()
        src = ""
        for b in cls.__mro__:
            m = inspect.getmodule(b)
            if m and getattr(m, "__file__", None):
                bases.add(pathlib.Path(m.__file__).name)
        m = inspect.getmodule(cls)
        if m:
            try:
                src = inspect.getsource(m)
            except OSError:
                src = ""
        if (bases & couverts) or "Oracle._http" in src:
            continue
        out[kind] = pathlib.Path(getattr(m, "__file__", "?")).name if m else "?"
    return out


class NoHttpModuleConcludesOnAWall(unittest.TestCase):

    def test_la_liste_des_exceptions_est_EXACTEMENT_celle_admise(self):
        hors = _hors_temoin()
        self.assertEqual(sorted(hors), sorted(HORS_TEMOIN_ADMIS),
                         "un module a quitté (ou rejoint) la couverture du témoin sans que la "
                         "raison soit écrite — c'est ainsi qu'un « reste » devient invisible")

    def test_chaque_exception_porte_sa_RAISON(self):
        for kind, raison in HORS_TEMOIN_ADMIS.items():
            with self.subTest(kind=kind):
                self.assertTrue(raison.strip(), f"{kind} est exclu sans justification écrite")

    def test_le_temoin_couvre_la_TRES_GRANDE_MAJORITE(self):
        total, hors = len(list(mods.kinds())), len(_hors_temoin())
        self.assertLess(hors / total, 0.15,
                        f"{hors}/{total} kinds hors témoin — la dette a rouvert")

    def test_aucune_exception_n_est_un_oracle_a_preuve(self):
        """Un oracle à PREUVE hors témoin serait le pire cas : il promeut sur une page de mur."""
        from forge.modules.oracle import Oracle
        for kind in _hors_temoin():
            with self.subTest(kind=kind):
                self.assertNotIsInstance(mods.get(kind), Oracle)


if __name__ == "__main__":
    unittest.main()

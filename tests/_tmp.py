# SPDX-License-Identifier: AGPL-3.0-or-later
"""Répertoire temporaire de test, supprimé QUOI QU'IL ARRIVE (P7.1-a).

Pourquoi ce helper existe : la suite Python laissait **82 répertoires / 568 Kio** derrière elle
(mesuré le 2026-08-05, `TMPDIR` dédié et vide, contrôle positif du compteur). Cause : 22 appels à
`tempfile.mkdtemp()` en `setUp()` ou en corps de test, sans nettoyage. Sur une machine où `/tmp` est
en zram — le cas ici — une suite qui fuit à chaque exécution consomme de la RAM, pas du disque.

`addCleanup()` plutôt qu'un `tearDown()` ou un `try/finally` : unittest l'exécute même si `setUp()`
lève à mi-parcours, même si le test échoue, et dans l'ordre inverse d'enregistrement. Un `tearDown()`
n'est PAS appelé quand `setUp()` échoue — c'est précisément le cas où un fixture reste orphelin.

`ignore_errors=True` : le nettoyage ne doit jamais transformer un test rouge en erreur d'arrachage,
ni masquer l'échec réel derrière une `OSError` sur un fichier déjà supprimé par le test lui-même.

Usage :
    from _tmp import temp_dir

    class T(unittest.TestCase):
        def setUp(self):
            self.dir = temp_dir(self, "forge-monsujet-")
"""
import shutil
import tempfile
from pathlib import Path


def temp_dir(case, prefix):
    """Crée un répertoire temporaire et programme sa suppression sur `case`.

    `case` est le `unittest.TestCase` courant (`self`) ; `prefix` nomme le répertoire pour qu'un
    résidu éventuel reste attribuable à son test d'origine. Renvoie un `Path`.
    """
    d = Path(tempfile.mkdtemp(prefix=prefix))
    case.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return d

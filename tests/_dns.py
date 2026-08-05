# SPDX-License-Identifier: AGPL-3.0-or-later
"""DÉTERMINISME DNS — neutralise le SEUL point d'I/O réseau de la gate ROE.

La gate résout le hostname AU POINT DE TIR (`forge/roe.py`, `resolve_target_ips`) avec une deadline
dure de `_RESOLVE_TIMEOUT` (5 s). Les hôtes de test sont en `.test`/`.example`, TLD **réservés**
(RFC 6761) qui ne résolvent JAMAIS : le chemin nominal est donc NXDOMAIN -> `[]` -> hôte inconnu,
non-privé -> FIRE avec un pin vide.

Sauf que le lookup part quand même sur le fil. Avec les défauts glibc (`timeout:5 attempts:2`) et
sans cache local, **un seul datagramme UDP perdu coûte ≥ 5 s** — exactement la deadline. On bascule
alors en `_ResolveTimeout` -> **VETO fail-closed**, et le résultat est **mémoïsé pour tout le run** :
un unique blip réseau fait VETO-er toute une vague, la découverte n'a jamais lieu, et un test qui
attendait une action chaînée voit une liste vide. Flake mesuré ~1/5-8, corrélé aux runs lents.

Le VETO fail-closed est **correct et délibéré** côté produit — c'est le harnais qui n'était pas
hermétique. On force donc un NXDOMAIN IMMÉDIAT : le résultat GARANTI d'un `.test`, mais instantané.
Sémantique inchangée, chemin ROE pleinement exercé (résolution -> branche hôte-inconnu -> verdict),
zéro paquet émis.

Un test qui vérifie une résolution SPÉCIFIQUE (IP privée, publique, timeout, out_scope-par-IP)
re-patche `getaddrinfo` LOCALEMENT : son `with mock.patch.object` prime puis restaure ce défaut en
sortant. Ces preuves-là restent intactes.

Usage — les deux noms sont les hooks que unittest appelle, donc l'alias suffit :

    from tests._dns import setUpModule, tearDownModule        # noqa: F401,E402

⚠️ PAS un `conftest.py` : la CI et le Makefile lancent `python3 -m unittest discover`
(`.github/workflows/ci.yml`, `Makefile`), où un conftest serait purement inerte.
"""
import unittest.mock as _mock

import forge.roe as _roe_mod

_patch = None
_depth = 0


def setUpModule():
    """Installe le NXDOMAIN immédiat. Ré-entrant : unittest exécute les modules en séquence, mais un
    compteur évite qu'un `tearDownModule` prématuré ne rende le réseau à un module encore actif."""
    global _patch, _depth
    _depth += 1
    if _patch is None:
        _patch = _mock.patch.object(
            _roe_mod.socket, "getaddrinfo",
            side_effect=_roe_mod.socket.gaierror("mocked NXDOMAIN (.test/.example, RFC 6761)"))
        _patch.start()


def tearDownModule():
    global _patch, _depth
    _depth = max(0, _depth - 1)
    if _depth == 0 and _patch is not None:
        _patch.stop()
        _patch = None

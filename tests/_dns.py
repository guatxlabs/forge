# SPDX-License-Identifier: AGPL-3.0-or-later
"""DÉTERMINISME DNS — rend le harnais HERMÉTIQUE : aucune résolution de nom ne part sur le fil.

Le point sensible est la gate ROE : elle résout le hostname AU POINT DE TIR (`forge/roe.py:78`,
`_resolve_ips`) avec une deadline dure de `_RESOLVE_TIMEOUT` (5 s). Les hôtes de test sont en
`.test`/`.example`, TLD **réservés** (RFC 6761) qui ne résolvent JAMAIS : le chemin nominal est donc
NXDOMAIN -> `[]` -> hôte inconnu, non-privé -> FIRE avec un pin vide.

Sauf que le lookup part quand même sur le fil. Avec les défauts glibc (`timeout:5 attempts:2`) et
sans cache local, **un seul datagramme UDP perdu coûte ≥ 5 s** — exactement la deadline. On bascule
alors en `_ResolveTimeout` -> **VETO fail-closed**, et le résultat est **mémoïsé pour tout le run** :
un unique blip réseau fait VETO-er toute une vague, la découverte n'a jamais lieu, et un test qui
attendait une action chaînée voit une liste vide. Flake mesuré ~1/5-8, corrélé aux runs lents.

Le VETO fail-closed est **correct et délibéré** côté produit — c'est le harnais qui n'était pas
hermétique. On force donc un NXDOMAIN IMMÉDIAT : le résultat GARANTI d'un `.test`, mais instantané.
Sémantique inchangée, chemin ROE pleinement exercé (`_resolve_ips` -> thread + deadline ->
`socket.getaddrinfo` -> `gaierror` -> `[]` -> branche hôte-inconnu -> verdict), zéro paquet émis.

POINT DE PATCH — `socket.getaddrinfo` GLOBAL, avec passe-droit LOOPBACK
-----------------------------------------------------------------------
Le patch est volontairement GLOBAL (le module `socket`, donc tout le process) et NON limité au nom
`socket` de `forge.roe`. Une variante « chirurgicale » (façade substituée à `forge.roe.socket`) a été
implémentée et MESURÉE : elle laisse repartir sur le fil tout ce qui n'est pas la gate — les modules
qui tirent vraiment (`urllib.request.urlopen` vers `https://app.test/...`, `recon_surface.py:444`
`socket.getaddrinfo`). Mesure sur la suite complète : **88 résolutions réelles de `app.test`
ré-apparaissaient dans le seul `test_chaining.py`**, pourtant déjà gardé. Trop étroit : la gate n'est
pas le seul consommateur de DNS d'un test qui fait tirer un module.

Mais patcher `getaddrinfo` globalement SANS nuance casse 27 tests (mesuré : passe-droit neutralisé
-> `27 failed, 1491 passed`) : plusieurs fichiers ouvrent de VRAIS serveurs HTTP stdlib
(`http.server` + `socket.create_connection`, cf. `test_connectors.py`, `test_p2b.py`) et perdent la
résolution de leur propre loopback. D'où le passe-droit : une adresse **littérale** ou `localhost`
est déléguée au vrai resolver. Ces cibles-là ne coûtent AUCUN paquet
(parsing numérique local / `/etc/hosts` via `nsswitch: files`), donc le passe-droit ne rouvre aucun
chemin flakeux — il rend juste au harnais son propre loopback. Tout NOM non-loopback -> NXDOMAIN
immédiat.

Le passe-droit vaut aussi correction : `forge/roe.py:69-71` court-circuite déjà les IP littérales
avant `getaddrinfo`, mais si une littérale arrivait ici, la refuser transformerait « IP privée »
(VETO) en « hôte inconnu » (FIRE) — un verdict INVERSÉ. La déléguer préserve la sémantique.

Un test qui vérifie une résolution SPÉCIFIQUE (IP privée, publique, timeout, out_scope-par-IP)
re-patche `getaddrinfo` LOCALEMENT : son `with mock.patch.object` prime puis restaure ce défaut en
sortant. Ces preuves-là restent intactes (`test_roe.py`, `test_pin_rebind.py`).

COUVERTURE — mesurée en comptant les appels qui atteignent le VRAI `getaddrinfo` sur une passe de
suite complète : **27 résolutions de noms avant, 5 après**. Les 5 restantes sont dans des fichiers
NON gardés — `test_pin_rebind.py` (2 × `pinned.invalid`, un test qui VEUT une résolution réelle
contre son serveur épinglé), `test_toolspec_catalog.py` et `test_all_tools_schema_args.py`
(1 × `good.test` chacun), `test_p2c.py` (1 × `app.test`). Les y étendre = ajouter la même ligne
d'import (sauf `test_pin_rebind.py`, à examiner : sa résolution est le sujet du test).

Usage — les deux noms sont les hooks que unittest appelle, donc l'alias suffit :

    from tests._dns import setUpModule, tearDownModule        # noqa: F401,E402

⚠️ PAS un `conftest.py` : la CI et le Makefile lancent `python3 -m unittest discover`
(`.github/workflows/ci.yml`, `Makefile`), où un conftest serait purement inerte. (pytest, lui,
honore `setUpModule`/`tearDownModule` : les deux lanceurs sont couverts par le même import.)
"""
import ipaddress as _ipaddress
import socket as _socket
import unittest.mock as _mock

import forge.roe as _roe_mod

# Capturé À L'IMPORT, avant toute substitution : c'est LE vrai resolver vers lequel le passe-droit
# loopback délègue. `forge.roe` lie le module `socket` GLOBAL (`forge/roe.py:28`) -> patcher ici
# couvre la gate ROE **et** tout module qui tire (urllib, http.client, recon_surface).
_REAL_GETADDRINFO = _socket.getaddrinfo
assert _roe_mod.socket is _socket, "forge.roe doit lier le module socket global (forge/roe.py:28)"

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


def _is_local(host) -> bool:
    """True si `host` se résout SANS toucher le réseau : `None`/`""` (bind toutes interfaces),
    IP littérale (parsing numérique local), ou nom de loopback (`/etc/hosts`, `nsswitch: files`)."""
    if host is None:
        return True
    h = str(host).strip()
    if not h or h.lower() in _LOOPBACK_NAMES:
        return True
    try:
        _ipaddress.ip_address(h.strip("[]"))          # littérale v4/v6 (forme URL `[::1]` incluse)
    except ValueError:
        return False
    return True


def _nxdomain_unless_local(host, *args, **kwargs):
    """Remplaçant de `socket.getaddrinfo` : loopback/littérale -> vrai resolver (zéro paquet) ;
    tout autre NOM -> `gaierror` immédiate, soit exactement ce que rendrait un resolver joignable
    face à un `.test`/`.example` (RFC 6761), mais sans la fenêtre de 5 s qui fait flaker la gate."""
    if _is_local(host):
        return _REAL_GETADDRINFO(host, *args, **kwargs)
    raise _socket.gaierror(_socket.EAI_NONAME,
                           "mocked NXDOMAIN (.test/.example, RFC 6761) — tests/_dns.py")


_patch = None
_depth = 0


def setUpModule():
    """Installe le NXDOMAIN immédiat. Ré-entrant : unittest exécute les modules en séquence, mais un
    compteur évite qu'un `tearDownModule` prématuré ne rende le réseau à un module encore actif."""
    global _patch, _depth
    _depth += 1
    if _patch is None:
        # `new=` (fonction nue) plutôt qu'un Mock à `side_effect` : pas d'enregistrement d'appels
        # (la suite en fait des centaines, dont depuis des threads), et un traceback lisible.
        _patch = _mock.patch.object(_socket, "getaddrinfo", _nxdomain_unless_local)
        _patch.start()


def tearDownModule():
    global _patch, _depth
    _depth = max(0, _depth - 1)
    if _depth == 0 and _patch is not None:
        _patch.stop()
        _patch = None

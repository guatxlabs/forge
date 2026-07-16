# SPDX-License-Identifier: AGPL-3.0-only
"""Épinglage d'IP au fire-time (anti-rebinding END-TO-END) — LIÉ autour d'un `fire()` gouverné par
l'engine et HONORÉ par les chokepoints de CONNEXION (`Oracle._http`, `httpflow._timed`).

CONTEXTE — la boucle est bouclée avec le ROE. `roe.py` résout la cible UNE SEULE FOIS au POINT DE TIR,
rend le verdict CONTRE l'IP résolue (privé / out_scope), et ÉPINGLE cette/ces IP sur
`Decision.pinned_ips`. Le moteur expose la liste au module (`action.params["_pinned_ips"]`) ET lie CE
contexte (`using(target, ips)`). Les chokepoints consultent `ip_for(url)` : si l'hôte de l'URL de
connexion CORRESPOND à l'hôte épinglé, ils SE CONNECTENT à l'IP épinglée AU LIEU de re-résoudre le DNS.
Cela ferme la fenêtre de DNS-rebinding sub-ms entre la résolution du ROE (decide/fire) et le connect
réel du module (que la couche connexion urllib/socket re-résolvait sinon).

TLS PRÉSERVÉ — connecter par-IP N'AFFAIBLIT JAMAIS la vérification : le `Host:` header reste l'HÔTE
D'ORIGINE et, en HTTPS, le SNI + la validation du certificat restent l'HÔTE D'ORIGINE (jamais validés
contre l'IP). Voir `Oracle._pinned_open` / `httpflow._timed`.

INVARIANTS :
  - contexte ABSENT / `ips` vide      => `ip_for()` renvoie None => résolution DNS NORMALE
    (BYTE-IDENTIQUE au comportement historique). L'épinglage est ADDITIF.
  - hôte NON épinglé (ex : cible d'une REDIRECTION cross-origin, hôte différent) => None => résolution
    normale. HONNÊTETÉ : une redirection vers un AUTRE hôte re-résout (le pin ne couvre que l'hôte de
    la cible d'origine). Un saut vers le MÊME hôte reste épinglé.
  - jamais d'exception (fail-safe) : une entrée malformée => aucun pin (ne casse pas le fire).
Zéro dépendance (stdlib). Même idiome que `throttle`/`session` (contexte thread-local restauré en sortie)."""
import threading

from .roe import Scope                      # Scope._host : normalisation d'hôte canonique (source unique)

_state = threading.local()                  # contexte courant (par thread) : map {host: ip} ou None


def pick(ips):
    """Première IP littérale NON VIDE de `ips` (list/tuple/str), sinon None. Ne lève jamais.
    Le ROE a déjà VÉTOÉ le tir si l'UNE des IP résolues était privée/out_scope -> toute IP épinglée est
    sûre ; on retient la 1re (déterministe, suffisant : elles pointent le même hôte gouverné)."""
    if not ips:
        return None
    if isinstance(ips, str):
        ips = [ips]
    for cand in ips:
        try:
            s = str(cand).strip()
        except Exception:                   # noqa: BLE001
            continue
        if s:
            return s
    return None


def current():
    """Map {host: ip} liée au thread, ou None (hors contexte -> aucun pin). Ne lève jamais."""
    return getattr(_state, "map", None)


def ip_for(url):
    """IP épinglée pour l'hôte de `url` si un pin est lié pour CET hôte, sinon None (résolution normale).
    L'hôte est normalisé via `Scope._host` (même canon que le ROE) -> matching cohérent. Ne lève jamais."""
    m = current()
    if not m:
        return None
    try:
        return m.get(Scope._host(url))
    except Exception:                       # noqa: BLE001 (URL illisible -> pas de pin, jamais de crash)
        return None


class using:
    """Context manager : lie l'IP épinglée `ip` (1re non vide de `ips`) à l'hôte de `target` le temps
    d'un `fire()`. `ips` vide/None -> lie None (no-op, résolution normale). Restaure le contexte
    précédent en sortie (réentrance sûre). Ne lève jamais à la construction."""

    def __init__(self, target, ips):
        ip = pick(ips)
        host = ""
        try:
            host = Scope._host(target)
        except Exception:                   # noqa: BLE001
            host = ""
        self.map = {host: ip} if (host and ip) else None

    def __enter__(self):
        self.prev = getattr(_state, "map", None)
        _state.map = self.map
        return self.map

    def __exit__(self, *a):
        _state.map = self.prev
        return False

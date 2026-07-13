# SPDX-License-Identifier: AGPL-3.0-only
"""Throttle partagé (min-interval / token-bucket simple) + compteur de blocages 429/WAF — LIÉ autour
d'un `fire()` gouverné par l'engine et HONORÉ par `Oracle._http` (le chokepoint HTTP des oracles).

INVARIANTS :
  - rate <= 0 / None  => AUCUN throttle (byte-identique au défaut) ; `using(rate)` lie un contexte VIDE.
  - le contexte n'est JAMAIS lié en test unitaire (les oracles patchent `_fetch`, pas `_http`) : seul
    l'engine le lie autour d'un vrai `fire()`. `current()` renvoie None hors contexte -> no-op total.
  - back-off 429 : `Oracle._http` incrémente `blocked` quand une réponse 429/503+challenge PERSISTE après
    back-off borné -> l'engine lit ce compteur APRÈS `fire()` pour surfacer un marqueur « rate-limited »
    au lieu d'empties silencieux.

Seams horaires (`_sleep`/`_now`) au niveau module -> patchables par les tests (spy d'intervalle)."""
import threading
import time

_sleep = time.sleep          # seam patchable (tests) : la fonction de sommeil
_now = time.monotonic        # seam patchable (tests) : l'horloge monotone

_state = threading.local()   # contexte courant (par thread) : un Bucket ou None


class Bucket:
    """Fenêtre de débit min-interval. `wait()` dort le temps nécessaire pour ne pas dépasser `rate`
    req/s (min-interval = 1/rate). Thread-safe (lock). rate <= 0 -> min_interval 0 -> jamais de sommeil.
    `blocked` compte les réponses 429/WAF persistantes (renseigné par le back-off de `Oracle._http`)."""

    def __init__(self, rate):
        try:
            r = float(rate)
        except (TypeError, ValueError):
            r = 0.0
        self.rate = r
        self.min_interval = (1.0 / r) if r > 0 else 0.0
        self._next_ok = 0.0
        self._lock = threading.Lock()
        self.blocked = 0

    def wait(self):
        """Dort si nécessaire pour respecter le min-interval. Renvoie le temps DORMI (s). No-op si
        min_interval <= 0. RÉSERVE le prochain créneau SOUS lock puis DORT HORS lock (jamais de sommeil
        sous verrou : pas de sérialisation-deadlock ; borne le débit même en rafale). Ne lève jamais."""
        if self.min_interval <= 0:
            return 0.0
        with self._lock:
            t = _now()
            if self._next_ok <= t:                # créneau libre : réserve le suivant, aucun sommeil
                self._next_ok = t + self.min_interval
                return 0.0
            slept = self._next_ok - t             # créneau occupé : réserve APRÈS le mien, dors dehors
            self._next_ok = self._next_ok + self.min_interval
        _sleep(slept)                             # DORT HORS DU LOCK (défense anti-deadlock)
        return slept

    def mark_blocked(self):
        """Signale un blocage 429/WAF PERSISTANT (après back-off borné). Le lock protège le compteur."""
        with self._lock:
            self.blocked += 1


def current():
    """Bucket courant lié au thread, ou None (hors contexte -> aucun throttle). Ne lève jamais."""
    return getattr(_state, "bucket", None)


class using:
    """Context manager : lie un Bucket pour `rate` (req/s) le temps d'un `fire()`. rate <= 0/None -> lie
    None (no-op). Restaure le contexte précédent en sortie (réentrance sûre)."""

    def __init__(self, rate):
        self.bucket = Bucket(rate) if _positive(rate) else None

    def __enter__(self):
        self.prev = getattr(_state, "bucket", None)
        _state.bucket = self.bucket
        return self.bucket

    def __exit__(self, *a):
        _state.bucket = self.prev
        return False


def _positive(rate):
    try:
        return float(rate) > 0
    except (TypeError, ValueError):
        return False

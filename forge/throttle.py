# SPDX-License-Identifier: AGPL-3.0-or-later
"""Throttle — DEUX étages de débit, et il a fallu une cible morte pour comprendre qu'un seul ne suffit pas.

  · ÉTAGE ACTION (`Bucket`, historique) — un seau NEUF par `fire()`, lié en THREAD-LOCAL par l'engine.
    Il lisse la RAFALE D'UNE ACTION : un oracle qui tire 30 sondes ne les envoie pas en 30 ms.
  · ÉTAGE RUN (`RunCap`, ajouté) — UN SEUL seau PARTAGÉ par tout le run, TOUS THREADS CONFONDUS. Il
    borne le débit du RUN, ce que l'étage action ne peut structurellement pas faire.

POURQUOI L'ÉTAGE RUN EXISTE — la mesure, pas l'intuition. `throttle` bornait le débit d'une ACTION,
jamais d'un RUN, et c'était consigné sans être corrigé. À horloge virtuelle, `rate=5` :

    30 requêtes DANS UNE action      -> 5,2 req/s   ✅ (l'étage action fait son travail)
    30 requêtes sur 30 ACTIONS       -> non borné   ❌ (un seau NEUF par fire : le 1er tir de chaque
                                                       action trouve son créneau LIBRE, ne dort jamais)
    … et le seau étant THREAD-LOCAL, le plafond effectif est encore MULTIPLIÉ par le parallélisme.

Le coût de ce trou est mesuré, avec horodatage : une cible (Juice Shop) laissée 34 min SANS être
ciblée reste stable (102 -> 21 Mio) ; campagne lancée à 13:12:42, **3,78 Gio à 13:13:24**, morte
(`Exited(139)`) à 13:14:47. Mettre une cible à genoux viole « avoid service degradation », clause de
la quasi-totalité des programmes de bug bounty — c'est un motif d'exclusion, pas un détail de confort.

CE QUE L'ÉTAGE RUN NE FAIT PAS, ET C'EST DÉLIBÉRÉ :
  · il ne REMPLACE PAS l'étage action. Les deux sont CHAÎNÉS (`_Chain`) : une requête attend le
    créneau du RUN **puis** celui de son ACTION. Un run large avec des actions serrées garde ses
    actions serrées ; l'inverse aussi. Supprimer l'un des deux est une MUTATION que les tests tuent ;
  · il n'est PAS actif par défaut. `rate: 5` imposé aux OUTILS externes ferait passer naabu de 1,1 min
    à 3,6 h (mesuré, cf. `docs/CONFIGURATION.md` §2bis) : un plafond de run armé d'office effondrerait
    la couverture. Il s'arme donc par `scope.run_rate`, ou en dérivé de `rate` quand l'opérateur a
    DÉJÀ demandé le bridage global (`rate_explicit`) — le cadre qui existait déjà ;
  · il ne borne QUE ce qui passe par le chokepoint HTTP des oracles (`Oracle._http`) : les 36 modules
    natifs. Un sous-process (nuclei, feroxbuster, naabu) n'y passe pas — son débit se bride par son
    PROPRE drapeau, dérivé de `rate` sous `rate_explicit`. Portée honnête, écrite ici pour qu'on ne
    lise pas ce module comme un plafond machine.

INVARIANTS :
  - AUCUN plafond de run ET rate <= 0/None  => `using()` lie un contexte VIDE (byte-identique au défaut) ;
  - le contexte n'est JAMAIS lié en test unitaire d'oracle (ils patchent `_fetch`, pas `_http`) : seul
    l'engine le lie autour d'un vrai `fire()`. `current()` renvoie None hors contexte -> no-op total ;
  - back-off 429 : `Oracle._http` incrémente `blocked` quand une réponse 429/503+challenge PERSISTE après
    back-off borné -> l'engine lit ce compteur APRÈS `fire()` pour surfacer un marqueur « rate-limited »
    au lieu d'empties silencieux. Le chaînage le propage aux DEUX étages (le run compte les blocages
    de tout le run, l'action garde le sien : l'engine lit celui de l'ACTION, inchangé).

Seams horaires (`_sleep`/`_now`) au niveau module -> patchables par les tests (spy d'intervalle, horloge
virtuelle ou ACCÉLÉRÉE : c'est ainsi que le débit RUN se mesure sans dormir une seconde réelle)."""
import threading
import time

_sleep = time.sleep          # seam patchable (tests) : la fonction de sommeil
_now = time.monotonic        # seam patchable (tests) : l'horloge monotone

_state = threading.local()   # contexte courant (par thread) : un Bucket/_Chain ou None


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
        sous verrou : pas de sérialisation-deadlock ; borne le débit même en rafale). Ne lève jamais.

        LA RÉSERVATION EST CE QUI REND LE PARTAGE INTER-THREADS CORRECT : `_next_ok` avance d'un
        intervalle par appelant, sous lock, AVANT le sommeil. Dix threads qui entrent ensemble
        repartent donc échelonnés de `min_interval`, pas tous à la même seconde."""
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


class RunCap(Bucket):
    """PLAFOND DE DÉBIT AU NIVEAU DU RUN — un seul seau, PARTAGÉ par toutes les actions et tous les
    threads du run. C'est la seule différence de fond avec `Bucket`, et c'est toute la correction : le
    seau d'action est reconstruit à chaque `fire()` et vit en thread-local, donc il ne peut RIEN dire
    du débit d'un run. Celui-ci est créé UNE FOIS par `Engine.__init__` et passé à chaque `using()`.

    IL COMPTE CE QU'IL FAIT, parce qu'un run bridé doit le DIRE et non ralentir mystérieusement :
    `calls` (requêtes cadencées), `waited` (secondes réellement dormies à cause du plafond), et la
    fenêtre `first`/`last` d'où `observed()` dérive le DÉBIT MESURÉ. Ces chiffres remontent au ledger
    (`engine.run_rate`) et à `Engine.coverage()['run_rate']`.

    `source` dit D'OÙ vient le plafond (`scope.run_rate` ou `scope.rate` via `rate_explicit`) : un
    opérateur qui voit son run bridé doit pouvoir remonter au réglage en une lecture."""

    def __init__(self, rate, source=""):
        super().__init__(rate)
        self.source = str(source or "")
        self.calls = 0            # requêtes passées par le plafond de run
        self.waited = 0.0         # secondes DORMIES à cause du plafond (0 => le plafond n'a rien coûté)
        self.first = None         # horodatage monotone de la 1re requête cadencée
        self.last = None          # … et de la dernière (la fenêtre d'où sort le débit observé)

    def wait(self):
        slept = Bucket.wait(self)
        t = _now()
        with self._lock:
            self.calls += 1
            self.waited += slept
            if self.first is None:
                self.first = t
            self.last = t
        return slept

    def observed(self):
        """Ce que le plafond a RÉELLEMENT produit : `{requests, span, rate, waited}` — le CHIFFRE.

        `rate` = (requests - 1) / span : N requêtes cadencées à R req/s occupent (N-1) intervalles,
        donc cette division rend R exactement quand le plafond mord. Moins de 2 requêtes, ou une
        fenêtre nulle -> `rate: None` (on ne divise pas par zéro pour avoir un chiffre à montrer).

        CE QUE CE CHIFFRE N'EST PAS : un débit INSTANTANÉ. La fenêtre couvre tout le run, temps mort
        compris (un run à 5 req/s qui passe 20 min dans des sous-process affichera bien moins que 5).
        C'est `waited` qui dit si le plafond a MORDU : à 0 s d'attente, il n'a rien bridé du tout."""
        with self._lock:
            n, first, last, waited = self.calls, self.first, self.last, self.waited
        span = (last - first) if (first is not None and last is not None) else 0.0
        rate = ((n - 1) / span) if (n > 1 and span > 0) else None
        return {"requests": n, "span": round(span, 3), "rate": (round(rate, 3) if rate else rate),
                "waited": round(waited, 3)}


class _Chain:
    """Les DEUX étages, dans l'ordre : plafond de RUN d'abord, seau d'ACTION ensuite.

    Chaîner et non arbitrer : chaque étage tient sa propre réservation, donc le débit résultant est
    borné par le PLUS SERRÉ des deux, sans que l'un n'annule l'autre. Prendre le `min` des deux débits
    dans un seul seau serait plus court à écrire et FAUX : le seau d'action doit rester NEUF à chaque
    fire (il lisse une rafale, il ne reporte pas la dette d'une action sur la suivante), là où le
    plafond de run doit au contraire se SOUVENIR de tout le run.

    `blocked`/`rate` sont exposés en lecture pour tout appelant qui tiendrait la chaîne plutôt que le
    seau d'action (l'engine, lui, tient le seau d'action que `using.__enter__` lui rend)."""

    __slots__ = ("run", "action")

    def __init__(self, run, action):
        self.run = run
        self.action = action

    def wait(self):
        return self.run.wait() + self.action.wait()

    def mark_blocked(self):
        self.run.mark_blocked()
        self.action.mark_blocked()

    @property
    def blocked(self):
        return self.action.blocked

    @property
    def rate(self):
        return self.action.rate or self.run.rate


def current():
    """Contexte de débit lié au thread (`Bucket` ou `_Chain`), ou None (hors contexte -> aucun
    throttle). Ne lève jamais. Les deux formes exposent `wait()` / `mark_blocked()` : `Oracle._http`
    n'a rien à savoir du nombre d'étages."""
    return getattr(_state, "bucket", None)


class using:
    """Context manager : lie le contexte de débit le temps d'un `fire()`.

    `rate` = débit de l'ACTION (req/s) ; `run` = plafond de RUN PARTAGÉ (`RunCap`) ou None.

      run=None, rate<=0   -> lie None                     (BYTE-IDENTIQUE au défaut historique)
      run=None, rate>0    -> lie un Bucket neuf           (comportement historique)
      run=RunCap          -> lie une `_Chain(run, Bucket(rate))` — le seau d'action existe TOUJOURS,
                             même à rate<=0 (min_interval 0 => `wait()` no-op), pour que `blocked`
                             reste un compteur PAR ACTION : sans lui, l'engine relirait le compteur
                             CUMULÉ du run et rééditerait le marqueur « rate-limited » à chaque action
                             suivant le premier 429 du run.

    `__enter__` rend le seau d'ACTION (ce que l'engine relit après le tir) ; c'est la CHAÎNE qui est
    liée au thread. Restaure le contexte précédent en sortie (réentrance sûre)."""

    def __init__(self, rate, run=None):
        self.run = run if isinstance(run, RunCap) else None
        if self.run is not None:
            self.bucket = Bucket(rate if _positive(rate) else 0)
            self.bound = _Chain(self.run, self.bucket)
        else:
            self.bucket = Bucket(rate) if _positive(rate) else None
            self.bound = self.bucket

    def __enter__(self):
        self.prev = getattr(_state, "bucket", None)
        _state.bucket = self.bound
        return self.bucket

    def __exit__(self, *a):
        _state.bucket = self.prev
        return False


def _positive(rate):
    try:
        return float(rate) > 0
    except (TypeError, ValueError):
        return False

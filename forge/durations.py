# SPDX-License-Identifier: AGPL-3.0-or-later
"""Magasin de DURÉES OBSERVÉES par KIND — l'estimation de lenteur qui alimente le préchauffage.

À QUOI ÇA SERT. `engine._preheat_order` met « au four d'avance » les actions les plus LONGUES d'une
vague, sinon rejetées en fin de vague par le planner (EV = value*confidence/cost : un coût élevé
baisse l'EV). Jusqu'ici sa seule estimation de lenteur était `action.cost` — le seul porteur existant.
Or `cost` est une donnée de GOUVERNANCE (le prix qu'on accepte de payer), PAS une mesure de DURÉE :
les deux corrèlent souvent, rien ne le garantit. Un module cher-mais-rapide était préchauffé pour
rien ; un module gratuit-mais-lent immobilisait le pool. Ce module fournit la mesure qui manquait.

CE QUI EST STOCKÉ, ET RIEN D'AUTRE — L'AGRÉGAT EST **PAR KIND**, JAMAIS PAR CIBLE.
C'est la bonne conception sur les deux tableaux, pas une contrainte subie :
  • CONFIDENTIALITÉ — un magasin de durées PAR CIBLE serait un journal de reconnaissance qui SURVIT à
    l'engagement (« combien de temps l'hôte X a mis à répondre à testssl », donc : quels hôtes
    existaient, lesquels étaient lents, lesquels filtraient). Rien de tout cela n'est écrit ici : la
    CLÉ est le kind du module (`web.testssl`), la VALEUR un agrégat de secondes. Aucune cible, aucune
    URL, aucun hôte, aucun paramètre ne peut y entrer — l'appelant (`Engine._record_duration`) ne
    passe QUE `action.kind`, et ce kind a nécessairement un module ENREGISTRÉ (sinon `_decide_blocking`
    sort avant le tir) ; `record()` re-valide en plus la grammaire d'un kind, fail-closed.
  • UTILITÉ — le préchauffage n'a de toute façon besoin QUE du kind : il ordonne des familles d'actions
    (« testssl est lent »), pas des cibles.

TAILLE BORNÉE, PAS UNE LISTE QUI GRANDIT. Nombre de kinds plafonné (`MAX_KINDS`, éviction
DÉTERMINISTE des moins observés) ; par kind, un agrégat de TAILLE FIXE : un compteur `n` et un anneau
des `RING` dernières durées. Un run de 10 000 actions n'écrit pas un octet de plus qu'un run de 10.

CONFIANCE, SANS MODÈLE. Une moyenne sur n=1 est du bruit : sous `MIN_SAMPLES` observations, le kind
n'a PAS d'estimation (`estimate` -> None) et l'appelant retombe sur `action.cost`. Au-delà, l'estimation
est la MÉDIANE de l'anneau (robuste à un tir aberrant — un outil absent qui échoue en 3 ms), QUANTIFIÉE
à un chiffre significatif (`_quantize`). La quantification n'est pas cosmétique : `_preheat_order`
raisonne par PALIERS (« palier complet ou rien »), et deux kinds de lenteur comparable doivent tomber
dans le MÊME palier — sans quantification, deux médianes mesurées ne sont jamais égales, chaque kind
formerait son propre palier et le groupe d'actions lentes serait cassé en deux (mesuré ailleurs à
-16 %). Pas d'apprentissage, pas de modèle, pas de seuil réglable.

LECTURE GELÉE / ÉCRITURE TRAVERSANTE. `estimate()` répond depuis un instantané figé À LA CHARGE ;
`record()` alimente un tampon séparé, écrit au `save()`. Conséquence VOULUE : pendant un run, l'ordre
de soumission est une fonction PURE de (vague, magasin au démarrage) — deux runs sur le même magasin
préchauffent exactement pareil, alors qu'un magasin rafraîchi en cours de run ferait varier l'ordre
d'une exécution à l'autre au gré des microsecondes mesurées. Le prix : c'est le run SUIVANT qui
profite des mesures, pas les vagues suivantes du même run.

PORTÉE : PAR-ENGAGEMENT. Le fichier est un SIDECAR du ledger (`<ledger>.durations`), comme `<ledger>.hwm`
et `<ledger>.ed25519`. La console donne à CHAQUE engagement son ledger dédié (`engagement-<id>.jsonl`,
cf. `derive_engagement_ledger_path`) : le magasin hérite donc de cette isolation par construction, et
disparaît avec le ledger de l'engagement. Aucun magasin GLOBAL, aucun état sous $HOME : une durée
mesurée chez un client ne peut pas suivre l'opérateur chez le suivant. Sans `--ledger` (CLI directe,
tests), il n'y a AUCUN fichier et le moteur retombe sur `action.cost` — comportement historique.

ZÉRO DÉPENDANCE (stdlib). Ne lève JAMAIS : un fichier absent/corrompu/illisible rend un magasin INERTE
(aucune estimation), donc le repli `action.cost`. Un cache de performance ne doit jamais casser un run.
"""
from __future__ import annotations

import json
import math
import os
import re
import threading
from pathlib import Path
from typing import Any

# Grammaire d'un KIND de module (`recon.httpx`, `access_control.idor`, `web.nuclei`) : segments
# séparés par des points, chacun commençant par une lettre minuscule. Tout ce qui n'est pas de cette
# forme est REFUSÉ à l'enregistrement comme à la lecture — une IP littérale (`198.51.100.7`), un
# `host:port`, une URL ou un chemin ne peuvent PAS devenir une clé du magasin.
#
# PORTÉE EXACTE, parce qu'une garde qu'on croit totale est pire qu'une garde qu'on sait partielle :
# ce filtre discrimine des FORMES, pas des identités. Un nom d'hôte tout en minuscules
# (`app.example.com`) a exactement la forme d'un kind et PASSERAIT. Il n'est donc pas le rempart
# contre la fuite de cible — c'est un garde-fou de dernier recours contre un appelant futur qui
# passerait une URL ou une IP. Le vrai rempart est en amont et tient en une phrase : `engine` est
# l'UNIQUE appelant de `record()` et ne lui passe QUE `action.kind`. Un contrôle d'appartenance au
# registre (`modules.registry.kinds()`) fermerait le trou de forme, mais interdirait tout kind
# synthétique — modules chargés dynamiquement, doubles de test, bancs — pour un trou qu'aucun
# appelant n'atteint : disproportionné. Ce qui est PROUVÉ, et qui est la garantie réellement offerte,
# c'est l'absence de cible dans le fichier écrit par une vague réelle (cf. tests, lecture des octets).
_KIND_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
_KIND_MAX_LEN = 64

# Kill-switch d'exploitant : `FORGE_DURATIONS=0` (ou off/false/no) => aucun fichier, aucune mesure
# persistée, préchauffage sur `action.cost` — exactement le comportement d'avant ce chantier.
_OFF = frozenset({"0", "off", "false", "no"})


def _quantize(seconds: float) -> float:
    """Arrondit à UN chiffre significatif (0,63 -> 0,6 ; 1,24 -> 1 ; 63 -> 60 ; 0,043 -> 0,04).

    C'est le quantificateur de « lenteur comparable » qui rend les PALIERS de `_preheat_order`
    utilisables sur des mesures : deux kinds tombent dans le même palier dès qu'ils s'accordent au
    premier chiffre. L'échelle de `cost` (1 / 2 / 3) est déjà grossière au même titre. Ne lève jamais."""
    if not (seconds > 0.0) or seconds != seconds or seconds == float("inf"):
        return 0.0
    return round(seconds, -int(math.floor(math.log10(seconds))))


class _KindStat:
    """Agrégat de TAILLE FIXE pour UN kind : un compteur d'observations + un anneau des dernières
    durées. Aucun champ ne peut croître avec le nombre d'actions — c'est ce qui borne le fichier."""

    __slots__ = ("n", "samples")

    def __init__(self, n: int = 0, samples: "list[float] | None" = None) -> None:
        self.n = int(n)
        self.samples: list[float] = list(samples or [])

    def add(self, seconds: float, ring: int, n_cap: int) -> None:
        """Ajoute une observation ; l'anneau ne dépasse JAMAIS `ring` entrées, `n` jamais `n_cap`."""
        self.samples.append(seconds)
        if len(self.samples) > ring:
            del self.samples[:len(self.samples) - ring]
        if self.n < n_cap:
            self.n += 1

    def median(self) -> float:
        """Médiane de l'anneau (0.0 s'il est vide). Robuste à un tir aberrant isolé."""
        s = sorted(self.samples)
        if not s:
            return 0.0
        mid = len(s) // 2
        return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2.0

    def to_dict(self) -> dict[str, Any]:
        return {"n": self.n, "s": self.samples}


class DurationStore:
    """Durées d'exécution observées, agrégées PAR KIND, persistées par-engagement.

    Trois gestes seulement :
      • `estimate(kind)` -> secondes quantifiées, ou None si le kind n'est pas assez observé (l'appelant
        retombe alors sur son estimation d'origine — pour le moteur, `action.cost`) ;
      • `record(kind, seconds)` -> enregistre UNE observation (sûr depuis plusieurs threads de tir) ;
      • `save()` -> fusionne le tampon du run dans le fichier et le réécrit atomiquement.
    """

    VERSION = 1
    RING = 8              # échantillons conservés par kind (agrégat de TAILLE FIXE)
    MIN_SAMPLES = 3       # seuil de confiance : sous ce nombre d'observations, aucune estimation
    MAX_KINDS = 256       # plafond dur (le registre en compte ~78) — éviction déterministe au-delà
    N_CAP = 1_000_000     # borne du compteur (jamais d'entier qui grossit sans fin)
    MAX_SECONDS = 86_400.0  # garde-fou : une « durée » au-delà d'un jour est une aberration, pas une mesure

    def __init__(self, path: "str | os.PathLike[str] | None" = None,
                 stats: "dict[str, _KindStat] | None" = None) -> None:
        self.path = Path(path) if path else None
        self._disk: dict[str, _KindStat] = dict(stats or {})
        # INSTANTANÉ GELÉ des estimations, calculé UNE fois à la construction : `record()` ne le
        # déplace pas. C'est ce qui rend l'ordre de soumission d'un run reproductible.
        self._frozen: dict[str, float] = {
            k: _quantize(st.median()) for k, st in self._disk.items() if st.n >= self.MIN_SAMPLES}
        self._pending: dict[str, _KindStat] = {}      # observations DE CE RUN, écrites au save()
        self._lock = threading.Lock()                 # `record()` est appelé depuis les workers de tir

    # --- construction -----------------------------------------------------------------------------
    @classmethod
    def load(cls, path: "str | os.PathLike[str]") -> "DurationStore":
        """Charge le magasin depuis `path`. Fichier absent, illisible, corrompu, ou de version
        inconnue -> magasin VIDE (inerte) : le moteur retombe sur `action.cost`. Ne lève jamais."""
        stats: dict[str, _KindStat] = {}
        try:
            raw = Path(path).read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict) and data.get("v") == cls.VERSION:
                stats = cls._parse_kinds(data.get("kinds"))
        except (OSError, ValueError, TypeError):
            stats = {}
        return cls(path, stats)

    @classmethod
    def for_ledger(cls, ledger_path: "str | os.PathLike[str] | None") -> "DurationStore | None":
        """Magasin PAR-ENGAGEMENT dérivé du ledger : sidecar `<ledger>.durations`, comme `<ledger>.hwm`.
        Rend None (aucun fichier, aucune mesure) si aucun ledger n'est branché — la CLI directe et les
        tests gardent donc EXACTEMENT le comportement historique — ou si `FORGE_DURATIONS` est désactivé."""
        if not ledger_path:
            return None
        if os.environ.get("FORGE_DURATIONS", "").strip().lower() in _OFF:
            return None
        return cls.load(str(ledger_path) + ".durations")

    @classmethod
    def _parse_kinds(cls, kinds: Any) -> dict[str, _KindStat]:
        """Valide/normalise le bloc `kinds` d'un fichier. FAIL-CLOSED entrée par entrée : une clé qui
        n'a pas la forme d'un kind (IP, `host:port`, URL, chemin — cf. `_KIND_RE` et sa portée
        exacte), un agrégat malformé ou une durée aberrante est SILENCIEUSEMENT ÉCARTÉE, sans
        invalider le reste du fichier."""
        out: dict[str, _KindStat] = {}
        if not isinstance(kinds, dict):
            return out
        for kind, blob in kinds.items():
            if not cls._valid_kind(kind) or not isinstance(blob, dict):
                continue
            samples = []
            for v in (blob.get("s") or [])[-cls.RING:]:
                s = cls._valid_seconds(v)
                if s is not None:
                    samples.append(s)
            try:
                n = int(blob.get("n", 0))
            except (TypeError, ValueError):
                continue
            if n <= 0 or not samples:
                continue
            out[kind] = _KindStat(min(n, cls.N_CAP), samples)
        return cls._evict(out)

    @classmethod
    def _valid_kind(cls, kind: Any) -> bool:
        """True pour ce qui a la FORME d'un identifiant de module. Garde-fou de dernier recours, pas
        rempart : voir la portée exacte documentée sur `_KIND_RE` — un nom d'hôte en minuscules a la
        même forme qu'un kind et passerait. Le rempart est que `engine` ne passe QUE `action.kind`."""
        return (isinstance(kind, str) and len(kind) <= _KIND_MAX_LEN
                and bool(_KIND_RE.match(kind)))

    @classmethod
    def _valid_seconds(cls, value: Any) -> "float | None":
        """Durée exploitable (finie, >= 0, sous le garde-fou), sinon None. NaN/inf/négatif écartés."""
        try:
            s = float(value)
        except (TypeError, ValueError):
            return None
        if s != s or s < 0.0 or s > cls.MAX_SECONDS:      # NaN (s != s), négatif, aberrant
            return None
        return round(s, 4)

    @classmethod
    def _evict(cls, stats: dict[str, _KindStat]) -> dict[str, _KindStat]:
        """Borne le nombre de kinds. Éviction DÉTERMINISTE : on garde les plus OBSERVÉS (`n`
        décroissant), départagés par NOM croissant — jamais par ordre d'insertion d'un dict."""
        if len(stats) <= cls.MAX_KINDS:
            return stats
        keep = sorted(stats.items(), key=lambda kv: (-kv[1].n, kv[0]))[:cls.MAX_KINDS]
        return dict(keep)

    # --- lecture (GELÉE) --------------------------------------------------------------------------
    def estimate(self, kind: str) -> "float | None":
        """Durée observée pour ce kind, en secondes QUANTIFIÉES — ou None si le kind est inconnu ou
        vu moins de `MIN_SAMPLES` fois (une moyenne sur n=1 est du bruit : l'appelant doit alors
        garder son estimation d'origine). Pure, gelée à la charge, ne lève jamais."""
        return self._frozen.get(kind)

    def observed_kinds(self) -> int:
        """Nombre de kinds disposant d'une estimation exploitable (audit/tests)."""
        return len(self._frozen)

    # --- écriture (TRAVERSANTE) -------------------------------------------------------------------
    def record(self, kind: str, seconds: float) -> None:
        """Enregistre UNE durée observée pour `kind`. Appelé depuis les workers de tir -> verrouillé.
        REFUSE tout ce qui n'est pas un kind de module (garde de non-identification) et toute durée
        non exploitable. N'affecte PAS `estimate()` de ce run (lecture gelée). Ne lève jamais."""
        if not self._valid_kind(kind):
            return
        s = self._valid_seconds(seconds)
        if s is None:
            return
        with self._lock:
            st = self._pending.get(kind)
            if st is None:
                if len(self._pending) >= self.MAX_KINDS:   # tampon borné, même plafond que le fichier
                    return
                st = self._pending[kind] = _KindStat()
            st.add(s, self.RING, self.N_CAP)

    def save(self) -> bool:
        """Fusionne les observations du run dans le fichier et le réécrit ATOMIQUEMENT (tmp + rename).
        Relit le disque d'abord : deux runs du même engagement se fusionnent au lieu de s'écraser.
        No-op (True) si rien n'a été observé ; False sur échec d'écriture — un cache de performance ne
        casse JAMAIS un run, l'appelant peut ignorer le retour. Ne lève jamais."""
        if self.path is None:
            return False
        with self._lock:
            pending = {k: _KindStat(st.n, list(st.samples)) for k, st in self._pending.items()}
        if not pending:
            return True
        merged = self._merge(self.load(self.path)._disk, pending)
        payload = {"v": self.VERSION,
                   "kinds": {k: merged[k].to_dict() for k in sorted(merged)}}
        tmp = Path(str(self.path) + ".tmp")
        try:
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)                    # rename atomique (POSIX)
            return True
        except (OSError, ValueError):                     # ValueError : chemin refusé par l'OS (octet nul)
            try:
                tmp.unlink()
            except (OSError, ValueError):
                pass
            return False

    @classmethod
    def _merge(cls, base: dict[str, _KindStat],
               pending: dict[str, _KindStat]) -> dict[str, _KindStat]:
        """Fusionne le tampon dans l'état disque : `n` s'additionne (plafonné), les anneaux se
        concatènent puis se retaillent aux `RING` derniers. Puis éviction déterministe."""
        out = {k: _KindStat(st.n, list(st.samples)) for k, st in base.items()}
        for kind, st in pending.items():
            cur = out.get(kind)
            if cur is None:
                out[kind] = _KindStat(min(st.n, cls.N_CAP), st.samples[-cls.RING:])
                continue
            cur.n = min(cur.n + st.n, cls.N_CAP)
            cur.samples = (cur.samples + st.samples)[-cls.RING:]
        return cls._evict(out)

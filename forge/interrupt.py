# SPDX-License-Identifier: AGPL-3.0-or-later
"""BUDGET DE TEMPS + ARRÊT GRACIEUX — pour qu'un run coupé RENDE quand même son livrable.

CE QUI S'EST PASSÉ, DEUX FOIS. Deux campagnes réelles contre une cible autorisée ont été tuées par un
timeout EXTERNE (90 min, puis 4 h). À chaque fois le même dommage : **aucun `report.md`** alors que
`--report` était passé, **aucun sidecar `.durations`** — et un ledger COMPLET (5 646 puis 11 407
lignes, 5 318 findings). Tout le travail était fait ; seul le rendu manquait.

LA CAUSE, MESURÉE (pas supposée). Le mécanisme d'arrêt gracieux EXISTAIT DÉJÀ (`Terminate` levé à une
frontière d'action, flush partiel, statut `timeout` côté console) — mais il était **entièrement
conditionné à `--console`** : `forge/cli/engine.py` n'installait son handler SIGTERM et ne branchait
son `checkpoint` QUE dans la branche `if args.console`. Les deux campagnes tuées tournaient en CLI
directe (leur `run.log` ne porte aucune ligne `Console <- ingest`) : **aucun handler n'était posé**,
le SIGTERM tombait sur le handler PAR DÉFAUT de Python, le process mourait à l'instruction courante —
avant le `build_report` et le `save()` des durées, tous deux placés APRÈS la boucle.

POURQUOI UN RENDU UNIQUE GARANTI, ET PAS UN RAPPORT ÉCRIT AU FIL DE L'EAU. Les deux conceptions sont
défendables ; celle-ci a été choisie sur MESURE, sur le corpus réel de la campagne tuée (5 318
findings, ledger de 12 879 entrées) :

  * `build_report` seul : **0,10 s** (37 300 lignes, 1,5 MiB) — un instantané périodique serait donc
    presque gratuit… tant qu'AUCUN ledger n'est branché ;
  * `Ledger.verify()`, que `build_report` appelle dès qu'un ledger est là : **2,15 s** sur 12 879
    entrées, et ce coût CROÎT avec le ledger. Un instantané toutes les 60 s d'un run de 4 h
    re-vérifierait le ledger ~240 fois, en le relisant ENTIER à chaque fois : quadratique, pour un
    fichier qui grossit précisément parce que le run avance ;
  * `report._assist_section` peut déclencher un appel LLM **avec egress** (opt-in `scope.llm`) :
    répéter le rendu répéterait l'egress — inacceptable en silence.

Un rendu au fil de l'eau achèterait donc la survie au SIGKILL au prix d'un coût croissant et d'un
egress répété. Or le SIGKILL est DÉJÀ couvert, et mieux : le ledger EST le journal d'écriture
anticipée du moteur (append-only, flushé par entrée). Vérifié : le rapport de la campagne tuée a été
reconstruit ENTIÈREMENT depuis son seul `ledger.jsonl` — 37 300 lignes, 0,34 s. On garde donc UN
rendu, et on garantit qu'on l'ATTEINT : arrêt gracieux à une frontière d'action + émission dans un
`finally` qui couvre les trois causes (échéance de budget, signal externe, exception non rattrapée).

CE QUE CE MODULE NE FAIT PAS. Il n'annule aucun verdict et n'en fabrique aucun. Une action non tirée
faute de budget n'est PAS `tested`, PAS `not_vulnerable`, PAS un finding : elle n'entre nulle part —
elle est COMPTÉE comme non tentée (`Engine.not_attempted`) et le rapport le DIT. C'est l'acquis
« zéro faux positif » du dépôt : un module qui n'a pas pu vérifier rend `skipped`, jamais un verdict.

stdlib uniquement. Aucun import de `forge.*` : ce module est importé PAR le moteur et par la CLI.
"""
from __future__ import annotations

import os
import re
import signal
import threading
import time
from typing import Any, Callable

# --- CAUSES D'INTERRUPTION -------------------------------------------------------------------------
# Vocabulaire FERMÉ (le rapport en dérive sa phrase d'en-tête). Les trois causes du cahier des charges,
# et rien d'autre : un run partiel doit dire POURQUOI il est partiel, sans catégorie fourre-tout.
CAUSE_BUDGET = "budget"        # échéance du budget de temps (interne, décidée par l'opérateur)
CAUSE_SIGNAL = "signal"        # SIGTERM/SIGINT externe (watchdog console, `timeout`, Ctrl-C)
CAUSE_ERROR = "error"          # exception non rattrapée remontée jusqu'à la boucle de run

CAUSE_LABELS = {
    CAUSE_BUDGET: "budget de temps épuisé",
    CAUSE_SIGNAL: "signal d'arrêt externe reçu",
    CAUSE_ERROR: "exception non rattrapée",
}

# Bornes du budget, ALIGNÉES sur celles que la console applique déjà au même levier
# (`console/src/runs_validate.rs` : `ResourceKnob { key: "run_timeout", min: 1, max: 604_800 }`).
# Une seule grammaire de valeur pour les deux couches — un budget accepté par l'UI l'est par la CLI.
MIN_SECONDS = 1
MAX_SECONDS = 604_800          # 7 jours

# Nom de la variable d'environnement du levier. Lu depuis `resource_profile.ENV_OVERRIDES` quand ce
# module est disponible (source de vérité unique) ; la constante n'est qu'un repli défensif.
ENV_RUN_TIMEOUT = "FORGE_RUN_TIMEOUT"

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smh]?)\s*$", re.IGNORECASE)
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600}

#: Nom du param d'action par lequel le MOTEUR passe le budget de temps RESTANT (secondes, float) au
#: module, juste avant le tir — protocole OPTIONNEL, symétrique de `_pinned_ips`. Vit ICI, dans le
#: module du budget, parce que c'est un mot de VOCABULAIRE du budget et que `forge.interrupt`
#: n'importe rien de `forge.*` : le moteur ET les modules peuvent le lire sans cycle d'import.
#:
#: DEUX USAGES, un seul sens de lecture (le module ne l'écrit jamais) :
#:   1. `Engine._budget_gate` le pose, puis demande sa borne au module -> un module qui SAIT réduire
#:      son travail (`NucleiScan._batch` : un lot de 17 URLs redevient un lot de 3) rend une borne
#:      DÉJÀ adaptée, et passe la gate au lieu d'être écarté en entier ;
#:   2. absent (aucun budget posé) => aucun module ne s'adapte, comportement byte-identique.
ACTION_BUDGET_PARAM = "_budget_remaining"


class Terminate(BaseException):
    """Arrêt GRACIEUX d'un run. Dérive de `BaseException` (PAS de `Exception`) EXPRÈS : le
    `except Exception` du moteur (M6, robustesse du tir) et le garde best-effort de `_run_checkpoint`
    ne doivent PAS l'avaler — il doit dérouler la campagne jusqu'à la finalisation (finally) pour ne
    perdre AUCUN travail.

    `cause` dit POURQUOI (vocabulaire fermé ci-dessus) et `detail` le raconte à un humain. Les deux
    remontent tels quels dans l'en-tête du rapport partiel : c'est ce qui interdit à un rapport
    tronqué de ressembler à un rapport complet. Les arguments sont OPTIONNELS — `Terminate()` reste
    valide (la forme historique, levée par le `_checkpoint` de la CLI sur watchdog console)."""

    def __init__(self, cause: str = CAUSE_SIGNAL, detail: str = "") -> None:
        super().__init__(detail or CAUSE_LABELS.get(cause, cause))
        self.cause = cause
        self.detail = detail or CAUSE_LABELS.get(cause, cause)


# --- LE LEVIER : `run_timeout_secs` ---------------------------------------------------------------
def parse_run_timeout(text: Any) -> int:
    """Parse une valeur de budget EXPLICITE (drapeau CLI). Accepte un nombre de SECONDES (`5400`) ou
    un suffixe d'unité (`90m`, `2h`, `45s`) — un opérateur pense « au plus 90 minutes », pas « 5400 ».

    FAIL-CLOSED (convention des drapeaux de ce dépôt, cf. `_parse_cli_params`) : tout ce qui n'est pas
    une durée valide et dans les bornes lève `ValueError`. Un budget qu'on croit avoir posé et qui
    aurait été silencieusement ignoré serait pire que pas de budget du tout — c'est exactement le
    genre de silence que ce lot supprime."""
    if text is None:
        raise ValueError("durée manquante")
    m = _DURATION_RE.match(str(text))
    if not m:
        raise ValueError(f"durée invalide '{text}' — attendu un entier de SECONDES (ex : 5400) "
                         f"ou un suffixe d'unité s/m/h (ex : 90m, 2h)")
    secs = int(m.group(1)) * _UNITS[m.group(2).lower()]
    if secs < MIN_SECONDS or secs > MAX_SECONDS:
        raise ValueError(f"durée hors bornes '{text}' -> {secs}s "
                         f"(bornes {MIN_SECONDS}..{MAX_SECONDS}s, comme la console)")
    return secs


def _env_run_timeout() -> "int | None":
    """Budget venu de l'ENVIRONNEMENT (`FORGE_RUN_TIMEOUT`), ou None. C'est le canal que la console
    utilise DÉJÀ au spawn du moteur (`ResourceOptions::env_pairs`) et celui que son propre watchdog
    lit (`console/src/boot.rs`) : brancher le budget IN-PROCESS sur la MÊME variable aligne l'arrêt
    interne sur le watchdog externe au lieu d'inventer un second réglage à tenir en cohérence.

    FAIL-OPEN sur une valeur illisible — comme `resource_profile._coerce` le fait déjà pour tous les
    overrides d'env : un environnement pollué ne doit pas empêcher un run de démarrer. La différence
    de traitement avec le drapeau CLI (fail-closed) est VOULUE : un drapeau est une intention
    explicite, une variable d'env est un défaut ambiant."""
    name = ENV_RUN_TIMEOUT
    try:                                                   # source de vérité : la table du profil
        from . import resource_profile
        name = resource_profile.ENV_OVERRIDES.get("run_timeout_secs", ENV_RUN_TIMEOUT)
    except Exception:                                      # noqa: BLE001 — repli sur la constante
        pass
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return None
    try:
        secs = parse_run_timeout(raw)
    except ValueError:
        return None
    return secs


def resolve_run_timeout(explicit: Any = None) -> "int | None":
    """Budget EFFECTIF de ce run, en secondes — ou None (AUCUN budget, comportement historique).

        drapeau CLI `--run-timeout`  >  env `FORGE_RUN_TIMEOUT`  >  **rien**

    Les deux premiers échelons sont ceux de `resource_profile` (« override explicite > override d'env
    > profil > défaut-code »). Le troisième s'en écarte DÉLIBÉRÉMENT, et c'est la seule décision de
    ce module qui mérite d'être discutée : le levier `run_timeout_secs` a DÉJÀ une valeur de profil
    (low 1800 / balanced 3600 / full 7200), qu'on pourrait appliquer par défaut. On ne le fait PAS.
    L'en-tête de `resource_profile` dit exactement pourquoi — pour ce levier la table « EXPOSE ici
    pour DÉRIVER/DOCUMENTER l'env, pas pour l'imposer », le défaut ayant toujours vécu côté reaper
    Rust. L'appliquer ici couperait À 1 H tout run existant qui n'a jamais rien demandé — la campagne
    de 4 h aurait été tronquée par un défaut que personne n'a posé. Un budget est une décision
    d'opérateur : sans décision, pas de budget."""
    if explicit is not None:
        return int(explicit)
    return _env_run_timeout()


class Budget:
    """Échéance de temps d'un run. Horloge MONOTONE (insensible aux sauts d'heure système) et
    INJECTABLE : une preuve d'échéance se fait en avançant l'horloge, jamais en dormant."""

    def __init__(self, seconds: int, clock: "Callable[[], float]" = time.monotonic) -> None:
        self.seconds = int(seconds)
        self._clock = clock
        self.start = clock()

    @property
    def deadline(self) -> float:
        return self.start + self.seconds

    def elapsed(self) -> float:
        return max(0.0, self._clock() - self.start)

    def remaining(self) -> float:
        return self.deadline - self._clock()

    def expired(self) -> bool:
        return self._clock() >= self.deadline

    def describe(self) -> str:
        return f"{self.elapsed():.0f}s écoulées sur un budget de {self.seconds}s"


class GracefulStop:
    """Décide QUAND un run doit s'arrêter proprement, et le dit au moteur.

    DEUX SOURCES, une seule sortie :
      * un SIGNAL externe (SIGTERM du watchdog console ou de `timeout(1)`, SIGINT d'un Ctrl-C) —
        capté par un handler qui ne meurt PAS sur place : il POSE un drapeau (et coupe les groupes
        d'outils en vol, sans quoi le moteur resterait bloqué dans `communicate()` au lieu d'atteindre
        sa prochaine frontière d'action) ;
      * l'ÉCHÉANCE du budget de temps.
    `reason()` rend un `Terminate` prêt à lever, ou None. Le moteur l'appelle À CHAQUE frontière
    d'action : le signal l'emporte sur le budget (un ordre externe prime une décision interne).

    DEUXIÈME SIGNAL = ARRÊT DUR. Le premier SIGTERM/SIGINT demande l'arrêt gracieux ; le SECOND
    restaure le handler par défaut et se re-délivre. Un opérateur qui refait Ctrl-C DOIT pouvoir tuer
    le process — un arrêt « gracieux » dont on ne peut plus sortir serait une régression d'ergonomie,
    et un handler qui avale indéfiniment SIGTERM empêcherait un superviseur de faire son travail.

    S'utilise en gestionnaire de contexte : les handlers précédents sont TOUJOURS restaurés à la
    sortie (y compris sur exception). Hors thread principal / plateforme sans ces signaux,
    l'installation échoue proprement (`ValueError`/`OSError` avalés) et seul le budget reste actif —
    dégradation nommée, jamais un crash."""

    SIGNALS = tuple(s for s in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None))
                    if s is not None)

    def __init__(self, budget: "Budget | None" = None,
                 on_signal: "Callable[[], None] | None" = None,
                 emit: "Callable[[str], None] | None" = None) -> None:
        self.budget = budget
        self._on_signal = on_signal
        self._emit = emit
        self.signalled: "int | None" = None       # numéro du signal reçu, None sinon
        self._saved: dict[Any, Any] = {}
        self.installed = False

    # --- installation -----------------------------------------------------------------------------
    def install(self) -> "GracefulStop":
        for sig in self.SIGNALS:
            try:
                self._saved[sig] = signal.signal(sig, self._handler)
                self.installed = True
            except (ValueError, OSError):          # pas le thread principal / signal indisponible
                continue
        return self

    def restore(self) -> None:
        for sig, prev in list(self._saved.items()):
            try:
                signal.signal(sig, prev)
            except (ValueError, OSError):
                pass
        self._saved.clear()

    def __enter__(self) -> "GracefulStop":
        return self.install()

    def __exit__(self, *exc: Any) -> bool:
        self.restore()
        return False

    # --- handler ----------------------------------------------------------------------------------
    def _handler(self, signum: int, frame: Any) -> None:
        if self.signalled is not None:            # DEUXIÈME signal -> arrêt DUR, on rend la main à l'OS
            self.restore()
            try:
                signal.raise_signal(signum)       # py>=3.8
            except Exception:                     # noqa: BLE001 — un handler ne doit JAMAIS lever
                os._exit(130)
            return
        self.signalled = signum
        self._say(f"arrêt gracieux demandé (signal {signum}) — le run s'arrête à la prochaine "
                  f"frontière d'action et rend son rapport PARTIEL (2e signal = arrêt dur)")
        if self._on_signal is not None:
            try:
                self._on_signal()
            except Exception:                     # noqa: BLE001 — idem
                pass

    def _say(self, line: str) -> None:
        if self._emit is None:
            return
        try:
            self._emit(line)
        except Exception:                         # noqa: BLE001
            pass

    # --- décision ---------------------------------------------------------------------------------
    def reason(self) -> "Terminate | None":
        """`Terminate` à lever, ou None. PUR (aucun effet de bord) : le moteur l'appelle à CHAQUE
        action, il doit rester au prix d'une comparaison de flottants."""
        if self.signalled is not None:
            name = _signal_name(self.signalled)
            detail = f"{name} reçu (arrêt externe : watchdog, timeout(1) ou opérateur)"
            if self.budget is not None:
                detail += f" — {self.budget.describe()}"
            return Terminate(CAUSE_SIGNAL, detail)
        if self.budget is not None and self.budget.expired():
            return Terminate(CAUSE_BUDGET,
                             f"échéance atteinte : {self.budget.describe()} "
                             f"(--run-timeout / {ENV_RUN_TIMEOUT})")
        return None


# --- PART DU BUDGET PAR KIND : aucun module ne mange la moitié du run ------------------------------
# LE DÉFAUT MESURÉ (campagne réelle du 2026-08-10, `--run-timeout 60m`, 3 cibles). Le sidecar
# `.durations` du run donne les durées OBSERVÉES, une entrée par tir :
#
#     web.testssl        600,96 · 282,47 · 600,24 s   -> 1 483,7 s, soit 41 % du budget
#     web.nuclei         279,75 · 377,52 · 415,72 s   -> 1 073,0 s, soit 30 %
#     xss.dalfox         294,07 ·  21,49 · 295,39 s   ->   610,9 s, soit 17 %
#
# `web.testssl` seul a donc consommé ~30 des 60 minutes, DEUX de ses trois tirs ayant été TUÉS À LEUR
# MUR (600 s, la borne `spec.timeout`) : ce n'est pas « un tir qui a duré », c'est le mur payé plein
# tarif, trois fois. Pendant ce temps la vague 1 n'a pas fini et la découverte n'a jamais été
# replanifiée.
#
# LA GATE ABSOLUE NE POUVAIT PAS L'ATTRAPER, et c'est structurel : elle compare la borne d'UNE action
# au temps RESTANT (`Engine._budget_gate`). Or 600 s « tient » dans 3600 s, puis dans 3000 s, puis dans
# 2400 s — chaque tir est individuellement raisonnable, c'est leur SOMME qui ne l'est pas. Il manquait
# la dimension CUMULATIVE, par kind.
#
# CE QU'ON AJOUTE : la MÊME gate, une clause de plus. On ne démarre pas un tir dont la consommation
# PRÉVUE, AJOUTÉE à ce que son kind a DÉJÀ consommé sur ce run, dépasserait sa PART. Prospectif comme
# la clause absolue (« on ne démarre pas ce qui ne tient pas »), même vocabulaire de refus, même
# conséquence : un SKIP NOMMÉ, listé au rapport, AUCUN verdict. Une action non démarrée n'est ni
# `tested`, ni `not_vulnerable`, ni un finding.
#
# CE QU'ON N'AJOUTE PAS, ET POURQUOI :
#   · pas de second réglage de temps : la part est RELATIVE au budget que l'opérateur a déjà posé
#     (`--run-timeout` / FORGE_RUN_TIMEOUT). Sans budget, aucune part, aucune gate — no-op strict ;
#   · pas de troncature d'un tir EN VOL : raboter le timeout d'une action qui tourne FABRIQUE des
#     verdicts négatifs pour les cibles qu'elle n'a pas atteintes (le dépôt l'interdit, cf. supra) ;
#   · pas de cap sur les classes QUALIFIANTES : le moteur les exempte via `planner.is_floored` —
#     la même règle qui, dans `Planner.order`, interdit au budget de plan d'affamer une voie payable.
#     Une seule définition de « qualifiant », deux consommateurs.
#
# LA PART PAR DÉFAUT EST 1/3. Le cahier des charges dit « aucun module ne devrait pouvoir manger la
# MOITIÉ du budget » : 1/2 serait donc la limite tolérée, pas une cible. 1/3 la respecte strictement
# tout en laissant les scanners lents TOURNER — sur les durées mesurées ci-dessus et un budget de
# 3600 s (cap = 1200 s), `web.nuclei` (1073 s) et `xss.dalfox` (611 s) passent ENTIERS, et seul le
# 3e `web.testssl` est refusé. C'est l'effet voulu : borner, pas supprimer.
KIND_SHARE_DEFAULT = 1.0 / 3.0
ENV_KIND_SHARE = "FORGE_KIND_BUDGET_SHARE"


def resolve_kind_share(explicit: Any = None) -> float:
    """Part de budget accordée à UN kind : drapeau/appelant > env `FORGE_KIND_BUDGET_SHARE` > 1/3.

    FAIL-OPEN sur une valeur illisible ou hors bornes (comme `_env_run_timeout` et
    `resource_profile._coerce`) : un environnement pollué ne doit pas changer un plan en silence, il
    retombe sur le défaut. `0` (ou négatif) DÉSACTIVE la part — échappatoire explicite pour un
    opérateur qui veut le comportement d'avant ce lot. Une part `>= 1` est acceptée et vaut « pas de
    borne utile » (un kind peut prendre tout le budget) : on ne la corrige pas, on l'obéit."""
    for raw in (explicit, os.environ.get(ENV_KIND_SHARE)):
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        if value != value or value < 0:               # NaN / négatif -> pas d'information
            continue
        return value
    return KIND_SHARE_DEFAULT


class KindShare:
    """Comptabilité CUMULATIVE du temps consommé PAR KIND, et la porte qui en découle.

    `observe(remaining)` est appelé à chaque consultation du budget restant : le PLAFOND retenu est le
    PLUS GRAND restant jamais vu, c'est-à-dire le budget INITIAL à la latence de la première action
    près. C'est délibéré — ça évite d'exiger que l'appelant (CLI, console, test) transmette un
    deuxième canal pour une valeur que le moteur observe déjà. Monotone : le plafond ne peut que
    monter, donc la part ne rétrécit jamais en cours de run.

    `record(kind, secs)` est appelé depuis les WORKERS de tir (`Engine._record_duration`) -> verrouillé.

    LIMITE CONNUE, ET BORNÉE : en parallèle, jusqu'à `pool` actions du même kind peuvent franchir la
    porte avant qu'aucune n'ait été comptabilisée (elles sont évaluées avant de tirer). Le dépassement
    de part est donc borné par `pool - 1` tirs de ce kind. On ne sérialise pas la porte pour ça : ce
    serait payer un verrou global sur le chemin de tir pour resserrer une borne déjà petite.

    stdlib seule ; aucun import de `forge.*` (ce module est importé PAR le moteur et la CLI)."""

    def __init__(self, share: Any = None) -> None:
        self.share = resolve_kind_share(share)
        self._spent: dict[str, float] = {}
        self._fires: dict[str, int] = {}              # nb de tirs comptabilisés (pour la MOYENNE)
        self._ceiling = 0.0
        self._lock = threading.Lock()

    # --- alimentation ------------------------------------------------------------------------------
    def observe(self, remaining: float) -> None:
        """Enregistre un budget RESTANT observé. Le plafond retenu est le maximum (== budget initial)."""
        try:
            value = float(remaining)
        except (TypeError, ValueError):
            return
        if value != value:                            # NaN -> aucune information
            return
        with self._lock:
            if value > self._ceiling:
                self._ceiling = value

    def record(self, kind: str, seconds: float) -> None:
        """Ajoute une durée OBSERVÉE au compteur de ce kind. Best-effort, ne lève jamais."""
        try:
            value = float(seconds)
        except (TypeError, ValueError):
            return
        if value != value or value <= 0:
            return
        with self._lock:
            self._spent[str(kind)] = self._spent.get(str(kind), 0.0) + value
            self._fires[str(kind)] = self._fires.get(str(kind), 0) + 1

    # --- lecture -----------------------------------------------------------------------------------
    @property
    def ceiling(self) -> float:
        """Budget de référence retenu (le plus grand restant observé)."""
        with self._lock:
            return self._ceiling

    @property
    def cap(self) -> float:
        """Secondes qu'UN kind peut consommer au total. 0.0 => aucune part active (gate inerte)."""
        with self._lock:
            return self._ceiling * self.share

    def spent(self, kind: str) -> float:
        with self._lock:
            return self._spent.get(str(kind), 0.0)

    def mean(self, kind: str) -> "float | None":
        """Durée MOYENNE observée pour ce kind SUR CE RUN, ou None (jamais tiré)."""
        with self._lock:
            n = self._fires.get(str(kind), 0)
            return (self._spent.get(str(kind), 0.0) / n) if n else None

    def exhausted(self) -> "dict[str, float]":
        """{kind: secondes} des kinds ayant atteint ou dépassé leur part — pour l'observabilité."""
        cap = self.cap
        if cap <= 0:
            return {}
        with self._lock:
            return {k: v for k, v in sorted(self._spent.items()) if v >= cap}

    # --- décision ----------------------------------------------------------------------------------
    @staticmethod
    def _positive(value: Any) -> "float | None":
        """Flottant STRICTEMENT positif, ou None (absent / illisible / NaN / <= 0). Pur."""
        if value is None:
            return None
        try:
            out = float(value)
        except (TypeError, ValueError):
            return None
        return out if (out == out and out > 0) else None

    def refuse(self, kind: str, bound: Any = None, estimate: "float | None" = None) -> str:
        """Raison NOMMÉE de ne pas DÉMARRER ce tir, ou "" (rien à signaler).

        INERTE tant qu'aucune part n'est active (`share <= 0`) ou qu'aucun budget n'a été observé
        (`ceiling == 0`) : c'est le cas de tout appelant sans `--run-timeout`, donc le comportement
        historique, à une comparaison de flottants près.

        CE QU'ON PRÉDIT, ET POURQUOI PAS LA BORNE — mesuré, et ça change le verdict. La clause absolue
        raisonne sur la BORNE déclarée (le mur), parce qu'il s'agit d'y tenir dans tous les cas. La
        part, elle, raisonne sur la CONSOMMATION, et la borne en est un très mauvais estimateur : sur
        le run de référence, `web.nuclei` déclare 600 s et a consommé 280/378/416 s. Prédire 600 s pour
        son 3e tir le refusait à tort (658 + 600 > 1200), alors qu'il tenait (658 + 416). On prédit donc
        par ordre de préférence :
          1. la MOYENNE OBSERVÉE du kind SUR CE RUN (`mean`) — la meilleure information disponible, et
             elle porte sur CETTE surface : nuclei 329 s -> 3e tir ACCEPTÉ, testssl 441 s -> 3e tir
             REFUSÉ (il a effectivement repris 600 s au mur). C'est ce que la mesure sait, pas ce que
             la déclaration promet ;
          2. à défaut, l'estimation du magasin de durées (`durations.DurationStore.estimate`, le
             sidecar `.durations` du run PRÉCÉDENT de cet engagement) ;
          3. à défaut, la borne déclarée.
        La prédiction est TOUJOURS plafonnée par la borne déclarée : le module ne peut pas dépasser son
        propre mur, prédire au-delà serait refuser sur une valeur impossible."""
        cap = self.cap
        if cap <= 0:
            return ""
        # UNE BORNE DÉCLARÉE N'EST PAS REQUISE ICI, contrairement à la clause absolue — et c'est
        # délibéré. La clause absolue fait fail-open sans borne parce que gater un oracle à 0,1 ms sur
        # une borne fictive supprimerait de la couverture pour rien. La part n'a pas ce problème : un
        # oracle à 0,1 ms n'atteindra JAMAIS un tiers du budget, alors qu'un module natif SANS borne
        # peut parfaitement le manger (`origin.find` : 1 864 s, 24 % du travail du run de référence).
        # Sans borne, on prédit par la mesure (moyenne du run, puis sidecar) ; sans mesure non plus,
        # aucune information -> aucune gate.
        need = self._positive(bound)
        used = self.spent(kind)
        # LA PREMIÈRE ACTION D'UN KIND N'EST JAMAIS REFUSÉE PAR LA PART, et c'est la clause qui
        # empêche l'EXCÈS INVERSE. Sans elle, un budget serré ferait taire ENTIÈREMENT les scanners
        # lents : `web.testssl` (borne 600 s) serait refusé d'office sous 1800 s de budget, `web.nikto`
        # sous 1800 s aussi — or `nikto` a produit les 16 SEULS signaux qualifiables du run mesuré.
        # La part borne la RÉPÉTITION d'un kind (« ne mange pas la moitié du run à toi seul »), pas son
        # EXISTENCE. Tout kind planifié qui passe la clause absolue tire donc AU MOINS UNE FOIS.
        if used <= 0:
            return ""
        predicted = None
        for source in (self.mean(kind), estimate, need):
            predicted = self._positive(source)
            if predicted is not None:
                break
        if predicted is None:                         # aucune information -> aucune gate
            return ""
        if need is not None:
            predicted = min(need, predicted)          # jamais au-delà du mur du module
        if used + predicted <= cap:
            return ""
        declared = f"borne déclarée {_secs_short(need)}" if need is not None else "aucune borne déclarée"
        return (f"non démarrée : part de budget du kind épuisée — `{kind}` a déjà consommé "
                f"{_secs_short(used)} et ce tir en prendrait ~{_secs_short(predicted)} ({declared}), "
                f"pour une part de {_secs_short(cap)} ({self.share:.0%} d'un budget de "
                f"{_secs_short(self.ceiling)}) ; AUCUN verdict n'est émis pour cette action "
                f"(non testée, pas « rien trouvé »)")


def _secs_short(value: float) -> str:
    """Secondes lisibles (`75s`, `1250s`) — miroir local de `engine._secs`, sans import croisé."""
    return f"{float(value):.0f}s"


def _signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except Exception:                             # noqa: BLE001
        return f"signal {signum}"


def interruption_record(term: "Terminate | None", budget: "Budget | None" = None,
                        engine: Any = None) -> "dict[str, Any] | None":
    """Fiche d'interruption consommée par le rapport (`report.build_report(interruption=...)`).

    Purement DÉRIVÉE : cause + détail du `Terminate`, budget s'il y en avait un, et les COMPTEURS de
    couverture que le moteur tient déjà (`results` = actions appliquées, `planned_total` = actions
    ordonnées par le planner, `not_attempted` = ordonnées jamais atteintes). Aucun chiffre fabriqué :
    si le moteur ne porte pas un compteur, la clé vaut None et le rapport dit « inconnu » plutôt que
    d'inventer un dénominateur rassurant. None quand le run n'a PAS été interrompu."""
    if term is None:
        return None
    rec: dict[str, Any] = {"cause": getattr(term, "cause", CAUSE_SIGNAL),
                           "detail": getattr(term, "detail", "") or str(term),
                           "label": CAUSE_LABELS.get(getattr(term, "cause", ""), "arrêt anticipé")}
    if budget is not None:
        rec["budget_secs"] = budget.seconds
        rec["elapsed_secs"] = round(budget.elapsed(), 1)
    if engine is not None:
        results = getattr(engine, "results", None)
        planned = getattr(engine, "planned_total", None)
        pending = getattr(engine, "not_attempted", None)
        rec["ran"] = len(results) if results is not None else None
        rec["planned"] = planned if planned else None
        rec["not_attempted"] = len(pending) if pending is not None else None
        rec["waves"] = getattr(engine, "waves", None)
    return rec

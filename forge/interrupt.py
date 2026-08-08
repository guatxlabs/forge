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

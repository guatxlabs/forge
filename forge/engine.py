# SPDX-License-Identifier: AGPL-3.0-or-later
"""Engine Forge — la boucle de contrôle : plan -> gate ROE -> dry|fire -> ledger -> findings.

Tout passe par la gate `Roe`. Un module n'est JAMAIS appelé en fire() sans verdict FIRE.
Chaque action est tracée (results) avec son verdict pour le rapport anti-masquage.

Le planner coverage-safe et le graphe d'engagement se branchent en option (P2) ; v0
fonctionne sans, en mode liste-d'actions explicite.
"""
from __future__ import annotations

import enum
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .roe import Roe, VETO, DRY_RUN, FIRE
from .graph import EngagementGraph
from . import infra_urls
from . import modules as mods
from . import pin
from . import purple
from . import resource_profile
from . import session
from . import throttle

if TYPE_CHECKING:                                         # imports paresseux (type-checking uniquement)
    from collections.abc import Callable, Iterable
    from .roe import Action, Scope
    from .ledger import Ledger
    from .planner import Planner
    from .schema import Finding, Target

# Kinds dont le module DÉCOUVRE/RÉSOUT des hôtes à runtime (au-delà de la cible gatée par le ROE) :
# l'engine leur injecte le périmètre (in_scope/out_scope) dans action.params pour que chaque hôte
# dérivé soit re-validé fail-closed AVANT émission/connexion (cf. _prepare + modules recon_surface/origin).
_SCOPE_INJECT_KINDS = frozenset({
    "origin.find", "recon.subdomains", "recon.dns", "recon.js_endpoints", "recon.urls", "recon.tech",
    # modules ACTIFS de reachability/discovery (recon_active.py) : ils requêtent/dérivent des assets
    # à runtime -> re-validation fail-closed contre le périmètre injecté (cf. recon_active).
    "recon.content", "recon.secrets", "recon.waf",
    # DÉCOUVERTE backed-browser (evasion.discover) : navigue derrière le WAF et EXTRAIT des endpoints
    # à runtime -> mêmes garanties que recon.js_endpoints : le périmètre injecté sert à RE-VALIDER
    # fail-closed chaque endpoint découvert avant émission (le scope-guard du module en dépend).
    "evasion.discover",
    # OUTILS OSS PRÉ-WRAPPÉS (toolcatalog.py) qui DÉCOUVRENT des ASSETS à runtime (sous-domaines, hosts
    # résolus, ports, URLs crawlées/archivées, routes) : le périmètre injecté sert au wrapper à RE-VALIDER
    # fail-closed chaque asset découvert avant d'émettre un finding (jamais un asset hors périmètre).
    "recon.subfinder", "recon.amass", "recon.dnsx", "recon.naabu",
    "recon.katana", "recon.gau", "recon.gospider", "recon.feroxbuster",
    # ORACLES à VÉRIFICATION qui sondent des URL DÉRIVÉES de params (urls/whoami/bypass/admin_urls,
    # IDs énumérés, cible d'origine) : le périmètre injecté active leur scope-guard PAR-URL fail-closed
    # (ScopeGuardedOracle) pour qu'aucune requête — ni le matériel de session gouverné qu'elle porte —
    # ne parte vers une URL hors périmètre. Sans injection, `_scope` serait permissif (enforce=False).
    "access_control.idor", "access_control.privesc", "auth.takeover", "cors.credentials",
})

def _oracle_rate_kinds():
    """Kinds à HTTP-oracle (sous-classes `Oracle`) : leur trafic sortant passe par `Oracle._http` et
    respecte donc le THROTTLE du scope (rate). DÉRIVÉ du registre — aucune liste à maintenir à la main
    (un nouvel oracle @register est couvert automatiquement). Ne lève jamais (registre indisponible -> ∅)."""
    try:
        from .modules.oracle import Oracle
        return frozenset(k for k in mods.kinds() if isinstance(mods.get(k), Oracle))
    except Exception:                                        # noqa: BLE001
        return frozenset()


# Kinds ACTIFS rate-limités : l'engine injecte le débit ROE du scope (`rate`) dans action.params pour
# que le module borne son trafic. Deux familles : (1) les modules de découverte active qui passent `rate`
# à leur outil (ex: ffuf -rate) ; (2) TOUS les oracles à HTTP (`Oracle._http`) qui respectent le throttle
# min-interval du moteur. Additif (setdefault) : n'écrase jamais un param posé. rate<=0/absent => no-op.
_RATE_LIMITED_KINDS = frozenset({"recon.content", "recon.secrets", "recon.waf"}) | _oracle_rate_kinds()

# Kinds d'OUTILS (natifs + wrappers) dont un DRAPEAU CLI de débit est piloté par `rate` (nmap --max-rate,
# nuclei -rl, httpx -rl, naabu -rate, masscan --rate, feroxbuster --rate-limit, sqlmap/wfuzz/dalfox/
# gobuster --delay dérivé). Le débit y est injecté UNIQUEMENT sur override EXPLICITE (`scope.rate_explicit`)
# -> sans override, aucun drapeau n'est ajouté (argv BYTE-IDENTIQUE au défaut ; masscan garde --rate 1000).
_RATE_FLAG_KINDS = frozenset({
    "recon.nmap", "web.nuclei", "recon.httpx", "recon.naabu", "recon.masscan", "recon.feroxbuster",
    "sqli.sqlmap", "fuzz.wfuzz", "xss.dalfox", "recon.gobuster_dns",
})


# --- PARALLÉLISME INTRA-VAGUE BORNÉ (G3) ----------------------------------------------------------
# L'exécution d'une action se scinde en DEUX temps (cf. Engine._decide_blocking / _apply) :
#   (1) le TIR bloquant (module.fire/dry — sous-process nikto/nuclei/testssl, I/O réseau) qui LIBÈRE le
#       GIL et se PARALLÉLISE sans risque (aucun effet de bord partagé) ; il tourne dans un pool de
#       threads BORNÉ ;
#   (2) les MUTATIONS D'ÉTAT (append ledger, ingest console/checkpoint, decision ROE journalisée,
#       findings/graph/compteurs, sessions.inherit) qui, elles, restent STRICTEMENT SÉRIELLES et
#       ORDONNÉES (thread principal, dans l'ordre d'action) — pour que la chaîne append-only du ledger
#       demeure reproductible et tamper-evident (H1/M1/M2) et que D1/E2/E3/E4 composent inchangés.
# La parallélisation ne concerne QUE (1). (2) n'est jamais concurrent. FORGE_PARALLELISM=1 (ou pool<=1)
# => chemin sériel historique, byte-identique. Défaut CONSERVATEUR = 4.
_DEFAULT_PARALLELISM = 4


def _parallelism() -> int:
    """Cap de l'exécuteur intra-vague. PRÉCÉDENCE : `FORGE_PARALLELISM` (override env, PRIME toujours —
    rétro-compat) > profil de ressources (`FORGE_RESOURCE_PROFILE`) > défaut-code 4. `balanced` (défaut)
    == 4 => profil non défini byte-identique. `low` => 1 (chemin SÉRIEL historique). Valeur illisible =>
    fail-through vers le profil. Borné à [1, 64] (garde-fou anti-abus)."""
    env = os.environ.get("FORGE_PARALLELISM")
    v = resource_profile.resolve("parallelism", override=env, default=_DEFAULT_PARALLELISM)
    if not isinstance(v, int):
        v = _DEFAULT_PARALLELISM
    if v < 1:
        return 1
    return min(v, 64)


def _action_cost(action: Action) -> float:
    """Coût d'une action, NORMALISÉ pour servir de clé de palier de REPLI (cf. `Engine._preheat_key`).
    Un coût absent / non numérique / NaN / <= 0 vaut 1.0 (neutre) : les paliers restent comparables
    et ordonnables, aucune vague ne peut faire lever le tri. Miroir du `max(action.cost, 0.01)` du
    planner, côté ordonnancement."""
    try:
        c = float(getattr(action, "cost", 1.0))
    except (TypeError, ValueError):
        return 1.0
    if c != c or c <= 0.0:                             # NaN (c != c) ou coût nul/négatif -> neutre
        return 1.0
    return c


def _shutdown_executor(ex: Any) -> None:
    """Ferme l'exécuteur SANS attendre (`wait=False`) et ANNULE les tâches encore en file d'attente
    (`cancel_futures`) — sur un arrêt gracieux (_Terminate) ou une exception, on ne DÉMARRE plus de
    nouveau tir ; les tirs DÉJÀ en vol sont coupés séparément par le handler SIGTERM du moteur
    (`runner.terminate_live_tool_groups`, E4). `cancel_futures` (py>=3.9) — repli défensif sinon."""
    try:
        ex.shutdown(wait=False, cancel_futures=True)
    except TypeError:  # pragma: no cover — cancel_futures indisponible (<3.9)
        ex.shutdown(wait=False)


class Verdict(enum.Enum):
    """Verdict d'exécution d'une action — enum INTERNE au moteur. Les trois verdicts ROE
    (VETO/DRY_RUN/FIRE) reprennent VERBATIM les chaînes de `roe` (source de vérité, comparées par
    `coverage()`), plus les deux verdicts propres au moteur (ERROR/SKIP). La sérialisation
    (`ExecResult.to_dict`) émet TOUJOURS la CHAÎNE (`.value`) : la frontière JSON (results/ledger/
    console/rapport) reste byte-à-byte identique au pré-refactor."""
    VETO = VETO
    DRY_RUN = DRY_RUN
    FIRE = FIRE
    ERROR = "ERROR"
    SKIP = "SKIP"


class Phase(enum.Enum):
    """Étage de la boucle `execute()` qui a PRODUIT un résultat — enum INTERNE (jamais sérialisé :
    absent de `to_dict()`, donc aucun changement de forme de sortie). Sert à nommer sans ambiguïté
    les six points de construction d'un `ExecResult` (traçabilité de la gouvernance/gate)."""
    NO_MODULE = "no_module"                    # aucun module enregistré pour le kind
    GOVERNANCE_DISABLED = "governance_disabled"  # connecteur désactivé (console)
    TECHNIQUE_DESELECTED = "technique_deselected"  # technique hors sélection par-scope
    INFRA_NON_TARGET = "infra_non_target"      # cible = namespace d'edge RÉSERVÉ (CDN/WAF) — pas une cible
    UNAVAILABLE = "unavailable"                # outil/service sous-jacent absent
    DECIDED = "decided"                        # verdict rendu par la gate ROE (VETO/DRY_RUN/FIRE)
    FIRE_ERROR = "fire_error"                  # M6 — exception LEVÉE pendant le tir (module.fire/post-traitement)


@dataclass
class ExecResult:
    """Résultat d'exécution d'une action. Centralise la construction des enregistrements auparavant
    bâtis à la main en 5 endroits. `to_dict()` reproduit EXACTEMENT les clés/valeurs historiques
    ({action,target,kind,verdict,reasons,output}) — `phase` reste interne (non émis). `verdict` peut
    être un `Verdict` (chemins moteur) ou la chaîne de verdict ROE brute (chemin `decision.verdict`) ;
    dans les deux cas `to_dict` émet la chaîne."""
    action: str
    target: str
    kind: str
    verdict: Verdict | str
    reasons: list[str]
    output: object = None
    phase: Phase | None = None

    def to_dict(self) -> dict[str, Any]:
        verdict = self.verdict.value if isinstance(self.verdict, Verdict) else self.verdict
        return {"action": self.action, "target": self.target, "kind": self.kind,
                "verdict": verdict, "reasons": self.reasons, "output": self.output}


@dataclass
class _Pending:
    """Résultat du TIR BLOQUANT d'une action (`Engine._decide_blocking`), calculé DANS un thread worker
    SANS AUCUN effet de bord sur l'état du moteur/ledger/console. `Engine._apply` le consomme sur le
    THREAD PRINCIPAL, dans l'ORDRE d'action déterministe, pour appliquer les mutations (append ledger,
    ingest, decision ROE, findings/graph/compteurs) — le point de sérialisation qui préserve l'ordre
    append-only du ledger. Deux familles de chemin :

      • CHEMIN SIMPLE (module absent / SKIP gouvernance-connecteur / technique désélectionnée / outil
        indisponible) : le `res` est déjà construit (aucune décision ROE) — `_apply` l'ajoute juste à
        `results` (+ `engine.error` au ledger si `simple_ledger_error`).
      • CHEMIN DÉCISION (VETO/DRY_RUN/FIRE) : porte la `Decision` (dont le log `roe.decision` est DIFFÉRÉ
        à `_apply`), le module, la sortie `dry()` (DRY_RUN), et — pour FIRE — les findings BRUTS du
        `fire()` (`raw`) OU l'exception CAPTURÉE du tir (`fire_exc` -> devient un ExecResult FIRE_ERROR à
        l'application, miroir du try/except M6 sériel), plus les compteurs de throttle relus après le tir."""
    action: Action
    simple_res: dict[str, Any] | None = None
    simple_ledger_error: bool = False            # chemin simple -> engine.error (NO_MODULE)
    simple_non_target: str = ""                  # famille d'infra reconnue -> CONSTAT unique dans _apply
    decision: Any = None                         # roe.Decision — log `roe.decision` différé à _apply
    module: Any = None
    output: Any = None                           # sortie dry() (DRY_RUN) ; None (VETO)
    is_fire: bool = False
    raw: "list[Any] | None" = None               # findings bruts du fire() (FIRE réussi)
    fire_exc: BaseException | None = None        # exception capturée du fire() (FIRE en erreur)
    bucket_blocked: int = 0                      # 429/WAF persistants relus sur le throttle après le tir
    bucket_rate: float = 0.0


class Engine:
    def __init__(self, scope: Scope, ledger: "Ledger | None" = None, mode: str = "propose",
                 memory: Any = None, graph: EngagementGraph | None = None,
                 campaign: str | None = None, run_id: str | None = None,
                 progress: "Callable[[str], None] | None" = None,
                 durations: Any = None) -> None:
        self.scope = scope
        self.ledger = ledger
        self.memory = memory       # memory.Memory | None — dedup + persistance des findings
        # DURÉES OBSERVÉES PAR KIND (`durations.DurationStore` | None) — la seule chose qu'elles
        # pilotent est l'ORDRE DE SOUMISSION du préchauffage (`_preheat_key`) ; AUCUNE décision de tir
        # n'en dépend. None (défaut : CLI directe sans `--ledger`, tests) => aucune mesure enregistrée,
        # aucun fichier, et `_preheat_key` retombe sur `action.cost` — comportement byte-identique à
        # avant l'instrumentation. Cf. `forge/durations.py` pour la portée par-engagement et la garde
        # de non-identification (agrégat PAR KIND, jamais par cible).
        self.durations = durations
        self.graph = graph if graph is not None else EngagementGraph()
        self.roe = Roe(scope, ledger=ledger, mode=mode)
        # SESSION GOUVERNÉE (SECRET) : store d'authentification dérivé du scope (`session` défaut global
        # + `sessions` par-hôte). Lié autour de chaque fire() (execute) ; les modules recon/oracle y
        # puisent le matériel à attacher AUX SEULES requêtes in-scope. Store inerte si rien de configuré.
        self.sessions = session.SessionStore.from_scope(scope)
        # CONTEXTE D'AUTHENTIFICATION PAR-ENGAGEMENT (R5, SECRET) : comptes de test LABELLISÉS de
        # l'opérateur (attaquant + victime) + idor_targets structurés, dérivés du bloc `scope.auth`.
        # None si aucun bloc `auth` (INERTE : l'oracle IDOR retombe sur son chemin historique « config
        # manquante » — aucun changement de comportement). Injecté dans les actions IDOR par `_prepare`
        # et sa MISE EN USAGE est journalisée une fois (`engine.auth_context`, labels + compte de
        # cibles, JAMAIS les secrets) pour qu'un run ayant utilisé des creds soit auditable.
        self.auth_context = session.AuthContext.from_scope(scope)
        self._auth_ledgered = False                       # `engine.auth_context` émis au plus une fois
        # SÉLECTION DE TECHNIQUES PAR-SCOPE (enforcement fail-closed) — snapshot de l'ensemble EFFECTIF
        # de kinds ACTIVÉS pour ce scope (profil + toggles catégorie/technique, DÉRIVÉ de la table
        # unique). `enabled_kinds is None` <=> scope LEGACY (aucune sélection) => AUCUN filtrage
        # (rétro-compat STRICTE : n'importe quel kind enregistré — y compris un connecteur ad-hoc hors
        # table — tire comme avant). Configuré => une technique HORS de cet ensemble n'est NI planifiée
        # (_prepare) NI tirée (execute), en PLUS du scope-guard et de la gouvernance connecteur. Le scope
        # ne change pas pendant un run -> snapshot unique.
        self.enabled_kinds = (scope.effective_technique_kinds()
                              if scope.technique_selection_configured() else None)
        self.campaign_id = campaign  # boucle purple : corrèle les run-records à la campagne…
        self.run_id = run_id         # …et au run (console). None tant que non fournis (additif).
        # ÉMISSION PROGRESSIVE (OPTIONNELLE, additive) : callback `progress(line: str)` invoqué au fil de
        # l'eau — une ligne par action exécutée (via run()) + une bannière par vague (via campaign()) —
        # pour que la console STREAME l'avancement en direct (SSE). None par défaut (CLI directe, tests) :
        # AUCUN appel, AUCUNE sortie -> comportement byte-à-byte inchangé. Ne touche RIEN de la
        # gouvernance/ROE ni des findings : pure observabilité (ne fait que refléter des res déjà décidés).
        self._progress = progress
        self.findings: list[Finding] = []
        self.results: list[dict[str, Any]] = []          # [{action, verdict, reasons, output}]
        self.run_records: list[dict[str, Any]] = []      # boucle purple : un record ATT&CK par action tirée
        self.skipped_budget: list[Action] = []           # actions déférées par le planner (defer != delete)
        self.coverage_gaps: dict[str, list[str]] = {}    # classes jamais tentées, par cible
        # ANTI-LACUNE SILENCIEUSE (bucket manquant) : modules SÉLECTIONNÉS/DISPONIBLES que le planner
        # n'a JAMAIS ordonnancés (jamais entrés dans results) -> {kind: raison}. Un module dont l'outil
        # était présent mais que le plan n'a pas planifié (mode lecture seule, capacités de l'engagement,
        # surface non concordante) ne tombait dans AUCUN bucket (ni fired/dry/vetoed/errors ni skipped_budget
        # ni coverage_gaps) : il DISPARAISSAIT du rapport. Rempli par campaign() ; la raison est DÉRIVÉE des
        # métadonnées du module + des capacités du scope (jamais fabriquée).
        self.selected_modules: set[str] = set()          # univers des modules demandés pour ce run
        self.not_planned: dict[str, str] = {}            # {kind: raison} — disponibles mais jamais planifiés
        self.dups = 0              # findings ignorés car déjà en mémoire
        self.waves = 0             # nb de vagues plan->observe->replan exécutées (campagne itérative)
        # PROFIL DE RESSOURCES ACTIF (audit) — rempli au lancement de campaign() (snapshot profil +
        # leviers effectifs). None tant qu'aucune campagne n'a démarré (run() direct des tests).
        self.resource_profile: dict[str, Any] | None = None
        # NON-CIBLES D'INFRASTRUCTURE RECONNUES (`infra_urls`) : {cible: famille d'edge}. Le CONSTAT est
        # DIT UNE FOIS par cible (ligne de progression + entrée ledger `engine.non_target`), mais CHAQUE
        # action visée reste un SKIP nommé dans `results` -> comptée dans `coverage()['errors']` et LISTÉE
        # dans le rapport. Reconnu != supprimé : rien n'est écarté en silence.
        self.non_targets: dict[str, str] = {}

    # --- usage du contexte d'authentification (audit) ---
    def _ledger_auth_use(self) -> None:
        """Journalise UNE SEULE FOIS qu'un contexte d'auth par-engagement a été MIS EN USAGE (injecté
        dans une action IDOR). Détail SÛR : labels des comptes + nombre de cibles (via
        `AuthContext.ledger_summary`) — JAMAIS un secret (header/cookie/bearer). No-op si aucun
        contexte, si déjà journalisé, ou si aucun ledger n'est branché."""
        if self._auth_ledgered or self.auth_context is None:
            return
        self._auth_ledgered = True
        if self.ledger is not None:
            self.ledger.append("engine.auth_context", self.auth_context.ledger_summary())
        # MATÉRIEL PÉRIMÉ — le DIRE au RUN, pas seulement finding par finding. Un jeton dont l'`exp`
        # est dépassé désarme les oracles de contrôle d'accès : sans ce signal, le run se déroule
        # normalement et rend un rapport PROPRE et VIDE qui ressemble à « cible saine ». Émis une
        # seule fois (même garde que l'événement ci-dessus), et UNIQUEMENT quand la péremption est
        # PROUVÉE (`exp` lisible et dépassé) : aucun bruit sur du matériel opaque. SÛR : des LABELS
        # et un compteur, JAMAIS un jeton (même contrat que `ledger_summary`).
        dead = self.auth_context.expired_labels()
        if not dead:
            return
        if self.ledger is not None:
            self.ledger.append("engine.auth_expired",
                               {"accounts": dead, "census": self.auth_context.expiry_census()})
        self._emit(f"[AUTH] matériel d'authentification EXPIRÉ pour {dead} — les oracles de contrôle "
                   "d'accès rendront 'skipped' (non testé), JAMAIS 'rien trouvé'")

    # --- armement délégué (gestes journalisés) ---
    def arm(self, reason: str = "armed by operator") -> None:
        self.roe.arm(reason)

    def approve(self, action_id: str, reason: str = "approved by operator") -> None:
        self.roe.approve(action_id, reason)

    # --- exécution d'une action via son module ---
    # SCINDÉE en DEUX (G3, parallélisme intra-vague) : `_decide_blocking` fait le TIR BLOQUANT (fire/dry)
    # SANS effet de bord (parallélisable dans un pool de threads borné) ; `_apply` fait TOUTES les mutations
    # d'état (ledger/ingest/decision/findings/graph/compteurs) SÉRIELLEMENT, dans l'ordre d'action. En
    # SÉRIEL, `execute` compose simplement les deux -> byte-identique à l'ancien monolithe (mêmes opérations,
    # même ordre, même thread). Seul détail : `roe.decision` est journalisée dans `_apply` (après le tir)
    # au lieu de pendant `decide()` — mais TOUJOURS avant les findings/run-record de l'action, donc l'ORDRE
    # append-only du ledger est identique (seul l'horodatage — déjà non reproductible d'un run à l'autre —
    # se décale). Cette symétrie est le socle de la preuve de déterminisme parallèle==sériel.
    def execute(self, action: Action) -> dict[str, Any]:
        return self._apply(self._decide_blocking(action))

    def _decide_blocking(self, action: Action) -> _Pending:
        """PHASE 1 (parallélisable) : résout le module, applique les portes SKIP, rend le verdict ROE
        (SANS journaliser — log différé), et exécute le TIR BLOQUANT (`module.dry`/`module.fire`, les
        sous-process/I/O). AUCUN effet de bord sur l'état du moteur/ledger/console : tout est renvoyé dans
        un `_Pending` que `_apply` consommera sur le thread principal, dans l'ordre. Sûr à appeler depuis
        plusieurs threads : les contextes throttle/session/pin sont THREAD-LOCAL (liés DANS ce thread), le
        registre pgid de `runner` est verrouillé, et le cache DNS du scope est verrouillé (résolution
        déterministe par-hôte). Une exception du `fire()` est CAPTURÉE (pas propagée) pour devenir un
        FIRE_ERROR à l'application — miroir exact du try/except M6 sériel."""
        module = mods.get(action.kind)
        if module is None:
            res = ExecResult(action=action.id, target=action.target, kind=action.kind,
                             verdict=Verdict.ERROR,
                             reasons=[f"aucun module enregistré pour '{action.kind}'"],
                             output=None, phase=Phase.NO_MODULE).to_dict()
            return _Pending(action, simple_res=res, simple_ledger_error=True)

        # GOUVERNANCE CONNECTEUR (console) : un kind DÉSACTIVÉ par l'opérateur (scope.disabled_modules)
        # est SKIP comme un outil absent — même si son binaire/service EST présent. C'est l'enforcement
        # au tir de la gouvernance UI : disabling un connecteur empêche RÉELLEMENT le module de tirer,
        # y compris quand c'est le planner (et non `--modules`) qui l'a choisi. Vérifié avant la sonde
        # `available` pour porter la raison la plus spécifique dans le rapport anti-masquage.
        disabled = getattr(self.scope, "disabled_modules", None) or set()
        if action.kind in disabled:
            res = ExecResult(action=action.id, target=action.target, kind=action.kind,
                             verdict=Verdict.SKIP,
                             reasons=["module désactivé par la console (gouvernance connecteur)"],
                             output=None, phase=Phase.GOVERNANCE_DISABLED).to_dict()
            return _Pending(action, simple_res=res)

        # SÉLECTION DE TECHNIQUES PAR-SCOPE — ENFORCEMENT AU TIR (fail-closed) : une technique HORS de
        # l'ensemble EFFECTIF activé pour ce scope (profil/catégorie/technique désactivée) est SKIP
        # EXACTEMENT comme un connecteur désactivé — MÊME si son module est disponible et la cible
        # in-scope. C'est le plancher qui garantit qu'une technique retirée « au scope » ne tire JAMAIS,
        # y compris si elle échappait au filtre du planner. No-op sur un scope legacy (enabled_kinds is
        # None). Vérifié AVANT la sonde `available` et la gate ROE (raison la + précise).
        if self.enabled_kinds is not None and action.kind not in self.enabled_kinds:
            res = ExecResult(action=action.id, target=action.target, kind=action.kind,
                             verdict=Verdict.SKIP,
                             reasons=["technique désactivée pour ce scope (sélection profil/catégorie/technique)"],
                             output=None, phase=Phase.TECHNIQUE_DESELECTED).to_dict()
            return _Pending(action, simple_res=res)

        # NON-CIBLE D'INFRASTRUCTURE (défense en profondeur, ZÉRO réseau) : la cible est une URL d'un
        # namespace d'edge RÉSERVÉ (Cloudflare `/cdn-cgi/`, défi Akamai/Incapsula…) — terminée à l'edge,
        # aucun code applicatif derrière, donc rien à tester. C'est le MUR pris pour la cible : sur un run
        # réel, l'URL de défi Cloudflare capturée par la découverte backed-browser a mangé 85 des 1573
        # tirs (5,4 %) et fait planter `origin.find`. Les modules de surface l'écartent déjà à l'ÉMISSION
        # (elle n'entre pas dans le graphe) ; cette gate couvre TOUTES les autres voies (crawlers
        # spec-driven, proposition directe, console) d'où une telle cible pourrait encore arriver.
        #
        # RECONNU != SUPPRIMÉ (contrat coverage-safe) : verdict SKIP — « je n'ai pas vérifié » — avec une
        # raison NOMMÉE (famille + pourquoi + les deux échappatoires), comptée dans `coverage()['errors']`
        # et LISTÉE dans le rapport. Jamais un `tested` (« j'ai vérifié, rien trouvé »), jamais un silence.
        # Vérifié AVANT `available` : « ce n'est pas une cible » explique mieux la classe entière de skips
        # que « l'outil est absent ». Échappatoires : motif in_scope nommant le chemin, ou
        # FORGE_ALLOW_INFRA_TARGETS=1 (un endpoint d'edge PEUT être une vraie cible sur certains engagements).
        family = infra_urls.classify(action.target, allow_patterns=self.scope.in_scope)
        if family:
            res = ExecResult(action=action.id, target=action.target, kind=action.kind,
                             verdict=Verdict.SKIP, reasons=[infra_urls.skip_reason(family)],
                             output=None, phase=Phase.INFRA_NON_TARGET).to_dict()
            return _Pending(action, simple_res=res, simple_non_target=family)

        if getattr(module, "available", True) is False:
            res = ExecResult(action=action.id, target=action.target, kind=action.kind,
                             verdict=Verdict.SKIP,
                             reasons=["module indisponible (outil sous-jacent absent)"],
                             output=None, phase=Phase.UNAVAILABLE).to_dict()
            return _Pending(action, simple_res=res)

        # le module peut imposer exploit/destructif au-delà de ce que l'action déclare
        action.exploit = action.exploit or bool(getattr(module, "exploit", False))
        action.destructive = action.destructive or bool(getattr(module, "destructive", False))

        # DÉCISION ROE — log DIFFÉRÉ (`log=False`) : le verdict est calculé ici (résolution DNS bornée +
        # épinglage IP inclus, chemin de tir), mais l'entrée `roe.decision` est journalisée par `_apply`
        # sur le thread principal, dans l'ordre déterministe -> le ledger reste mono-écrivain et ordonné.
        decision = self.roe.decide(action, log=False)

        if decision.verdict == VETO:
            return _Pending(action, decision=decision, module=module, output=None, is_fire=False)
        if decision.verdict == DRY_RUN:
            output = module.dry(action)              # AUCUN effet de bord (contrat module)
            return _Pending(action, decision=decision, module=module, output=output, is_fire=False)

        # FIRE — le TIR BLOQUANT. On lie les contextes THREAD-LOCAL (throttle/session/pin) le temps du
        # fire (voir la version historique pour le détail des trois garanties : throttle min-interval,
        # session gouvernée scope-guardée, pin anti-rebinding end-to-end). Tout se fait DANS ce thread :
        # les contextes sont donc visibles par `module.fire` (même thread) et isolés des autres workers.
        pending = _Pending(action, decision=decision, module=module, is_fire=True)
        if decision.pinned_ips:
            action.params["_pinned_ips"] = list(decision.pinned_ips)
        # INSTRUMENTATION DE DURÉE (horloge MONOTONE — jamais l'heure murale, qu'un NTP peut faire
        # reculer). On chronomètre EXACTEMENT ce qui occupe un worker du pool : le tir bloquant, liaison
        # des contextes thread-local comprise. Enregistré même si le tir LÈVE (le worker a bien été
        # occupé ; la médiane de l'anneau absorbe un échec isolé). Le DRY-RUN n'est PAS chronométré, et
        # c'est délibéré : `dry()` est sans effet de bord par contrat, donc quasi instantané — mesurer
        # une campagne non armée EMPOISONNERAIT le magasin en apprenant que `web.testssl` prend 3 ms.
        t0 = time.monotonic()
        try:
            with throttle.using(action.params.get("rate")) as _bucket, session.using(self.sessions), \
                    pin.using(action.target, action.params.get("_pinned_ips")):
                pending.raw = module.fire(action) or []
            # THROTTLING PERSISTANT : compteur 429/WAF relu après le tir (surface un marqueur « rate-limited »
            # dans les raisons à l'application, au lieu d'empties silencieux). Différé pour ne PAS muter
            # `decision.reasons` avant que `_apply` n'ait journalisé la `roe.decision` d'origine.
            if _bucket is not None:
                pending.bucket_blocked = int(getattr(_bucket, "blocked", 0) or 0)
                pending.bucket_rate = float(getattr(_bucket, "rate", 0.0) or 0.0)
        except Exception as e:  # noqa: BLE001 — capturée -> FIRE_ERROR à l'application (miroir M6 sériel)
            pending.fire_exc = e
        finally:
            self._record_duration(action.kind, time.monotonic() - t0)
        return pending

    def _note_non_target(self, target: str, family: str) -> None:
        """CONSTAT UNIQUE par cible non-ciblable : « ce n'est pas une cible, c'est le mur ». Dit UNE FOIS
        (ligne de progression + entrée ledger `engine.non_target`) au lieu d'être redécouvert action après
        action. Les actions SUIVANTES sur cette cible restent chacune un SKIP nommé dans `results` —
        c'est le constat qui est unique, pas la traçabilité. Appelé depuis `_apply` : thread principal,
        ordre d'action déterministe (le ledger reste mono-écrivain et reproductible)."""
        if target in self.non_targets:
            return                                       # déjà constaté -> on ne le redit pas
        self.non_targets[target] = family
        reason = infra_urls.skip_reason(family)
        self._emit(f"[NON-CIBLE] {target} — {reason}")
        if self.ledger:
            self.ledger.append("engine.non_target",
                               {"target": target, "family": family, "reason": reason})

    def _record_duration(self, kind: str, seconds: float) -> None:
        """Verse UNE durée observée au magasin par-engagement, s'il est branché. No-op strict sinon
        (une comparaison à None : c'est tout ce que coûte l'instrumentation quand elle est éteinte).
        Best-effort : un magasin en défaut ne doit JAMAIS avorter un tir. Appelé depuis les workers de
        tir -> `DurationStore.record` est verrouillé. Ne passe QUE le kind : aucune cible ne sort d'ici."""
        store = self.durations
        if store is None:
            return
        try:
            store.record(kind, seconds)
        except Exception:  # noqa: BLE001 — cache de performance : jamais une cause d'échec de run
            pass

    def _apply(self, pending: _Pending) -> dict[str, Any]:
        """PHASE 2 (SÉRIELLE, thread principal, ordre d'action) : applique les MUTATIONS d'état d'un
        `_Pending`. C'est le SEUL point où l'on écrit le ledger, journalise la décision ROE, déduplique/
        stocke les findings, enrichit le graphe, incrémente les compteurs et pose l'héritage de session.
        Jamais appelé concurremment -> la chaîne append-only du ledger et l'ingest console restent
        déterministes et reproductibles (identiques au sériel)."""
        action = pending.action

        # CHEMIN SIMPLE (aucune décision ROE) : le res est déjà construit.
        if pending.simple_res is not None:
            self.results.append(pending.simple_res)
            if pending.simple_ledger_error and self.ledger:
                self.ledger.append("engine.error", pending.simple_res)
            if pending.simple_non_target:
                self._note_non_target(action.target, pending.simple_non_target)
            return pending.simple_res

        decision = pending.decision
        module = pending.module
        # LOG DIFFÉRÉ de la décision ROE — MÊME appel best-effort que `_finish`/`_log` en sériel, mais posé
        # ICI (thread principal, ordre déterministe) et TOUJOURS AVANT les findings/run-record de l'action :
        # l'ordre relatif dans le ledger est donc identique au sériel (roe.decision -> finding(s) -> runrecord).
        self.roe._log("roe.decision", decision.to_dict())

        if not pending.is_fire:                      # VETO (output None) ou DRY_RUN (output = dry())
            res = ExecResult(action=action.id, target=action.target, kind=action.kind,
                             verdict=decision.verdict, reasons=decision.reasons, output=pending.output,
                             phase=Phase.DECIDED).to_dict()
            self.results.append(res)
            return res

        # FIRE — M6 : le post-traitement (+ la ré-émission d'une éventuelle exception CAPTURÉE au tir) est
        # enveloppé dans le MÊME try/except qu'en sériel. Une exception (tir OU append ledger/mémoire)
        # devient un ExecResult(ERROR) traçable (results + ledger) et la vague suivante continue.
        try:
            if pending.fire_exc is not None:
                raise pending.fire_exc               # exception du fire() -> même handler qu'en sériel
            raw = pending.raw or []
            # THROTTLING PERSISTANT : marqueur « rate-limited » (APRÈS le log roe.decision d'origine, comme
            # en sériel où l'augmentation suit le fire et ne touche pas l'entrée déjà journalisée).
            if pending.bucket_blocked:
                decision.reasons = list(decision.reasons) + [
                    f"rate-limited: {pending.bucket_blocked} réponse(s) 429/WAF après back-off "
                    f"(débit {pending.bucket_rate:g}/s)"]
            new = []
            for f in raw:
                if self.memory is not None and not self.memory.store(f):
                    self.dups += 1                   # déjà vu -> dedup (ordre déterministe : phase 2 sérielle)
                    continue
                new.append(f)
                self.findings.append(f)
                self.graph.add_finding(f)            # enrichit le world-model
                # SESSION À TRAVERS LA CHAÎNE : un module de découverte a dérivé un NOUVEL hôte/endpoint
                # in-scope (origine IP, sous-domaine, endpoint) depuis action.target. On fait HÉRITER à
                # cette cible dérivée la session gouvernée de la source (SCOPE-GUARDÉE : no-op si la
                # dérivée est hors-scope) pour que les oracles chaînés soient authentifiés. Le matériel
                # reste SECRET : `inherit` ne journalise/retourne rien et n'entre ni dans le finding, ni
                # dans le ledger, ni dans action.params, ni dans le graphe.
                dst = getattr(f, "target", None)
                if dst and dst != action.target:
                    self.sessions.inherit(action.target, dst)
                if self.ledger:
                    self.ledger.append("finding", f.to_dict())
            # run-record purple : la technique a été exécutée. Priorité du mitre (le VRAI prime) :
            #   1. params.mitre (posé par le scope/console)   2. mitre du 1er finding émis
            #   3. mitre déclaré par le module                4. fallback par-kind (DEFAULT_MITRE_BY_KIND)
            # Le repli par-kind garantit un record NON VIDE même pour un tir SANS finding sur un module
            # à mitre='' (sinon trou de couverture purple sur les tirs « rien trouvé »).
            mitre = (action.params.get("mitre") or (new[0].mitre if new else "")
                     or getattr(module, "mitre", "") or purple.mitre_for_kind(action.kind) or "")
            rr = purple.run_record(action.target, action.kind, mitre, fired=True,
                                   detail=f"{len(new)} finding(s)",
                                   run_id=self.run_id, campaign=self.campaign_id)
            self.run_records.append(rr)
            if self.ledger:
                self.ledger.append("purple.runrecord", rr)
            output = [f.to_dict() for f in new]
        except Exception as e:  # noqa: BLE001 — un crash de module ne doit jamais avorter la campagne
            res = ExecResult(action=action.id, target=action.target, kind=action.kind,
                             verdict=Verdict.ERROR,
                             reasons=[f"exception au tir (module '{action.kind}'.fire): {e!r}"],
                             output=None, phase=Phase.FIRE_ERROR).to_dict()
            self.results.append(res)
            if self.ledger:
                self.ledger.append("engine.error", res)
            return res

        res = ExecResult(action=action.id, target=action.target, kind=action.kind,
                         verdict=decision.verdict, reasons=decision.reasons, output=output,
                         phase=Phase.DECIDED).to_dict()
        self.results.append(res)
        return res

    # --- émission progressive (observabilité live ; no-op si aucun callback) ---
    def _emit(self, line: str) -> None:
        """Pousse une ligne d'avancement au callback `progress` s'il est branché. Best-effort :
        une exception du callback (console injoignable, etc.) n'interrompt JAMAIS le run."""
        cb = self._progress
        if cb is None:
            return
        try:
            cb(line)
        except Exception:  # noqa: BLE001 — l'observabilité ne doit jamais casser l'exécution gouvernée
            pass

    def _emit_result(self, res: dict[str, Any]) -> None:
        """Émet une ligne concise par action exécutée : verdict + kind + cible + 1re raison (courte).
        Rend VISIBLES en direct les SKIP/UNAVAILABLE (outil absent, technique désactivée, connecteur
        désactivé) et les VETO, là où seul le rapport final les montrait. Purement dérivé de `res`."""
        if self._progress is None:
            return
        reasons = res.get("reasons") or []
        reason = str(reasons[0]) if reasons else ""
        line = f"[{res['verdict']}] {res['kind']} -> {res['target']}"
        if reason:
            line += f" ({reason})"
        self._emit(line)

    def run(self, actions: Iterable[Action],
            checkpoint: "Callable[[], None] | None" = None,
            checkpoint_every: int = 0) -> list[dict[str, Any]]:
        # CHOKE POINT unique de l'émission par-action : chaque action passée à run() (proposition
        # directe ET chaque vague de campaign()) émet sa ligne d'avancement APRÈS décision. Les
        # actions DÉFÉRÉES par le planner (skipped_budget) ne passent pas ici -> pas de bruit.
        #
        # DURABILITÉ INCRÉMENTALE (additive) : quand `checkpoint` est branché et `checkpoint_every>0`,
        # on invoque le callback tous les `checkpoint_every` actions POUR PERSISTER le travail DÉJÀ
        # accompli (findings/run-records/décisions -> console) AVANT qu'un watchdog/kill n'avorte la
        # vague. Une vague de 500+ actions n'est plus « tout ou rien » : un run tué en cours de vague
        # conserve ce qui a été fait. No-op si aucun callback ou intervalle <=0 -> byte-identique
        # (CLI directe, tests, propositions ponctuelles).
        #
        # PARALLÉLISME INTRA-VAGUE BORNÉ (G3) : `FORGE_PARALLELISM>1` exécute les TIRS bloquants
        # (module.fire/dry — sous-process/I/O qui libèrent le GIL) dans un pool de threads BORNÉ, puis
        # APPLIQUE leurs mutations d'état (ledger/ingest/decision/findings/compteurs) STRICTEMENT DANS
        # L'ORDRE d'action sur le thread principal. Le déterminisme du ledger et l'ingest console sont
        # préservés (identiques au sériel). `FORGE_PARALLELISM<=1` (ou pool 1) => chemin sériel historique.
        pool = _parallelism()
        if pool <= 1:
            return self._run_serial(actions, checkpoint, checkpoint_every)
        return self._run_parallel(list(actions), checkpoint, checkpoint_every, pool)

    def _run_serial(self, actions: Iterable[Action],
                    checkpoint: "Callable[[], None] | None", checkpoint_every: int) -> list[dict[str, Any]]:
        """Chemin SÉRIEL historique (byte-identique) : une action à la fois, mutations en ligne. Utilisé
        quand `FORGE_PARALLELISM<=1`. Émission + checkpoint intra-vague inchangés."""
        out = []
        n = 0
        for a in actions:
            res = self.execute(a)
            self._emit_result(res)
            out.append(res)
            n += 1
            if checkpoint is not None and checkpoint_every > 0 and n % checkpoint_every == 0:
                self._run_checkpoint(checkpoint)
        return out

    def _run_parallel(self, actions: list[Action],
                      checkpoint: "Callable[[], None] | None", checkpoint_every: int,
                      pool: int) -> list[dict[str, Any]]:
        """Chemin PARALLÈLE borné (G3). Les TIRS bloquants (`_decide_blocking`, sans effet de bord) sont
        soumis à un `ThreadPoolExecutor(max_workers=pool)` en FENÊTRE GLISSANTE ; leurs résultats sont
        APPLIQUÉS (`_apply`) SÉRIELLEMENT, DANS L'ORDRE d'action, sur le thread principal — d'où le
        déterminisme identique au sériel (ledger/ingest/decision/findings ordonnés).

        POURQUOI UNE FENÊTRE ET NON DES LOTS. La version en lots soumettait `pool` tirs, les drainait
        TOUS, puis seulement soumettait les suivants : chaque lot était donc payé au prix de sa plus
        LENTE action, workers libres à l'arrêt pendant ce temps. Mesuré sur 12 actions dont une lente
        par lot (1,2 s contre 0,05 s), pool=4 : **3,90 s pour un plancher sériel de 4,05 s** — 4 % de
        gain, autant dire aucun. La fenêtre garde `pool` tirs EN VOL en permanence : une action lente
        n'immobilise plus que SON worker.

        BORNES INCHANGÉES : au plus `pool` tirs en vol (même plafond qu'un lot), donc la borne
        « travail après cancel » reste du même ordre — au plus `pool` actions au-delà du point
        d'application courant. L'émission et le checkpoint intra-vague gardent EXACTEMENT la même
        cadence : `n` s'incrémente une fois par action appliquée, aux mêmes frontières.

        PUIS : PRÉCHAUFFER LES PLUS LONGUES (`_preheat_order`). La fenêtre a supprimé le blocage de
        TÊTE, mais rien n'ORDONNAIT le travail — et l'ordre d'arrivée est PATHOLOGIQUE par construction.
        Le planner trie par EV = value*confidence/cost : un coût ÉLEVÉ (== une action LENTE, cf. la
        table `brain._CONTENT_SCANNER_EV` qui annote littéralement « LENT » / « TRÈS LENT ») donne une
        EV BASSE, donc une place en FIN DE VAGUE. Les plus lentes démarrent donc en dernier, quand il ne
        reste plus rien pour occuper les autres workers : le pool se vide en fin de vague (le classique
        « longest processing time first » de l'ordonnancement). On met désormais ces actions au four EN
        AVANCE, dans une part BORNÉE de la fenêtre. Mesuré (`tests/bench_engine_parallel_order.py`,
        pool=4, 52 actions ordonnées par le VRAI planner dont 6 lentes rejetées en queue par l'EV,
        plancher théorique travail/pool = 1,80 s, plancher sériel 7,25 s) : **2,45 s -> 1,83 s**, soit
        -25 % et 1,02x le plancher théorique au lieu de 1,36x. Sur une vague dont la queue lente
        remplit déjà le pool, ou dont les coûts sont uniformes, il n'y a RIEN à gagner et le banc
        mesure un no-op (3,08 s et 1,21 s, inchangés) : c'est voulu et structurel, `_preheat_order`
        rend une liste vide dans ces deux cas et `_fill` retombe sur la fenêtre glissante d'avant.

        « LENTE » SE MESURE MAINTENANT (`_preheat_key`) : la durée OBSERVÉE du kind, quand le magasin
        par-engagement en porte une, prime sur `action.cost` — qui reste le repli EXACT quand aucune
        mesure n'existe. Sur une vague dont les coûts DISENT VRAI, les deux donnent le même ordre et le
        même mur-à-mur (banc « straggler » : 1,84 s par coût, 1,83 s par durée — du bruit). L'écart
        n'apparaît QUE là où `cost` MENT, c'est-à-dire quand il n'est pas corrélé à la durée réelle —
        typiquement un module lent resté au `cost` par DÉFAUT (1.0), le cas de tout kind absent de la
        table du cerveau. Banc « cost-lies » (pool=4, 5 répétitions) : 1,88 s sans ordonnancement,
        **1,92 s par coût** (préchauffer par coût y est PIRE que ne rien faire — il met au four les
        actions rapides et raccourcit la piste), **1,60 s par durée observée**, soit -16,8 % et 1,05x
        le plancher travail/pool au lieu de 1,26x.

        L'ORDRE RÉORDONNÉ EST CELUI DE LA SOUMISSION, JAMAIS CELUI DE L'APPLICATION. On draine par
        INDICE D'ACTION croissant (`head`) quoi qu'il arrive : `_apply` reste sériel et dans l'ordre
        d'action, donc ledger/ingest/décisions/findings sortent exactement comme en sériel. La TÊTE est
        de plus soumise avec une PISTE d'au moins `pool + 1` actions d'avance (`_fill`) — jamais
        d'inversion de priorité : on n'attend jamais un résultat dont le tir n'aurait pas été soumis
        depuis longtemps.

        BORNES INCHANGÉES : au plus `2 x pool` tirs soumis-non-appliqués (invariant `len(futures) <=
        window`), donc la borne « travail après cancel » est la MÊME qu'avant en NOMBRE. Ce qui change
        est sa COMPOSITION : les actions tirées d'avance ne forment plus un préfixe contigu de la
        vague — au plus `pool - 1` actions de la QUEUE peuvent avoir été tirées tôt. Sans conséquence
        sur la gouvernance (chaque tir passe la gate ROE complète dans `_decide_blocking` : hors-scope
        = VETO, plancher exploit = VETO, technique désactivée = SKIP) ni sur la couverture (un tir non
        APPLIQUÉ n'entre ni au ledger ni aux findings — le planner coverage-safe garde exactement les
        mêmes garanties : on ne touche NI ce qui est planifié, NI l'ordre dans lequel c'est appliqué,
        seulement l'ordre de mise au four). L'émission et le checkpoint intra-vague gardent EXACTEMENT
        la même cadence : `n` s'incrémente une fois par action appliquée, aux mêmes frontières.

        COMPOSITION E3/E4 (cancel/timeout) : plusieurs tirs EN VOL enregistrent chacun leur pgid dans le
        registre verrouillé de `runner` ; un SIGTERM watchdog coupe TOUS les groupes en vol (E4) et
        `_run_checkpoint` lève `_Terminate` à la frontière d'action -> on ne DÉMARRE plus de lot ; le
        `finally` ferme l'exécuteur (annule les tirs en file). D1 : `_apply` étant sériel et ordonné, les
        offsets d'ingest et le compteur `n` sont identiques au sériel (aucun finding perdu ni doublé)."""
        from collections import deque
        from concurrent.futures import Future, ThreadPoolExecutor
        out: list[dict[str, Any]] = []
        n = 0
        total = len(actions)
        ex = ThreadPoolExecutor(max_workers=pool, thread_name_prefix="forge-wave")
        try:
            # FENÊTRE DE SOUMISSION > POOL — le point clé. On draine EN ORDRE d'action (déterminisme),
            # donc une action LENTE EN TÊTE bloque le réapprovisionnement : avec une fenêtre égale au
            # pool, les workers qui ont fini attendent la tête au lieu d'attaquer la suite. Une fenêtre
            # de `2 x pool` laisse l'exécuteur enfiler du travail d'avance : les workers libérés
            # démarrent l'action suivante sans attendre que la tête soit appliquée.
            # CONTREPARTIE, assumée et bornée : le « travail au-delà du point d'application » passe de
            # `pool` à `2 x pool` actions. C'est ce qui peut avoir été TIRÉ en trop si un cancel/watchdog
            # tombe — borné, petit, et sans effet sur le déterminisme (l'application reste ordonnée).
            window = max(pool, 2 * pool)
            futures: dict[int, Future] = {}            # indice d'action -> tir soumis (drainé par indice)
            # PRÉCHAUFFAGE : les actions LONGUES mises au four d'avance. Plafond `pool - 1` -> (a) il
            # reste TOUJOURS au moins `pool + 1` slots de piste, (b) un groupe d'actions longues qui
            # remplit le pool À LUI SEUL n'est JAMAIS préchauffé : drainé en bloc en fin de vague il ne
            # laisse aucun worker au repos, il n'y a rien à y gagner (mesuré : -1,2 % si on le fait).
            preheat: deque = deque(self._preheat_order(actions, pool - 1))
            runway = window - len(preheat)             # profondeur soumise EN ORDRE D'INDICE

            def _fill(head: int) -> None:
                """Remplit la fenêtre en DEUX ÉTAGES. Invariant : `len(futures) <= window` — même
                plafond de travail en avance qu'avant l'ordonnancement.

                (1) PISTE (`runway`) — les prochaines actions EN ORDRE D'INDICE, tête comprise, au moins
                    `pool + 1` d'avance. C'est ce qui rend l'ordonnancement SÛR : la tête est soumise
                    LONGTEMPS avant d'être attendue, jamais juste-à-temps. Un exécuteur est une FILE
                    FIFO : soumettre la tête en dernier la mettrait DERRIÈRE le travail long déjà en
                    file, et le drainage (ordonné) attendrait une action longue à CHAQUE pas. Mesuré :
                    par durée décroissante SANS piste, la forme « queue-large » du banc passe de
                    3,08 s à 4,86 s (-58 %) — la version naïve est PIRE que pas d'ordonnancement.
                (2) PRÉCHAUFFAGE (le reste de la fenêtre) — les actions les plus LONGUES de la vague,
                    mises au four EN AVANCE pour ne pas se retrouver seules en fin de vague pendant que
                    le pool se vide. Soumises APRÈS la piste : les workers prennent d'abord le travail
                    court dont le drainage a besoin, puis s'installent sur le travail long.

                Quand le préchauffage est épuisé (ou vide), la piste reprend TOUTE la fenêtre : on
                retombe alors exactement sur la fenêtre glissante en ordre d'indice d'avant."""
                limit = min(total, head + (runway if preheat else window))
                for i in range(head, limit):           # (1) PISTE — ordre d'indice, la tête d'abord
                    if i in futures:
                        continue
                    if len(futures) >= window:         # (la tête passe toujours : len <= window-1 ici)
                        break
                    futures[i] = ex.submit(self._decide_blocking, actions[i])
                while len(futures) < window and preheat:    # (2) PRÉCHAUFFAGE — les plus longues d'abord
                    i = preheat.popleft()
                    if i in futures:                   # déjà couverte par la piste — ne consomme rien
                        continue
                    futures[i] = ex.submit(self._decide_blocking, actions[i])

            _fill(0)
            head = 0
            while head < total:
                pending = futures.pop(head).result()   # propage une exception worker — mirror sériel
                head += 1
                # RÉ-ALIMENTATION IMMÉDIATE : on remplit la fenêtre AVANT l'application sérielle, pour
                # que l'écriture ledger/ingest ne laisse jamais un worker au repos.
                _fill(head)
                res = self._apply(pending)
                self._emit_result(res)
                out.append(res)
                n += 1
                if checkpoint is not None and checkpoint_every > 0 and n % checkpoint_every == 0:
                    self._run_checkpoint(checkpoint)   # peut lever _Terminate (BaseException) -> arrêt gracieux
            return out
        finally:
            _shutdown_executor(ex)

    def _preheat_order(self, actions: list[Action], capacity: int) -> list[int]:
        """Indices des actions à PRÉCHAUFFER (mettre au four d'avance), LES PLUS LONGUES D'ABORD, dans
        la limite de `capacity` slots. Ne touche JAMAIS l'ordre d'APPLICATION (`_run_parallel` draine
        par indice croissant) : c'est une priorité de SOUMISSION, rien d'autre.

        PALIER COMPLET OU RIEN — la règle contre-intuitive, et c'est la mesure qui l'a imposée. On
        préchauffe un palier de coût ENTIER ou pas du tout. Préchauffer la MOITIÉ d'un palier casse le
        groupe d'actions longues qui, restées ensemble en fin de vague, remplissaient le pool à elles
        seules : les rescapées se retrouvent seules à la toute fin, à 2 workers sur 4. Mesuré sur la
        forme « queue-large » du banc (4 actions très lentes en queue, pool=4) : préchauffer 2 des 4
        fait passer 3,08 s -> 3,58 s (-16 %) — PIRE que ne rien faire.

        `capacity` VAUT `pool - 1`, et ce n'est pas un réglage : c'est la condition EXACTE sous laquelle
        le préchauffage peut rapporter quelque chose. Un palier d'au moins `pool` actions longues occupe
        déjà tout le pool quand on le draine en bloc — il ne laisse aucun worker au repos, le mettre au
        four plus tôt ne raccourcit rien (mesuré : -1,2 % à cause de la piste raccourcie). Seul un
        palier STRICTEMENT plus petit que le pool laisse des workers à vide en fin de vague.

        Le palier le MOINS cher n'est jamais préchauffé (rien à y gagner par définition), donc une vague
        à coût UNIQUE rend une liste VIDE -> `_fill` retombe sur la fenêtre glissante en ordre d'indice,
        BYTE-IDENTIQUE à avant l'ordonnancement. C'est le cas de toute vague pilotée à la main / par la
        CLI, où `cost` garde son défaut 1.0 : zéro changement, zéro risque.

        D'OÙ VIENT L'ESTIMATION DE DURÉE — cf. `_preheat_key` : la durée OBSERVÉE du kind quand le
        magasin par-engagement en porte une, `action.cost` sinon.

        DÉTERMINISTE : les indices d'un même palier sortent en ORDRE D'INDICE, les paliers du plus
        long au plus court. Deux exécutions de la même vague AVEC LE MÊME MAGASIN préchauffent donc
        exactement le même ensemble, dans le même ordre (le magasin est GELÉ pour la durée du run, cf.
        `durations.DurationStore`). Le tri porte sur des flottants, jamais sur l'ordre d'insertion d'un
        dict. Pur, ne lève jamais : un `cost` non numérique / NaN / <= 0 est traité comme neutre (1.0),
        comme le `max(action.cost, 0.01)` du planner."""
        if capacity <= 0:
            return []
        keys = [self._preheat_key(a) for a in actions]
        tiers = sorted(set(keys), reverse=True)
        if len(tiers) < 2:                             # clé unique -> rien à préchauffer (identité)
            return []
        out: list[int] = []
        for tier in tiers[:-1]:                        # jamais le palier le PLUS COURT
            members = [i for i, c in enumerate(keys) if c == tier]
            if len(out) + len(members) > capacity:     # PALIER COMPLET OU RIEN (cf. supra)
                break
            out.extend(members)
        return out

    def _preheat_key(self, action: Action) -> float:
        """Estimation de LENTEUR d'une action — la clé de palier de `_preheat_order`.

        DEUX SOURCES, DANS CET ORDRE.
          1. LA DURÉE OBSERVÉE du kind (`durations.DurationStore.estimate`), en secondes quantifiées,
             mesurée par `_record_duration` sur les tirs des runs PRÉCÉDENTS de CE MÊME engagement.
             C'est la seule mesure de DURÉE du dépôt.
          2. À DÉFAUT, `action.cost` — donnée de GOUVERNANCE réutilisée en proxy de durée. Le cerveau
             la renseigne comme un coût de TEMPS (`brain._CONTENT_SCANNER_EV` annote ses coûts
             « quasi-instantané » 1.0 / « LENT » 2.0 / « TRÈS LENT » 3.0), mais rien ne le GARANTIT :
             un module cher-mais-rapide se fait préchauffer pour rien, un module gratuit-mais-lent
             immobilise le pool. C'est précisément ce que (1) corrige, quand (1) existe.

        REPLI EXACT — LA PROPRIÉTÉ QUI COMPTE. Sans magasin, ou avec un magasin SANS AUCUNE observation,
        cette fonction rend `_action_cost(action)` pour TOUTE action : `_preheat_order` calcule alors
        exactement les mêmes paliers qu'avant l'instrumentation, donc le même ensemble préchauffé, donc
        le même ordre de soumission. Zéro donnée observée == comportement d'hier, à l'identique.

        UNITÉS : les deux sources cohabitent dans la MÊME liste de clés quand une partie seulement des
        kinds est observée. C'est assumé et documenté : `cost` est alors lu comme des secondes, ce qui
        n'a pas d'exactitude numérique mais garde le bon SENS (les deux échelles croissent avec la
        lenteur) — une mesure déclasse toujours une supposition pour le kind qu'elle concerne. Calibrer
        l'une sur l'autre serait un MODÈLE, et un modèle n'a pas sa place dans un ordre de soumission."""
        store = self.durations
        if store is not None:
            est = store.estimate(action.kind)
            if est is not None:
                return est
        return _action_cost(action)

    def _run_checkpoint(self, checkpoint: "Callable[[], None] | None") -> None:
        """Invoque le callback de checkpoint (flush incrémental console) en BEST-EFFORT : une exception
        ORDINAIRE (console injoignable, erreur réseau) n'interrompt JAMAIS le run — miroir de `_emit`.
        En revanche un signal d'ARRÊT GRACIEUX (watchdog SIGTERM côté console) est propagé VOLONTAIREMENT
        par le callback via une `BaseException` (hors `Exception`) : elle TRAVERSE ce garde et déroule la
        campagne jusqu'au flush final (finally, côté CLI) — pour ne perdre AUCUN travail au watchdog."""
        if checkpoint is None:
            return
        try:
            checkpoint()
        except Exception:  # noqa: BLE001 — flush best-effort ; l'arrêt gracieux (BaseException) passe volontairement
            pass

    def _prepare(self, actions: list[Action], modules: "Iterable[str] | None",
                 global_params: dict[str, Any], attrs_by_host: dict[str, Any]) -> list[Action]:
        """Filtre (sélection modules) + injection de params/scope sur une VAGUE d'actions.

        Extrait de la boucle pour être appliqué identiquement à chaque vague (1re proposition ET
        re-propositions chaînées). N'AJOUTE aucune capacité : restreint + pré-remplit (setdefault).
        Retourne la liste filtrée+enrichie (les Actions sont mutées en place via leurs params)."""
        # (1) RESTRICTION par sélection de modules (UI/console) : ne garder que les kinds demandés.
        wanted = {m for m in (modules or []) if m}
        if wanted:
            actions = [a for a in actions if a.kind in wanted]

        # (1bis) SÉLECTION DE TECHNIQUES PAR-SCOPE — le PLAN est filtré par l'ensemble EFFECTIF activé
        # (== `pipeline_ordered` filtré par la sélection du scope). Une technique hors-profil/désactivée
        # n'est jamais PLANIFIÉE (le tir la re-refuserait de toute façon : défense en profondeur). No-op
        # sur un scope legacy (enabled_kinds is None). Appliqué à CHAQUE vague.
        if self.enabled_kinds is not None:
            actions = [a for a in actions if a.kind in self.enabled_kinds]

        # (2) params par-module -> action.params (la console les écrit dans scope ET target.attrs).
        #     Priorité : params spécifiques à la cible (target.attrs) > params globaux (scope).
        #     setdefault : on n'écrase jamais un param déjà posé par le cerveau.
        for a in actions:
            for src in (global_params, attrs_by_host.get(a.target, {})):
                for k, v in (src.get(a.kind, {}) or {}).items():
                    a.params.setdefault(k, v)

        # injecte les creds/URLs du scope dans les actions IDOR (grey/white box). setdefault PUR : une
        # action IDOR CHAÎNÉE sur un endpoint découvert porte déjà `urls=[endpoint]` (edge C) -> on ne
        # l'écrase pas, mais on lui injecte quand même les comptes/mitre du scope (sinon l'oracle
        # skiperait faute de creds). Une action IDOR de base (sans urls) reçoit urls=idor_targets.
        for a in actions:
            if a.cls in ("access_control", "idor", "bola"):
                # CONTEXTE AUTH PAR-ENGAGEMENT (R5) : si l'opérateur a fourni un bloc `auth`, on injecte
                # ses comptes LABELLISÉS (attacker/victim) et ses idor_targets STRUCTURÉS {url,owner,
                # marker} — l'oracle rejoue chaque cible avec la session de l'ATTAQUANT. Sinon (aucun
                # bloc auth) on retombe EXACTEMENT sur l'historique (known_creds) : INERTE, no-op.
                if self.auth_context is not None:
                    a.params.setdefault("accounts", self.auth_context.accounts_as_params())
                    if self.auth_context.idor_targets:
                        a.params.setdefault("idor_targets", list(self.auth_context.idor_targets))
                    self._ledger_auth_use()               # journalise la MISE EN USAGE (labels, pas de secret)
                else:
                    a.params.setdefault("accounts", self.scope.known_creds)
                a.params.setdefault("urls", self.scope.idor_targets)
                a.params.setdefault("mitre", "T1190")
            # CONTEXTE AUTH PAR-ENGAGEMENT (R5b) : l'oracle ATO/takeover consomme les MÊMES comptes
            # LABELLISÉS que l'IDOR — la session de l'ATTAQUANT est rejouée contre chaque idor_target
            # (whoami-like) et un takeover est PROUVÉ si le marqueur d'IDENTITÉ de la victime revient
            # dans SA réponse authentifiée. MÊME injection que l'IDOR (comptes + cibles structurées), pas
            # de chemin parallèle. ABSENT (aucun bloc auth) => aucune injection => l'oracle retombe sur
            # son chemin config-driven historique (whoami_url/victim_marker) : INERTE, no-op byte-identique.
            elif a.kind == "auth.takeover":
                if self.auth_context is not None and self.auth_context.accounts:
                    a.params.setdefault("accounts", self.auth_context.accounts_as_params())
                    if self.auth_context.idor_targets:
                        a.params.setdefault("idor_targets", list(self.auth_context.idor_targets))
                    self._ledger_auth_use()               # journalise la MISE EN USAGE (labels, pas de secret)

        # injecte le périmètre dans les actions qui DÉCOUVRENT/RÉSOLVENT des hôtes à runtime : la
        # cible (domaine) est gatée par le ROE, mais ces modules produisent de NOUVEAUX hôtes (IP
        # d'origine, sous-domaines, URLs historiques, endpoints JS) qui DOIVENT être re-validés
        # fail-closed contre le scope avant d'être émis/connectés (miroir de l'injection IDOR ci-dessus).
        for a in actions:
            if a.kind in _SCOPE_INJECT_KINDS:
                a.params.setdefault("in_scope", self.scope.in_scope)
                a.params.setdefault("out_scope", self.scope.out_scope)
            if a.kind in _RATE_LIMITED_KINDS:                # débit ROE -> borne le trafic actif du module
                a.params.setdefault("rate", self.scope.rate)
            elif getattr(self.scope, "rate_explicit", False) and a.kind in _RATE_FLAG_KINDS:
                # OUTIL avec drapeau de débit : injecté SEULEMENT sur override explicite (byte-identique sinon)
                a.params.setdefault("rate", self.scope.rate)

        # DÉRIVÉES D'UNITÉ du débit (pour les wrappers dont le drapeau est un DÉLAI par requête, pas un
        # req/s : sqlmap/wfuzz `--delay/-s` en secondes, dalfox `--delay` en ms, gobuster `--delay` en
        # durée Go). Calculées depuis `rate` (req/s) UNIQUEMENT si présent+positif ; setdefault (n'écrase
        # rien). Absent => aucune dérivée => les groupes `{param:rate_delay_*}` sont abandonnés (byte-identique).
        for a in actions:
            r = a.params.get("rate")
            try:
                rf = float(r)
            except (TypeError, ValueError):
                rf = 0.0
            if rf > 0:
                a.params.setdefault("rate_delay_s", f"{1.0 / rf:.3f}")
                a.params.setdefault("rate_delay_ms", str(max(1, round(1000.0 / rf))))
                a.params.setdefault("rate_delay_dur", f"{max(1, round(1000.0 / rf))}ms")
        return actions

    def _directive_actions(self, proposed: list[Action], modules: "Iterable[str] | None") -> list[Action]:
        """DIRECTIVE de sélection EXPLICITE : un module listé dans `--modules` est un ORDRE, pas une
        suggestion. Le cerveau heuristique ne PROPOSE qu'une poignée de kinds par host (httpx/nuclei/
        oracles/seeds) ; un kind explicitement demandé qu'il ne propose pas (ex. web.security_headers —
        jamais proposé — ou recon.tech/recon.waf — proposés SEULEMENT après une découverte de
        sous-domaine) n'entrait JAMAIS dans le plan et retombait SILENCIEUSEMENT dans `not_planned`
        (« surface non concordante »), même quand la recon venait de découvrir une surface web.

        Ici, pour CHAQUE kind explicitement demandé mais NON déjà proposé sur une cible, on émet une
        action sur CHAQUE cible NON-endpoint que le plan touche (hosts initiaux + surface DÉCOUVERTE :
        IP d'origine, host:port) — EXACTEMENT le périmètre sur lequel `web.nuclei` est proposé (raison
        pour laquelle nuclei tirait et pas les autres). Le module DÉCIDE ensuite : il tire, ou dégrade
        en `skipped`/`tested` visible s'il n'a pas de surface — jamais un report silencieux.

        NO-OP en mode AUTO (`modules` vide/None) : le cerveau + le planner coverage-safe restent seuls
        juges (EV-ordering + plancher qualifiant inchangés). N'ÉLARGIT AUCUN pouvoir : chaque directive
        repasse par `_prepare` (filtre `enabled_kinds` par-scope), puis `execute` (scope-guard, connecteur
        désactivé, technique désélectionnée, ROE, plancher exploit) — la gouvernance reste seule à tirer.
        Idempotent : l'id d'action est stable (kind:target) -> jamais rejoué entre vagues."""
        wanted = [m for m in (modules or []) if m]
        if not wanted:
            return []                                    # mode AUTO : comportement byte-identique
        from .brain import HeuristicBrain, _action       # import paresseux (évite tout cycle au chargement)
        have = {a.id for a in proposed}
        targets: list[str] = []
        seen_t: set[str] = set()
        for a in proposed:
            t = a.target
            # même surface que web.nuclei : hosts / host:port / IP d'origine — PAS les endpoints à chemin
            # (ceux-là sont vérifiés par les oracles ciblés du chaînage, edge (e), pas par les modules host).
            if t in seen_t or HeuristicBrain._is_endpoint(t):
                continue
            seen_t.add(t)
            targets.append(t)
        extra: list[Action] = []
        for tgt in targets:
            for kind in wanted:
                aid = f"{kind}:{tgt}"
                if aid not in have:
                    have.add(aid)
                    extra.append(_action(kind, tgt, desc=f"sélection explicite (--modules) : {kind}"))
        return extra

    def campaign(self, targets: list[Target], brain: Any, planner: Planner,
                 modules: "Iterable[str] | None" = None,
                 module_params: dict[str, Any] | None = None, max_waves: int = 4,
                 checkpoint: "Callable[[], None] | None" = None,
                 checkpoint_every: int = 0) -> dict[str, Any]:
        """ITÉRATIF : plan -> observe -> replan, jusqu'à un critère d'arrêt.

        Boucle (chaque vague) : `brain.propose(self.graph)` lit le world-model -> planner ordonne
        (coverage-safe) -> run gaté -> les findings enrichissent le graphe (fait dans execute()) ->
        re-propose à partir du graphe enrichi (chaînage : CDN->origin->nuclei/idor, fingerprint->oracles).

        Critères d'ARRÊT (le premier atteint) :
          1. plus de NOUVELLE action (toutes les actions proposées ont déjà été exécutées) -> point fixe ;
          2. `max_waves` vagues atteint (garde-fou anti-boucle) ;
          3. planner sans budget restant pour de nouvelles actions non-qualifiantes (implicite via order()).
        Le ROE/gouvernance reste appliqué À CHAQUE VAGUE (rien ne tire sans verdict FIRE).

        `targets` = list[Target]. `modules` / `module_params` : voir _prepare() (restriction +
        injection, inchangés, appliqués à chaque vague). `max_waves` borne le nombre d'itérations.

        Idempotence/dedup : on suit les ids d'actions DÉJÀ PLANIFIÉES (executed_ids) ; une action
        re-proposée à l'identique (id stable kind:target) n'est jamais rejouée -> point fixe garanti.
        skipped_budget et coverage_gaps sont ACCUMULÉS sur l'ensemble des vagues (anti-masquage).
        """
        # AUDIT DES RESSOURCES : capture le profil ACTIF (`FORGE_RESOURCE_PROFILE`) + les valeurs de
        # leviers RÉELLEMENT en vigueur (overrides d'env pris en compte) AU LANCEMENT de la campagne.
        # Émis au ledger (`engine.resource_profile`) quand un ledger est présent, et exposé au rapport
        # (`engine.resource_profile`) pour tracer quelles ressources ce run a consommées. Additif :
        # pure observabilité (n'influe NI sur le plan, NI sur le ROE, NI sur les findings).
        self.resource_profile = resource_profile.active_snapshot()
        if self.ledger:
            self.ledger.append("engine.resource_profile", self.resource_profile)

        for t in targets:                            # amorce le world-model avec les cibles
            # SESSION par-cible (SECRET) : matériel d'auth déclaré dans targets.json[].attrs.session.
            # RETIRÉ des attrs poussés au graphe (le secret ne doit JAMAIS entrer dans le world-model,
            # que le brain/rapport peuvent surfacer) et versé dans le store scope-guardé pour ce host.
            attrs = dict(t.attrs or {})
            tsess = attrs.pop("session", None)
            self.graph.add_host(t.host, kind=t.kind, **attrs)
            if tsess:
                self.sessions.add_host_session(t.host, tsess)

        global_params = module_params or {}
        attrs_by_host = {t.host: (t.attrs or {}).get("module_params", {}) or {} for t in targets}
        hosts = [t.host for t in targets]

        executed_ids: set[str] = set()               # ids d'actions déjà planifiées (dedup inter-vagues)
        skipped_by_id: dict[str, Action] = {}        # accumule les déférées (par id, pas de doublon)
        waves = 0
        while waves < max_waves:
            # le cerveau lit l'ÉTAT (graphe enrichi par la vague précédente), pas juste les cibles.
            proposed = brain.propose(self.graph)
            # DIRECTIVE de sélection EXPLICITE (--modules) : un kind demandé que le cerveau ne propose
            # PAS sur la surface qu'il travaille (ex. web.security_headers/recon.tech/recon.waf, jamais
            # dans le plan heuristique de base) est AJOUTÉ sur cette surface AVANT le filtre de _prepare
            # — sinon il retombait silencieusement dans `not_planned`. NO-OP en mode AUTO (modules vide).
            proposed = proposed + self._directive_actions(proposed, modules)
            proposed = self._prepare(proposed, modules, global_params, attrs_by_host)
            # NOUVELLES actions seulement (idempotence : on ne rejoue pas une action déjà planifiée).
            fresh = [a for a in proposed if a.id not in executed_ids]
            if not fresh:                            # critère d'arrêt 1 : point fixe (rien de neuf)
                break
            for a in fresh:
                executed_ids.add(a.id)

            # ENRICHISSEMENT LLM des payloads d'injection (R6) — OPTIONNEL, OFF par défaut, egress-gaté,
            # borné, fail-open, ADVISORY ONLY. Sur le THREAD PRINCIPAL (le seul écrivain du ledger) : le
            # LLM propose des payloads SUPPLÉMENTAIRES pour les endpoints/params d'injection, attachés à
            # `action.params['llm_payloads']`. L'oracle DÉTERMINISTE les teste/confirme au fire-time (edge
            # G1). Aucune donnée ne sort sans egress autorisé + ledgeré ; no-op quand le LLM est OFF.
            self._llm_enrich_injections(fresh)

            ordered, skipped = planner.order(fresh)
            for a in skipped:                        # defer != delete : accumulé, jamais jeté
                skipped_by_id[a.id] = a
            # bannière de vague (live) : borne visuellement les vagues plan->observe->replan et annonce
            # le nb d'actions ordonnées + différées. No-op si aucun callback (byte-identique).
            self._emit(f"=== vague {waves + 1} — {len(ordered)} action(s) ordonnée(s)"
                       + (f", {len(skipped)} différée(s)" if skipped else "") + " ===")
            # DURABILITÉ INCRÉMENTALE : le checkpoint est passé À CHAQUE run() (persistance intra-vague
            # tous les `checkpoint_every` actions) PUIS invoqué une fois de plus à la FRONTIÈRE de vague
            # (le travail d'une vague complète est flushé avant d'entamer la suivante). Sans callback, on
            # appelle run() avec sa SIGNATURE HISTORIQUE (aucun kwarg) -> byte-identique (les tests qui
            # espionnent `run(actions)` restent valides).
            if checkpoint is None:
                self.run(ordered)
            else:
                self.run(ordered, checkpoint=checkpoint, checkpoint_every=checkpoint_every)
            waves += 1
            self._run_checkpoint(checkpoint)

        self.skipped_budget = list(skipped_by_id.values())
        # une classe n'est une lacune QUE si elle n'a JAMAIS été tentée sur AUCUNE vague :
        # recalcul final à partir de tous les kinds réellement exécutés (results), par host.
        self.coverage_gaps = self._final_gaps(planner, hosts)
        # ANTI-LACUNE : accounting AU NIVEAU MODULE. L'univers DEMANDÉ pour ce run moins les modules
        # réellement planifiés (entrés dans results) = les modules disponibles JAMAIS ordonnancés. Chaque
        # module sélectionné est désormais soit planifié (fired/dry/vetoed/errors) soit listé ici avec sa
        # raison -> `not_planned ∪ planifiés == selected_modules` (aucune omission silencieuse).
        self.selected_modules = self._selected_universe(modules)
        self.not_planned = self.unplanned_modules(self.selected_modules)
        self.waves = waves
        return self.coverage()

    def _llm_enrich_injections(self, actions: list[Action]) -> None:
        """R6 — enrichit les actions d'INJECTION de la vague avec des payloads SUPPLÉMENTAIRES suggérés
        par le LLM gouverné (ADVISORY ONLY). Appelé sur le THREAD PRINCIPAL (mono-écrivain du ledger)
        AVANT le tir, si bien que l'appel LLM + l'egress `llm.egress` sont ordonnés/déterministes comme
        toute autre mutation d'état (jamais depuis un worker de tir).

        GOUVERNANCE (miroir d'enrich_triage — mêmes gardes) :
          - LLM OFF (défaut) => NO-OP total (aucun appel, aucun egress, actions BYTE-IDENTIQUES) ;
          - egress non autorisé (endpoint externe sans `allow_external`) => NO-OP (le gate tient) ;
          - levier `llm_enrich_max_endpoints` (resource_profile) <= 0 (défaut `low`) => NO-OP ;
          - sinon : BORNÉ aux TOP-N actions d'injection enrichissables (tri déterministe par id), chacune
            IN-SCOPE, param présent ; chaque appel est fail-open (échec => payloads déterministes intacts).
        L'oracle DÉTERMINISTE reste PRIMAIRE : il teste/confirme chaque payload suggéré avec sa preuve
        inchangée (scope-guardée, ROE-gatée). Ne lève JAMAIS (pure décoration best-effort)."""
        try:
            from . import llm as _llm                 # import paresseux (évite tout cycle au chargement)
            cfg = _llm.LLMConfig.from_dict(getattr(self.scope, "llm", None))
            if not cfg.enabled or not cfg.egress_authorized():
                return                                # OFF ou egress non autorisé => NO-OP (gate tient)
            max_n = resource_profile.resolve("llm_enrich_max_endpoints", default=0)
            try:
                max_n = int(max_n)
            except (TypeError, ValueError):
                max_n = 0
            if max_n <= 0:
                return                                # levier à 0 (profil low) => enrichissement désactivé
            # TOP-N déterministe : actions d'injection enrichissables, param présent, cible IN-SCOPE.
            cands = [a for a in actions
                     if a.kind in _llm.ENRICHABLE_KINDS
                     and isinstance(a.params.get("param"), str) and a.params.get("param")
                     and self.scope.is_in_scope(a.target)]
            cands.sort(key=lambda a: a.id)            # ordre STABLE (borne l'egress de façon reproductible)
            for a in cands[:max_n]:
                extra = _llm.enrich_payloads(a.kind, a.target, a.params.get("param"), cfg,
                                             ledger=self.ledger)
                if extra:
                    a.params["llm_payloads"] = list(extra)
        except Exception:  # noqa: BLE001 — advisory/best-effort : un échec n'avorte jamais la campagne
            pass

    def _selected_universe(self, modules: "Iterable[str] | None") -> set[str]:
        """Univers des modules DEMANDÉS pour ce run (base de l'accounting anti-lacune). Priorité,
        purement dérivée du run (aucune fabrication) :
          1. sélection `--modules` explicite (console/UI) -> ces kinds ;
          2. sinon sélection technique PAR-SCOPE (`enabled_kinds`) quand configurée ;
          3. sinon TOUS les modules enregistrés (run « select-all » : aucun filtre)."""
        wanted = {m for m in (modules or []) if m}
        if wanted:
            return wanted
        if self.enabled_kinds is not None:
            return set(self.enabled_kinds)
        return set(mods.kinds())

    def unplanned_modules(self, selected: "Iterable[str]") -> dict[str, str]:
        """Modules SÉLECTIONNÉS/DISPONIBLES mais JAMAIS planifiés par le planner (jamais entrés dans
        `results`) -> {kind: raison}. Comble le bucket manquant : un module dont l'outil était présent
        mais que le plan n'a pas ordonnancé (mode lecture seule, capacités de l'engagement, surface non
        concordante) n'apparaissait dans AUCUN autre bucket. `selected − planifiés` : par construction
        disjoint des kinds planifiés, donc `not_planned ∪ planifiés == selected` (accounting fermé)."""
        planned = {r["kind"] for r in self.results}
        return {kind: self._unplanned_reason(kind)
                for kind in sorted(selected) if kind not in planned}

    def _unplanned_reason(self, kind: str) -> str:
        """Raison — DÉRIVÉE des métadonnées du module + des capacités du scope, jamais fabriquée — pour
        laquelle un module sélectionné/disponible n'a pas été planifié. De la plus spécifique à la plus
        générale (miroir des SKIP au tir), pour que la lacune porte l'explication la plus précise."""
        module = mods.get(kind)
        if module is None:
            return "module non enregistré (kind demandé sans implémentation)"
        if getattr(module, "available", True) is False:
            return "outil sous-jacent absent (module indisponible, jamais planifié)"
        disabled = getattr(self.scope, "disabled_modules", None) or set()
        if kind in disabled:
            return "module désactivé par la console (gouvernance connecteur), jamais planifié"
        if self.enabled_kinds is not None and kind not in self.enabled_kinds:
            return "technique désactivée pour ce scope (sélection profil/catégorie/technique)"
        if getattr(module, "exploit", False) and not self.scope.allow_exploit:
            return "capacité exploit non autorisée par l'engagement (lecture seule) — non planifié"
        if getattr(module, "destructive", False) and not self.scope.allow_destructive:
            return "capacité destructif non autorisée par l'engagement — non planifié"
        return ("outil disponible, non planifié (hors périmètre du plan / surface non concordante / "
                "capacités de l'engagement)")

    def _final_gaps(self, planner: Planner, hosts: list[str]) -> dict[str, list[str]]:
        """Lacunes APRÈS toutes les vagues : classe de la checklist jamais tentée sur le host.

        Dérive des `results` (kinds réellement planifiés, toutes vagues confondues) -> reflète le
        chaînage (une classe tentée en vague 2 n'est plus une lacune). cls = suffixe du kind, comme
        la dataclass Action (`access_control.idor` -> `idor`... mais on garde la classe d'action si
        connue). On reconstruit la classe par la même règle que Action.__post_init__."""
        attempted: dict[str, set[str]] = {h: set() for h in hosts}
        for r in self.results:
            cls = r["kind"].split(".")[-1]
            # repli sur le préfixe pour les kinds composés (access_control.idor -> access_control)
            prefix = r["kind"].split(".")[0]
            tgt = str(r["target"])
            for h in hosts:
                # rattacher une action au host si la cible EST le host, ou en dérive par un
                # délimiteur franc (host:port, host/path). Un simple startswith rattacherait à tort
                # `app.test` à `app.testing`/`app.test.evil` -> faux « tenté » masquant une lacune.
                hs = str(h)
                if tgt == hs or tgt.startswith(hs + ":") or tgt.startswith(hs + "/"):
                    attempted[h].add(cls)
                    attempted[h].add(prefix)
        out: dict[str, list[str]] = {}
        for h in hosts:
            missing = [c for c in planner.checklist if c not in attempted[h]]
            if missing:
                out[h] = missing
        return out

    # --- transparence (anti-masquage) ---
    def coverage(self) -> dict[str, Any]:
        fired = [r for r in self.results if r["verdict"] == FIRE]
        dry = [r for r in self.results if r["verdict"] == DRY_RUN]
        vetoed = [r for r in self.results if r["verdict"] == VETO]
        errors = [r for r in self.results if r["verdict"] in ("ERROR", "SKIP")]
        # `non_targets` est ADDITIF (les consommateurs — report.py, console_client — lisent des clés
        # FIXES) : agrégat {cible: famille} des non-cibles d'infra RECONNUES. Chaque action visée est
        # DÉJÀ comptée+listée dans `errors` (SKIP nommé) ; cette clé donne le constat en une ligne.
        return {"fired": fired, "dry_run": dry, "vetoed": vetoed, "errors": errors,
                "non_targets": dict(self.non_targets)}

    def roe_decisions(self, start: int = 0) -> list[dict[str, Any]]:
        """Trace ROE sérialisable : un verdict par action évaluée (anti-masquage).

        Dérivé de `self.results` (le journal des décisions) — chaque entrée porte le
        verdict ROE et ses raisons, sans la sortie (output) du module. Consommé par la
        console pour exposer la couverture par action. Pur, sans réseau.

        `start` (défaut 0) : n'émet QUE les décisions à partir de cet index dans `self.results`
        — utilisé par le flush incrémental (delta) pour n'envoyer que les NOUVELLES décisions depuis
        le dernier checkpoint (aucun double-envoi ; `results` est append-only pendant un run)."""
        return [
            {"action_id": r["action"], "target": r["target"], "kind": r["kind"],
             "verdict": r["verdict"], "reasons": list(r.get("reasons") or [])}
            for r in self.results[start:]
        ]

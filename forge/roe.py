# SPDX-License-Identifier: AGPL-3.0-or-later
"""ROE / scope-guard fail-closed — le COEUR de sûreté de Forge.

Reprend un scope-guard fail-closed (appartenance + exploit/destructif default-deny)
et AJOUTE le modèle d'armement par couche de Plume : quatre couches
qui doivent TOUTES être franchies pour qu'une action LIVE parte. Par défaut Forge est
INERTE — rien ne peut tirer tant que l'opérateur n'a pas armé chaque couche consciemment.

  Couche 1  engagement armé ?     (global)     défaut: NON   -> sinon DRY_RUN
  Couche 2  cible in-scope ?      (par cible)   fail-closed   -> sinon VETO
  Couche 3  capacité autorisée ?  (par action)  exploit/destructif => allow_* explicite -> sinon VETO
  Couche 4  action approuvée ?    (par action)  défaut: propose-only -> sinon DRY_RUN

Verdicts :
  VETO     couche 2 ou 3 échoue        -> refus DUR, jamais simulé, jamais tiré
  DRY_RUN  in-scope + autorisé mais pas armé/approuvé -> simulation sûre (génère le PoC, ne tire pas)
  FIRE     1+2+3+4 OK                  -> action live autorisée

Politique fail-closed : toute erreur, champ inconnu, ou exception => VETO (jamais FIRE).
Chaque décision est journalisée dans le ledger append-time (qui/quoi/quand/verdict/raisons).
Zéro dépendance (stdlib).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import socket
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:                                         # imports paresseux (type-checking uniquement)
    from .ledger import Ledger

VETO = "VETO"
DRY_RUN = "DRY_RUN"
FIRE = "FIRE"

# --- RÉSOLUTION DNS BORNÉE (anti-rebinding / L1-L3) ------------------------------------------------
# Délai MAX d'une résolution `getaddrinfo` au POINT DE TIR. `getaddrinfo` n'honore PAS le timeout socket
# sur la plupart des plateformes -> on l'exécute dans un thread joint avec deadline (borne DURE de
# liveness : une résolution qui stalle ne bloque JAMAIS le moteur). Dépassement => `_ResolveTimeout` =>
# le ROE VÉTO (fail-closed : on ne peut pas PROUVER que la cible est publique). Une résolution qui échoue
# proprement (NXDOMAIN/gaierror) est distincte d'un timeout : elle rend `[]` (hôte inconnu, aucune
# connexion possible) et NE véto PAS par elle-même (le scope-guard reste juge du périmètre).
_RESOLVE_TIMEOUT = 5.0


class _ResolveTimeout(Exception):
    """La résolution DNS a dépassé `_RESOLVE_TIMEOUT` -> traitée fail-closed (VETO) par le ROE."""


_TIMEOUT = object()   # sentinelle de cache DNS : « résolution expirée » (VETO fail-closed persistant/run)


def _resolve_ips(host: str, timeout: float | None = None) -> list[str]:
    """Résout `host` en une liste d'IP (str), avec une DEADLINE dure via thread joint (getaddrinfo peut
    staller indéfiniment sans respecter le timeout socket). Sémantique :
      - succès            -> liste des IP littérales résolues (dé-doublonnée, ordre stable) ;
      - NXDOMAIN/gaierror -> [] (hôte inconnu : aucune connexion, donc aucune atteinte réseau) ;
      - DÉPASSEMENT       -> lève `_ResolveTimeout` (fail-closed en amont : VETO).
    Un `host` déjà littéral IP est renvoyé tel quel SANS I/O réseau (court-circuit sûr en plan/dry)."""
    if timeout is None:                                   # lu au call-time -> patchable en test/config
        timeout = _RESOLVE_TIMEOUT
    try:                                                  # court-circuit : host = IP littérale -> pas d'I/O
        ipaddress.ip_address(str(host).strip())
        return [str(host).strip()]
    except ValueError:
        pass
    box: dict[str, Any] = {}

    def _work() -> None:
        try:
            box["infos"] = socket.getaddrinfo(host, None)
        except Exception as e:                            # noqa: BLE001 (gaierror/réseau : hôte inconnu)
            box["err"] = e

    t = threading.Thread(target=_work, daemon=True)       # daemon : n'empêche jamais la sortie du process
    t.start()
    t.join(timeout)
    if t.is_alive():                                      # deadline dépassée : résolution encore en cours
        raise _ResolveTimeout(host)
    if "infos" not in box:                                # échec propre (gaierror) : hôte inconnu -> []
        return []
    out: list[str] = []
    for info in box["infos"]:
        sockaddr = info[4] if len(info) > 4 else None
        if sockaddr and sockaddr[0] and sockaddr[0] not in out:
            out.append(sockaddr[0])
    return out

# --- POLITIQUE RÉSEAU (privé/LAN/loopback) — enforcement AUTORITATIF fail-closed --------------------
# Ensemble EXPLICITE des plages à bloquer quand la politique est OFF. On liste les CIDR au lieu de
# s'appuyer sur les drapeaux stdlib `is_private`/`is_reserved` car CEUX-CI DÉRIVENT d'une version de
# Python à l'autre (p.ex. 3.14 marque les plages de DOCUMENTATION RFC5737 203.0.113/24 comme is_private)
# et DIVERGERAIENT alors du writer Rust `runs.rs` (Rust std `Ipv4Addr::is_private` = STRICTEMENT RFC1918).
# Cette liste = MIROIR EXACT de l'énumération Rust -> verdict STABLE et IDENTIQUE des deux côtés (contrat).
_PRIVATE_V4 = (
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("10.0.0.0/8"),      # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),   # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("0.0.0.0/8"),       # unspecified / « this network »
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT (RFC6598)
)
_ULA_V6 = ipaddress.ip_network("fc00::/7")            # ULA
_LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")    # link-local


def _ip_is_private(ip_str: str) -> bool:
    """True si `ip_str` est une IP LITTÉRALE privée/LAN/loopback. Couvre IPv4 (loopback 127/8, RFC1918,
    link-local 169.254/16, unspecified 0/8, CGNAT 100.64/10) et IPv6 (::1, ::, ULA fc00::/7, link-local
    fe80::/10, et IPv4-mapped ::ffff:a.b.c.d via l'IPv4 embarquée). Énumération EXACTE (miroir Rust) —
    PAS les drapeaux stdlib (version-dépendants). Une valeur non-IP => False (le chemin résolution gère)."""
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) : le verdict se décide sur l'IPv4 EMBARQUÉE (autoritatif).
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip.version == 4:
        return any(ip in net for net in _PRIVATE_V4)
    return ip.is_loopback or ip.is_unspecified or ip in _ULA_V6 or ip in _LINK_LOCAL_V6


class ScopeError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Action:
    """Une action proposée par le cerveau (ou la CLI). `kind` = clé d'un module enregistré.

    Champs de scoring (optionnels) consommés par le planner coverage-safe :
    `cls` (classe de vuln, défaut = suffixe de `kind`), `value`/`confidence` 0..1, `cost` >0.
    """
    kind: str
    target: str
    exploit: bool = False
    destructive: bool = False
    desc: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    cls: str = ""
    value: float = 0.5
    confidence: float = 0.5
    cost: float = 1.0
    id: str = ""
    # EGRESS TIERS DÉCLARÉ par le module qui exécutera cette action (hôtes contactés EN PLUS de la
    # cible). Rempli par `Engine._decide_blocking` depuis `module.egress` (duck-typé, comme
    # `module.exploit`/`max_runtime`) juste avant la gate — le cerveau et le planner n'en savent rien.
    # Vide (le cas de TOUS les modules d'aujourd'hui) => la couche 3bis de `Roe.decide` est inerte.
    egress: tuple = ()
    # Le module peut-il travailler SANS cet egress ? False (défaut) => il DÉGRADE (il lit
    # `params['_egress_allowed']` et retire la fonctionnalité qui sort) ; True => sans autorisation il
    # ne peut rien faire d'honnête -> VETO nommé plutôt qu'un tir qui sort en douce.
    egress_required: bool = False

    def __post_init__(self) -> None:
        if not self.cls:
            self.cls = self.kind.split(".")[-1]
        if not self.id:
            # id stable (cible+kind) — pas de Date.now/random : reproductible
            self.id = f"{self.kind}:{self.target}"


@dataclass
class Decision:
    verdict: str            # VETO | DRY_RUN | FIRE
    action_id: str
    target: str
    kind: str
    exploit: bool
    destructive: bool
    reasons: list[str]
    # IP ÉPINGLÉES au POINT DE TIR (anti-rebinding) : la/les IP contre lesquelles le verdict a été rendu
    # (résolution UNIQUE au fire-time). Vide sauf sur un FIRE. Le moteur les passe au module (action.params
    # ["_pinned_ips"]) ET lie le contexte `pin.using` : les chokepoints de connexion (Oracle._http, httpflow.
    # _timed) SE CONNECTENT à cette IP (Host/SNI/cert = hôte d'origine, TLS non affaibli) au lieu de
    # re-résoudre -> l'épinglage est END-TO-END (verdict ET connexion), fermant la fenêtre de rebinding.
    pinned_ips: list[str] = field(default_factory=list)
    ts: str = field(default_factory=_now)

    @property
    def will_fire(self) -> bool:
        return self.verdict == FIRE

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict, "action_id": self.action_id, "target": self.target,
            "kind": self.kind, "exploit": self.exploit, "destructive": self.destructive,
            "reasons": self.reasons, "pinned_ips": self.pinned_ips, "ts": self.ts,
        }


def _float_or_none(value: Any) -> "float | None":
    """Flottant lisible et non-NaN, ou None. Pur, ne lève jamais."""
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if out == out else None                    # NaN -> aucune information


def _run_rate(data: dict[str, Any]) -> "tuple[float, str]":
    """`(plafond de débit du RUN en req/s, nom du réglage d'origine)` — 0.0 => AUCUN plafond.

    TROIS ÉCHELONS, et le troisième est le plus important :

      1. `scope.run_rate` — le réglage DÉDIÉ. Il PRIME toujours, y compris pour DÉSARMER (`0`) un run
         qui serait sinon bridé par l'échelon 2. Illisible => traité comme ABSENT (on retombe sur
         l'échelon suivant, fail-open comme tous les overrides de ce dépôt) ;
      2. `rate_explicit: true` — le levier qui existait DÉJÀ et qui dit « bride TOUT, outils compris,
         cet engagement l'exige » (cf. `docs/CONFIGURATION.md` §2bis). Un opérateur qui l'arme a déjà
         accepté d'en payer le prix en couverture ; lui rendre en plus un `rate` qui vaut vraiment
         req/s AU RUN est ce qu'il croyait déjà avoir. C'est le seul armement automatique ;
      3. RIEN — pas de plafond. C'est le DÉFAUT, et il est délibéré : `rate: 5` imposé aux outils fait
         passer naabu de 1,1 min à 3,6 h (mesuré). Un plafond de run armé d'office effondrerait la
         couverture de tout run existant qui n'a rien demandé. Un frein est une décision d'opérateur ;
         sans décision, pas de frein — exactement la règle de `interrupt.resolve_run_timeout`.

    Pur, ne lève jamais."""
    if "run_rate" in data:
        explicit = _float_or_none(data.get("run_rate"))
        if explicit is not None:
            return (explicit, "scope.run_rate") if explicit > 0 else (0.0, "")
    if bool(data.get("rate_explicit", False)):
        derived = _float_or_none(data.get("rate", 5))
        if derived is not None and derived > 0:
            return derived, "scope.rate (rate_explicit)"
    return 0.0, ""


class Scope:
    """Périmètre autorisé. Appartenance fail-closed : in_scope vide => rien n'est en scope."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.mode = data.get("mode", "black")                 # white | grey | black
        self.in_scope = list(data.get("in_scope", []))
        self.out_scope = list(data.get("out_scope", []))
        self.rate = int(data.get("rate", 5))
        # DÉBIT EXPLICITE (opt-in per-run) : True si l'opérateur a fixé un `rate` au lancement (vs le
        # défaut). Gate l'injection du débit dans les DRAPEAUX des outils natifs/wrappers (nmap --max-rate,
        # nuclei -rl, naabu -rate, …) : sans override explicite, aucun drapeau de débit n'est ajouté
        # (argv BYTE-IDENTIQUE au défaut). Le throttle des oracles (Oracle._http) respecte `rate` en tout
        # temps (débit ROE), c'est l'ajout de drapeaux CLI aux sous-process qui est opt-in.
        self.rate_explicit = bool(data.get("rate_explicit", False))
        # PLAFOND DE DÉBIT AU NIVEAU DU RUN (`forge/throttle.RunCap`) — le second étage de débit. 0.0 =>
        # AUCUN plafond (défaut : comportement byte-identique). `run_rate_source` NOMME le réglage d'où
        # il vient, pour qu'un run bridé puisse être remonté à sa cause en une lecture. Cf. `_run_rate`.
        self.run_rate, self.run_rate_source = _run_rate(data)
        # EGRESS TIERS DES MODULES — l'opérateur autorise-t-il un module à sortir vers un HÔTE TIERS
        # (ni la cible, ni un service qu'il a lui-même configuré) ? Absent/False => REFUSÉ (fail-closed,
        # comme tout le reste de ce fichier). Trois formes acceptées, cf. `egress_allowed`.
        self.allow_tool_egress = data.get("allow_tool_egress", False)
        self.allow_exploit = bool(data.get("allow_exploit", False))
        self.allow_destructive = bool(data.get("allow_destructive", False))
        # POLITIQUE RÉSEAU (privé/LAN/loopback) — CONTRAT avec la console Rust (`runs.rs::run_create`
        # écrit `allow_private` = global master AND opt-in engagement). ABSENT => False (FAIL-CLOSED :
        # une base de scope legacy ou un scope.json crafté sans le champ ne peut PAS scanner de cible
        # privée). Quand False, `Roe.decide` VÉTO toute cible qui EST une IP privée OU qui RÉSOUT vers
        # une IP privée (anti-rebinding/SSRF) — couche INDÉPENDANTE et additive au scope-guard.
        self.allow_private = bool(data.get("allow_private", False))
        self.known_creds = data.get("known_creds", [])
        self.idor_targets = data.get("idor_targets", [])
        # CONTEXTE D'AUTHENTIFICATION PAR-ENGAGEMENT (R5) — bloc OPTIONNEL `auth` porté TEL QUEL
        # (interprété par `session.AuthContext.from_scope`, miroir de `allow_private`/`module_params` :
        # le Scope ne fait que TRANSPORTER, la logique vit ailleurs). Forme :
        #   auth: { accounts: [ {label, headers|cookies|bearer}, … ],
        #           idor_targets: [ {url: <in-scope>, owner: "victim", marker: "<preuve donnée victime>"} ] }
        # Les comptes de test sont ceux de L'OPÉRATEUR (attaquant + victime) sur des cibles IN-SCOPE ;
        # l'oracle IDOR REJOUE une requête vers une ressource possédée par la victime avec la session de
        # l'ATTAQUANT -> si la donnée victime revient (marqueur / 2xx là où l'anon est refusé) = IDOR
        # cross-compte. SECRET : les creds/cookies/bearer sont RÉDIGÉS partout où ils pourraient
        # affleurer (ledger/rapport/log/evidence) et n'entrent JAMAIS dans le ledger tels quels. ABSENT
        # => `AuthContext.from_scope` rend None => l'oracle se comporte comme aujourd'hui (skip « config
        # manquante ») : INERTE par défaut, aucun changement de comportement.
        self.auth = data.get("auth")
        # params par-module GLOBAUX (clé additive : ignorée par le ROE/Scope, consommée par l'engine).
        # Exposée ici pour que la CLI n'ait pas à re-lire/re-parser le scope.json une 2e fois.
        self.module_params = data.get("module_params") or {}
        # GOUVERNANCE CONNECTEUR (console) : ensemble de kinds de modules DÉSACTIVÉS par l'opérateur via
        # l'admin console (enabled=0 ou available_override=0). L'engine les SKIP EXACTEMENT comme un outil
        # absent — MÊME si le binaire/service est présent (l'opérateur a "désinstallé" le connecteur ;
        # cf. engine.execute). Couvre AUSSI les modules choisis par le planner, pas seulement `--modules`.
        # Additif/fail-closed lisible : absent/illisible => aucun module désactivé (comportement inchangé) ;
        # les entrées non-string sont ignorées (jamais une exception -> jamais un FIRE fabriqué).
        self.disabled_modules = {m for m in (data.get("disabled_modules") or []) if isinstance(m, str)}
        # SESSION (SECRET) — matériel d'authentification OPTIONNEL (cookies / en-têtes / bearer) que les
        # modules recon/oracle attachent UNIQUEMENT aux requêtes vers des hôtes IN-SCOPE (scope-guard ;
        # cf. forge/session.py). SECRET : jamais journalisé dans le ledger, jamais dans un finding/
        # rapport, jamais placé dans action.params ni dans le graphe d'engagement. `session` = défaut
        # global ; `sessions` = map hôte -> matériel par-hôte. Additifs : absents => aucun changement.
        self.session = data.get("session")             # défaut global (dict) | None
        self.sessions = data.get("sessions") or {}     # map hôte -> matériel de session (par-hôte)
        # SÉLECTION DE TECHNIQUES PAR-SCOPE (DÉRIVÉE de forge/techniques.py) — le levier « au scope
        # retirer des tests automatiques ». Trois champs OPTIONNELS, additifs et fail-closed :
        #   `profile`            : "bug_bounty" | "pentest" | "custom" (None => NON configuré).
        #   `techniques_enabled` : itérable de kinds OU map {kind:bool} (toggle on/off) | None.
        #   `categories_enabled` : itérable de vuln_class OU map {vuln_class:bool} (toggle) | None.
        # Absents (les 3 None) => scope LEGACY : effective set = TOUTES les techniques (aucun filtrage,
        # rétro-compat stricte). Présents => `effective_technique_kinds()` résout l'ensemble ACTIVÉ
        # (profil ∪ activations − désactivations) que l'engine ENFORCE (planner/brain + tir), en plus
        # du scope-guard. Une technique désactivée/hors-profil n'est JAMAIS ni planifiée ni tirée.
        self.profile = data.get("profile")
        self.techniques_enabled = data.get("techniques_enabled")
        self.categories_enabled = data.get("categories_enabled")
        # TRIAGE DES FINDINGS (couche de VUE post-collecte : dédup / cluster-bruit / score / rang) —
        # additif, fail-open, DÉFAUT SÛR (annote + classe, ne masque RIEN). Config OPTIONNELLE lue ici
        # comme un simple dict passé tel quel à `triage.TriageConfig.from_dict` (miroir de `allow_private`
        # /`module_params` : le Scope ne fait que le porter, l'interprétation vit dans forge/triage.py).
        # Absent => None => défauts sûrs (triage ON, auto_hide OFF). Ne change RIEN au ledger ni aux
        # findings bruts : le triage est appliqué au RENDU du rapport (build_report), pas au moteur.
        self.triage = data.get("triage")
        # ASSIST LLM (IA-2) — couche OPTIONNELLE, OFF PAR DÉFAUT, qui ENRICHIT la triage IA-1 d'un résumé
        # consultatif produit par un LLM OpenAI-compatible. Gouvernée EXACTEMENT comme `allow_private` :
        # absente/illisible => None => `llm.LLMConfig.from_dict` retombe sur `enabled=False` (aucun LLM,
        # rapport BYTE-IDENTIQUE). Le Scope ne fait que PORTER le dict ; l'interprétation, l'egress ledgeré
        # et le gate externe (`allow_external`) vivent dans forge/llm.py. Advisory-only : ne touche NI les
        # findings NI le ledger des findings (cf. report.build_report / llm.enrich_triage).
        self.llm = data.get("llm")
        self.notes = data.get("notes", "")
        # CACHE DNS PAR-RUN (anti-rebinding L2) : hôte canonique -> résultat de résolution. Évite de
        # re-résoudre (et re-staller) le même hôte à chaque décision d'un run, et STABILISE le verdict
        # (une seule vérité de résolution par run). Valeurs : list[str] (IP résolues, [] si NXDOMAIN) ou
        # la sentinelle `_TIMEOUT` (résolution expirée -> VETO fail-closed persistant pour le run).
        self._dns_cache: dict[str, Any] = {}
        # VERROU DE RÉSOLUTION (déterminisme sous PARALLÉLISME intra-vague) : sous l'exécuteur borné du
        # moteur (FORGE_PARALLELISM), plusieurs actions peuvent atteindre le point de tir en même temps et
        # résoudre le MÊME hôte concurremment. Sans garde, deux résolutions simultanées du même hôte
        # (avant la mise en cache) pourraient épingler des IP dans un ORDRE différent (round-robin DNS) et
        # rendre le verdict/pin NON reproductible AU SEIN d'un run. Ce verrou sérialise l'accès au cache :
        # le 1er thread résout, les suivants lisent le cache -> « une seule résolution par hôte et par run »
        # (le contrat legacy de la mémoïsation) est PRÉSERVÉ à l'identique en parallèle. En mode SÉRIEL
        # (pool<=1) le verrou n'est JAMAIS contendu -> zéro changement de comportement.
        self._dns_lock = threading.Lock()

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    @staticmethod
    def _host(value: Any) -> str:
        """Hôte canonique pour le matching glob : retire scheme/port, casefold.
        Conserve la valeur brute pour le chemin CIDR/IP (qui n'appelle pas ceci)."""
        s = str(value).strip().casefold()
        if "://" in s:                                        # retire le scheme
            s = s.split("://", 1)[1]
        s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in s:                                          # retire userinfo
            s = s.rsplit("@", 1)[1]
        if s.startswith("["):                                 # IPv6 littéral [::1]:port
            s = s[1:].split("]", 1)[0]
        elif s.count(":") == 1:                               # host:port (pas IPv6 nu)
            s = s.split(":", 1)[0]
        return s

    # Ports implicites — seuls ceux dont le scheme détermine le port SANS ambiguïté.
    _SCHEME_PORTS = {"http": 80, "https": 443}

    @staticmethod
    def _port(value: Any) -> int | None:
        """Port de `value` : explicite (`:NNNN`) sinon déduit du scheme, sinon None (= indéterminé).

        Miroir exact du découpage de `_host` pour que les deux ne divergent jamais sur une même
        entrée. None n'est PAS « n'importe quel port » : c'est « on ne sait pas », et les deux
        appelants en tirent des conclusions opposées (cf. `is_in_scope`)."""
        s = str(value).strip().casefold()
        scheme = ""
        if "://" in s:
            scheme, s = s.split("://", 1)
        s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in s:
            s = s.rsplit("@", 1)[1]
        raw = ""
        if s.startswith("["):                                 # [IPv6]:port
            rest = s.split("]", 1)[1] if "]" in s else ""
            raw = rest[1:] if rest.startswith(":") else ""
        elif s.count(":") == 1:                               # host:port (pas IPv6 nu)
            raw = s.split(":", 1)[1]
        if raw:
            try:
                p = int(raw)
            except ValueError:
                return None                                   # `host:abc` -> indéterminé, pas 0
            return p if 0 < p < 65536 else None
        return Scope._SCHEME_PORTS.get(scheme)

    def _match(self, target: str, patterns: Iterable[Any], *,
               unknown_port_matches: bool = False) -> bool:
        """Le motif décide de la granularité : SANS port il porte sur l'hôte entier (comportement
        historique), AVEC un port il ne porte que sur ce port.

        `unknown_port_matches` tranche le cas « le motif exige un port, la cible n'en révèle aucun ».
        Il n'y a pas de réponse neutre, donc chaque appelant choisit celle qui va vers la sûreté :
        False côté in_scope (on n'élargit pas un périmètre sur une supposition), True côté out_scope
        (un port indéterminable ne doit pas servir d'échappatoire à une interdiction)."""
        host = self._host(target)
        tport = self._port(target)
        for p in patterns:
            if not isinstance(p, str):                        # pattern non-string => fail-closed (ignore)
                continue
            try:                                              # CIDR / IP ?
                net = ipaddress.ip_network(p, strict=False)
                try:
                    # tester l'HÔTE CANONIQUE (scheme/port/path retirés), pas le `target` brut :
                    # sinon ip_address('http://10.0.0.5/admin') lève ValueError -> aucun match ->
                    # une IP out_scope (10.0.0.5/32) serait contournée via une URL ou un host:port.
                    if ipaddress.ip_address(host) in net:
                        return True
                except ValueError:
                    pass
                continue
            except ValueError:
                pass
            ph = self._host(p)                                # hôte canonique des deux côtés
            if not (fnmatch.fnmatch(host, ph) or host == ph):  # glob hostname normalisé
                continue
            pport = self._port(p)
            if pport is None:                                 # motif host-level => tous les ports
                return True
            if tport == pport:                                # motif port-level => CE port seulement
                return True
            if tport is None and unknown_port_matches:
                return True
        return False

    def is_in_scope(self, target: str) -> bool:
        if not target:
            return False
        if self._match(target, self.out_scope, unknown_port_matches=True):   # l'emporte toujours
            return False
        return self._match(target, self.in_scope)

    # --- POLITIQUE RÉSEAU (privé/LAN/loopback) : détection AUTORITATIVE (littéral + résolution) ---
    def resolve_target_ips(self, target: str) -> list[str]:
        """Résout la cible en IP ÉPINGLABLES (anti-rebinding). C'est LE point de résolution unique du ROE :
        appelé UNIQUEMENT au fire-time (pas en plan/dry -> pas de fuite d'intention opsec, L3), le résultat
        est mémoïsé par-run (L2) pour STABILISER le verdict et éviter de re-staller. Une IP littérale est
        renvoyée sans I/O. Un hôte inconnu (gaierror) rend []. Un DÉPASSEMENT de résolution lève
        `_ResolveTimeout` (le ROE le convertit en VETO fail-closed). Le décideur épingle CETTE liste et
        rend le verdict (privé / out_scope-par-IP) CONTRE ELLE."""
        host = self._host(target)
        if not host:
            return []
        # SOUS VERROU (cf. self._dns_lock) : check-cache-puis-résous est ATOMIQUE par-hôte -> un seul thread
        # résout un hôte donné, les autres attendent puis lisent le cache. Garantit « une résolution par
        # hôte et par run » même sous l'exécuteur parallèle (déterminisme du pin/verdict). Non contendu en
        # mode sériel. La résolution bornée (`_resolve_ips`, deadline 5s) reste sous le verrou : elle est
        # DÉJÀ mémoïsée après le 1er hit, la contention réelle est donc négligeable (peu d'hôtes distincts).
        with self._dns_lock:
            cached = self._dns_cache.get(host)
            if cached is _TIMEOUT:                            # timeout déjà observé ce run -> re-fail-closed
                raise _ResolveTimeout(host)
            if cached is not None:                            # liste résolue mémoïsée (y compris [])
                return list(cached)
            try:
                ips = _resolve_ips(host)
            except _ResolveTimeout:
                self._dns_cache[host] = _TIMEOUT              # mémoïse le timeout (verdict stable sur le run)
                raise
            self._dns_cache[host] = list(ips)
            return list(ips)

    def resolved_ips_private(self, ips: Iterable[str]) -> bool:
        """True si AU MOINS une IP (déjà résolue/épinglée) est privée/LAN/loopback. Une seule suffit."""
        return any(_ip_is_private(ip) for ip in ips)

    def out_scope_matches_ips(self, ips: Iterable[str]) -> bool:
        """True si une IP RÉSOLUE tombe dans un pattern CIDR/IP d'`out_scope` (L4 : symétrie avec le veto
        privé). Ferme l'asymétrie où un hostname RÉSOLVANT dans une plage out_scope contournait le matching
        littéral. Patterns non-CIDR (globs hostname) ignorés ici : ils sont déjà couverts par `is_in_scope`
        sur l'hôte. Patterns non-string ignorés (fail-closed lisible)."""
        ip_objs = []
        for ip in ips:
            try:
                ip_objs.append(ipaddress.ip_address(str(ip).strip()))
            except ValueError:
                continue
        if not ip_objs:
            return False
        for p in self.out_scope:
            if not isinstance(p, str):
                continue
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError:
                continue                                      # pattern hostname : hors de ce chemin IP
            if any(ip in net for ip in ip_objs):
                return True
        return False

    def safe_pinned_ip(self, target: str) -> str | None:
        """UNE IP SÛRE à ÉPINGLER pour une CONNEXION dérivée à runtime (ex : cible d'une REDIRECTION
        CROSS-HOST que le ROE n'a PAS déjà épinglée au fire-time), en appliquant les MÊMES règles
        fail-closed que `Roe.decide` au point de tir. Rend None (=> l'appelant REFUSE de suivre /
        connecter) si :
          - la résolution EXPIRE (`_ResolveTimeout`) ;
          - l'hôte est INCONNU / ne résout vers aucune IP ([]) ;
          - une IP résolue est PRIVÉE/LAN/loopback et `allow_private` est False (anti-rebinding) ;
          - une IP résolue tombe dans un CIDR/IP `out_scope`.
        Sinon la 1re IP résolue (déterministe — même choix que `pin.pick`). NE remplace PAS le
        scope-guard hostname (`is_in_scope`, que l'appelant a déjà vérifié) : c'est la COUCHE réseau
        anti-rebinding pour un hôte non déjà gouverné par une Decision. Utilise la résolution bornée +
        mémoïsée par-run. Ne lève jamais."""
        try:
            ips = self.resolve_target_ips(target)
        except _ResolveTimeout:
            return None
        if not ips:
            return None
        if not self.allow_private and self.resolved_ips_private(ips):
            return None
        if self.out_scope_matches_ips(ips):
            return None
        return ips[0]

    def is_private_target(self, target: str) -> bool:
        """True si la cible EST une IP privée/LAN/loopback OU RÉSOUT vers une telle IP (rétro-compat :
        API publique conservée). S'appuie sur `resolve_target_ips` (résolution bornée + cache). Un timeout
        de résolution est traité ici comme « non prouvé public » -> False pour préserver le contrat legacy
        (hôte inconnu => False) ; le CHEMIN DE DÉCISION (`Roe.decide`), lui, VÉTO sur timeout (fail-closed).
        Le check littéral reste sans I/O réseau (sûr en plan/dry)."""
        host = self._host(target)
        if not host:
            return False
        if _ip_is_private(host):                              # cible = IP LITTÉRALE privée (aucune I/O)
            return True
        try:
            return self.resolved_ips_private(self.resolve_target_ips(target))
        except _ResolveTimeout:
            return False

    # --- EGRESS TIERS DES MODULES (déclaré par le module, autorisé — ou non — par l'engagement) ---
    def egress_allowed(self, hosts: Iterable[Any]) -> bool:
        """L'engagement autorise-t-il ce module à sortir vers ces HÔTES TIERS ? Fail-closed.

        POURQUOI CETTE PORTE EXISTE. Forge gate DÉJÀ l'assist LLM (`scope.llm.allow_external`) et le
        backend mémoire à embeddings par un egress EXPLICITE. Elle ne gatait pas ses OUTILS — et la
        mesure a rendu l'incohérence intenable : `recon.httpx`, retenu comme loopback-safe, a
        téléchargé **92,6 Mio depuis huggingface.co à CHACUN de ses 4 tirs** (~370 Mio) via son drapeau
        `-tech-detect`, dans un banc annoncé « loopback strict ». C'est le SEUL egress prouvé sur
        4 906 findings, et il était invisible parce que l'exclusion portait sur l'INTENTION déclarée du
        module, jamais sur l'egress OBSERVÉ. Un module qui sort vers un tiers doit le DÉCLARER, et
        l'opérateur doit pouvoir le REFUSER : c'est la doctrine du dépôt, enfin appliquée aux outils.

        TROIS FORMES DE `scope.allow_tool_egress`, une seule clé :
          · absent / `false` / `null`  -> REFUS de tout egress déclaré (DÉFAUT, fail-closed) ;
          · `true`                     -> autorise tous les hôtes DÉCLARÉS (jamais les non déclarés :
                                          la déclaration reste le contrat) ;
          · liste (ou chaîne unique)   -> ALLOWLIST : chaque hôte déclaré doit matcher une entrée
                                          (`fnmatch`, insensible à la casse : `*.huggingface.co`).
                                          Liste VIDE => refus (fail-closed, pas « tout »).
        Toute autre forme (dict, nombre) => refus. `hosts` vide => True : il n'y a RIEN à autoriser,
        et c'est le cas de tous les modules d'aujourd'hui — la porte est donc inerte par défaut.
        Pure, ne lève jamais."""
        declared = [str(h).strip().lower() for h in (hosts or []) if str(h).strip()]
        if not declared:
            return True                                       # rien de déclaré -> rien à autoriser
        policy = self.allow_tool_egress
        if policy is True:
            return True
        if isinstance(policy, str):
            policy = [policy]
        if not isinstance(policy, (list, tuple, set, frozenset)):
            return False                                      # absent/False/dict/nombre -> fail-closed
        allowed = [str(p).strip().lower() for p in policy if str(p).strip()]
        if not allowed:
            return False                                      # allowlist VIDE => refus, pas « tout »
        return all(any(fnmatch.fnmatch(h, pattern) for pattern in allowed) for h in declared)

    # --- SÉLECTION DE TECHNIQUES PAR-SCOPE (enforcement fail-closed, en plus du scope-guard) ---
    def technique_selection_configured(self) -> bool:
        """True si ce scope porte une SÉLECTION de techniques (profil et/ou toggles). Sinon (scope
        LEGACY) l'effective set = toutes les techniques : aucun filtrage, rétro-compat stricte."""
        return (self.profile is not None
                or self.techniques_enabled is not None
                or self.categories_enabled is not None)

    def effective_technique_kinds(self) -> set[str]:
        """L'ENSEMBLE EFFECTIF de kinds-techniques ACTIVÉS pour ce scope (fail-closed). NON configuré
        -> TOUTES les techniques (aucun filtrage : rétro-compat). Configuré -> RÉSOLU depuis la table
        unique (profil bug_bounty par défaut) : profil ∪ activations − désactivations. C'est l'ensemble
        que l'engine ENFORCE : une technique hors de cet ensemble n'est NI planifiée NI tirée, même si
        son module est disponible et la cible in-scope. Import paresseux (roe reste stdlib au chargement)."""
        from . import techniques                        # lazy : garde roe sans dépendance au load
        if not self.technique_selection_configured():
            return set(techniques.technique_kinds())
        return techniques.resolve_enabled_kinds(
            profile=self.profile or "bug_bounty",
            techniques_enabled=self.techniques_enabled,
            categories_enabled=self.categories_enabled)


class Roe:
    """Gate ROE à quatre couches. Inerte par défaut (armed=False, mode='propose')."""

    def __init__(self, scope: Scope, ledger: "Ledger | None" = None, mode: str = "propose") -> None:
        self.scope = scope
        self.ledger = ledger                                  # ledger.Ledger | None
        self.mode = mode                                      # 'propose' (approbation requise) | 'auto'
        self.armed = False
        self._approved: set[str] = set()                      # ids d'actions approuvées

    # --- armement (gestes conscients, journalisés) ---
    def arm(self, reason: str = "armed by operator") -> None:
        self.armed = True
        self._log("roe.arm", {"reason": reason})

    def disarm(self, reason: str = "disarmed") -> None:
        self.armed = False
        self._log("roe.disarm", {"reason": reason})

    def approve(self, action_id: str, reason: str = "approved by operator") -> None:
        self._approved.add(action_id)
        self._log("roe.approve", {"action_id": action_id, "reason": reason})

    # --- décision (le coeur) ---
    def decide(self, action: Action, log: bool = True) -> Decision:
        """Rend le verdict ROE (VETO/DRY_RUN/FIRE) pour `action`. `log=True` (défaut) JOURNALISE la
        décision dans le ledger AU MOMENT DE LA DÉCISION (comportement historique, tous les appelants
        directs). `log=False` construit et rend la Decision SANS écrire au ledger : réservé à l'exécuteur
        PARALLÈLE du moteur (`Engine._decide_blocking`), qui calcule le verdict dans un thread worker SANS
        effet de bord puis JOURNALISE la `roe.decision` lui-même, sur le thread principal, dans l'ORDRE
        d'action déterministe (préserve l'ordre append-only du ledger). L'ordre relatif ledger reste
        identique au sériel : `roe.decision` est toujours écrite AVANT les findings/run-record de l'action."""
        reasons: list[str] = []
        try:
            # Couche 2 — appartenance (fail-closed)
            if not self.scope.is_in_scope(action.target):
                reasons.append(f"hors scope: {action.target}")
                return self._finish(VETO, action, reasons, log=log)

            # Couche 2bis-LITTÉRAL — POLITIQUE RÉSEAU (IP LITTÉRALE privée) : check SANS I/O réseau, sûr
            # en plan/dry. Une cible qui EST déjà une IP privée est VÉTOÉE tout de suite (même non armée) —
            # aucune résolution requise. Le volet ANTI-REBINDING (hostname qui RÉSOUT en privé) est reporté
            # au POINT DE TIR ci-dessous : on ne résout PAS en simulation (L3, opsec) et on épingle l'IP (L1).
            if not self.scope.allow_private and _ip_is_private(self.scope._host(action.target)):
                reasons.append("hors politique réseau (privé/LAN/loopback non autorisé)")
                return self._finish(VETO, action, reasons, log=log)

            # Couche 3 — capacité
            if action.exploit and not self.scope.allow_exploit:
                reasons.append("exploitation non autorisée par le ROE (allow_exploit=false)")
                return self._finish(VETO, action, reasons, log=log)
            if action.destructive and not self.scope.allow_destructive:
                reasons.append("action destructive interdite (allow_destructive=false)")
                return self._finish(VETO, action, reasons, log=log)

            # Couche 3bis — EGRESS TIERS. Même forme que la couche 3 : une CAPACITÉ que le module
            # DÉCLARE et que l'engagement doit avoir autorisée. Ne mord que sur un module qui déclare
            # son egress ET qui ne sait pas s'en passer (`egress_required`) ; un module capable de
            # DÉGRADER n'est jamais vétoé — il reçoit `params['_egress_allowed']=False` et retire la
            # fonctionnalité qui sort (c'est le chemin coverage-safe : borner, pas supprimer).
            if action.egress and action.egress_required \
                    and not self.scope.egress_allowed(action.egress):
                reasons.append(
                    "egress tiers non autorisé par l'engagement (allow_tool_egress) — ce module "
                    f"contacte {', '.join(str(h) for h in action.egress)} EN PLUS de la cible et ne "
                    "sait pas s'en passer ; aucun verdict n'est émis pour cette action")
                return self._finish(VETO, action, reasons, log=log)

            # in-scope + capacité OK -> au pire DRY_RUN, jamais VETO au-delà

            # Couche 1 — engagement armé ?  (AUCUNE résolution DNS avant ce point : chemin inerte pur, L3)
            if not self.armed:
                reasons.append("engagement non armé (dry-run)")
                return self._finish(DRY_RUN, action, reasons, log=log)

            # Couche 4 — action approuvée ?
            if self.mode != "auto" and action.id not in self._approved:
                reasons.append("action non approuvée (mode propose, dry-run)")
                return self._finish(DRY_RUN, action, reasons, log=log)

            # === POINT DE TIR — ANTI-REBINDING (L1/L2/L3/L4) ==========================================
            # On est sur le point de FIRE. C'EST ICI, et NULLE PART AILLEURS, qu'on résout le hostname
            # (résolution unique, bornée par timeout + mémoïsée par-run). Le verdict privé/out_scope est
            # rendu CONTRE l'IP résolue, qui est ensuite ÉPINGLÉE sur la Decision (le moteur la passe au
            # module ET lie `pin.using`). Ferme la TOCTOU sur le VERDICT : un hostname qui paraît public au
            # plan mais RÉSOUT en interne au tir est VÉTOÉ ici. L'épinglage est désormais END-TO-END : les
            # chokepoints de connexion (Oracle._http via `_pinned_open`, httpflow._timed) SE CONNECTENT à
            # l'IP épinglée (Host/SNI/cert = hôte d'origine) au lieu de re-résoudre -> fenêtre de rebinding
            # fermée aussi côté CONNEXION. SEULE EXCEPTION documentée : une redirection HTTP vers un AUTRE
            # hôte re-résout (le pin ne couvre que l'hôte de la cible d'origine ; même hôte reste épinglé).
            try:
                pinned = self.scope.resolve_target_ips(action.target)
            except _ResolveTimeout:                           # résolution expirée -> fail-closed (VETO)
                reasons.append("résolution DNS expirée au tir -> fail-closed (VETO)")
                return self._finish(VETO, action, reasons, log=log)

            # L1/anti-rebinding — l'IP effectivement résolue est-elle privée ? (le hostname pointe interne)
            if not self.scope.allow_private and self.scope.resolved_ips_private(pinned):
                reasons.append("hors politique réseau (privé/LAN/loopback non autorisé)")
                return self._finish(VETO, action, reasons, log=log)

            # L4 — l'IP résolue tombe-t-elle dans un CIDR/IP out_scope ? (symétrie avec le veto privé)
            if self.scope.out_scope_matches_ips(pinned):
                reasons.append(f"IP résolue dans une plage out_scope -> hors scope: {action.target}")
                return self._finish(VETO, action, reasons, log=log)

            reasons.append("armé + in-scope + autorisé + approuvé")
            return self._finish(FIRE, action, reasons, pinned_ips=pinned, log=log)
        except Exception as e:                                # fail-closed : toute erreur => VETO
            reasons.append(f"erreur d'évaluation -> fail-closed: {e!r}")
            return self._finish(VETO, action, reasons, log=log)

    # --- garde stricte (pour les modules : lève si pas FIRE) ---
    def guard(self, action: Action) -> Decision:
        d = self.decide(action)
        if not d.will_fire:
            raise ScopeError(f"{d.verdict}: {action.target} — " + " ; ".join(d.reasons))
        return d

    def _finish(self, verdict: str, action: Action, reasons: list[str],
                pinned_ips: list[str] | None = None, log: bool = True) -> Decision:
        d = Decision(verdict, action.id, action.target, action.kind,
                     action.exploit, action.destructive, reasons,
                     pinned_ips=list(pinned_ips or []))
        # `log=False` -> l'appelant (exécuteur parallèle du moteur) journalisera `roe.decision` lui-même,
        # sur le thread principal, dans l'ordre d'action déterministe. Le ledger reste mono-écrivain.
        if log:
            self._log("roe.decision", d.to_dict())
        return d

    def _log(self, kind: str, detail: dict[str, Any]) -> None:
        # FAIL-SAFE (L5) : un échec d'écriture du ledger (disque plein, permission, WORM verrouillé, etc.)
        # ne doit JAMAIS altérer ni annuler un verdict fail-closed. On journalise en BEST-EFFORT : la
        # Decision est déjà construite et RETOURNÉE par `_finish` quoi qu'il arrive. Sinon une exception
        # d'`append` remonterait dans `decide()` -> convertie en VETO d'un côté, mais surtout casserait le
        # log d'un FIRE légitime : on préfère un verdict CORRECT non journalisé à un verdict corrompu.
        if self.ledger is None:
            return
        try:
            self.ledger.append(kind, detail)
        except Exception:                                     # noqa: BLE001 (le log ne décide jamais)
            pass

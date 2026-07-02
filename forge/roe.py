"""ROE / scope-guard fail-closed — le COEUR de sûreté de Forge.

Hérite de la `Scope` de secpipe (appartenance fail-closed + exploit/destructif
default-deny) et AJOUTE le modèle d'armement de `respond.sh` (Plume) : quatre couches
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
import fnmatch
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

VETO = "VETO"
DRY_RUN = "DRY_RUN"
FIRE = "FIRE"


class ScopeError(Exception):
    pass


def _now():
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
    params: dict = field(default_factory=dict)
    cls: str = ""
    value: float = 0.5
    confidence: float = 0.5
    cost: float = 1.0
    id: str = ""

    def __post_init__(self):
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
    reasons: list
    ts: str = field(default_factory=_now)

    @property
    def will_fire(self):
        return self.verdict == FIRE

    def to_dict(self):
        return {
            "verdict": self.verdict, "action_id": self.action_id, "target": self.target,
            "kind": self.kind, "exploit": self.exploit, "destructive": self.destructive,
            "reasons": self.reasons, "ts": self.ts,
        }


class Scope:
    """Périmètre autorisé. Appartenance fail-closed : in_scope vide => rien n'est en scope."""

    def __init__(self, data):
        self.mode = data.get("mode", "black")                 # white | grey | black
        self.in_scope = list(data.get("in_scope", []))
        self.out_scope = list(data.get("out_scope", []))
        self.rate = int(data.get("rate", 5))
        self.allow_exploit = bool(data.get("allow_exploit", False))
        self.allow_destructive = bool(data.get("allow_destructive", False))
        self.known_creds = data.get("known_creds", [])
        self.idor_targets = data.get("idor_targets", [])
        # params par-module GLOBAUX (clé additive : ignorée par le ROE/Scope, consommée par l'engine).
        # Exposée ici pour que la CLI n'ait pas à re-lire/re-parser le scope.json une 2e fois.
        self.module_params = data.get("module_params") or {}
        # SESSION (SECRET) — matériel d'authentification OPTIONNEL (cookies / en-têtes / bearer) que les
        # modules recon/oracle attachent UNIQUEMENT aux requêtes vers des hôtes IN-SCOPE (scope-guard ;
        # cf. forge/session.py). SECRET : jamais journalisé dans le ledger, jamais dans un finding/
        # rapport, jamais placé dans action.params ni dans le graphe d'engagement. `session` = défaut
        # global ; `sessions` = map hôte -> matériel par-hôte. Additifs : absents => aucun changement.
        self.session = data.get("session")             # défaut global (dict) | None
        self.sessions = data.get("sessions") or {}     # map hôte -> matériel de session (par-hôte)
        self.notes = data.get("notes", "")

    @classmethod
    def load(cls, path):
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    @staticmethod
    def _host(value):
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

    def _match(self, target, patterns):
        host = self._host(target)
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
            if fnmatch.fnmatch(host, ph) or host == ph:       # glob hostname normalisé
                return True
        return False

    def is_in_scope(self, target):
        if not target:
            return False
        if self._match(target, self.out_scope):               # out_scope l'emporte toujours
            return False
        return self._match(target, self.in_scope)


class Roe:
    """Gate ROE à quatre couches. Inerte par défaut (armed=False, mode='propose')."""

    def __init__(self, scope, ledger=None, mode="propose"):
        self.scope = scope
        self.ledger = ledger                                  # ledger.Ledger | None
        self.mode = mode                                      # 'propose' (approbation requise) | 'auto'
        self.armed = False
        self._approved = set()                                # ids d'actions approuvées

    # --- armement (gestes conscients, journalisés) ---
    def arm(self, reason="armed by operator"):
        self.armed = True
        self._log("roe.arm", {"reason": reason})

    def disarm(self, reason="disarmed"):
        self.armed = False
        self._log("roe.disarm", {"reason": reason})

    def approve(self, action_id, reason="approved by operator"):
        self._approved.add(action_id)
        self._log("roe.approve", {"action_id": action_id, "reason": reason})

    # --- décision (le coeur) ---
    def decide(self, action):
        reasons = []
        try:
            # Couche 2 — appartenance (fail-closed)
            if not self.scope.is_in_scope(action.target):
                reasons.append(f"hors scope: {action.target}")
                return self._finish(VETO, action, reasons)

            # Couche 3 — capacité
            if action.exploit and not self.scope.allow_exploit:
                reasons.append("exploitation non autorisée par le ROE (allow_exploit=false)")
                return self._finish(VETO, action, reasons)
            if action.destructive and not self.scope.allow_destructive:
                reasons.append("action destructive interdite (allow_destructive=false)")
                return self._finish(VETO, action, reasons)

            # in-scope + capacité OK -> au pire DRY_RUN, jamais VETO au-delà

            # Couche 1 — engagement armé ?
            if not self.armed:
                reasons.append("engagement non armé (dry-run)")
                return self._finish(DRY_RUN, action, reasons)

            # Couche 4 — action approuvée ?
            if self.mode != "auto" and action.id not in self._approved:
                reasons.append("action non approuvée (mode propose, dry-run)")
                return self._finish(DRY_RUN, action, reasons)

            reasons.append("armé + in-scope + autorisé + approuvé")
            return self._finish(FIRE, action, reasons)
        except Exception as e:                                # fail-closed : toute erreur => VETO
            reasons.append(f"erreur d'évaluation -> fail-closed: {e!r}")
            return self._finish(VETO, action, reasons)

    # --- garde stricte (pour les modules : lève si pas FIRE) ---
    def guard(self, action):
        d = self.decide(action)
        if not d.will_fire:
            raise ScopeError(f"{d.verdict}: {action.target} — " + " ; ".join(d.reasons))
        return d

    def _finish(self, verdict, action, reasons):
        d = Decision(verdict, action.id, action.target, action.kind,
                     action.exploit, action.destructive, reasons)
        self._log("roe.decision", d.to_dict())
        return d

    def _log(self, kind, detail):
        if self.ledger is not None:
            self.ledger.append(kind, detail)

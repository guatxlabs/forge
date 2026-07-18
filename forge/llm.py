# SPDX-License-Identifier: AGPL-3.0-only
"""IA-2 — couche d'assistance LLM OPT-IN, compatible OpenAI, gouvernée (enterprise-safe).

IA-1 (`forge/triage.py`) est la triage NATIVE, DÉTERMINISTE, zéro-egress : elle ANNOTE + CLASSE les
findings sans jamais rien supprimer. IA-2 (ce module) est une COUCHE OPTIONNELLE qui ENRICHIT cette
triage avec un résumé en langage naturel produit par un LLM — SANS jamais devenir autoritaire.

Principe de gouvernance (miroir EXACT de `scope.allow_private` / `scope.triage`) :

  1. OFF PAR DÉFAUT. La communauté / config par défaut => AUCUN LLM, rapport BYTE-IDENTIQUE. Un
     réglage gouverné (`scope.llm.enabled`) l'active. `LLMConfig()` seul = inerte.
  2. EGRESS EXPLICITE + LEDGERÉ. Envoyer la synthèse de triage à l'endpoint LLM = SORTIE DE DONNÉES.
     Quand activé ET qu'un appel est fait, un événement `llm.egress` est journalisé (endpoint
     + CLASSE de données + COMPTES — jamais de secret). Si le `base_url` est NON-loopback (externe),
     l'egress exige une AUTORISATION OPÉRATEUR explicite (`scope.llm.allow_external`, gaté comme
     `allow_private`) ; loopback (Ollama local) = faible risque mais TOUJOURS off-par-défaut + ledgeré.
  3. AVISORY UNIQUEMENT — jamais autoritaire, ne masque JAMAIS un finding. La sortie LLM ENRICHIT la
     triage IA-1 (résumé + hints de priorité) ; elle NE réordonne / NE réécrit / NE supprime NI les
     findings bruts NI le ledger. Le résultat déterministe d'IA-1 fait foi ; le LLM n'ajoute qu'un bloc
     ANNOTÉ « Assist LLM (advisory) ».
  4. FAIL-OPEN + BORNÉ. Endpoint absent / lent / erreur / timeout => capté, sauté, résultat IA-1
     inchangé, AUCUN crash. Timeout court, UN SEUL appel par run (batché sur la synthèse, PAS par
     finding), petit modèle par défaut, `keep_alive` court (le modèle n'est pas épinglé en RAM).
  5. AUCUNE FUITE DE SECRET. `api_key` est un secret WRITE-ONLY (comme le matériel de session) : jamais
     renvoyé par `to_dict()` (GET config), jamais journalisé, jamais dans le ledger. La sortie LLM est
     re-passée au rédacteur unique (`forge.redact`) avant rendu.

STDLIB ONLY (`urllib`) — aucune dépendance nouvelle. Généralisé depuis le pattern éprouvé de
`deepsearch.ollama()` (urllib chat, stream=False, timeout) vers l'API OpenAI-compatible
(`POST <base_url>/v1/chat/completions`), qui fonctionne avec Ollama (`/v1/chat/completions`), OpenAI,
et tout endpoint compatible.
"""
from __future__ import annotations

import ipaddress
import json
import re
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from . import pin
from .redact import redact_secrets
from . import resource_profile
# Prédicat AUTORITAIRE privé/link-local + résolveur BORNÉ de forge/roe.py (source UNIQUE de la logique
# CIDR : loopback 127/8, RFC1918, link-local 169.254/16, ULA fc00::/7, link-local fe80::/10). On les
# RÉUTILISE ici pour la sous-gate d'egress LLM — AUCUNE ré-implémentation de la logique réseau. Import
# au load sûr : roe ne dépend PAS de llm (pas de cycle) et n'importe que la stdlib à son chargement.
from .roe import _ip_is_private, _resolve_ips

# Kind de l'événement d'AUDIT d'egress LLM émis par le MOTEUR (Python). Volontairement PAS `console.*` :
# le ledger RÉSERVE le préfixe `console.` aux entrées de la console Rust (chaîne SHA-256 non signée) et
# REJETTE au `verify()` toute entrée `console.*` signée ed25519 (garde anti-downgrade, cf.
# ledger._alg_kind_allowed). Le moteur signe en ed25519 -> il émet donc `llm.egress` (namespace moteur).
# Quand la CONSOLE (Rust) fera elle-même l'egress dans SON chemin de rapport, elle émettra le pendant
# `console.llm.egress` (console-signé) — hors périmètre FORGE-ONLY (Python) de ce module.
EGRESS_KIND = "llm.egress"

# --- endpoint / loopback --------------------------------------------------------------------------


def is_loopback(base_url: Any) -> bool:
    """True si `base_url` pointe vers loopback (127.0.0.0/8, ::1, localhost). FAIL-CLOSED : URL
    illisible / hôte absent => False (traité comme EXTERNE, donc gaté). Pur, ne lève jamais."""
    try:
        host = urlsplit((str(base_url) if base_url else "").strip()).hostname
    except Exception:
        return False
    if not host:
        return False
    h = host.strip("[]").lower()
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _endpoint_host(base_url: Any) -> str:
    """Hôte lisible de l'endpoint (pour le ledger / le rapport). Jamais le path/creds. Ne lève jamais."""
    try:
        h = urlsplit((str(base_url) if base_url else "").strip()).hostname
        return h or (str(base_url) if base_url else "?")
    except Exception:
        return "?"


# --- SOUS-GATE défense-en-profondeur : destination privée/link-local (anti-SSRF) ------------------
# `allow_external` autorise TOUT hôte non-loopback — y compris RFC1918 (10/8, 172.16/12, 192.168/16),
# link-local 169.254.169.254 (metadata cloud/IMDS) et ULA/link-local v6. Config OPÉRATEUR (pas
# attaquant-atteignable), mais sur un réseau d'entreprise un `base_url` mal réglé toucherait un service
# interne / l'IMDS. On AJOUTE une sous-gate : on RÉSOUT l'hôte de `base_url` et on REFUSE l'egress si
# l'ADRESSE RÉSOLUE est privée/link-local, SAUF opt-in opérateur explicite `allow_private`. Loopback
# (Ollama local) reste TOUJOURS exempt. On RÉUTILISE le prédicat AUTORITAIRE de forge/roe.py
# (`_ip_is_private`, source UNIQUE de la logique CIDR) et son résolveur BORNÉ (`_resolve_ips`, deadline
# dure via thread joint — 5 s par défaut). On vérifie l'ADRESSE RÉSOLUE, pas seulement le littéral : un
# hostname peut résoudre vers 169.254.169.254. FAIL-CLOSED : timeout / NXDOMAIN / [] / toute erreur de
# résolution => traité comme PRIVÉ => egress refusé (l'advisory fail-open est simplement sauté).


def _resolve_destination(config: "LLMConfig") -> "tuple[list[str], bool]":
    """RÉSOUT l'hôte de `config.base_url` UNE SEULE FOIS -> `(ips, blocked)`. `blocked=True` si l'adresse
    RÉSOLUE est privée/link-local OU non prouvée publique (fail-closed). SOURCE UNIQUE de la résolution :
    le VERDICT privé ET l'IP à ÉPINGLER pour la connexion dérivent du MÊME appel `_resolve_ips` — ce qui
    FERME le check-vs-use (DNS-rebinding) : sans ça, le gate résout, puis `urlopen` re-résout au connect
    (une IP publique au gate, `169.254.169.254` au connect). Réutilise `roe._resolve_ips` (borné) +
    `roe._ip_is_private` (autoritatif — aucune logique CIDR dupliquée). FAIL-CLOSED : timeout
    (`_ResolveTimeout`), NXDOMAIN/hôte inconnu ([]) ou toute erreur => `([], True)`. Ne lève jamais."""
    host = _endpoint_host(config.base_url)
    if not host or host == "?":
        return [], True                                # hôte illisible => fail-closed (bloqué)
    try:
        ips = _resolve_ips(host)                        # littéral IP -> renvoyé tel quel (aucune I/O)
    except Exception:                                   # _ResolveTimeout / gaierror / toute erreur
        return [], True                                 # non prouvé public => fail-closed (bloqué)
    if not ips:                                         # NXDOMAIN / hôte inconnu => fail-closed
        return [], True
    return ips, any(_ip_is_private(ip) for ip in ips)   # une seule IP privée suffit (anti-rebinding)


def _resolved_destination_private(config: "LLMConfig") -> bool:
    """True si l'hôte de `config.base_url` RÉSOUT vers une adresse privée/link-local OU n'est PAS
    prouvé public. Délègue à `_resolve_destination` (source UNIQUE de la résolution). FAIL-CLOSED :
    timeout / NXDOMAIN / erreur => True (bloqué). Ne lève jamais."""
    return _resolve_destination(config)[1]


# --- CLASSIFICATEUR d'egress UNIFIÉ (source UNIQUE pour enrich_triage / enrich_payloads / egress_authorized)
# STRINGS d'état ÉMISES TELLES QUELLES dans le rapport (`report.py` branche dessus) — NE PAS renommer.
EGRESS_OK = "ok"
EGRESS_GATED_EXTERNAL = "gated_external"
EGRESS_GATED_PRIVATE = "gated_private"


def _classify_egress(config: "LLMConfig") -> "tuple[str, str | None]":
    """Classe l'egress LLM en `(status, vetted_ip)`, `status ∈ {ok, gated_external, gated_private}`.
    UN SEUL classificateur consommé par `enrich_triage`, `enrich_payloads` ET `egress_authorized` :
    ils ne peuvent plus DÉRIVER (auparavant enrich_triage ré-implémentait le gate inline tandis que
    enrich_payloads passait par `egress_authorized`). Le caller a déjà vérifié `config.enabled`.

    `vetted_ip` = l'IP RÉSOLUE (UNE fois, via `_resolve_destination`) à ÉPINGLER pour la connexion réelle
    (anti-rebinding : la MÊME résolution sert au verdict ET au connect) quand la destination externe est
    prouvée publique ; `None` pour loopback (aucune résolution) et pour l'override `allow_private`
    (résolution normale acceptée par l'opérateur). Ne lève jamais."""
    if is_loopback(config.base_url):
        return EGRESS_OK, None                         # loopback (Ollama local) : aucune résolution, no-op
    if not config.allow_external:
        return EGRESS_GATED_EXTERNAL, None             # gate opérateur externe (fail-closed)
    if config.allow_private:
        return EGRESS_OK, None                         # override opérateur explicite : connexion normale
    ips, blocked = _resolve_destination(config)         # RÉSOUT UNE FOIS : verdict + IP épinglée
    if blocked:
        return EGRESS_GATED_PRIVATE, None              # privé/link-local OU non prouvé public (fail-closed)
    return EGRESS_OK, pin.pick(ips)                     # IP VETTÉE à épingler (pas de 2e résolution au connect)


def _egress_blocked_private(config: "LLMConfig") -> bool:
    """Sous-gate anti-SSRF : True si l'egress vers `base_url` doit être REFUSÉ parce que la destination
    RÉSOUT en privé/link-local SANS override explicite. Loopback => jamais bloqué (cas local par défaut,
    AUCUNE résolution). `allow_private` => override opérateur (AUCUNE résolution). Sinon résolution
    bornée + verdict fail-closed via `_resolved_destination_private`."""
    if is_loopback(config.base_url):
        return False                                   # loopback (Ollama local) TOUJOURS autorisé
    if config.allow_private:
        return False                                   # opt-in opérateur explicite (override)
    return _resolved_destination_private(config)


# --- configuration (miroir de allow_private / TriageConfig : lu depuis scope.json, défaut SÛR) -----
@dataclass
class LLMConfig:
    enabled: bool = False              # OFF PAR DÉFAUT (communauté / défaut => aucun LLM)
    base_url: str = "http://127.0.0.1:11434"   # Ollama local (loopback) par défaut
    model: str = "llama3.2:1b"         # petit modèle par défaut (borné)
    api_key: str = ""                  # SECRET WRITE-ONLY — jamais renvoyé/journalisé/ledgeré
    timeout: float = 30.0              # court (fail-open borné)
    max_tokens: int = 512              # borné (défaut-code == profil `balanced`)
    num_ctx: int = 0                   # fenêtre de contexte (option Ollama, loopback) ; 0 = NE PAS envoyer
    temperature: float = 0.2
    keep_alive: str = "0"              # Ollama : ne PAS épingler le modèle en RAM (extension ignorée par OpenAI)
    allow_external: bool = False       # GATE OPÉRATEUR : autorise l'egress vers un endpoint NON-loopback
    allow_private: bool = False        # SOUS-GATE OPÉRATEUR (défense en profondeur, anti-SSRF) : autorise
                                       # l'egress vers une destination qui RÉSOUT en privé/link-local
                                       # (RFC1918, 169.254 metadata, ULA/link-local v6). Défaut False =>
                                       # FAIL-CLOSED : un `base_url` externe résolvant en interne est REFUSÉ
                                       # même avec `allow_external`. Loopback (Ollama local) reste exempt.

    @classmethod
    def from_dict(cls, data: Any) -> "LLMConfig":
        """Construit depuis `scope.llm` (dict) ou une valeur folle. FAIL-OPEN, TOLÉRANT : toute clé
        absente / illisible retombe sur le défaut SÛR (donc `enabled=False`). `data` non-dict/None =>
        défauts (LLM OFF). Ne lève jamais."""
        if not isinstance(data, dict):
            return cls()
        d = cls()

        def _b(key: str, default: bool) -> bool:
            v = data.get(key, default)
            return bool(v) if isinstance(v, (bool, int)) else default

        def _s(key: str, default: str) -> str:
            v = data.get(key, default)
            return v if isinstance(v, str) and v.strip() else default

        def _i(key: str, default: int, lo: int, hi: int) -> int:
            try:
                return max(lo, min(hi, int(data.get(key, default))))
            except (TypeError, ValueError):
                return default

        def _f(key: str, default: float, lo: float, hi: float) -> float:
            try:
                return max(lo, min(hi, float(data.get(key, default))))
            except (TypeError, ValueError):
                return default

        d.enabled = _b("enabled", d.enabled)
        d.base_url = _s("base_url", d.base_url)
        d.model = _s("model", d.model)
        d.api_key = data.get("api_key") if isinstance(data.get("api_key"), str) else d.api_key
        d.timeout = _f("timeout", d.timeout, 1.0, 120.0)
        # DÉFAUT résolu par profil quand `scope.llm` ne fixe PAS la clé : override explicite (clé présente)
        # > profil (llm_max_tokens / llm_num_ctx) > défaut-code. `balanced` == 512 / 0 -> byte-identique ;
        # `low` allège (256 / 2048). num_ctx=0 == sentinelle « ne pas envoyer » (payload inchangé).
        d.max_tokens = _i("max_tokens", resource_profile.resolve("llm_max_tokens", default=d.max_tokens),
                          16, 8192)
        d.num_ctx = _i("num_ctx", resource_profile.resolve("llm_num_ctx", default=d.num_ctx), 0, 131072)
        d.temperature = _f("temperature", d.temperature, 0.0, 2.0)
        d.keep_alive = _s("keep_alive", d.keep_alive)
        d.allow_external = _b("allow_external", d.allow_external)
        d.allow_private = _b("allow_private", d.allow_private)   # sous-gate privé/link-local (défaut False)
        return d

    def to_dict(self) -> dict[str, Any]:
        """Représentation RÉDIGÉE pour un GET config : l'`api_key` N'Y FIGURE JAMAIS — seul un booléen
        `api_key_set` indique sa présence. C'est la vue write-only du secret (comme session)."""
        return {
            "enabled": self.enabled, "base_url": self.base_url, "model": self.model,
            "api_key_set": bool(self.api_key), "timeout": self.timeout,
            "max_tokens": self.max_tokens, "num_ctx": self.num_ctx, "temperature": self.temperature,
            "keep_alive": self.keep_alive, "allow_external": self.allow_external,
            "allow_private": self.allow_private,
            "loopback": is_loopback(self.base_url),
        }

    def is_external(self) -> bool:
        return not is_loopback(self.base_url)

    def egress_authorized(self) -> bool:
        """L'egress LLM est-il autorisé à SORTIR ? True seulement si activé ET (loopback OU l'opérateur
        a explicitement autorisé l'externe) ET la destination RÉSOLUE n'est PAS privée/link-local (sauf
        opt-in `allow_private`). Chemins FAIL-CLOSED : endpoint externe sans `allow_external` => refus ;
        `base_url` externe qui RÉSOUT en RFC1918/169.254-metadata/ULA sans `allow_private` => refus
        (sous-gate défense-en-profondeur anti-SSRF). Loopback (Ollama local) => TOUJOURS autorisé, sans
        aucune résolution (chemin par défaut inchangé). DÉLÈGUE au classificateur UNIFIÉ `_classify_egress`
        (source unique : même verdict que enrich_triage/enrich_payloads, aucune dérive)."""
        if not self.enabled:
            return False
        status, _ = _classify_egress(self)
        return status == EGRESS_OK


# --- connexion ÉPINGLÉE (anti-rebinding) : dial l'IP VETTÉE au lieu de re-résoudre --------------------
def _pinned_urlopen(req: "urllib.request.Request", ip: str, timeout: float) -> Any:
    """Ouvre `req` en DIALANT l'IP VETTÉE `ip` (résolue UNE fois par le gate) au lieu de re-résoudre le
    DNS au connect — RÉUTILISE `pin.build_pinned_opener` (l'infra d'épinglage END-TO-END déjà employée
    par les oracles/httpflow/recon) : le `Host:` header + le SNI + la validation du certificat restent
    l'HÔTE D'ORIGINE, seule la CIBLE du connect TCP devient l'IP vettée. Ferme la fenêtre de
    DNS-rebinding sub-ms entre le gate et le connect. Seam module-level (monkeypatchable en test comme
    `urllib.request.urlopen`)."""
    return pin.build_pinned_opener(override_ip=ip).open(req, timeout=timeout)


# --- client OpenAI-compatible (stdlib urllib, fail-open, borné) ------------------------------------
class LLMClient:
    """Client chat OpenAI-compatible minimal (`POST <base_url>/v1/chat/completions`). UN appel, borné
    par timeout, FAIL-OPEN (toute erreur => None, jamais d'exception propagée). Compatible Ollama
    (`/v1/chat/completions`), OpenAI, et tout endpoint compatible."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    def _build_request(self, messages: list[dict[str, str]]) -> "urllib.request.Request":
        cfg = self.config
        url = cfg.base_url.rstrip("/") + "/v1/chat/completions"
        payload: dict[str, Any] = {
            "model": cfg.model,
            "messages": messages,
            "temperature": cfg.temperature,
            "max_tokens": cfg.max_tokens,
            "stream": False,
        }
        # `keep_alive` est une EXTENSION Ollama (ne pas épingler le modèle en RAM) sans équivalent OpenAI,
        # et un endpoint OpenAI strict peut REJETER un paramètre inconnu. On ne l'envoie donc QU'aux
        # endpoints loopback (Ollama local) : la compat OpenAI (cloud/externe) reste stricte.
        if cfg.keep_alive and is_loopback(cfg.base_url):
            payload["keep_alive"] = cfg.keep_alive
        # `num_ctx` est une option OLLAMA (fenêtre de contexte) sans équivalent OpenAI strict : envoyée
        # UNIQUEMENT si > 0 ET endpoint loopback (comme keep_alive). num_ctx=0 (profil `balanced`) => AUCUNE
        # option ajoutée => payload BYTE-IDENTIQUE au défaut. Un endpoint OpenAI externe ne la voit jamais.
        if cfg.num_ctx and cfg.num_ctx > 0 and is_loopback(cfg.base_url):
            payload.setdefault("options", {})["num_ctx"] = cfg.num_ctx
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if cfg.api_key:                          # Bearer optionnel (OpenAI / endpoints protégés)
            headers["Authorization"] = f"Bearer {cfg.api_key}"
        return urllib.request.Request(url, data=body, headers=headers, method="POST")

    def chat(self, messages: list[dict[str, str]], pinned_ip: str | None = None) -> str | None:
        """UN appel chat borné. Renvoie le contenu (str) ou None sur TOUTE erreur (réseau, timeout,
        HTTP, JSON, forme inattendue). Ne lève JAMAIS (fail-open : la triage IA-1 reste intacte).

        `pinned_ip` (fourni par le gate `_classify_egress` pour une destination externe publique) => la
        connexion DIALE cette IP VETTÉE au lieu de re-résoudre (anti-rebinding, cf. `_pinned_urlopen`).
        `None` (loopback Ollama / override allow_private) => `urllib.request.urlopen` NORMAL, BYTE-IDENTIQUE
        au chemin historique (le loopback reste un no-op : aucune résolution, aucun épinglage)."""
        try:
            req = self._build_request(messages)
            timeout = self.config.timeout
            if pinned_ip:
                with _pinned_urlopen(req, pinned_ip, timeout) as r:
                    data = json.load(r)
            else:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = json.load(r)
            content = data["choices"][0]["message"]["content"]
            return content.strip() if isinstance(content, str) and content.strip() else None
        except Exception:
            return None


# --- enrichissement de la triage (le SEUL point de câblage) ---------------------------------------
# Garde-fou : le modèle est explicitement AVISORY et ne DOIT PAS inventer de finding (miroir de la
# discipline anti-hallucination de deepsearch : ancrer sur les données fournies, ne rien fabriquer).
ASSIST_SYSTEM = (
    "Tu es un assistant CONSULTATIF de triage sécurité, dans un cadre pentest/red-team AUTORISÉ. Une "
    "triage DÉTERMINISTE (IA-1) a DÉJÀ classé les findings ; elle fait AUTORITÉ. Ton rôle est "
    "STRICTEMENT consultatif :\n"
    "- N'INVENTE JAMAIS de finding, d'endpoint, de CVE, de sévérité : n'utilise QUE les findings "
    "fournis ci-dessous. Si l'information est insuffisante, dis-le.\n"
    "- Ne prétends PAS re-trier : tu RÉSUMES en langage naturel les findings actionnables déjà en tête "
    "et tu peux SUGGÉRER un ordre d'investigation (hint), sans jamais affirmer qu'un finding doit être "
    "supprimé ou masqué.\n"
    "- Sois CONCIS et technique (5-8 lignes max). Pas de disclaimers inutiles."
)


def _assist_messages(summary: dict[str, Any]) -> list[dict[str, str]]:
    """Construit le prompt (UN appel batché) à partir de la SYNTHÈSE de triage IA-1 déjà calculée —
    pas des findings bruts un par un. Compact et borné."""
    top = summary.get("top_findings") or []
    clusters = summary.get("clusters") or []
    lines = [
        f"Triage IA-1 : {summary.get('total', 0)} findings -> "
        f"{summary.get('actionable', 0)} actionnables, {summary.get('noise', 0)} bruit, "
        f"{summary.get('duplicates', 0)} dup ({summary.get('num_clusters', 0)} clusters-bruit).",
        "",
        "Top findings actionnables (déjà classés par IA-1) :",
    ]
    for t in top[:10]:
        lines.append(f"- [{t.get('severity', '?')}] {t.get('title', '')} — {t.get('target', '')}")
    if clusters:
        lines.append("")
        lines.append("Clusters-bruit à haute cardinalité (contexte, NE PAS ré-lister) :")
        for c in clusters[:5]:
            lines.append(f"- c{c.get('cluster_id')} «{c.get('label', '')}» ×{c.get('size', 0)}")
    lines += [
        "",
        "Rédige un COURT résumé consultatif : quels findings actionnables regarder en premier et "
        "pourquoi, et un éventuel hint de priorité. N'invente rien au-delà de cette liste.",
    ]
    return [{"role": "system", "content": ASSIST_SYSTEM},
            {"role": "user", "content": "\n".join(lines)}]


def _egress_detail(config: LLMConfig, summary: dict[str, Any]) -> dict[str, Any]:
    """Détail de l'événement ledger `llm.egress` : endpoint + CLASSE de données + COMPTES.
    JAMAIS de secret (pas d'api_key), JAMAIS le contenu des findings — seulement des agrégats."""
    return {
        "endpoint": _endpoint_host(config.base_url),
        "external": config.is_external(),
        "loopback": is_loopback(config.base_url),
        "model": config.model,
        "data_class": "triage_summary",
        "counts": {
            "total": int(summary.get("total", 0) or 0),
            "actionable": int(summary.get("actionable", 0) or 0),
            "noise": int(summary.get("noise", 0) or 0),
            "clusters": int(summary.get("num_clusters", 0) or 0),
            "top_findings_sent": len(summary.get("top_findings") or []),
        },
    }


def enrich_triage(triage_result: Any, config: LLMConfig, ledger: Any = None) -> dict[str, Any] | None:
    """IA-2 : enrichit la synthèse de triage IA-1 avec un résumé LLM CONSULTATIF.

    Contrat gouverné :
      - LLM OFF (défaut) => renvoie None IMMÉDIATEMENT : AUCUN appel réseau, AUCUN ledger (byte-identique).
      - Endpoint EXTERNE sans `allow_external` => GATÉ : AUCUNE donnée envoyée, AUCUN egress ledgeré ;
        renvoie un bloc `status="gated_external"` (le rapport le signale).
      - Destination qui RÉSOUT en privé/link-local (RFC1918/169.254-metadata/ULA) sans `allow_private`
        (sous-gate anti-SSRF, loopback exempt) => GATÉ : AUCUNE donnée envoyée, AUCUN egress ledgeré ;
        renvoie un bloc `status="gated_private"`. Résolution échouée/expirée => fail-closed (gaté).
      - Autorisé => LEDGER `llm.egress` (endpoint + comptes, PAS de secret) AVANT l'appel
        (la donnée SORT), puis UN appel borné/fail-open. Erreur/timeout => `status="unavailable"`,
        IA-1 intacte. Succès => `status="ok"`, narrative RÉDIGÉE (forge.redact) — advisory only.

    Ne mute NI les findings, NI leur ordre, NI le ledger des findings : ajoute seulement, si egress
    autorisé, l'événement d'AUDIT `llm.egress` (la trace de gouvernance de la sortie).
    """
    if not isinstance(config, LLMConfig) or not config.enabled:
        return None                                    # OFF => rien (byte-identique, zéro réseau)

    host = _endpoint_host(config.base_url)
    external = config.is_external()
    summary = getattr(triage_result, "summary", None) or {}

    # GATE UNIFIÉ (`_classify_egress`, source unique partagée avec enrich_payloads/egress_authorized) :
    #  - `gated_external` : endpoint externe non autorisé par l'opérateur => aucune sortie, aucun egress.
    #  - `gated_private`  : sous-gate anti-SSRF — la destination RÉSOUT en privé/link-local (RFC1918 /
    #    169.254 metadata / ULA v6) sans opt-in `allow_private`, OU la résolution échoue/expire
    #    (fail-closed) — loopback EXEMPT => aucune donnée envoyée, aucun egress ledgeré.
    #  - `ok` : `vetted_ip` = l'IP RÉSOLUE UNE FOIS à ÉPINGLER au connect (anti-rebinding) ; None pour
    #    loopback / override allow_private (connexion normale). L'advisory fail-open continue : IA-1 intacte.
    status_gate, vetted_ip = _classify_egress(config)
    if status_gate == EGRESS_GATED_EXTERNAL:
        return {"status": "gated_external", "endpoint": host, "external": True,
                "model": config.model, "narrative": ""}
    if status_gate == EGRESS_GATED_PRIVATE:
        return {"status": "gated_private", "endpoint": host, "external": external,
                "model": config.model, "narrative": ""}

    # EGRESS : on est sur le point d'ENVOYER la synthèse de triage -> journaliser (comptes, pas de secret).
    if ledger is not None:
        try:
            ledger.append(EGRESS_KIND, _egress_detail(config, summary))
        except Exception:
            pass                                       # un échec ledger ne casse jamais le run (fail-open)

    # Connexion épinglée sur l'IP VETTÉE (destination externe publique) — pas de 2e résolution au connect.
    narrative = LLMClient(config).chat(_assist_messages(summary), pinned_ip=vetted_ip)   # None si erreur
    if not narrative:
        return {"status": "unavailable", "endpoint": host, "external": external,
                "model": config.model, "narrative": ""}
    return {"status": "ok", "endpoint": host, "external": external, "model": config.model,
            "narrative": redact_secrets(narrative)}    # sortie LLM RÉDIGÉE avant rendu (anti-fuite)


# =================================================================================================
#  IA-2 (R6) — enrichissement OPTIONNEL de PAYLOADS d'injection (advisory-only, gouverné à l'identique)
# =================================================================================================
# Deuxième point de câblage LLM (miroir EXACT d'enrich_triage : OFF par défaut, egress ledgeré, gate
# externe, fail-open borné, sortie RÉDIGÉE). Ici le LLM ne fait que PROPOSER des CHAÎNES de payload
# SUPPLÉMENTAIRES pour un endpoint/param crawlé ; l'ORACLE DÉTERMINISTE existant (forge/modules/
# injection.py) les TESTE et les CONFIRME avec sa PREUVE minimale/bénigne inchangée. Le LLM n'élargit
# JAMAIS la capacité de l'oracle (ni son espace d'action, ni son scope-guard, ni le ROE) : il ne fournit
# que des candidats de plus, testés au MÊME titre que les payloads codés en dur. AUCUN finding LLM-only :
# un finding exige TOUJOURS la confirmation déterministe de l'oracle (preuve concrète échoée).
#
# Techniques ENRICHISSABLES : uniquement les oracles à boucle de payload UNIQUE + preuve UNIVERSELLE
# (le produit arithmétique de SSTI est vérifiable quel que soit le wrapper). ssti.eval qualifie : un
# wrapper de template SUGGÉRÉ (contenant les opérandes littéraux N et M) est substitué puis prouvé par
# le MÊME test « le produit évalué apparaît dans la réponse ». Un wrapper qui n'évalue rien -> tested
# (jamais de faux positif). Étendre cet ensemble = câbler la consommation `_llm_extra_payloads` dans
# l'oracle correspondant AVANT d'y ajouter le kind.
ENRICHABLE_KINDS = frozenset({"ssti.eval"})

MAX_ENRICH_PAYLOADS = 8          # cap DUR du nb de payloads suggérés RETENUS par appel (anti-explosion)
_MAX_PAYLOAD_LEN = 256           # un payload suggéré au-delà => rejeté (malformé / bruit)

# Garde-fou anti-hallucination (miroir d'ASSIST_SYSTEM) : le modèle NE propose QUE des chaînes de
# payload, jamais un verdict/endpoint/CVE. La preuve reste 100 % déterministe côté oracle.
_PAYLOAD_SYSTEM = (
    "Tu es un assistant CONSULTATIF de test d'injection SSTI, dans un cadre pentest/red-team AUTORISÉ. "
    "Un oracle DÉTERMINISTE injectera CHAQUE chaîne que tu proposes et vérifiera lui-même la preuve "
    "(le PRODUIT arithmétique évalué apparaît dans la réponse) — tu ne juges RIEN.\n"
    "- Propose UNIQUEMENT des WRAPPERS de template supplémentaires (syntaxes SSTI variées), UN PAR LIGNE.\n"
    "- Utilise les DEUX jetons littéraux majuscules N et M comme opérandes de la multiplication (ex: "
    "`{{N*M}}`, `${N*M}`) : l'oracle les remplacera par ses propres facteurs. CHAQUE ligne DOIT contenir "
    "`N*M`.\n"
    "- AUCUNE prose, AUCUN commentaire, AUCUN bloc de code, AUCUNE numérotation : que des payloads bruts.\n"
    "- N'invente NI endpoint NI finding : tu ne fais que suggérer des chaînes."
)


def _payload_messages(kind: str, target: Any, param: Any) -> list[dict[str, str]]:
    """Prompt COMPACT et BORNÉ pour la suggestion de payloads (un seul appel par endpoint/param)."""
    user = (
        f"Technique: {kind}. Endpoint: {target}. Paramètre injectable: {param}.\n"
        f"Propose jusqu'à {MAX_ENRICH_PAYLOADS} wrappers de template SSTI supplémentaires, un par ligne, "
        f"chacun contenant N*M. Rien d'autre."
    )
    return [{"role": "system", "content": _PAYLOAD_SYSTEM}, {"role": "user", "content": user}]


def _parse_payloads(text: Any) -> list[str]:
    """Parse TOLÉRANT de la sortie LLM en liste de chaînes candidates. Accepte un tableau JSON de
    chaînes, un objet `{"payloads": [...]}`, ou (repli) une chaîne LIGNE-PAR-LIGNE dont on retire les
    puces/numérotations et les clôtures de code. Ne lève JAMAIS (fail-open : garbage -> []). La
    VALIDATION/dédup/borne finale est faite par l'appelant (`enrich_payloads`)."""
    t = (str(text) if text is not None else "").strip()
    if not t:
        return []
    try:                                             # forme JSON stricte (tableau ou objet payloads)
        obj = json.loads(t)
        if isinstance(obj, list):
            return [x for x in obj if isinstance(x, str)]
        if isinstance(obj, dict) and isinstance(obj.get("payloads"), list):
            return [x for x in obj["payloads"] if isinstance(x, str)]
    except Exception:                                # noqa: BLE001 — pas du JSON -> repli ligne-par-ligne
        pass
    out = []
    for line in t.splitlines():
        s = line.strip().strip("`").strip()
        s = re.sub(r"^\s*[-*•]\s*", "", s)      # puce en tête
        s = re.sub(r"^\s*\d+[.)]\s*", "", s)          # numérotation en tête
        if s:
            out.append(s)
    return out


def _payload_egress_detail(config: LLMConfig, kind: str, target: Any, param: Any) -> dict[str, Any]:
    """Détail de l'événement ledger `llm.egress` pour l'enrichissement de payloads : endpoint LLM +
    CLASSE de données + technique + nom de paramètre (jamais de secret, jamais de payload envoyé/reçu,
    jamais l'URL complète — seulement l'hôte de l'endpoint sondé)."""
    return {
        "endpoint": _endpoint_host(config.base_url),
        "external": config.is_external(),
        "loopback": is_loopback(config.base_url),
        "model": config.model,
        "data_class": "injection_context",
        "kind": str(kind),
        "target_host": _endpoint_host(target),
        "param": str(param),
    }


def enrich_payloads(kind: Any, target: Any, param: Any, config: Any,
                    ledger: Any = None) -> list[str]:
    """IA-2 (R6) : renvoie des CHAÎNES de payload SUPPLÉMENTAIRES proposées par le LLM pour un
    endpoint/param d'injection — ADVISORY ONLY. L'oracle déterministe les teste et les confirme.

    Contrat gouverné (miroir d'enrich_triage) :
      - LLM OFF (défaut) OU kind non enrichissable OU param manquant => `[]` IMMÉDIATEMENT : AUCUN appel
        réseau, AUCUN ledger (byte-identique au comportement sans-LLM).
      - Endpoint EXTERNE sans `allow_external` (egress non autorisé) => `[]` : AUCUNE donnée envoyée,
        AUCUN egress ledgeré (le gate tient).
      - Autorisé => LEDGER `llm.egress` (endpoint + technique + param, PAS de secret, PAS de payload)
        AVANT l'appel (la donnée SORT), puis UN appel borné/fail-open. Erreur/timeout/garbage => `[]`
        (fail-open : le run continue avec les payloads déterministes inchangés).
      - Sortie VALIDÉE : chaînes non vides uniquement, longueur bornée (`_MAX_PAYLOAD_LEN`), dédupliquées,
        plafonnées à `MAX_ENRICH_PAYLOADS`, chacune RÉDIGÉE (`forge.redact`) avant retour (anti-fuite).

    Ne mute RIEN (ni findings, ni ordre, ni capacité de l'oracle) : ajoute seulement, si egress autorisé,
    l'événement d'AUDIT `llm.egress`. Ne lève JAMAIS (fail-open total)."""
    try:
        if not isinstance(config, LLMConfig) or not config.enabled:
            return []                                # OFF => rien (byte-identique, zéro réseau)
        if kind not in ENRICHABLE_KINDS:
            return []                                # technique non câblée pour l'enrichissement
        if not param or not isinstance(param, str):
            return []                                # pas de point d'injection => rien à enrichir
        # GATE UNIFIÉ (`_classify_egress`, source unique partagée avec enrich_triage/egress_authorized) :
        # tout état != `ok` (gated_external / gated_private / résolution fail-closed) => [] (le gate tient,
        # aucune sortie). `vetted_ip` = l'IP RÉSOLUE UNE FOIS à ÉPINGLER au connect (anti-rebinding).
        status_gate, vetted_ip = _classify_egress(config)
        if status_gate != EGRESS_OK:
            return []                                # externe non autorisé / privé / fail-closed => gate tient

        # EGRESS : on est sur le point d'ENVOYER le contexte d'injection -> journaliser (pas de secret).
        if ledger is not None:
            try:
                ledger.append(EGRESS_KIND, _payload_egress_detail(config, kind, target, param))
            except Exception:                        # noqa: BLE001 — un échec ledger ne casse jamais le run
                pass

        raw = LLMClient(config).chat(_payload_messages(kind, target, param), pinned_ip=vetted_ip)  # None si erreur
        if not raw:
            return []                                # indisponible/vide => fail-open (déterministe intact)

        out, seen = [], set()
        for cand in _parse_payloads(raw):
            if not isinstance(cand, str):
                continue
            s = cand.strip()
            if not s or len(s) > _MAX_PAYLOAD_LEN:
                continue                             # vide / trop long => rejeté (malformé)
            s = redact_secrets(s)                    # sortie LLM RÉDIGÉE avant usage (anti-fuite)
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
            if len(out) >= MAX_ENRICH_PAYLOADS:      # borne DURE (anti-explosion d'actions)
                break
        return out
    except Exception:                                # noqa: BLE001 — fail-open TOTAL : jamais de crash
        return []

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
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .redact import redact_secrets
from . import resource_profile

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
        return d

    def to_dict(self) -> dict[str, Any]:
        """Représentation RÉDIGÉE pour un GET config : l'`api_key` N'Y FIGURE JAMAIS — seul un booléen
        `api_key_set` indique sa présence. C'est la vue write-only du secret (comme session)."""
        return {
            "enabled": self.enabled, "base_url": self.base_url, "model": self.model,
            "api_key_set": bool(self.api_key), "timeout": self.timeout,
            "max_tokens": self.max_tokens, "num_ctx": self.num_ctx, "temperature": self.temperature,
            "keep_alive": self.keep_alive, "allow_external": self.allow_external,
            "loopback": is_loopback(self.base_url),
        }

    def is_external(self) -> bool:
        return not is_loopback(self.base_url)

    def egress_authorized(self) -> bool:
        """L'egress LLM est-il autorisé à SORTIR ? True seulement si activé ET (loopback OU l'opérateur
        a explicitement autorisé l'externe). Un endpoint externe sans `allow_external` => FAIL-CLOSED."""
        if not self.enabled:
            return False
        return True if is_loopback(self.base_url) else bool(self.allow_external)


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

    def chat(self, messages: list[dict[str, str]]) -> str | None:
        """UN appel chat borné. Renvoie le contenu (str) ou None sur TOUTE erreur (réseau, timeout,
        HTTP, JSON, forme inattendue). Ne lève JAMAIS (fail-open : la triage IA-1 reste intacte)."""
        try:
            req = self._build_request(messages)
            with urllib.request.urlopen(req, timeout=self.config.timeout) as r:
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

    if external and not config.allow_external:
        # GATE : endpoint externe non autorisé par l'opérateur => aucune sortie, aucun egress.
        return {"status": "gated_external", "endpoint": host, "external": True,
                "model": config.model, "narrative": ""}

    # EGRESS : on est sur le point d'ENVOYER la synthèse de triage -> journaliser (comptes, pas de secret).
    if ledger is not None:
        try:
            ledger.append(EGRESS_KIND, _egress_detail(config, summary))
        except Exception:
            pass                                       # un échec ledger ne casse jamais le run (fail-open)

    narrative = LLMClient(config).chat(_assist_messages(summary))   # None sur toute erreur (borné)
    if not narrative:
        return {"status": "unavailable", "endpoint": host, "external": external,
                "model": config.model, "narrative": ""}
    return {"status": "ok", "endpoint": host, "external": external, "model": config.model,
            "narrative": redact_secrets(narrative)}    # sortie LLM RÉDIGÉE avant rendu (anti-fuite)

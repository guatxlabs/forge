"""Cerveau — propose des actions à partir de l'ÉTAT D'ENGAGEMENT (le graphe), pas d'une simple
liste de cibles. C'est ce qui rend la campagne ITÉRATIVE : le cerveau (re)lit le world-model
enrichi par la vague précédente et CHAÎNE les actions (ex: une origine hors-CDN découverte ->
nuclei sur l'IP ; un fingerprint -> oracles à preuve selon la techno).

Interface (le seam où Forge branche l'orchestrateur Claude) :
    Brain.propose(graph_state) -> list[Action]

`graph_state` = un `EngagementGraph` (hosts/services/findings). Rétro-compat : si on passe encore
une `list[Target]` (ancien contrat), `propose()` la convertit en graphe éphémère — les anciens
appels `propose([Target(...)])` restent valides.

En usage orchestré, le cerveau EST l'orchestrateur (Claude Code) : il lit l'état (le graphe) et
passe des actions. `HeuristicBrain` est le défaut autonome sûr (mapping cible→classes + chaînage
sur findings). La priorité réelle est garantie par le planner coverage-safe, pas par le cerveau
(anti-starvation) : le cerveau peut sur-/sous-noter sans affamer une voie qualifiante.
"""
from .roe import Action
from .graph import EngagementGraph
from . import techniques


def _action(kind, target, **kw):
    """Action dont `cls` (classe planner) et `exploit` sont DÉRIVÉS de la table unique
    (forge/techniques.py) — plus d'affectation par-kind recopiée dans le cerveau. Un override
    explicite reste possible (setdefault) ; `cls=""` laisse l'Action dériver le suffixe du kind."""
    kw.setdefault("cls", techniques.action_class(kind))
    kw.setdefault("exploit", techniques.action_exploit(kind))
    return Action(kind, target, **kw)


def _as_graph(graph_state):
    """Accepte un EngagementGraph (nouveau contrat) OU une list[Target] (ancien contrat).

    Rétro-compat : un `propose([Target(...)])` historique est converti en graphe éphémère amorcé
    avec les hosts/attrs des cibles. Détection par duck-typing (`hosts()` = méthode du graphe)."""
    if hasattr(graph_state, "hosts") and callable(getattr(graph_state, "hosts")):
        return graph_state
    g = EngagementGraph()
    for t in (graph_state or []):
        g.add_host(t.host, kind=getattr(t, "kind", "host"), **(getattr(t, "attrs", None) or {}))
    return g


class Brain:
    def propose(self, graph_state):
        raise NotImplementedError


class HeuristicBrain(Brain):
    """Mapping cible→actions candidates + CHAÎNAGE sur l'état du graphe. Volontairement bête : le
    planner protège les classes qualifiantes même si le cerveau les sous-note.

    Deux niveaux :
      1. base (par host)   : recon + scan + oracles qualifiants selon le type/fingerprint.
      2. chaîne (findings) : ré-propose des actions DÉRIVÉES des findings de la vague précédente
         (origine hors-CDN -> nuclei sur l'IP ; fingerprint techno -> oracles ciblés). Idempotent :
         l'id d'action est stable (kind:target), donc une chaîne déjà jouée n'est jamais reproposée."""

    def propose(self, graph_state):
        graph = _as_graph(graph_state)
        out, seen = [], set()

        def add(a):
            if a.id not in seen:
                seen.add(a.id)
                out.append(a)

        # --- niveau 1 : actions de base par host (recon + oracles qualifiants) ---
        for host in graph.hosts():
            attrs = self._host_attrs(graph, host)
            svc = str(attrs.get("service", "")).lower()
            kind = attrs.get("kind", "host")
            is_web = kind in ("url", "app") or "http" in svc or (kind == "host" and not svc)
            for a in self._base_actions(host, kind, svc, is_web, attrs):
                add(a)

        # --- niveau 2 : CHAÎNAGE — actions dérivées des findings déjà au graphe ---
        for host in graph.hosts():
            for a in self._chained_actions(graph, host):
                add(a)

        return out

    # --- helpers ---
    @staticmethod
    def _host_attrs(graph, host):
        """Attrs structurels du nœud host (kind/service/fingerprint...) tels que posés par l'engine."""
        return dict(graph.nodes.get(("host", str(host)), {}) or {})

    def _base_actions(self, host, kind, svc, is_web, attrs):
        # cls/exploit dérivés de la table unique via _action() (plus d'affectation par-kind ici).
        cands = []
        if is_web:
            cands += [
                _action("recon.httpx", host, value=0.3, confidence=0.7, cost=1, desc="fingerprint HTTP"),
                _action("web.nuclei", host, value=0.4, confidence=0.6, cost=2, desc="scan nuclei (medium+)"),
                # classes qualifiantes : sous-notées mais le planner les plancher-protège
                _action("access_control.idor", host,
                        value=0.8, confidence=0.3, cost=2, desc="IDOR/BOLA 2-comptes (diff oracle)"),
                # oracles à PREUVE (self-contained, calqués sur access_control.idor) : proposés sur
                # toute cible web (le planner les plancher-protège, le ROE les gate, les modules ne
                # tirent qu'avec leur config — sinon finding INFO `tested`, jamais de faux positif).
                _action("ssrf.callback", host,
                        value=0.7, confidence=0.3, cost=2, desc="SSRF callback-vérifié (CWE-918)"),
                _action("auth.takeover", host,
                        value=0.8, confidence=0.2, cost=3, desc="ATO/auth-bypass à preuve (CWE-287/640)"),
                _action("cors.credentials", host,
                        value=0.6, confidence=0.3, cost=1, desc="CORS-credentials à preuve (CWE-942)"),
                # origine derrière CDN : découverte (non-exploit), amorce le chaînage vers l'IP.
                _action("origin.find", host, value=0.5, confidence=0.4, cost=2,
                        desc="IP d'origine derrière CDN/WAF"),
            ]
        # ÉVASION (accès derrière CDN/WAF/anti-bot) : pour une cible WEB explicitement marquée PROTÉGÉE
        # (attrs.protected/waf/cdn, posé par le scope/console ou un fingerprint), proposer les enablers
        # d'accès. Ils DÉGRADENT proprement (module `available=False` si le service browser est absent
        # -> SKIP) et restent gatés par le ROE. Rend evasion.* SÉLECTIONNABLE par le planner / --modules.
        if is_web and self._is_protected(attrs):
            cands += self._evasion_actions(host, chained_from="")
        if kind in ("host", "service"):
            cands += [_action("recon.nmap", host, value=0.3, confidence=0.7, cost=2, desc="nmap -sV")]
        return cands

    @staticmethod
    def _is_protected(attrs):
        """Cible « protégée » (derrière CDN/WAF/anti-bot) : marqueur explicite dans les attrs du nœud
        (`protected`/`waf`/`cdn`, posé par le scope/console ou un fingerprint recon.waf chaîné)."""
        return any(attrs.get(k) for k in ("protected", "waf", "cdn"))

    @staticmethod
    def _evasion_actions(host, chained_from=""):
        """Enablers d'évasion (accès derrière CDN/WAF) pour un host PROTÉGÉ. Non-exploit (xhr/turnstile)
        -> proposés d'office ; le module `available` (santé du service browser) et le ROE font le reste."""
        suffix = f" (chaîné depuis {chained_from})" if chained_from else ""
        return [
            _action("evasion.xhr", host, value=0.4, confidence=0.4, cost=1,
                    desc=f"observation requêtes via browser (accès derrière CDN/WAF){suffix}"),
            _action("evasion.turnstile", host, value=0.4, confidence=0.3, cost=1,
                    desc=f"franchir le Turnstile interactif (enabler d'accès){suffix}"),
        ]

    def _chained_actions(self, graph, host):
        """CHAÎNAGE : lit les findings du graphe pour ce host et propose des actions DÉRIVÉES sur de
        NOUVELLES cibles (IP d'origine, service:port). Une action dérivée sur une cible NOUVELLE n'est
        pas un doublon du plan de base (qui ne connaît que les hosts initiaux) -> chaînage observable.

        Règles (idempotentes — l'id stable kind:target empêche tout doublon entre vagues) :
          - origine hors-CDN VÉRIFIÉE (origin.find -> finding HIGH sur une IP) : la cible n'est plus
            le domaine WAF mais l'IP d'origine -> nuclei + IDOR + SSRF + ATO + CORS sur l'IP (bypass WAF).
            C'est le levier majeur : tout le panel d'oracles est rejoué DIRECTEMENT sur l'origine.
          - service HTTP découvert (graph.services, posé par nmap) : on fingerprinte host:port, qui
            amorcera lui-même les oracles web sur cette nouvelle cible à la vague suivante."""
        out = []
        findings = graph.findings_for(host)

        # (a) origine hors-CDN vérifiée -> pivoter TOUT le panel d'oracles sur l'IP d'origine.
        for f in findings:
            title = str(f.get("title", "")).lower()
            origin_found = (f.get("status") == "vulnerable" and "origine" in title
                            and "cdn" in title)
            # le finding origin.find porte l'IP comme `target` ; on attaque l'IP, pas le domaine WAF.
            ip = f.get("target")
            if origin_found and ip and ip != host:
                out += [
                    _action("web.nuclei", ip, value=0.6, confidence=0.6, cost=2,
                            desc=f"nuclei sur origine {ip} (bypass WAF, chaîné depuis origin.find)"),
                    _action("access_control.idor", ip, value=0.8, confidence=0.4, cost=2,
                            desc=f"IDOR sur origine {ip} (bypass WAF, chaîné)"),
                    _action("ssrf.callback", ip, value=0.7, confidence=0.4, cost=2,
                            desc=f"SSRF sur origine {ip} (bypass WAF, chaîné)"),
                    _action("auth.takeover", ip, value=0.8, confidence=0.3, cost=3,
                            desc=f"ATO sur origine {ip} (bypass WAF, chaîné)"),
                    _action("cors.credentials", ip, value=0.6, confidence=0.4, cost=1,
                            desc=f"CORS sur origine {ip} (bypass WAF, chaîné)"),
                ]

        # (b) service HTTP exposé (nmap) -> fingerprint host:port (nouvelle cible -> oracles ensuite)
        for s in graph.services(host):
            name = str(s.get("name", "")).lower()
            port = s.get("port")
            if "http" in name and port:
                out.append(_action("recon.httpx", f"{host}:{port}", value=0.4, confidence=0.6, cost=1,
                                    desc=f"fingerprint service {port} (chaîné depuis nmap)"))

        # (c) WAF/CDN identifié (finding recon.waf) -> la cible est PROTÉGÉE : proposer les enablers
        # d'évasion (accès derrière CDN/WAF) sur ce host. Chaîné depuis le fingerprint, planner-selectable.
        for f in findings:
            if "waf/cdn identifié" in str(f.get("title", "")).lower():
                out += self._evasion_actions(host, chained_from="recon.waf")
                break
        return out

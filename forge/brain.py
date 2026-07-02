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
      1. base (par host)   : recon + scan + oracles qualifiants + SEEDS de découverte selon le type.
      2. chaîne (findings) : ré-propose des actions DÉRIVÉES des findings de la vague précédente. La
         campagne S'AUTO-ALIMENTE, scope-locked (chaque cible dérivée est re-gatée par le ROE) :
           - origine hors-CDN -> tout le panel d'oracles sur l'IP (bypass WAF) ;
           - sous-domaine découvert (recon.subdomains) -> fingerprint techno/WAF + oracles ;
           - endpoint découvert (recon.js_endpoints / recon.urls) -> oracles CIBLÉS (IDOR/XSS/SQLi) ;
           - fingerprint techno -> oracles ; WAF identifié -> enablers d'évasion.
         Idempotent : l'id d'action est stable (kind:target), une chaîne déjà jouée n'est jamais
         reproposée. BORNÉ : le fan-out des cibles DÉRIVÉES est plafonné (MAX_CHAIN_TARGETS) et la
         profondeur par engine.max_waves — garde-fous anti-runaway."""

    # Fan-out bound (anti-runaway) : nb MAX de cibles DÉRIVÉES par découverte (sous-domaines/endpoints)
    # chaînées par proposition. La profondeur est bornée séparément par engine.max_waves.
    MAX_CHAIN_TARGETS = 32

    def propose(self, graph_state):
        graph = _as_graph(graph_state)
        out, seen = [], set()

        def add(a):
            if a.id not in seen:
                seen.add(a.id)
                out.append(a)

        hosts = graph.hosts()
        # cibles DÉRIVÉES par une découverte antérieure (sous-domaine/endpoint/URL historique) : elles
        # arrivent en volume (jusqu'à MAX_HOSTS/MAX_ENDPOINTS par module) -> FAN-OUT BOUND déterministe
        # (tri stable + tête) pour éviter le runaway. Le reste (cibles initiales, origines IP, host:port)
        # n'est pas plafonné (peu nombreux, à haute valeur).
        derived = sorted(h for h in hosts if self._discovery_marker(graph, h))
        derived_set = set(derived)
        kept_derived = set(derived[:self.MAX_CHAIN_TARGETS])
        process = [h for h in hosts if h not in derived_set or h in kept_derived]

        # --- niveau 1 : actions de base par host (recon + oracles + seeds de découverte) ---
        for host in process:
            if self._is_endpoint(host):
                continue                                  # endpoints -> vérification via edge C seulement
            attrs = self._host_attrs(graph, host)
            svc = str(attrs.get("service", "")).lower()
            kind = attrs.get("kind", "host")
            is_web = kind in ("url", "app") or "http" in svc or (kind == "host" and not svc)
            # NE PAS re-semer la découverte sur une cible DÉJÀ dérivée d'une découverte (borne la
            # profondeur : racine -> sous-domaines, mais un sous-domaine ne relance pas l'énumération).
            seed = host not in kept_derived
            for a in self._base_actions(host, kind, svc, is_web, attrs, seed_discovery=seed):
                add(a)

        # --- niveau 2 : CHAÎNAGE — actions dérivées des findings déjà au graphe ---
        for host in process:
            for a in self._chained_actions(graph, host):
                add(a)

        return out

    # --- helpers ---
    @staticmethod
    def _is_endpoint(target):
        """True si `target` désigne un ENDPOINT (chemin/query), pas un hôte nu. Un endpoint est vérifié
        par le chaînage d'oracles CIBLÉS (edge C), jamais par les actions de base (qui sèmeraient
        recon/nmap/origin sur une URL). Robuste : hôte nu / host:port / IP -> False ; URL à chemin -> True."""
        s = str(target)
        if "://" in s:
            s = s.split("://", 1)[1]
        if "?" in s or "#" in s:
            return True
        _, _, path = s.partition("/")
        return bool(path.strip("/"))

    def _discovery_marker(self, graph, host):
        """Marqueur ('' sinon) attestant que `host` a été DÉCOUVERT par une vague précédente (sous-domaine,
        endpoint, URL historique). Détecté via le TITRE des findings (constantes techniques.DISCOVERY_*,
        partagées avec les émetteurs recon). Sert au fan-out bound et à ne pas re-semer la découverte."""
        markers = (techniques.DISCOVERY_SUBDOMAIN_MARKER, techniques.DISCOVERY_ENDPOINT_MARKER,
                   techniques.DISCOVERY_HISTORICAL_URL_MARKER)
        for f in graph.findings_for(host):
            title = str(f.get("title", ""))
            for m in markers:
                if m in title:
                    return m
        return ""
    @staticmethod
    def _host_attrs(graph, host):
        """Attrs structurels du nœud host (kind/service/fingerprint...) tels que posés par l'engine."""
        return dict(graph.nodes.get(("host", str(host)), {}) or {})

    def _base_actions(self, host, kind, svc, is_web, attrs, seed_discovery=True):
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
            # SEEDS DE DÉCOUVERTE (passifs, in-scope-locked) — c'est ce qui rend la campagne
            # AUTO-ALIMENTÉE : leurs findings (hôtes/endpoints in-scope) reviennent au graphe comme
            # cibles de vérification aux vagues suivantes (edges (d)/(e)). NON re-semés sur une cible
            # déjà dérivée d'une découverte (seed_discovery=False) pour borner la profondeur.
            if seed_discovery:
                cands += [
                    _action("recon.subdomains", host, value=0.3, confidence=0.5, cost=1,
                            desc="énumération passive de sous-domaines (amorce la chaîne)"),
                    _action("recon.js_endpoints", host, value=0.3, confidence=0.5, cost=1,
                            desc="endpoints référencés dans le JS (cartographie -> oracles)"),
                    _action("recon.urls", host, value=0.3, confidence=0.5, cost=1,
                            desc="URLs historiques passives (cartographie -> oracles)"),
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
        """Enablers d'évasion (accès derrière CDN/WAF) pour un host PROTÉGÉ. Non-exploit (xhr/turnstile/
        discover) -> proposés d'office ; le module `available` (santé du service browser) et le ROE font
        le reste. `evasion.discover` DÉBLOQUE la chaîne discovery->oracle derrière WAF : il franchit le
        challenge puis émet des endpoints in-scope (DISCOVERY_ENDPOINT_MARKER) que le cerveau chaîne
        vers les oracles (edge e) — là où la recon HTTP challengée n'aurait rien découvert."""
        suffix = f" (chaîné depuis {chained_from})" if chained_from else ""
        return [
            _action("evasion.xhr", host, value=0.4, confidence=0.4, cost=1,
                    desc=f"observation requêtes via browser (accès derrière CDN/WAF){suffix}"),
            _action("evasion.turnstile", host, value=0.4, confidence=0.3, cost=1,
                    desc=f"franchir le Turnstile interactif (enabler d'accès){suffix}"),
            HeuristicBrain._evasion_discover_action(host, chained_from=chained_from),
        ]

    @staticmethod
    def _evasion_discover_action(host, chained_from=""):
        """UNE action `evasion.discover` (voie backed-browser) pour un host. Isolée de `_evasion_actions`
        (tout le panel d'évasion sur un host explicitement PROTÉGÉ) car l'edge (f) « challenge-gaté » ne
        veut proposer QUE la découverte : la recon plain-HTTP a été bloquée par un challenge (0 endpoint +
        signature), on franchit le challenge et ré-alimente la chaîne discovery->oracle, rien de plus.
        Id STABLE (kind:target) partagé avec `_evasion_actions` -> dédupliqué (jamais deux discover)."""
        suffix = f" (chaîné depuis {chained_from})" if chained_from else ""
        return _action("evasion.discover", host, value=0.5, confidence=0.4, cost=1,
                       desc=f"découverte d'endpoints backed-browser derrière WAF (-> oracles){suffix}")

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

        # (f) HOST CHALLENGE-GATÉ : la recon plain-HTTP (recon.js_endpoints / recon.content) a observé une
        # signature de challenge/WAF managé ET n'a extrait AUCUN endpoint (DISCOVERY_CHALLENGE_MARKER).
        # Sans cet edge, la chaîne discovery->oracle serait affamée (0 endpoint = 0 oracle derrière le WAF).
        # On AUTO-PROPOSE la SEULE `evasion.discover` pour ce host in-scope : elle franchit le challenge
        # (browser gouverné) et émet des endpoints (DISCOVERY_ENDPOINT_MARKER) que l'edge (e) chaîne vers
        # les oracles. Scope : le host porte déjà le finding (donc in-scope ; un endpoint découvert HORS
        # périmètre est écarté par le module puis re-gaté par le ROE avant tout oracle). BORNÉ + ANTI-BOUCLE :
        # id stable (kind:target) -> reproposé sans jamais re-tirer ; et `evasion.discover` n'émet JAMAIS le
        # marqueur de challenge (seuls recon.js_endpoints/recon.content le posent) -> sa sortie ne peut pas
        # se re-déclencher (pas d'evasion->evasion). Garde `_is_endpoint` : jamais sur une URL à chemin.
        if not self._is_endpoint(host) and any(
                techniques.DISCOVERY_CHALLENGE_MARKER in str(f.get("title", "")) for f in findings):
            out.append(self._evasion_discover_action(host, chained_from="recon.challenge"))

        # (d) SOUS-DOMAINE découvert (recon.subdomains) -> fingerprint techno/WAF sur le NOUVEL hôte
        # in-scope. Les oracles web sont déjà semés par les actions de base (l'hôte est un nœud du
        # graphe) ; on AJOUTE ici recon.tech + recon.waf demandés par le chaînage discovery->verif.
        # (Le fingerprint WAF peut lui-même déclencher l'évasion via l'edge (c) à la vague suivante.)
        if any(techniques.DISCOVERY_SUBDOMAIN_MARKER in str(f.get("title", "")) for f in findings):
            out += [
                _action("recon.tech", host, value=0.4, confidence=0.6, cost=1,
                        desc="fingerprint techno (chaîné depuis recon.subdomains)"),
                _action("recon.waf", host, value=0.4, confidence=0.6, cost=1,
                        desc="fingerprint WAF/CDN (chaîné depuis recon.subdomains)"),
            ]

        # (e) ENDPOINT découvert (recon.js_endpoints / recon.urls) -> oracles de vérification CIBLÉS sur
        # l'endpoint in-scope. L'endpoint N'EST PAS semé par les actions de base (edge exclusif) : le
        # chaînage est la SEULE source d'actions dessus. La session gouvernée est portée par l'engine
        # (le SessionStore fait hériter à l'endpoint dérivé la session in-scope de sa source).
        if any((techniques.DISCOVERY_ENDPOINT_MARKER in str(f.get("title", ""))
                or techniques.DISCOVERY_HISTORICAL_URL_MARKER in str(f.get("title", "")))
               for f in findings):
            out += self._endpoint_oracles(host)
        return out

    def _endpoint_oracles(self, endpoint):
        """Oracles de vérification CIBLÉS sur un endpoint in-scope découvert (IDOR/access-control, SQLi,
        XSS reflected). Si l'endpoint porte un paramètre de query, il est passé aux oracles à injection
        (`param`) pour une sonde RÉELLE ; sinon ils dégradent proprement en `tested` (jamais de faux
        positif). IDOR reçoit urls=[endpoint] (les comptes/creds sont injectés par l'engine depuis le
        scope). access_control.idor reste exploit=True (dérivé de la table) -> gaté par le ROE : il ne
        TIRE que si l'opt-in exploit est armé, sinon DRY_RUN (le plancher exploit reste OFF par défaut)."""
        param = self._first_query_param(endpoint)
        inj = {"param": param} if param else {}
        return [
            _action("access_control.idor", endpoint, value=0.8, confidence=0.3, cost=2,
                    params={"urls": [endpoint]}, desc="IDOR sur endpoint découvert (chaîné)"),
            _action("sqli.probe", endpoint, value=0.7, confidence=0.3, cost=2,
                    params=dict(inj), desc="SQLi à preuve sur endpoint découvert (chaîné)"),
            _action("xss.reflected", endpoint, value=0.6, confidence=0.3, cost=1,
                    params=dict(inj), desc="XSS reflected à preuve sur endpoint découvert (chaîné)"),
        ]

    @staticmethod
    def _first_query_param(url):
        """Nom du 1er paramètre de query d'une URL ('' si aucun) — point d'injection pour les oracles
        SQLi/XSS chaînés sur un endpoint découvert. Pur, ne lève jamais."""
        from urllib.parse import urlsplit, parse_qsl
        try:
            pairs = parse_qsl(urlsplit(str(url)).query)
            return pairs[0][0] if pairs else ""
        except Exception:            # noqa: BLE001
            return ""

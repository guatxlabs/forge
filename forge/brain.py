# SPDX-License-Identifier: AGPL-3.0-or-later
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
import json as _json

from .roe import Action
from .graph import EngagementGraph
from .modules.oracle import Oracle          # PAYLOAD_SLOT : le créneau d'injection, source unique
from . import resource_profile
from . import techniques


# Priorité d'ORDONNANCEMENT des scanners de CONTENU HTTP (EV = value*confidence/cost, cf. planner). Les
# scanners RAPIDES à FORT SIGNAL (fingerprint HTTP, en-têtes de sécurité, nuclei, techno) doivent passer
# AVANT les ÉNUMÉRATEURS LENTS (nikto, testssl, feroxbuster/content, katana) : sinon, à budget de
# temps borné, `web.nuclei` — le scanner le plus productif vs un scan manuel — restait ordonné DERRIÈRE
# ~40 oracles par port (EV du sweep ~0.25) et n'était JAMAIS atteint (T27), et un nikto qui hang gelait
# tout le pipeline avant que le moindre verdict profond ne sorte. C'est un RÉ-ORDONNANCEMENT (pas un
# changement de capacité) : les lents restent TOUS planifiés, juste APRÈS (defer != delete côté planner ;
# aucune classe qualifiante affamée — elles restent plancher-protégées). Les (value, confidence, cost) sont
# choisis pour que l'ORDRE respecte le tiering ET que les 4 rapides passent au-dessus du sweep auto-pentest
# ET du plancher qualifiant (0.5) — EV DÉCROISSANT :
_CONTENT_SCANNER_EV = {
    "recon.httpx":          (0.9, 0.9, 1.0),   # 0.81 — fingerprint HTTP quasi-instantané (1 requête)
    "web.security_headers": (0.9, 0.85, 1.0),  # 0.765 — audit d'en-têtes (1 GET), fort signal
    "web.nuclei":           (0.9, 0.8, 1.0),   # 0.72 — le scanner le plus productif (templates medium+)
    "recon.tech":           (0.8, 0.75, 1.0),  # 0.60 — fingerprint techno
    "recon.waf":            (0.6, 0.6, 1.0),   # 0.36 — détection WAF/CDN
    "recon.content":        (0.4, 0.4, 2.0),   # 0.08 — feroxbuster/ffuf (brute de répertoires, LENT)
    "recon.katana":         (0.4, 0.4, 2.0),   # 0.08 — crawl (LENT)
    "web.nikto":            (0.35, 0.4, 2.0),  # 0.07 — scan de vulns web (LENT, sujet aux hangs)
    "web.testssl":          (0.3, 0.4, 3.0),   # 0.04 — audit TLS (TRÈS LENT)
}
# EV par défaut d'un scanner de contenu non listé (chaîné sur service découvert) — préserve l'ancien 0.2.
_CONTENT_SCANNER_EV_DEFAULT = (0.4, 0.5, 1.0)


def _content_scanner_action(kind, target, desc, **kw):
    """Action d'un scanner de CONTENU HTTP avec l'EV de son TIER (`_CONTENT_SCANNER_EV`) — source unique de
    la priorité d'ordonnancement (plan de base ET chaînage sur service découvert). Un override explicite de
    value/confidence/cost via `kw` reste possible (setdefault du tier sinon)."""
    v, c, cost = _CONTENT_SCANNER_EV.get(kind, _CONTENT_SCANNER_EV_DEFAULT)
    kw.setdefault("value", v)
    kw.setdefault("confidence", c)
    kw.setdefault("cost", cost)
    return _action(kind, target, desc=desc, **kw)


def _action(kind, target, **kw):
    """Action dont `cls` (classe planner) et `exploit` sont DÉRIVÉS de la table unique
    (forge/techniques.py) — plus d'affectation par-kind recopiée dans le cerveau. Un override
    explicite reste possible (setdefault) ; `cls=""` laisse l'Action dériver le suffixe du kind."""
    kw.setdefault("cls", techniques.action_class(kind))
    kw.setdefault("exploit", techniques.action_exploit(kind))
    return Action(kind, target, **kw)


#: Valeur NEUTRE par type GraphQL, pour compléter un appel sans rien deviner. On ne cherche pas à
#: satisfaire une logique métier — seulement à produire un appel bien formé, que le résolveur puisse
#: atteindre. Un type inconnu retombe sur une chaîne : c'est le cas le plus courant et le plus inerte.
_NEUTRAL_ARG = {"String": '"forge"', "ID": '"1"', "Int": "1", "Float": "1.0", "Boolean": "true"}


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

    # Nb MAX de paramètres de query SONDÉS par endpoint découvert. Un endpoint crawlé multi-params
    # (`?TOPIC=x&QUERY=y`) chaîne chaque oracle à injection UNE FOIS PAR PARAMÈTRE (sinon seul le 1er
    # était testé et `QUERY` restait « config manquante ») — mais BORNÉ ici pour ne pas exploser le
    # fan-out (endpoints ≤ MAX_CHAIN_TARGETS × params ≤ MAX_PARAMS_PER_ENDPOINT × |panel|). Le 1er
    # paramètre garde l'id d'action STABLE (kind:target) — dédup INCHANGÉ vs l'auto-pentest ; les
    # suivants portent un id suffixé (kind:target#param) pour coexister sans s'auto-écraser.
    MAX_PARAMS_PER_ENDPOINT = 3

    # SET COMPLET des scanners de CONTENU HTTP chaînés sur un SERVICE WEB DÉCOUVERT (host:port). Le plan de
    # base ne sème que httpx+nuclei sur un host web ; sur un port DÉCOUVERT (nmap/httpx/naabu/masscan), on
    # chaîne TOUT le panel de contenu — sinon nikto/tech/waf/content/katana/testssl/security_headers
    # ne l'atteignaient JAMAIS en AUTO (ils tapaient le bare :80). Chaque scanner est re-gaté par le ROE
    # (host:port hors-scope -> VETO) et dégrade proprement s'il n'est pas HTTP. httpx/nuclei y figurent aussi
    # (déjà semés par le plan de base -> dédupliqués par l'id d'action stable). Borné : ≤ MAX_CHAIN_TARGETS
    # services découverts × ce set.
    HTTP_CONTENT_SCANNERS = ("recon.httpx", "web.nuclei", "web.nikto", "recon.tech", "recon.waf",
                             "recon.content", "recon.katana", "web.testssl",
                             "web.security_headers")

    def propose(self, graph_state):
        graph = _as_graph(graph_state)
        out, seen = [], set()
        raw_host = self._raw_target_kinds()

        def add(a):
            # MÊME GARDE, COUVERTURE ÉTENDUE (défaut D16) : un kind dont l'outil reçoit la cible TELLE
            # QUELLE et la RÉSOUT comme un hôte n'a RIEN à voir sur une cible qui n'est pas un hôte nu
            # (URL de racine, `host:port`). Cf. `_raw_target_kinds`. Vaut pour le plan de base ET le
            # chaînage — les deux passent par ici.
            if a.kind in raw_host and not self._is_bare_host(a.target):
                return
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
        # Cap fan-out RÉSOLU par profil (`content_fanout_max`) : override > profil > défaut-classe
        # (`self.MAX_CHAIN_TARGETS`). `balanced` == 32 == défaut -> byte-identique ; `low`=8, `full`=64.
        max_chain = resource_profile.resolve("content_fanout_max", default=self.MAX_CHAIN_TARGETS)
        kept_derived = set(derived[:max_chain])
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
        recon/nmap/origin sur une URL).

        DÉLÈGUE à `planner.is_endpoint_target` — SOURCE UNIQUE. Le planner a besoin du MÊME prédicat
        (un producteur de surface n'en est un que sur un HÔTE, cf. `planner.stage`) : la définition a
        donc été remontée là-bas et ce nom reste l'alias historique du cerveau."""
        from .planner import is_endpoint_target       # import paresseux (aucun cycle au chargement)
        return is_endpoint_target(target)

    @staticmethod
    def _is_bare_host(target):
        """True si `target` est un HÔTE NU (ni scheme, ni chemin/query, ni `:port`) — la forme qu'un
        outil qui RÉSOUT un hôte peut consommer telle quelle. DÉLÈGUE à `planner.is_bare_host_target`
        — SOURCE UNIQUE, comme `_is_endpoint` au-dessus (mêmes deux consommateurs, une définition)."""
        from .planner import is_bare_host_target      # import paresseux (aucun cycle au chargement)
        return is_bare_host_target(target)

    @staticmethod
    def _raw_target_kinds():
        """Kinds dont l'outil reçoit la cible **TELLE QUELLE** et la RÉSOUT comme un nom d'hôte —
        donc AVEUGLES sur toute cible qui n'est pas un hôte nu (URL de racine, `host:port`).

        C'EST LA MÊME GARDE QUE `_host_scoped_kinds`, AVEC UNE COUVERTURE ÉTENDUE, PAS UNE SECONDE.
        `_host_scoped_kinds` (D9) répond à « ce kind a-t-il quelque chose à voir sur un ENDPOINT ? » ;
        celui-ci répond à « …sur une cible qui n'est PAS un hôte ? ». Le second ensemble est un
        SOUS-ENSEMBLE STRICT du premier, et il le faut : sur une URL de RACINE, `recon.katana`,
        `recon.feroxbuster`, `recon.content`, `recon.httpx` ou `recon.js_endpoints` — tous
        host-scoped — travaillent PARFAITEMENT (ils prennent une URL). Appliquer l'ensemble D9 tel
        quel aux URL de racine aurait décapité la découverte de contenu : c'est feroxbuster qui a
        trouvé les 1558 findings de DVWA piste B. Le discriminant n'est donc pas « consomme un hôte »
        mais « reçoit la cible SANS NORMALISATION ».

        DÉRIVÉ, jamais recopié — deux sources, exactement comme la garde voisine :
          1. `spec.argv_template` porte un token `{target}` BRUT (ni `{target_host}` — qui retire
             scheme/chemin/userinfo — ni `{target_url}` — qui parle HTTP). Un `ToolSpec` ajouté demain
             est classé sans que personne n'ait à penser à ce fichier. MESURE au moment du lot :
             **0 spec du catalogue** est dans ce cas ; le mécanisme est donc là pour l'avenir, et il
             ne retire rien aujourd'hui.
          2. `recon.nmap` — le NATIF que le système de spec ne peut pas introspecter : il fait
             `argv.append(action.target)` (recon.py, « cible en POSITIONNEL (dernier) »). C'est le
             seul kind que cette garde retire aujourd'hui, et c'est EXACTEMENT celui que le banc a
             mesuré aveugle 13 fois sur 13 (`Nmap done: 0 IP addresses (0 hosts up)`).
             `origin.find`, l'autre natif nommé par la garde voisine, n'y figure PAS : il normalise
             déjà sa cible en hôte (origin.py, « scheme/port/chemin/userinfo retirés »).

        Lu PARESSEUSEMENT et ne lève jamais : registre indisponible -> le natif seul."""
        out = {"recon.nmap"}
        try:
            from .modules import registry as _registry

            def _toks(tpl):
                for tok in tpl or ():
                    if isinstance(tok, (tuple, list)):
                        yield from _toks(tok)
                    else:
                        yield str(tok)
            for kind, module in dict(_registry.REGISTRY).items():
                spec = getattr(module, "spec", None)
                if spec is None:
                    continue
                if any("{target}" in t for t in _toks(getattr(spec, "argv_template", ()))):
                    out.add(kind)
        except Exception:                            # noqa: BLE001 — registre absent -> natif seul
            pass
        return frozenset(out)

    def _discovery_marker(self, graph, host):
        """Marqueur ('' sinon) attestant que `host` a été DÉCOUVERT par une vague précédente (sous-domaine,
        endpoint, URL historique). Détecté via le TITRE des findings (constantes techniques.DISCOVERY_*,
        partagées avec les émetteurs recon). Sert au fan-out bound et à ne pas re-semer la découverte."""
        markers = (techniques.DISCOVERY_SUBDOMAIN_MARKER, techniques.DISCOVERY_ENDPOINT_MARKER,
                   techniques.DISCOVERY_HISTORICAL_URL_MARKER, techniques.DISCOVERY_SERVICE_MARKER)
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
                # scanners de contenu RAPIDES à FORT SIGNAL -> EV de tier (`_CONTENT_SCANNER_EV`) : ordonnés
                # tôt (avant le sweep d'oracles / les énumérateurs lents), sinon nuclei n'était jamais atteint.
                _content_scanner_action("recon.httpx", host, "fingerprint HTTP"),
                _content_scanner_action("web.nuclei", host, "scan nuclei (medium+)"),
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

        # (g) SERVICE WEB DÉCOUVERT (host:port émis par nmap/httpx/naabu/masscan avec DISCOVERY_SERVICE_MARKER)
        # -> chaîner le SET COMPLET des scanners de CONTENU HTTP sur ce service, pas juste httpx+nuclei du
        # plan de base. C'est le correctif du trou E1 : un port découvert n'était scanné (en AUTO) que par
        # httpx+nuclei ; nikto/tech/waf/content/katana/testssl/security_headers ne l'atteignaient
        # jamais et tapaient le bare :80. `host` EST le host:port (nœud dérivé). Chaque scanner est re-gaté
        # par le ROE à la vague suivante (host:port hors-scope -> VETO), dégrade proprement si non-HTTP (C1),
        # et l'id d'action stable dédoublonne httpx/nuclei déjà semés. Borné (≤ MAX_CHAIN_TARGETS × le set).
        if self._discovery_marker(graph, host) == techniques.DISCOVERY_SERVICE_MARKER:
            for kind in self.HTTP_CONTENT_SCANNERS:
                # EV PAR TIER (`_CONTENT_SCANNER_EV`) : les rapides à fort signal (httpx/security_headers/
                # nuclei/tech) passent AVANT les lents (nikto/testssl/ferox/katana) — l'ORDRE change,
                # aucun scanner n'est retiré (tous restent chaînés/planifiés, juste plus tard pour les lents).
                out.append(_content_scanner_action(
                    kind, host, f"scanner de contenu HTTP sur service découvert {host} (chaîné)"))

        # (h) ARGUMENT GRAPHQL DÉCOUVERT (recon.graphql) -> chaîner le panel d'injection AVEC son
        # gabarit de corps. C'est le dernier maillon du chemin GraphQL : sans lui, la surface est
        # décrite et personne ne la teste. Mesuré : DVGA rendait 0 sur 6 classes opposables parce
        # qu'une API GraphQL n'a NI query-string NI formulaire — son point d'injection est un argument
        # dans la chaîne `query`, que `_chain_from_endpoint` (qui lit des paramètres d'URL) ne peut
        # pas voir. Le titre du finding est décodé par la MÊME fonction qui l'a écrit.
        out += self._chain_from_graphql(findings)

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

    # Panel d'oracles à INJECTION param-drivés chaîné sur un endpoint PORTEUR d'un paramètre de query
    # (en PLUS d'IDOR/SQLi/XSS toujours chaînés). Chacun requiert `params.param` (sinon « config manquante ») :
    # le chaînage le lui FOURNIT (param+value extraits de l'URL) -> il prend son CHEMIN DE TEST RÉEL. Les
    # kinds exploit (rce.probe) restent exploit=True (dérivé de la table) -> gatés par le ROE (plancher
    # exploit OFF par défaut : DRY_RUN tant que l'opt-in fort-impact n'est pas armé). (value, confidence, cost)
    # modérés — le planner plancher-protège les qualifiants, le cerveau peut sous-noter sans les affamer.
    # BORNÉ : ≤ MAX_PARAMS_PER_ENDPOINT paramètres par endpoint -> fan-out =
    # endpoints(≤MAX_CHAIN_TARGETS) × params(≤MAX_PARAMS_PER_ENDPOINT) × |panel|.
    _PARAM_INJECTION_ORACLES = (
        ("ssti.eval",                 0.6, 0.3, 2, "SSTI"),
        ("cmdi.probe",                0.7, 0.3, 2, "command-injection"),
        ("nosql.probe",               0.6, 0.3, 2, "NoSQLi"),
        ("lucene.probe",              0.4, 0.3, 1, "search/Lucene injection"),
        ("rce.probe",                 0.8, 0.2, 3, "RCE (exploit-gaté ROE)"),
        ("redirect.open",             0.4, 0.3, 1, "open-redirect"),
        ("prototype_pollution.probe", 0.4, 0.3, 1, "prototype-pollution"),
        ("ssrf.xspa",                 0.5, 0.3, 2, "XSPA/scan de ports via param"),
        ("ssrf.cloud_metadata",       0.6, 0.3, 2, "SSRF cloud-metadata via param"),
    )

    #: Fan-out borné du chaînage GraphQL. Un schéma large × un panel d'oracles produit vite des
    #: milliers d'actions ; la borne est DÉCLARÉE, et ce qu'elle écarte est dit dans le `desc`.
    MAX_GRAPHQL_ARGS = 12

    def _chain_from_graphql(self, findings):
        """Actions dérivées des ARGUMENTS GraphQL découverts par `recon.graphql`.

        Le finding porte l'opération / le champ / l'argument dans son TITRE, encodés par
        `techniques.graphql_arg_title` et relus ici par `parse_graphql_arg_title` — une seule source
        pour le format, jamais deux copies qui divergent.

        On construit le gabarit MINIMAL : `{op{champ(arg:"<créneau>")}}`. Il ne porte AUCUN
        co-argument, et c'est assumé — un producteur générique ne peut pas inventer le mot de passe
        que `systemDiagnostics` exige. Un champ ainsi gaté rendra « non concluant », ce qui est le bon
        sens de l'erreur : l'oracle s'abstient au lieu d'affirmer. L'opérateur qui connaît les
        co-arguments fournit son propre `body_template`, qui n'est jamais écrasé (`setdefault`)."""
        out = []
        for f in findings[:200]:
            parsed = techniques.parse_graphql_arg_title(f.get("title", ""))
            if not parsed:
                continue
            op, field, arg, returns_object, siblings = parsed
            endpoint = f.get("target")
            if not endpoint or len(out) >= self.MAX_GRAPHQL_ARGS * (1 + len(self._PARAM_INJECTION_ORACLES)):
                continue
            slot = Oracle.PAYLOAD_SLOT
            # SÉLECTION DE SOUS-CHAMPS : obligatoire sur un champ qui rend un OBJET, interdite sur un
            # scalaire. `__typename` est le seul champ disponible sur TOUT type objet — il évite de
            # deviner un nom de sous-champ, et il est inerte. La mauvaise forme rendrait « must have a
            # selection of subfields », que l'oracle lirait comme « pas vulnérable » : un faux négatif
            # total et silencieux, charge pourtant envoyée.
            selection = "{__typename}" if returns_object else ""
            # CO-ARGUMENTS — la leçon de D6 (le `Submit` de DVWA) dans une surface nouvelle : une
            # action doit porter les co-paramètres que l'application EXIGE. Mesuré : la chaîne
            # automatique n'atteignait qu'UNE classe sur six, et l'unique cause était là —
            # `{systemDiagnostics(username:"…")}` n'a même pas de commande à exécuter, et
            # `{systemDiagnostics(cmd:"…")}` est refusé faute d'identifiants.
            # On donne aux frères une valeur NEUTRE PAR TYPE : on complète un APPEL, on ne devine
            # aucun secret. Un champ gaté par une authentification restera non concluant — c'est le
            # bon sens de l'erreur, et l'opérateur qui connaît les valeurs fournit son gabarit.
            co = "".join(f",{n}:{_NEUTRAL_ARG.get(t, '"forge"')}" for n, t in siblings)
            tmpl = _json.dumps({"query": '%s{%s(%s:"%s"%s)%s}' % (
                "" if op == "query" else "mutation ", field, arg, slot, co, selection)})
            params = {"param": arg, "method": "POST",
                      "headers": {"Content-Type": "application/json"},
                      "body_template": tmpl}
            base = f"argument GraphQL {op} {field}({arg})"
            # IDENTIFIANT DISTINCT PAR ARGUMENT — sans lui, les N arguments d'un même endpoint
            # partagent l'id `kind:target` et s'ÉCRASENT entre eux. Mesuré sur DVGA : 8 actions
            # `sqli.probe` chaînées -> **2 findings**. La découverte trouvait 26 arguments et un
            # seul était réellement testé. Même convention que `_chain_from_endpoint` (suffixe `#`),
            # ici qualifiée par le CHAMP en plus de l'argument : deux champs peuvent porter un
            # argument de même nom (`paste(title)` et `createPaste(title)`).
            suffix = f"#{op}.{field}.{arg}"
            for kind, value, conf, cost, label in (
                    ("sqli.probe", 0.7, 0.3, 2, "SQLi"),) + self._PARAM_INJECTION_ORACLES:
                out.append(_action(kind, endpoint, value=value, confidence=conf, cost=cost,
                                   params=dict(params), id=f"{kind}:{endpoint}{suffix}",
                                   desc=f"{label} sur {base} (chaîné)"))
        return out

    def _endpoint_oracles(self, endpoint):
        """Oracles de vérification CIBLÉS sur un endpoint in-scope découvert. IDOR + SQLi + XSS reflected
        sont TOUJOURS chaînés (SQLi/XSS dégradent proprement en `tested` sans param — jamais de faux
        positif). Si l'endpoint porte un ou plusieurs PARAMÈTRES de query (URL-décodés, valeurs VIDES
        incluses — `?q=` est injectable), chacun (borné à MAX_PARAMS_PER_ENDPOINT, dédupliqué par nom) est
        passé (`param`+`value`) à SQLi/XSS ET à TOUT le panel d'oracles à injection param-drivés
        (`_PARAM_INJECTION_ORACLES`) : ils prennent alors leur CHEMIN DE TEST RÉEL au lieu d'émettre
        « config manquante ». IDOR reçoit urls=[endpoint] (comptes/creds injectés par l'engine depuis le
        scope). access_control.idor & rce.probe restent exploit=True (dérivé de la table) -> gatés par le
        ROE (le plancher exploit reste OFF par défaut ; DRY_RUN sinon).

        BORNÉ + DÉDUP INTER-VAGUES : le 1er paramètre garde l'id d'action STABLE (kind:target) -> aucun
        doublon entre vagues ET la variante param-portée gagne la course d'id sur l'auto-pentest (qui ne
        sème que l'id bare `kind:target`) ; les paramètres SUIVANTS portent un id suffixé (kind:target#param)
        pour coexister sans s'auto-écraser. Fan-out ≤ MAX_CHAIN_TARGETS × MAX_PARAMS_PER_ENDPOINT × |panel|."""
        params = self._query_params(endpoint)
        # IDOR (param-agnostique) : toujours chaîné, urls=[endpoint] (comptes/creds injectés par l'engine).
        out = [
            _action("access_control.idor", endpoint, value=0.8, confidence=0.3, cost=2,
                    params={"urls": [endpoint]}, desc="IDOR sur endpoint découvert (chaîné)"),
        ]
        if not params:
            # SANS param : SQLi/XSS restent chaînés (ils dégradent proprement en `tested`, jamais de faux
            # positif) ; le panel élargi N'est PAS chaîné (il dégraderait TOUT en « config manquante »).
            out += [
                _action("sqli.probe", endpoint, value=0.7, confidence=0.3, cost=2,
                        desc="SQLi à preuve sur endpoint découvert (chaîné)"),
                _action("xss.reflected", endpoint, value=0.6, confidence=0.3, cost=1,
                        desc="XSS reflected à preuve sur endpoint découvert (chaîné)"),
            ]
            return out
        # AVEC param(s) : SQLi/XSS + le panel élargi, chacun UNE FOIS PAR PARAMÈTRE (borné), param+value ->
        # sonde réelle. Le 1er param porte l'id STABLE ; les suivants un id suffixé (#param).
        panel = (("sqli.probe",   0.7, 0.3, 2, "SQLi"),
                 ("xss.reflected", 0.6, 0.3, 1, "XSS reflected")) + self._PARAM_INJECTION_ORACLES
        for i, (param, value) in enumerate(params):
            inj = {"param": param}
            if value:
                inj["value"] = value
            for kind, v, c, cost, label in panel:
                aid = f"{kind}:{endpoint}" if i == 0 else f"{kind}:{endpoint}#{param}"
                out.append(_action(kind, endpoint, value=v, confidence=c, cost=cost, params=dict(inj),
                                   id=aid,
                                   desc=f"{label} à preuve sur endpoint découvert (param={param}, chaîné)"))
        return out

    @staticmethod
    def _query_params(url):
        """Liste BORNÉE et DÉ-DUPLIQUÉE de (nom, valeur) des paramètres de query d'une URL, URL-DÉCODÉS
        (`+`/`%xx` via parse_qsl), valeurs VIDES INCLUSES (`keep_blank_values` : `?q=` est injectable —
        c'était le trou live où `?QUERY=` restait « config manquante »), dédupliqués par NOM (1re
        occurrence), plafonnés à MAX_PARAMS_PER_ENDPOINT. Points d'injection portés aux oracles à injection
        chaînés sur un endpoint découvert. Pur, ne lève jamais."""
        from urllib.parse import urlsplit, parse_qsl
        try:
            pairs = parse_qsl(urlsplit(str(url)).query, keep_blank_values=True)
        except Exception:            # noqa: BLE001
            return []
        out, seen = [], set()
        # Cap params/endpoint RÉSOLU par profil (`crawl_max_params`) : override > profil > défaut-classe.
        # `balanced` == 3 == défaut -> byte-identique ; `low`=2, `full`=5.
        max_params = resource_profile.resolve(
            "crawl_max_params", default=HeuristicBrain.MAX_PARAMS_PER_ENDPOINT)
        for name, value in pairs:
            if name and name not in seen:
                seen.add(name)
                out.append((name, value))
            if len(out) >= max_params:
                break
        return out

    @staticmethod
    def _first_query_pair(url):
        """(nom, valeur) du 1er paramètre de query d'une URL — ('', '') si aucun. Point d'injection porté
        (param+value) aux oracles chaînés. Délègue à `_query_params` (URL-décodage, valeurs vides incluses).
        Pur, ne lève jamais."""
        ps = HeuristicBrain._query_params(url)
        return ps[0] if ps else ("", "")


class AutoPentestBrain(HeuristicBrain):
    """Cerveau MODE AUTO-PENTEST : balaie TOUTES les techniques ACTIVÉES à travers la surface DÉCOUVERTE
    (recon -> chaînage -> oracles), de bout en bout, gouverné À L'IDENTIQUE d'un run normal (scope-guard,
    plancher exploit, ledger). Il ÉTEND `HeuristicBrain` (recon + oracles heuristiques + chaînage
    discovery/origin/endpoints) puis AJOUTE, sur CHAQUE cible que le plan heuristique touche (hôtes
    initiaux + sous-domaines/endpoints/IP d'origine découverts), une action pour CHAQUE technique
    ACTIVÉE encore non proposée. L'engine filtre ensuite par l'effective set du scope et gate chaque
    action par le ROE — « il balaie simplement le pipeline effectif du scope » (aucun câblage par-technique).

    `enabled_kinds` = l'ensemble EFFECTIF de kinds activés (typiquement `scope.effective_technique_kinds()`).
    Défaut (None) = tout le pipeline. BORNÉ : les cibles balayées proviennent du plan heuristique (déjà
    fan-out-borné) ; idempotent (id d'action stable kind:target) -> point fixe garanti sur les vagues.

    LE BALAYAGE PASSE PAR LE MÊME GARDE HÔTE/ENDPOINT QUE LE PLAN DE BASE (défaut D9 du banc). Le plan
    de base REFUSE, depuis toujours, de semer « recon/nmap/origin sur une URL » (`_is_endpoint`, et le
    `continue` de `propose`) : un endpoint est vérifié par les oracles CIBLÉS du chaînage (edge e), pas
    par des actions qui consomment un HÔTE. Le balayage, lui, proposait CHAQUE kind sur CHAQUE cible
    touchée, endpoints DÉRIVÉS compris — il contournait le garde. MESURÉ au ledger du banc (DVWA,
    piste B) : **22 findings `recon.nmap` sur 22** portent `Nmap done: 0 IP addresses (0 hosts up)`,
    tous rendus `status=tested`. nmap sort `rc=0` (« Unable to split netmask from target expression »),
    donc la borne `rc != 0` de `blindness.tool_did_not_run` ne peut PAS voir ce silence : une action
    qui n'a RIEN pu regarder affirmait avoir vérifié. Ici on ne réécrit pas le garde — on l'APPLIQUE
    (`_host_scoped_kinds`)."""

    def __init__(self, enabled_kinds=None):
        self.enabled = (set(enabled_kinds) if enabled_kinds is not None
                        else set(techniques.technique_kinds()))

    @staticmethod
    def _host_scoped_kinds():
        """Kinds qui consomment un HÔTE (jamais un chemin) -> RIEN à voir sur un endpoint dérivé.

        DÉRIVÉ, jamais recopié — deux sources déjà en place dans le dépôt, plus le seul nom que le
        garde existant cite à la main :

          1. `planner.surface_producers()` — l'ensemble des PRODUCTEURS de surface (déclaré par le
             spec de l'outil : `asset_hits` / `emit_*_discovery`, plus les natifs test-gardés par
             `TestNativeProducerList`). `planner.stage()` dit DÉJÀ, et à la mesure, qu'« un producteur
             ne l'est que sur un HÔTE, jamais sur un ENDPOINT déjà dérivé » : il refuse de les CLASSER
             producteurs là-bas. On ne fait que tirer la conséquence — on ne les y PROPOSE plus.
          2. `spec.speaks_http` FAUX — le discriminant est DANS L'ARGV : un outil invoqué avec
             `{target_host}` (testssl, dig, dnsx, amass, subfinder, naabu, gau, gobuster_dns) reçoit
             un hôte NU ; le chemin de l'endpoint est jeté avant même le lancement. Sur 19 endpoints
             du même hôte, `web.testssl` ne fait pas 19 vérifications : il refait 19 fois la MÊME,
             à 600 s de mur chacune.
          3. `origin.find` — le TROISIÈME nom de la phrase du garde existant (« qui sèmeraient
             recon/nmap/origin sur une URL », `_is_endpoint`). Le planner l'exclut délibérément de
             `surface_producers()`, mais pour une raison d'ORDONNANCEMENT (cf. son en-tête), pas
             parce qu'il saurait lire un chemin : il résout l'IP d'origine d'un DOMAINE.

        Rien n'est RETIRÉ de la couverture d'un endpoint : les oracles (IDOR/SQLi/XSS/le panel à
        injection et tout le reste du pipeline) continuent d'y être balayés à l'identique — seuls
        partent les kinds qui, structurellement, n'y regardent rien. Lu PARESSEUSEMENT (aucun import
        de `forge.modules` au chargement du cerveau) et ne lève jamais : registre indisponible ->
        producteurs natifs seuls, jamais une exception."""
        from .planner import surface_producers      # import paresseux (aucun cycle au chargement)
        out = set(surface_producers()) | {"origin.find"}
        try:
            from .modules import registry as _registry
            for kind, module in dict(_registry.REGISTRY).items():
                spec = getattr(module, "spec", None)
                if spec is not None and not getattr(spec, "speaks_http", True):
                    out.add(kind)
        except Exception:                            # noqa: BLE001 — registre absent -> dérivé partiel
            pass
        return frozenset(out)

    def propose(self, graph_state):
        base = super().propose(graph_state)          # recon + oracles heuristiques + chaînage
        order = techniques.techniques_for(self.enabled)   # kinds ACTIVÉS, ordre du pipeline
        seen_ids = {a.id for a in base}
        # cibles touchées par le plan heuristique (respecte son fan-out bound) — on y balaie l'ensemble.
        targets, seen_t = [], set()
        for a in base:
            if a.target not in seen_t:
                seen_t.add(a.target)
                targets.append(a.target)
        host_scoped = self._host_scoped_kinds()
        raw_host = self._raw_target_kinds()
        extra = []
        for tgt in targets:
            # MÊME GARDE QUE LE PLAN DE BASE, EN DEUX SEUILS SELON LA FORME DE LA CIBLE :
            #   - ENDPOINT (chemin/query)  -> tout `_host_scoped_kinds` (D9, inchangé) ;
            #   - PAS un HÔTE NU (URL de racine, `host:port`) -> `_raw_target_kinds`, le
            #     SOUS-ENSEMBLE qui reçoit la cible SANS normalisation et la résout comme un nom
            #     d'hôte (D16 : `nmap … http://h:p` -> « Unable to split netmask », `nmap … h:p`
            #     -> « Failed to resolve », les deux à rc=0 et « 0 IP addresses (0 hosts up) »).
            # Sur un hôte NU, rien ne change. Les deux seuils sont dérivés, aucun n'est listé à la main.
            if self._is_endpoint(tgt):
                blocked = host_scoped
            elif not self._is_bare_host(tgt):
                blocked = raw_host
            else:
                blocked = frozenset()
            for kind in order:
                aid = f"{kind}:{tgt}"
                if kind in blocked:
                    continue
                if aid not in seen_ids:              # ne double jamais une action déjà proposée
                    seen_ids.add(aid)
                    extra.append(_action(kind, tgt, desc=f"auto-pentest : balayage {kind}"))
        return base + extra

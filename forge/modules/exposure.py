"""framework.exposure — oracle de SURFACE DE FRAMEWORK EXPOSÉE à PREUVE MINIMALE (T1592.002 / CWE-200).

Détecte des surfaces de framework sensibles JOIGNABLES et FUYANTES sur un hôte in-scope, sans jamais
weaponiser ni exfiltrer un secret :

  - Spring Boot Actuator : endpoints `/actuator/*` (`/actuator/env`, `/configprops`, `/heapdump`,
    `/threaddump`, `/beans`, `/mappings`…). PREUVE = un endpoint SENSIBLE joignable dont le corps FUIT
    la configuration/l'état (ex `/env` -> `propertySources`/`activeProfiles`). `/actuator/health` seul
    (non sensible) reste `tested`.
  - Next.js : `__NEXT_DATA__` / `runtimeConfig` fuités dans le HTML livré au navigateur. PREUVE =
    `serverRuntimeConfig`/`runtimeConfig`/`env` présents avec des valeurs (config serveur exposée au
    client). La simple présence de `__NEXT_DATA__` (normale) reste `tested`.
  - Laravel : panneaux de debug/monitoring (Telescope `/telescope`, Horizon `/horizon`) accessibles SANS
    authentification, OU page d'erreur Ignition/Whoops en mode debug fuitant la stack/l'environnement.
    PREUVE = tableau de bord non authentifié joignable OU page Ignition exposée.

INVARIANT — toute valeur de SECRET détectée est RÉDIGÉE (`<redacted-…>`) : l'evidence ne restitue que le
NOM de la clé et un extrait NEUTRALISÉ (preuve d'exposition, jamais la valeur du secret).

GARDE-FOUS (prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : hôte hors périmètre -> `skipped`, AUCUNE requête émise ; chaque chemin
      sondé est RE-VALIDÉ in-scope (défense en profondeur) ;
  (2) PREUVE MINIMALE : promotion `vulnerable` UNIQUEMENT sur une surface sensible qui FUIT réellement
      (config/état) ; une surface simplement présente/non sensible reste `tested` ;
  (3) NON DESTRUCTIF : GET en lecture seule (exploit=False, destructive=False) — jamais de mutation ;
  (4) DÉGRADATION GRACIEUSE : aucune réponse (réseau indisponible) -> `skipped` (offline-safe).

Bâti sur `ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP partagés). Zéro
dépendance (stdlib). Le seam `_fetch` est monkeypatché par les tests (aucun réseau réel).
"""
import json
import re

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import techniques
from ..roe import Scope


# --- chemins Spring Boot Actuator (index + endpoints sensibles) ------------------------------------
_ACTUATOR_PATHS = [
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/configprops", "/actuator/beans",
    "/actuator/mappings", "/actuator/threaddump", "/actuator/heapdump", "/actuator/metrics",
    "/actuator/loggers", "/actuator/httptrace", "/actuator/scheduledtasks",
    # variantes Spring Boot 1.x (sans préfixe /actuator)
    "/env", "/configprops", "/beans", "/mappings", "/heapdump", "/threaddump", "/trace",
]
# endpoints actuator considérés SENSIBLES (leur corps fuit config/état) -> promotion possible.
_ACTUATOR_SENSITIVE = ("/env", "/configprops", "/heapdump", "/threaddump", "/beans", "/httptrace",
                       "/trace")
# marqueurs de corps confirmant un actuator (index) ou une fuite de config (env/configprops).
_ACTUATOR_INDEX_SIGNS = ('"_links"', '"self"', '"health"', '"actuator"')
_ACTUATOR_ENV_SIGNS = ('"propertysources"', '"activeprofiles"', '"systemproperties"', '"applicationconfig"')

# --- Laravel Telescope / Horizon (panneaux non authentifiés) + Ignition/Whoops (debug) --------------
_LARAVEL_PATHS = ["/telescope", "/telescope/requests", "/horizon", "/horizon/dashboard"]
_TELESCOPE_SIGNS = ("laravel telescope", "telescope-", 'id="telescope"', "window.telescope")
_HORIZON_SIGNS = ("laravel horizon", "horizon-", 'id="horizon"', "window.horizon")
_IGNITION_SIGNS = ("whoops, looks like something went wrong", "ignition", "illuminate\\",
                   "laravel/framework", "vendor/laravel")

# --- Next.js __NEXT_DATA__ / runtimeConfig ----------------------------------------------------------
_NEXT_DATA_RX = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.I | re.S)
_NEXT_RUNTIME_KEYS = ("serverRuntimeConfig", "runtimeConfig", "publicRuntimeConfig", "env")

# --- rédaction de secrets (valeurs jamais restituées dans l'evidence) -------------------------------
# clés dont la VALEUR est un secret -> rédigée. On garde le NOM de la clé (preuve d'exposition).
_SECRET_KEY_RX = re.compile(
    r'(?i)("?(?:pass(?:word)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|'
    r'client[_-]?secret|aws[_-]?secret|db[_-]?password|connection[_-]?string|authorization|'
    r'bearer|credential|app[_-]?key)"?\s*[:=]\s*)("?)([^"\'\s,}&]{3,})(\2)')
_PRIVKEY_RX = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
                         re.I | re.S)


def _redact(text):
    """Remplace toute valeur de secret par `<redacted-secret>` (le NOM de la clé est conservé) et masque
    les blocs de clé privée. Pur, ne lève jamais : l'evidence prouve l'exposition SANS livrer le secret."""
    if not text:
        return ""
    out = _PRIVKEY_RX.sub("-----BEGIN PRIVATE KEY----- <redacted-secret> -----END PRIVATE KEY-----", str(text))
    out = _SECRET_KEY_RX.sub(r"\1\2<redacted-secret>\4", out)
    return out


@register("framework.exposure")
class FrameworkExposure(ScopeGuardedOracle):
    kind = "framework.exposure"
    exploit = False                      # GET en lecture seule -> non-exploit
    destructive = False                  # aucune mutation
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("framework.exposure")   # source de vérité : techniques.py (T1592.002)
    cwe = "CWE-200"                                       # category + cwe des findings
    tool = "forge/modules/exposure.py:framework.exposure"
    fix = ("Ne pas exposer publiquement les surfaces de framework sensibles : verrouiller les endpoints "
           "Spring Boot Actuator (`management.endpoints.web.exposure`), désactiver Laravel Telescope/"
           "Horizon/Ignition en production (`APP_DEBUG=false`), et ne jamais fuiter `serverRuntimeConfig`/"
           "secrets dans `__NEXT_DATA__` livré au client ; exiger une authentification et un contrôle "
           "d'accès sur toute console d'admin/debug (CWE-200).")
    description = ("Oracle d'exposition de framework : Spring Actuator (/actuator/*), Next.js "
                   "__NEXT_DATA__/runtimeConfig, Laravel Telescope/Horizon/Ignition. PREUVE = surface "
                   "sensible joignable qui FUIT config/données (secret rédigé). Sinon tested. CWE-200.")

    MAX_PATHS = 40                                        # borne le nombre de chemins actuator sondés

    @staticmethod
    def _fetch(url, headers=None, timeout=15):
        """(status, body) — adosse le câblage urllib partagé (Oracle._http). Seam monkeypatché par les tests."""
        st, body, _ = Oracle._http(url, headers=headers, timeout=timeout, maxlen=300000)
        return st, body

    @staticmethod
    def _base(target):
        return (target if "://" in str(target) else "https://" + str(target)).rstrip("/")

    def dry(self, action):
        base = self._base(action.target)
        return (f"# GET {base}/actuator/* (Spring), {base} (__NEXT_DATA__/runtimeConfig Next.js), "
                f"{base}/telescope|/horizon (Laravel) + fingerprint Ignition ; PREUVE = surface sensible "
                f"joignable qui fuit config/données (secret RÉDIGÉ) ; lecture seule ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hôte hors périmètre -> skipped, AUCUNE requête émise.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        base = self._base(action.target)
        timeout = action.params.get("timeout", 15)
        exposures, seen_network = [], False

        # --- (A) Spring Boot Actuator ---
        for path in (action.params.get("actuator_paths") or _ACTUATOR_PATHS)[:self.MAX_PATHS]:
            url = base + (path if str(path).startswith("/") else "/" + str(path))
            # RE-VALIDATION périmètre par-URL (défense en profondeur) — hors-scope -> ignoré, aucun I/O.
            if not self._in_scope(action, url):
                continue
            st, body = self._fetch(url, timeout=timeout)
            if st is None:
                continue
            seen_network = True
            if st != 200 or not body:
                continue
            low = body.lower()
            is_sensitive = any(path.endswith(s) for s in _ACTUATOR_SENSITIVE)
            leaks = any(s in low for s in _ACTUATOR_ENV_SIGNS)
            index = any(s in low for s in _ACTUATOR_INDEX_SIGNS)
            if is_sensitive and (leaks or path.endswith(("/heapdump", "/threaddump", "/beans", "/httptrace", "/trace"))):
                exposures.append({
                    "surface": f"Spring Boot Actuator {path}", "severity": "HIGH", "proven": True,
                    "target": url,
                    "evidence": (f"HTTP 200 sur endpoint actuator SENSIBLE {path} — fuite de configuration/"
                                 f"état ({'propertySources/env' if leaks else 'dump'}). Extrait rédigé : "
                                 f"{_redact(body)[:400]}")})
            elif index or leaks:
                exposures.append({
                    "surface": f"Spring Boot Actuator {path}", "severity": "MEDIUM", "proven": False,
                    "target": url,
                    "evidence": (f"HTTP 200 sur actuator {path} (index/non sensible exposé) ; pas de fuite "
                                 f"directe de secret. Extrait rédigé : {_redact(body)[:200]}")})

        # --- (B) Laravel Telescope / Horizon (non authentifiés) + Ignition (debug) ---
        for path in (action.params.get("laravel_paths") or _LARAVEL_PATHS):
            url = base + path
            if not self._in_scope(action, url):
                continue
            st, body = self._fetch(url, timeout=timeout)
            if st is None:
                continue
            seen_network = True
            if st != 200 or not body:
                continue
            low = body.lower()
            if any(s in low for s in _TELESCOPE_SIGNS):
                exposures.append({
                    "surface": f"Laravel Telescope {path}", "severity": "HIGH", "proven": True,
                    "target": url,
                    "evidence": (f"HTTP 200 : tableau de bord Laravel Telescope accessible SANS "
                                 f"authentification ({path}) — expose requêtes/exceptions/données. Extrait "
                                 f"rédigé : {_redact(body)[:200]}")})
            elif any(s in low for s in _HORIZON_SIGNS):
                exposures.append({
                    "surface": f"Laravel Horizon {path}", "severity": "HIGH", "proven": True,
                    "target": url,
                    "evidence": (f"HTTP 200 : tableau de bord Laravel Horizon accessible SANS "
                                 f"authentification ({path}) — expose files/jobs. Extrait rédigé : "
                                 f"{_redact(body)[:200]}")})

        # Ignition / Whoops (mode debug) sur la racine
        st, home = self._fetch(base + "/", timeout=timeout)
        if st is not None:
            seen_network = True
            if home:
                low = home.lower()
                if any(s in low for s in _IGNITION_SIGNS):
                    exposures.append({
                        "surface": "Laravel Ignition/Whoops (mode debug)", "severity": "HIGH",
                        "proven": True, "target": base + "/",
                        "evidence": (f"Page d'erreur de debug (Ignition/Whoops) exposée en production — "
                                     f"fuite de stack trace / environnement. Extrait rédigé : "
                                     f"{_redact(home)[:300]}")})

            # --- (C) Next.js __NEXT_DATA__ / runtimeConfig ---
            nx = self._next_data_leak(home)
            if nx:
                exposures.append(dict(nx, target=base + "/"))

        # (4) DÉGRADATION GRACIEUSE — aucune réponse du tout (réseau indisponible) -> skipped (offline-safe).
        if not seen_network:
            return [self.degraded(
                target=base, title="framework.exposure non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse HTTP (transport indisponible) sur les surfaces sondées ; offline-safe.",
                poc=self.dry(action))]

        if not exposures:
            return [self.proof(
                target=base, proven=False,
                title="framework.exposure non confirmé — aucune surface de framework sensible exposée",
                severity="INFO",
                evidence=("Aucun endpoint Spring Actuator sensible, panneau Laravel Telescope/Horizon, page "
                          "Ignition ni fuite runtimeConfig Next.js détecté. Surfaces sondées en lecture seule."),
                poc=self.dry(action))]

        findings = []
        for e in exposures:
            findings.append(self.proof(
                target=e["target"], proven=e["proven"],
                title=(f"Surface de framework EXPOSÉE ({e['surface']}) — fuite de configuration/données "
                       f"(secret rédigé)" if e["proven"]
                       else f"Surface de framework présente ({e['surface']}) — exposée mais sans fuite directe"),
                severity=e["severity"],
                evidence=e["evidence"] + " ; toute valeur de secret est RÉDIGÉE (exposition prouvée, valeur non livrée)",
                poc=self.dry(action)))
        return findings

    def _next_data_leak(self, html):
        """Détecte une fuite `runtimeConfig`/`serverRuntimeConfig`/`env` dans le `__NEXT_DATA__` du HTML.
        Renvoie un dict d'exposition (proven=True si config serveur avec valeurs), ou None. Ne lève jamais.
        La simple présence de `__NEXT_DATA__` (normale) -> pas d'exposition (retourne None)."""
        if not html:
            return None
        m = _NEXT_DATA_RX.search(html)
        if not m:
            return None
        blob = m.group(1) or ""
        try:
            data = json.loads(blob)
        except ValueError:
            data = None
        # cherche runtimeConfig/serverRuntimeConfig/env non vides (fuite de config serveur au client)
        found_keys = []
        if isinstance(data, dict):
            props = data.get("runtimeConfig") or data.get("props") or {}
            for key in _NEXT_RUNTIME_KEYS:
                val = None
                if isinstance(props, dict) and props.get(key):
                    val = props.get(key)
                elif data.get(key):
                    val = data.get(key)
                if val:
                    found_keys.append(key)
        else:
            low = blob.lower()
            for key in _NEXT_RUNTIME_KEYS:
                if f'"{key.lower()}"' in low:
                    found_keys.append(key)
        # serverRuntimeConfig/runtimeConfig avec valeur -> fuite de config SERVEUR -> proven.
        server_leak = any(k in found_keys for k in ("serverRuntimeConfig", "runtimeConfig", "env"))
        if server_leak:
            return {"surface": "Next.js __NEXT_DATA__ runtimeConfig", "severity": "MEDIUM", "proven": True,
                    "evidence": (f"__NEXT_DATA__ expose une configuration serveur au client (clés : "
                                 f"{', '.join(found_keys)}). Extrait rédigé : {_redact(blob)[:400]}")}
        # __NEXT_DATA__ présent sans config serveur sensible -> informatif (tested).
        return {"surface": "Next.js __NEXT_DATA__", "severity": "INFO", "proven": False,
                "evidence": ("__NEXT_DATA__ présent (comportement Next.js normal) ; aucune fuite de "
                             "serverRuntimeConfig/env détectée.")}

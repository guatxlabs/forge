# SPDX-License-Identifier: AGPL-3.0-or-later
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
      (config/état), attestée par une signature de CORPS PROPRE À CET ENDPOINT (`_actuator_leak`) —
      JAMAIS par le seul code 200, et JAMAIS sur une réponse HTML ; une surface simplement présente/
      non sensible reste `tested` ;
  (2b) SONDE DE CONTRÔLE CATCH-ALL : avant de deviner le moindre chemin, on demande deux chemins qui
      NE PEUVENT PAS exister. S'ils répondent 2xx, la cible ne discrimine pas ses routes -> la
      découverte de chemin rend `skipped` et AUCUN chemin n'est sondé (cf. `Oracle.path_discrimination`) ;
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
from ..redact import redact_secrets as _redact_secrets
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

# =================================================================================================
#  PREUVE POSITIVE, PAR CHEMIN — la correction du défaut le plus grave du dépôt.
#
#  CE QUI ÉTAIT ÉCRIT (et qui a produit 8 findings HIGH FAUX sur une cible tierce réelle) :
#      if is_sensitive and (leaks or path.endswith(("/heapdump", "/threaddump", "/beans",
#                                                   "/httptrace", "/trace"))):
#  Pour ces CINQ chemins, `path.endswith(...)` est VRAI INCONDITIONNELLEMENT — la disjonction rendait
#  `leaks` (le seul terme qui lisait le CORPS) totalement inopérant. Le verdict `HIGH, proven=True`
#  tombait donc sur le seul `st == 200`. Sur `cloud.konghq.com` — une SPA qui rend le MÊME
#  `index.html` de 3 427 octets en HTTP 200 pour n'importe quel chemin — cela a produit
#  `/actuator/beans`, `/actuator/heapdump`, `/actuator/threaddump`, `/actuator/httptrace`, `/beans`,
#  `/heapdump`, `/threaddump`, `/trace` en « fuite de configuration ». Aucun actuator n'y existe.
#
#  CE QUI EST EXIGÉ MAINTENANT : une signature de CORPS PROPRE À CHAQUE ENDPOINT. Chaque endpoint
#  actuator a une forme reconnaissable, et c'est elle — jamais le statut — qui promeut :
#    /env, /configprops -> JSON `propertySources`/`activeProfiles`/`systemProperties` ;
#    /beans             -> JSON `"beans"` (Boot 2 : `{"contexts":{…{"beans":{…}}}}`, Boot 1 : liste) ;
#    /threaddump        -> JSON `"threads"`/`threadName`/`threadState`, OU dump jstack texte
#                          (`java.lang.Thread.State`, `nid=0x`) ;
#    /httptrace, /trace -> JSON `"traces"` (Boot 2) ou liste `timestamp`+`info`/`headers` (Boot 1) ;
#    /heapdump          -> BINAIRE HPROF : le corps COMMENCE par le magic `JAVA PROFILE 1.0`.
#
#  ET UN INTERDIT ABSOLU, ANTÉRIEUR À TOUTE SIGNATURE : une réponse `text/html` qui commence par
#  `<!DOCTYPE html>`/`<html` N'EST un actuator dans AUCUN cas. C'est exactement ce que la cible kong
#  renvoyait, et c'est la porte que la sonde de contrôle catch-all (`Oracle.path_discrimination`)
#  ferme une seconde fois, en amont.
# =================================================================================================
_HTML_PREFIXES = ("<!doctype html", "<html", "<!doctype>", "<?xml")
_HPROF_MAGIC = "JAVA PROFILE"                    # magic HPROF (ASCII) en tête d'un heapdump binaire
_THREADDUMP_TEXT_SIGNS = ("java.lang.thread.state", "nid=0x", '"main" ', "at java.")
_ACTUATOR_LEAK_SIGNS = {
    "/env": _ACTUATOR_ENV_SIGNS,
    "/configprops": _ACTUATOR_ENV_SIGNS + ('"contexts"', '"beans"', '"prefix"'),
    "/beans": ('"beans"',),
    "/threaddump": ('"threads"', '"threadname"', '"threadstate"', '"lockedmonitors"'),
    "/httptrace": ('"traces"',),
    "/trace": ('"traces"', '"timestamp"'),
}


def _looks_structured(body):
    """Le corps est-il un document STRUCTURÉ (JSON/array) ? Un actuator sert du JSON — pas une page.
    Pur, ne lève jamais."""
    return str(body or "").lstrip()[:1] in ("{", "[")


def _is_html(body):
    """Le corps est-il une page HTML/XML livrée au navigateur ? Une page HTML n'est un endpoint
    actuator dans AUCUN cas — c'est la réponse d'une SPA catch-all. Pur, ne lève jamais."""
    return str(body or "").lstrip()[:64].lower().startswith(_HTML_PREFIXES)


def _actuator_leak(path, body):
    """(fuite: bool, pourquoi: str) — PREUVE POSITIVE tirée du CORPS pour l'endpoint `path`.

    Contrat : renvoie True UNIQUEMENT si le corps porte la signature PROPRE à cet endpoint. Aucun code
    de statut n'entre ici — l'appelant a déjà exigé 200, ce qui ne prouve RIEN sur une cible catch-all.
    Pur, ne lève jamais."""
    b = str(body or "")
    p = str(path or "")
    # /heapdump : dump BINAIRE. Sa seule signature honnête est le magic HPROF en tête. (Le corps est
    # décodé en utf-8 'replace' par `_fetch` : le magic ASCII survit intact.)
    if p.endswith("/heapdump"):
        if b.lstrip().startswith(_HPROF_MAGIC):
            return True, "magic HPROF « JAVA PROFILE » en tête du corps (dump mémoire binaire servi)"
        return False, ""
    # INTERDIT ABSOLU : une page HTML n'est jamais un actuator (c'est la réponse d'une SPA catch-all).
    if _is_html(b):
        return False, ""
    low = b.lower()
    # /threaddump : JSON (Boot 2) OU dump jstack TEXTE (Boot 1 / `-Dmanagement…`).
    if p.endswith("/threaddump"):
        if _looks_structured(b) and any(s in low for s in _ACTUATOR_LEAK_SIGNS["/threaddump"]):
            return True, "JSON de threaddump (threads/threadName/threadState) — état d'exécution fuité"
        if any(s in low for s in _THREADDUMP_TEXT_SIGNS):
            return True, "dump jstack texte (java.lang.Thread.State / nid=0x) — état d'exécution fuité"
        return False, ""
    for suffix, signs in _ACTUATOR_LEAK_SIGNS.items():
        if suffix == "/threaddump" or not p.endswith(suffix):
            continue
        hits = [s for s in signs if s in low]
        if hits and _looks_structured(b):
            return True, f"JSON d'actuator {suffix} portant {', '.join(hits)} — configuration/état fuité"
        return False, ""
    return False, ""

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
# DÉLÉGATION à la surface UNIQUE et auditée `forge.redact` (cf. son docstring). L'ancienne
# implémentation locale était la PIRE des trois : privkey + KV seulement (aucun token cloud ni JWT) ET
# une regex PEM `[A-Z ]*` qui ratait un type contenant un CHIFFRE (ex `EC2 PRIVATE KEY`) — de vrais
# secrets FUYAIENT dans l'evidence Actuator-env. `_redact` garde son nom/sa signature (appelée partout
# dans `fire`/`_next_data_leak`) mais N'est plus qu'un WRAPPER FIN préservant le contrat local
# (falsy -> `""`).


def _redact(text):
    """Rédige toute valeur de secret de l'evidence — DÉLÈGUE à `forge.redact.redact_secrets` (surface
    unique). Pur, ne lève jamais : l'evidence prouve l'exposition SANS livrer le secret (falsy -> `""`)."""
    if not text:
        return ""
    return _redact_secrets(str(text))


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
    MAXLEN = 300000                                       # corps actuator plus gros -> troncature élargie

    @staticmethod
    def _base(target):
        return (target if "://" in str(target) else "https://" + str(target)).rstrip("/")

    def dry(self, action):
        base = self._base(action.target)
        ctl = ", ".join(self.catchall_paths(self._origin_of(base)))
        return (f"# sonde de CONTRÔLE catch-all d'abord : GET {base}{{{ctl}}} (chemins qui ne peuvent pas "
                f"exister — 2xx sur les deux => la cible ne discrimine pas ses routes => skipped)\n"
                f"# GET {base}/actuator/* (Spring), {base} (__NEXT_DATA__/runtimeConfig Next.js), "
                f"{base}/telescope|/horizon (Laravel) + fingerprint Ignition ; PREUVE = signature de CORPS "
                f"propre à l'endpoint (jamais le seul HTTP 200, jamais du HTML) ; lecture seule ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hôte hors périmètre -> skipped, AUCUNE requête émise.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        base = self._base(action.target)
        timeout = action.params.get("timeout", 15)
        exposures, seen_network = [], False

        # (0) SONDE DE CONTRÔLE « CATCH-ALL » — AVANT de deviner le moindre chemin. Une SPA qui rend
        #     200 sur n'importe quoi rend TOUTE la découverte de chemin non concluante : on ne sonde
        #     alors PAS les 20 chemins actuator/Laravel (aucun verdict possible, et autant de trafic
        #     inutile), et on rend `skipped` pour cette surface — jamais `tested` ni `vulnerable`.
        disc = self.path_discrimination(action, base, timeout=timeout)
        if disc.probes:
            seen_network = True
        path_sweep_ok = not disc.catchall

        # --- (A) Spring Boot Actuator ---
        for path in ((action.params.get("actuator_paths") or _ACTUATOR_PATHS)[:self.MAX_PATHS]
                     if path_sweep_ok else []):
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
            # PREUVE POSITIVE tirée du CORPS, propre à CE chemin (cf. `_actuator_leak`). Le statut 200
            # n'entre plus dans la promotion : il est nécessaire, jamais suffisant.
            leaks, leak_why = _actuator_leak(path, body) if is_sensitive else (False, "")
            env_leak = any(s in low for s in _ACTUATOR_ENV_SIGNS) and _looks_structured(body)
            index = (any(s in low for s in _ACTUATOR_INDEX_SIGNS) and _looks_structured(body))
            if leaks:
                exposures.append({
                    "surface": f"Spring Boot Actuator {path}", "severity": "HIGH", "proven": True,
                    "target": url,
                    "evidence": (f"HTTP 200 sur endpoint actuator SENSIBLE {path} — PREUVE DE CORPS : "
                                 f"{leak_why}. Extrait rédigé : {_redact(body)[:400]}")})
            elif index or env_leak:
                exposures.append({
                    "surface": f"Spring Boot Actuator {path}", "severity": "MEDIUM", "proven": False,
                    "target": url,
                    "evidence": (f"HTTP 200 sur actuator {path} (index/non sensible exposé) ; pas de fuite "
                                 f"directe de secret. Extrait rédigé : {_redact(body)[:200]}")})

        # --- (B) Laravel Telescope / Horizon (non authentifiés) + Ignition (debug) ---
        for path in ((action.params.get("laravel_paths") or _LARAVEL_PATHS) if path_sweep_ok else []):
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

        # CATCH-ALL CONSTATÉ : la découverte de chemin (Actuator + Telescope/Horizon) n'a PAS pu être
        # vérifiée. `skipped` (« je n'ai pas pu vérifier »), jamais `tested` (« j'ai vérifié, rien
        # trouvé ») ni `vulnerable`. Les constats de RACINE (Ignition/Next.js), qui ne devinent aucun
        # chemin, restent rendus tels quels à côté.
        findings = []
        if disc.catchall:
            findings.append(self.catchall_degraded(
                target=base, what="framework.exposure (surfaces devinées : Actuator, Telescope/Horizon)",
                disc=disc, poc=self.dry(action)))
        elif not exposures:
            return [self.proof(
                target=base, proven=False,
                title="framework.exposure non confirmé — aucune surface de framework sensible exposée",
                severity="INFO",
                evidence=("Aucun endpoint Spring Actuator sensible, panneau Laravel Telescope/Horizon, page "
                          "Ignition ni fuite runtimeConfig Next.js détecté. Surfaces sondées en lecture seule."),
                poc=self.dry(action))]

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

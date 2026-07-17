"""LOT CLIENT-FLOW — trois oracles de VÉRIFICATION client-side / flux de requête à PREUVE MINIMALE
et IMPACTANTE (`xss.reflected`, `redirect.open`, `csrf.state_change`).

Ces oracles CONFIRMENT qu'une faiblesse est RÉELLE avec une preuve MINIMALE et BÉNIGNE — détection/
vérification pour test autorisé, PAS de weaponization ni de vol de données :

  - xss.reflected    : injecte un marqueur BÉNIGN aléatoire-unique (alphanumérique + ponctuation) et
                       confirme qu'il revient NON échappé dans un contexte JS-exécutable (dans un
                       `<script>`, un attribut gestionnaire d'événement `on*=`, ou un DOM sink connu).
                       PREUVE = reflet en contexte exécutable NON échappé. On note explicitement que
                       confirmer l'EXÉCUTION réelle + la chaînabilité exige le module navigateur/évasion.
                       AUCUNE charge weaponisée n'est jamais envoyée. (CWE-79 / T1059)
  - redirect.open    : injecte une cible de redirection attaquant-contrôlée (hôte marqueur bénin) et
                       lit la redirection SANS LA SUIVRE (garde-fou de sûreté + scope). Promu
                       `vulnerable` UNIQUEMENT si la cible est attaquant-contrôlable ET chaînable à un
                       sink sensible (OAuth/token/email) — miroir de la règle workspace « open redirect
                       only if chained ». Une redirection simple reste `tested`. (CWE-601)
  - csrf.state_change: détecte une action ÉTATIQUE/critique dépourvue d'anti-CSRF ET de SameSite via un
                       probe GET NON destructif (inspection de Set-Cookie + corps). Promu `vulnerable`
                       UNIQUEMENT pour une action GENUINEMENT critique avec absence de SameSite CONFIRMÉE
                       et anti-CSRF absent — miroir de la règle « CSRF only if critical action + SameSite
                       absent ». Sinon `tested`. AUCUNE requête mutante cross-site n'est émise. (CWE-352)

GARDE-FOUS (chaque oracle les respecte, prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : une cible hors périmètre est REFUSÉE avant tout réseau (hérité de
      `ScopeGuardedOracle._in_scope` ; hors-scope -> `skipped`, AUCUNE requête émise).
  (2) PREUVE MINIMALE & BÉNIGNE + IMPACTANTE : promotion `vulnerable` uniquement sur preuve concrète ET
      réellement impactante (reflet exécutable non échappé / redirection attaquant-contrôlée chaînée /
      action critique sans contrôle) ; sinon `tested`. Marqueurs bénins seulement, jamais de payload live.
  (3) NON DESTRUCTIF : lecture/vérification seule (exploit=False, destructive=False) ; le plancher
      exploit/destructif du ROE reste OFF par défaut (opt-in inchangé). Aucune mutation d'état.
  (4) SESSION SECRÈTE : le matériel d'auth gouverné (SessionStore) est fusionné par `Oracle._http`
      UNIQUEMENT sur des URL in-scope et n'est JAMAIS journalisé/rapporté (les PoC dérivent des en-têtes
      de l'appelant, pas de la requête fusionnée ; les cookies de RÉPONSE ne sont exposés que par nom).
  (5) DÉGRADATION GRACIEUSE : réseau indisponible -> `skipped` (offline-safe).

Bâti sur la base partagée `ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP +
curl partagés). exploit=False, destructive=False : sondes de vérification bénignes — gardées par le ROE
comme toute interaction web (web_allowed).
"""
import hashlib
import re
import urllib.parse

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from ..roe import Scope
from .. import browser_client as bc
from .. import techniques


class ClientFlowOracle(ScopeGuardedOracle):
    """Base des oracles client-side/flux. Hérite le scope-guard fail-closed + la dégradation gracieuse ;
    ajoute un `_fetch` conservant TOUTES les en-têtes de réponse (indispensable pour Location et les
    Set-Cookie MULTIPLES) et un `_send_h` d'injection d'un paramètre renvoyant aussi les en-têtes."""

    exploit = False              # sonde de VÉRIFICATION bénigne (ni exfil ni exécution) -> non-exploit
    destructive = False          # lecture/vérification seule : aucune mutation d'état
    web_allowed = True           # interaction web (réseau) -> gardée par le ROE
    available = True             # urllib stdlib -> toujours disponible ; dégrade à runtime si besoin

    # --- câblage HTTP header-aware (seam monkeypatché par les tests) ---
    @staticmethod
    def _fetch(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
        """(status, body, pairs) — adosse le câblage urllib partagé (Oracle._http). `pairs` = liste de
        tuples (nom, valeur) préservant les en-têtes DUPLIQUÉS (plusieurs Set-Cookie). Le SessionStore
        gouverné (scope-guardé) est fusionné par `_http` uniquement sur des URL in-scope. Seam patché."""
        st, body, h = Oracle._http(url, headers=headers, timeout=timeout, method=method,
                                   data=data, maxlen=200000, follow_redirects=follow_redirects)
        pairs = list(h.items()) if h is not None else []
        return st, body, pairs

    @staticmethod
    def _get(pairs, name):
        """Première valeur d'en-tête `name` (insensible à la casse), ou None."""
        low = name.lower()
        for k, v in pairs:
            if str(k).lower() == low:
                return v
        return None

    @staticmethod
    def _get_all(pairs, name):
        """TOUTES les valeurs d'en-tête `name` (insensible à la casse) — pour les Set-Cookie multiples."""
        low = name.lower()
        return [v for k, v in pairs if str(k).lower() == low]

    @staticmethod
    def _marker(target, param, salt=""):
        """Marqueur BÉNIGN déterministe-par-cible (reproductible, rejouable) et distinctif :
        `forge` + 12 hex — quasi impossible à rencontrer par coïncidence dans une réponse."""
        h = hashlib.sha256(f"{target}|{param}|forge-{salt}".encode()).hexdigest()
        return "forge" + h[:12]

    def _send_h(self, action, param, payload, method="GET", follow_redirects=True, base=None):
        """Émet l'injection et renvoie (où, status, body, pairs). GET -> payload dans la query ; autre
        méthode -> corps urlencodé. Les en-têtes explicites (action.params.headers) priment ; la session
        gouvernée (scope-guardée) est fusionnée SOUS eux par `_http`.

        `base` (défaut None) — base URL déjà NORMALISÉE au scheme (cf. web_url_candidates) à utiliser à la
        place de `action.target` : indispensable pour une cible hôte nu / host:port (sans lui, urllib
        lèverait `unknown url type`). None -> `action.target` (byte-identique pour les cibles URL)."""
        headers = dict(action.params.get("headers", {}))
        tgt = str(base) if base is not None else action.target
        if method.upper() == "GET":
            sep = "&" if "?" in tgt else "?"
            url = f"{tgt}{sep}{urllib.parse.urlencode({param: payload})}"
            st, body, pairs = self._fetch(url, headers=headers, method="GET",
                                          follow_redirects=follow_redirects)
            return url, st, body, pairs
        st, body, pairs = self._fetch(tgt, headers=headers, method=method.upper(),
                                      data=urllib.parse.urlencode({param: payload}),
                                      follow_redirects=follow_redirects)
        return tgt, st, body, pairs


# =================================================================================================
#  xss.reflected — Reflected XSS à PREUVE par marqueur BÉNIGN réfléchi NON échappé (T1059 / CWE-79)
# =================================================================================================
# Ponctuation BÉNIGNE (PAS un payload : aucun nom de balise, aucun gestionnaire, aucune fonction JS) —
# sert à prouver que le reflet revient NON échappé (si l'app encode, `&#39;`/`&quot;`/`&lt;`/`&gt;`
# remplacent ces caractères et aucun `marker+char` brut n'apparaît).
_XSS_PROBE = "'\"<>"
# DOM sinks connus (minuscules) — un marqueur RAW à leur portée = contexte JS-exécutable.
_DOM_SINKS = (
    "eval(", "settimeout(", "setinterval(", "function(", "document.write(", "document.writeln(",
    ".innerhtml", ".outerhtml", ".insertadjacenthtml", "location.href", "location.assign(",
    "location.replace(", "window.location", ".src=", ".setattribute(",
)
_SCRIPT_RX = re.compile(r"(?is)<script\b[^>]*>(.*?)</script>")


def _reflected_unescaped(body, marker):
    """True si une occurrence du marqueur est immédiatement suivie d'au moins un caractère de sonde
    RAW (non encodé en entité HTML). App qui échappe -> aucun `marker+char` brut -> False."""
    return any((marker + c) in body for c in _XSS_PROBE)


def _executable_context(body, marker):
    """'script' | 'event-handler' | 'dom-sink' | '' — le contexte JS-exécutable où le marqueur atterrit.
    Un reflet en contenu HTML visible (hors de ces contextes) renvoie '' (-> pas de preuve d'exécutabilité)."""
    # 1) à l'intérieur d'un bloc <script>…</script>
    for m in _SCRIPT_RX.finditer(body):
        if marker in m.group(1):
            return "script"
    # 2) à l'intérieur d'un attribut gestionnaire d'événement inline  on...="…marker…"
    if re.search(r"(?is)\bon[a-z]+\s*=\s*([\"'])(?:(?!\1).)*?" + re.escape(marker), body):
        return "event-handler"
    # 3) à portée d'un DOM sink connu (fenêtre courte AVANT le marqueur)
    low = body.lower()
    idx = low.find(marker.lower())
    while idx != -1:
        window = low[max(0, idx - 90):idx]
        if any(sink in window for sink in _DOM_SINKS):
            return "dom-sink"
        idx = low.find(marker.lower(), idx + 1)
    return ""


@register("xss.reflected")
class XssReflected(ClientFlowOracle):
    kind = "xss.reflected"
    mitre = techniques.mitre_for("xss.reflected")        # source de vérité : forge/techniques.py (T1059)
    cwe = "CWE-79"                                        # category + cwe des findings
    tool = "forge/modules/clientflow.py:xss.reflected"
    fix = ("Échapper/encoder la sortie selon le CONTEXTE (HTML, attribut, JS, URL) ; ne jamais réfléchir "
           "une entrée utilisateur non encodée dans un `<script>`, un attribut `on*=` ou un DOM sink ; "
           "CSP stricte (sans 'unsafe-inline'), frameworks auto-échappants, validation d'entrée en "
           "allowlist (CWE-79).")
    description = ("Oracle Reflected XSS à PREUVE BÉNIGNE : marqueur unique réfléchi NON échappé en "
                   "contexte JS-exécutable (<script>/on*=/DOM sink). L'exécution réelle + la chaînabilité "
                   "exigent le module navigateur/évasion. Sinon tested. CWE-79.")

    def dry(self, action):
        param = action.params.get("param", "?")
        marker = self._marker(action.target, action.params.get("param", ""), "xss")
        return (f"# injecte {param}={marker}{_XSS_PROBE} (marqueur bénin + ponctuation, PAS un payload) "
                f"dans {action.target} ; PREUVE = le marqueur revient NON échappé en contexte "
                f"JS-exécutable (<script>/on*=/DOM sink) ; sinon tested")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="XSS reflected non testé — config manquante",
                evidence=("Requiert params.param (paramètre réfléchi). Optionnel : params.method, "
                          "params.headers."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        marker = self._marker(action.target, param, "xss")
        payload = marker + _XSS_PROBE
        where, st, body, _pairs = self._send_h(action, param, payload, method)
        if st is None:
            return [self.degraded(
                target=where, title="XSS reflected non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]
        body = body or ""
        reflected = marker in body
        unescaped = _reflected_unescaped(body, marker)
        context = _executable_context(body, marker) if reflected else ""
        proven = reflected and unescaped and bool(context)
        return [self.proof(
            target=where, proven=proven,
            title=(f"XSS reflected CONFIRMÉ — marqueur bénin réfléchi NON échappé en contexte "
                   f"JS-exécutable ({context})" if proven
                   else "XSS reflected non confirmé — pas de reflet exécutable non échappé (pas de verdict aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"marqueur={marker} ; réfléchi={reflected} ; non_échappé={unescaped} ; "
                      f"contexte_exécutable={context or 'aucun'} ; NOTE: confirmer l'EXÉCUTION réelle "
                      f"et la chaînabilité (vol de session / action au nom d'un tiers) exige le module "
                      f"navigateur/évasion (browser/evasion) — cet oracle prouve le reflet exécutable, "
                      f"pas l'exécution live ; aucune charge weaponisée envoyée."),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = le marqueur bénin {marker} revient NON échappé dans un contexte "
                 f"JS-exécutable (<script>/on*=/DOM sink) ; charge weaponisée JAMAIS envoyée"))]


# =================================================================================================
#  redirect.open — Open Redirect à PREUVE IMPACTANTE (chaîné à un sink sensible) — CWE-601 / T1204.001
# =================================================================================================
# Jetons de FLUX SENSIBLE (OAuth/token/email) : une redirection ouverte n'est promue que si elle
# chaîne vers l'un d'eux (sinon `tested`, règle workspace « open redirect only if chained »).
_REDIRECT_STRONG = (
    "oauth", "openid", "sso", "saml", "authorize", "authorization", "callback", "id_token",
    "access_token", "token", "email", "verify", "reset", "magiclink", "magic-link",
)
# Indices de redirection CLIENT-SIDE dans un corps 200 (meta-refresh / JS location).
_CLIENT_REDIRECT_HINTS = (
    'http-equiv="refresh"', "http-equiv='refresh'", "window.location", "location.href",
    "location.replace", "location.assign",
)


@register("redirect.open")
class OpenRedirect(ClientFlowOracle):
    kind = "redirect.open"
    mitre = techniques.mitre_for("redirect.open")        # source de vérité : forge/techniques.py (T1204.001)
    cwe = "CWE-601"                                       # category + cwe des findings
    tool = "forge/modules/clientflow.py:redirect.open"
    fix = ("Ne pas rediriger vers une URL fournie par le client : allowlist stricte de destinations "
           "(chemins relatifs internes), ou mapper un identifiant -> URL interne ; valider le host de "
           "destination contre une allowlist ; ne JAMAIS placer une redirection ouverte dans un flux "
           "OAuth/token/email (vol de jeton via redirect_uri) (CWE-601).")
    description = ("Oracle open-redirect à PREUVE IMPACTANTE : promu vulnerable UNIQUEMENT si la cible "
                   "est attaquant-contrôlée ET chaînable à un sink sensible (OAuth/token/email). "
                   "Redirections NON suivies (sûreté + scope). Redirection simple -> tested. CWE-601.")

    def _chainable(self, action):
        """(bool, raison) — la redirection chaîne-t-elle vers un sink sensible ? Affirmation opérateur
        (params.chainable / params.sink) OU contexte de flux sensible détecté dans la cible/le paramètre.
        Sinon False -> reste `tested` (règle workspace « open redirect only if chained »)."""
        if action.params.get("chainable") is True:
            return True, "chaîne vers un sink sensible affirmée par l'opérateur (params.chainable=True)"
        sink = str(action.params.get("sink", "")).strip().lower()
        if sink:
            return True, f"sink sensible déclaré (params.sink={sink})"
        hay = (str(action.params.get("param", "")) + " " + str(action.params.get("flow", ""))
               + " " + str(action.target)).lower()
        hits = sorted({w for w in _REDIRECT_STRONG if w in hay})
        if hits:
            return True, "contexte de flux sensible détecté (" + ", ".join(hits) + ")"
        return False, ("redirection simple sans sink sensible — reste tested "
                       "(règle: open redirect only if chained)")

    def dry(self, action):
        param = action.params.get("param", "?")
        marker = self._marker(action.target, action.params.get("param", ""), "redir")
        attacker = str(action.params.get("attacker_url") or f"https://forge-redirect.example/{marker}")
        return (f"# injecte {param}={attacker} dans {action.target} SANS suivre la redirection ; "
                f"PREUVE = la réponse redirige vers l'hôte attaquant ET le flux chaîne vers un sink "
                f"sensible (OAuth/token/email) ; redirection simple -> tested")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="Open redirect non testé — config manquante",
                evidence=("Requiert params.param (paramètre de redirection, ex next/url/returnTo). "
                          "Optionnel : params.attacker_url, params.chainable ou params.sink (chaîne "
                          "sensible), params.method."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        marker = self._marker(action.target, param, "redir")
        attacker = str(action.params.get("attacker_url") or f"https://forge-redirect.example/{marker}")
        # redirections NON suivies : on lit la CIBLE sans émettre de requête vers l'hôte attaquant
        # (potentiellement hors-scope) — garde-fou de sûreté + détection.
        where, st, body, pairs = self._send_h(action, param, attacker, method, follow_redirects=False)
        if st is None:
            return [self.degraded(
                target=where, title="Open redirect non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]
        body = body or ""
        location = self._get(pairs, "Location") or ""
        attacker_host = Scope._host(attacker)
        controllable, via = False, ""
        # (A) redirection SERVEUR : 3xx + Location pointant vers l'hôte attaquant
        if 300 <= st < 400 and location:
            if location.startswith(attacker) or Scope._host(location) == attacker_host:
                controllable, via = True, f"header Location (HTTP {st} -> {location})"
        # (B) redirection CLIENT-SIDE : la cible attaquant apparaît dans un sink de redirection du corps
        if not controllable and attacker in body:
            low = body.lower()
            if any(h in low for h in _CLIENT_REDIRECT_HINTS):
                controllable, via = True, "redirection client-side (meta-refresh/JS) vers la cible attaquant"
        chainable, chain_why = self._chainable(action)
        proven = controllable and chainable
        if proven:
            title = "Open redirect CONFIRMÉ — cible attaquant-contrôlée ET chaînable à un sink sensible"
        elif controllable:
            title = ("Open redirect NON promu — redirection ouverte mais NON chaînée "
                     "(reste tested, règle workspace)")
        else:
            title = "Open redirect non confirmé — cible non attaquant-contrôlée (pas de verdict aveugle)"
        return [self.proof(
            target=where, proven=proven,
            title=title, severity=("HIGH" if proven else "INFO"),
            evidence=(f"attaquant_contrôlable={controllable} ({via or '—'}) ; "
                      f"chaînable={chainable} ({chain_why}) ; cible_injectée={attacker}"),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# (curl ne suit PAS les redirections par défaut) PREUVE = la réponse redirige vers "
                 f"{attacker} ET le flux chaîne vers un sink sensible (OAuth/token/email)"))]


# =================================================================================================
#  csrf.state_change — CSRF à PREUVE CIBLÉE (action critique + anti-CSRF absent + SameSite absent) —
#  CWE-352 / T1204 — NON DESTRUCTIF (détection seule, aucune requête mutante cross-site émise)
# =================================================================================================
# Indices d'un jeton anti-CSRF (minuscules) dans le corps/les en-têtes -> protection PRÉSENTE.
_CSRF_TOKEN_HINTS = (
    "csrf", "xsrf", "authenticity_token", "_token", "csrfmiddlewaretoken",
    "__requestverificationtoken", "requestverificationtoken", "anti-forgery", "antiforgery",
)
# Indices d'action CRITIQUE/étatique (minuscules) dans params.action / la cible.
_CRITICAL_HINTS = (
    "password", "passwd", "email", "e-mail", "delete", "remove", "transfer", "payment", "withdraw",
    "fund", "beneficiary", "payout", "role", "admin", "grant", "permission", "privilege", "2fa",
    "mfa", "recovery", "deactivate", "disable", "api-key", "apikey", "close-account", "close_account",
)


@register("csrf.state_change")
class CsrfStateChange(ClientFlowOracle):
    kind = "csrf.state_change"
    mitre = techniques.mitre_for("csrf.state_change")    # source de vérité : forge/techniques.py (T1204)
    cwe = "CWE-352"                                       # category + cwe des findings
    tool = "forge/modules/clientflow.py:csrf.state_change"
    fix = ("Protéger chaque action mutante par un jeton anti-CSRF par requête (vérifié côté serveur) ET "
           "des cookies de session SameSite=Lax/Strict ; vérifier Origin/Referer sur les actions "
           "sensibles ; ne pas exposer une action critique en GET (CWE-352).")
    description = ("Oracle CSRF à PREUVE CIBLÉE (non destructif) : promu vulnerable UNIQUEMENT pour une "
                   "action CRITIQUE dont l'anti-CSRF est ABSENT ET le SameSite du cookie de session "
                   "CONFIRMÉ ABSENT. Détection seule (aucune mutation cross-site). Sinon tested. CWE-352.")

    def _is_critical(self, action):
        """(bool, raison) — l'action est-elle GENUINEMENT critique ? Affirmation opérateur
        (params.critical) OU indice critique dans params.action / la cible. Non critique -> `tested`
        (règle workspace « CSRF only if critical action »)."""
        c = action.params.get("critical")
        if c is True:
            return True, "action critique affirmée par l'opérateur (params.critical=True)"
        if c is False:
            return False, "action déclarée NON critique (params.critical=False) — pas de promotion CSRF"
        hay = (str(action.params.get("action", "")) + " " + str(action.target)).lower()
        hits = sorted({w for w in _CRITICAL_HINTS if w in hay})
        if hits:
            return True, "action critique/étatique détectée (" + ", ".join(hits) + ")"
        return False, "action non critique — reste tested (règle: CSRF only if critical action)"

    def _samesite_absent(self, pairs, action):
        """(True|False|None, raison) — le cookie de session est-il SANS SameSite=Lax/Strict ? None si
        indéterminable (aucun Set-Cookie pertinent observé -> pas de confirmation, donc pas de preuve).
        Source des Set-Cookie : échantillon opérateur (params.set_cookie, capturé sur SON compte) OU la
        réponse du probe. On n'expose que les NOMS de cookies (jamais les valeurs)."""
        raw = action.params.get("set_cookie")
        if raw:
            cookies = [raw] if isinstance(raw, str) else list(raw)
        else:
            cookies = self._get_all(pairs, "Set-Cookie")
        if not cookies:
            return None, "aucun Set-Cookie observé — absence de SameSite NON confirmée"
        want = str(action.params.get("session_cookie", "")).strip().lower()
        relevant = [c for c in cookies if (not want or str(c).split("=", 1)[0].strip().lower() == want)]
        if not relevant:
            return None, f"cookie de session '{want}' absent des Set-Cookie observés — non confirmé"

        def _protected(c):
            low = str(c).lower()
            return "samesite=lax" in low or "samesite=strict" in low
        absent = not any(_protected(c) for c in relevant)
        names = ", ".join(sorted({str(c).split("=", 1)[0].strip() for c in relevant}))
        return absent, (f"cookie(s) de session [{names}] SANS SameSite=Lax/Strict" if absent
                        else f"cookie(s) de session [{names}] protégé(s) par SameSite")

    def _csrf_absent(self, body, pairs, action):
        """(bool, raison) — l'anti-CSRF est-il ABSENT ? Affirmation opérateur (params.csrf_present) OU
        absence d'indice de jeton dans le corps/les en-têtes de réponse."""
        p = action.params.get("csrf_present")
        if p is True:
            return False, "jeton anti-CSRF présent (params.csrf_present=True)"
        if p is False:
            return True, "anti-CSRF absent (params.csrf_present=False)"
        low = (body or "").lower()
        hints = tuple(_CSRF_TOKEN_HINTS) + tuple(str(x).lower() for x in (action.params.get("csrf_field_names") or []))
        in_body = any(h in low for h in hints)
        in_headers = any(("csrf" in str(k).lower() or "xsrf" in str(k).lower()) for k, _ in pairs)
        present = in_body or in_headers
        return (not present), ("jeton anti-CSRF détecté (corps/en-têtes)" if present
                               else "aucun jeton anti-CSRF détecté (corps/en-têtes)")

    def dry(self, action):
        probe = action.params.get("probe_url") or action.target
        return (f"# probe GET NON destructif de {probe} : inspecte Set-Cookie (SameSite) + le corps "
                f"(jeton anti-CSRF) ; PREUVE = action critique + SameSite absent + anti-CSRF absent "
                f"(AUCUNE requête mutante cross-site émise) ; sinon tested")

    def fire(self, action):
        probe = action.params.get("probe_url") or action.target
        if not self._in_scope(action, probe):
            return [self._scope_refused(action)]
        # config : l'opérateur DOIT déclarer la nature de l'action (une évaluation CSRF sans savoir si
        # l'action est étatique/critique n'a pas de sens).
        if "critical" not in action.params and "action" not in action.params:
            return [self.skip(
                target=action.target, title="CSRF non testé — config manquante",
                evidence=("Requiert de déclarer la nature de l'action : params.critical (bool) ou "
                          "params.action (ex 'password_change'). Optionnel : params.probe_url, "
                          "params.session_cookie, params.set_cookie, params.csrf_present."),
                poc=self.dry(action))]
        headers = dict(action.params.get("headers", {}))
        # probe NON destructif : un simple GET (aucune mutation). On ne rejoue JAMAIS la requête mutante.
        st, body, pairs = self._fetch(probe, headers=headers, method="GET")
        if st is None:
            return [self.degraded(
                target=probe, title="CSRF non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur au probe GET non destructif ; offline-safe.",
                poc=self.dry(action))]
        critical, crit_why = self._is_critical(action)
        ss_absent, ss_why = self._samesite_absent(pairs, action)
        csrf_absent, csrf_why = self._csrf_absent(body, pairs, action)
        # PREUVE : action GENUINEMENT critique + SameSite CONFIRMÉ absent (True, pas None) + anti-CSRF absent.
        proven = bool(critical) and (ss_absent is True) and bool(csrf_absent)
        return [self.proof(
            target=probe, proven=proven,
            title=("CSRF state-change CONFIRMÉ — action critique SANS anti-CSRF ni SameSite" if proven
                   else "CSRF non promu — (action critique + anti-CSRF absent + SameSite absent) non réunis"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"action_critique={critical} ({crit_why}) ; anti_CSRF_absent={csrf_absent} "
                      f"({csrf_why}) ; SameSite_absent={ss_absent} ({ss_why}) ; NON DESTRUCTIF: probe GET "
                      f"seul, aucune requête mutante cross-site émise"),
            poc=(f"# probe non destructif: {self._curl(probe, headers, 'GET')}\n"
                 f"# PREUVE = action critique + cookie de session sans SameSite=Lax/Strict + aucun jeton "
                 f"anti-CSRF ; la requête mutante cross-site n'est PAS exécutée (détection seule)"))]


# =================================================================================================
#  xss.stored — Stored / DOM XSS à PREUVE MINIMALE via le CHEMIN BROWSER/ÉVASION (T1059 / CWE-79)
# =================================================================================================
# Persiste un MARQUEUR BÉNIGN unique (marqueur + ponctuation de sonde, PAS un payload) dans un champ
# PERSISTANT via le compte de l'OPÉRATEUR, puis RE-RENDU d'une AUTRE vue par le module navigateur pour
# confirmer que le marqueur atterrit NON échappé dans un contexte JS-exécutable (<script>/on*=/DOM sink)
# du DOM effectivement rendu. NÉCESSITE le module navigateur (browser-automation) : indisponible ->
# dégradation `skipped` (offline-safe). Aucune charge weaponisée n'est jamais envoyée ; le marqueur vit
# dans le PROPRE champ de l'opérateur (compte-opérateur, non destructif).
@register("xss.stored")
class XssStored(ClientFlowOracle):
    kind = "xss.stored"
    exploit = False              # marqueur BÉNIGN dans le champ de l'opérateur -> non-exploit
    destructive = False          # persistance d'un marqueur bénin dans SON PROPRE champ : pas destructif
    web_allowed = True           # interaction web (réseau) -> gardée par le ROE
    available = True             # listé/sélectionnable ; DÉGRADE en skipped à fire-time si browser absent
    mitre = techniques.mitre_for("xss.stored")           # source de vérité : techniques.py (T1059)
    cwe = "CWE-79"                                        # category + cwe des findings
    tool = "forge/modules/clientflow.py:xss.stored"
    fix = ("Encoder/échapper la sortie selon le CONTEXTE (HTML/attribut/JS) sur TOUTE donnée persistée "
           "puis re-rendue ; ne jamais réinjecter une valeur stockée non encodée dans un `<script>`, un "
           "attribut `on*=` ou un DOM sink ; CSP stricte (sans 'unsafe-inline'), frameworks auto-"
           "échappants, validation d'entrée en allowlist (CWE-79).")
    description = ("Oracle Stored/DOM XSS à PREUVE BÉNIGNE via le module navigateur : persiste un marqueur "
                   "unique (compte opérateur) et confirme qu'il se reflète NON échappé en contexte "
                   "JS-exécutable sur une AUTRE vue rendue. Browser requis -> sinon skipped. CWE-79.")

    # --- seams navigateur (patchables ; mêmes conventions que les seams sqlmap d'injection.py) ---
    @staticmethod
    def _browser_available():
        """Seam (patchable) : le service browser-automation répond-il ? Absent -> dégradation `skipped`."""
        return bc.health()

    @staticmethod
    def _browser_render(url, tab=bc.DEFAULT_TAB):
        """Seam (patchable) : navigue vers `url` via le browser gouverné et renvoie (status, DOM rendu).
        La session authentifiée SECRÈTE vit DANS le service (jamais lue/loggée/reportée ici)."""
        bc.goto(url, tab=tab)
        cst, body = bc.content(tab=tab)
        if isinstance(body, dict):
            dom = body.get("content") or body.get("html") or body.get("body") or ""
        else:
            dom = body if isinstance(body, str) else str(body or "")
        return cst, dom

    def _persist(self, action, store_url, param, payload):
        """Persiste le marqueur (compte opérateur) : POST par défaut (ou params.store_method) dans un
        champ persistant. GET -> query ; autre -> corps urlencodé. Renvoie (status, body). En-têtes
        explicites priment ; session gouvernée scope-guardée fusionnée SOUS eux par `Oracle._http`."""
        headers = dict(action.params.get("headers", {}))
        method = str(action.params.get("store_method", "POST")).upper()
        if method == "GET":
            sep = "&" if "?" in store_url else "?"
            url = f"{store_url}{sep}{urllib.parse.urlencode({param: payload})}"
            st, _body, _pairs = self._fetch(url, headers=headers, method="GET")
            return st
        st, _body, _pairs = self._fetch(store_url, headers=headers, method=method,
                                        data=urllib.parse.urlencode({param: payload}))
        return st

    def dry(self, action):
        param = action.params.get("param", "?")
        store_url = action.params.get("store_url") or action.target
        view_url = action.params.get("view_url") or action.target
        marker = self._marker(store_url, action.params.get("param", ""), "storedxss")
        return (f"# persiste {param}={marker}{_XSS_PROBE} (marqueur BÉNIGN, compte opérateur) sur {store_url} ; "
                f"puis RE-REND {view_url} via le module navigateur ; PREUVE = le marqueur revient NON "
                f"échappé en contexte JS-exécutable (<script>/on*=/DOM sink) du DOM rendu ; browser requis "
                f"-> sinon skipped ; sinon tested")

    def fire(self, action):
        store_url = action.params.get("store_url") or action.target
        view_url = action.params.get("view_url") or action.target
        # (1) SCOPE-GUARD fail-closed sur la persistance ET la vue — l'un hors périmètre -> skipped, ZÉRO I/O.
        if not self._in_scope(action, store_url):
            return [self._scope_refused(action)]
        if not self._in_scope(action, view_url):
            return [self.degraded(
                target=view_url,
                title="XSS stored non testé — vue hors périmètre (scope-guard fail-closed)",
                evidence="La vue de re-rendu n'est pas in-scope ; aucune requête émise (fail-closed).",
                poc=self.dry(action))]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="XSS stored non testé — config manquante",
                evidence=("Requiert params.param (champ persistant). Optionnel : params.store_url (défaut "
                          "cible), params.view_url (AUTRE vue de re-rendu, défaut cible), params.store_method, "
                          "params.headers."),
                poc=self.dry(action))]
        # (5) BROWSER REQUIS : le module navigateur atteste le rendu DOM. Absent -> dégradation `skipped`.
        if not self._browser_available():
            return [self.degraded(
                target=view_url,
                title="XSS stored non testé — module navigateur indisponible (dégradation gracieuse)",
                evidence=("Cet oracle EXIGE le module navigateur (browser-automation) pour rendre la vue et "
                          "attester le contexte JS-exécutable ; service injoignable -> skipped (offline-safe). "
                          "Lancer toolkit/browser-automation (port 8080) pour activer."),
                poc=self.dry(action))]
        marker = self._marker(store_url, param, "storedxss")
        payload = marker + _XSS_PROBE
        # 1) PERSISTER le marqueur bénin (compte opérateur, son propre champ) — non destructif.
        pst = self._persist(action, store_url, param, payload)
        if pst is None:
            return [self.degraded(
                target=store_url, title="XSS stored non testé — persistance indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur à la persistance du marqueur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]
        # 2) RE-RENDRE une AUTRE vue via le module navigateur et lire le DOM effectif.
        rst, dom = self._browser_render(view_url, tab=action.params.get("tab", bc.DEFAULT_TAB))
        if rst is None or not dom:
            return [self.degraded(
                target=view_url, title="XSS stored non testé — rendu navigateur indisponible (dégradation gracieuse)",
                evidence="Le module navigateur n'a pas renvoyé de DOM pour la vue de re-rendu ; offline-safe.",
                poc=self.dry(action))]
        reflected = marker in dom
        unescaped = _reflected_unescaped(dom, marker)
        context = _executable_context(dom, marker) if reflected else ""
        proven = reflected and unescaped and bool(context)
        return [self.proof(
            target=view_url, proven=proven,
            title=(f"XSS stored CONFIRMÉ — marqueur BÉNIGN persistant réfléchi NON échappé en contexte "
                   f"JS-exécutable ({context}) sur une autre vue rendue" if proven
                   else "XSS stored non confirmé — pas de reflet exécutable non échappé dans le DOM rendu"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"persistance HTTP {pst} (champ opérateur) ; vue re-rendue={view_url} (DOM navigateur) ; "
                      f"marqueur={marker} réfléchi={reflected} non_échappé={unescaped} contexte_exécutable="
                      f"{context or 'aucun'} ; module NAVIGATEUR utilisé pour le rendu DOM ; aucune charge "
                      f"weaponisée envoyée (marqueur bénin, compte opérateur) ; session navigateur SECRÈTE "
                      f"non journalisée"),
            poc=(f"# 1) persister (compte opérateur) : {param}={marker}{_XSS_PROBE} sur {store_url}\n"
                 f"# 2) rendre {view_url} via le module navigateur (browser-automation) et lire le DOM\n"
                 f"# PREUVE = le marqueur bénin revient NON échappé en contexte JS-exécutable "
                 f"(<script>/on*=/DOM sink) ; charge weaponisée JAMAIS envoyée"))]

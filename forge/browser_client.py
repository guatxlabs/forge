"""Client stdlib du service browser-automation (YesWeHack/toolkit/browser-automation).

Le service (FastAPI + Camoufox + Xvfb, port 8080) est la couche ACCÈS/ÉVASION : franchir
Cloudflare Turnstile (vision-click-os), rejouer les requêtes qui passent le WAF (browser_xhr),
modifier une requête en vol (intercept-modify, IDOR GraphQL persisted-query). Forge lui parle
en HTTP — ce n'est pas une lib importable (deps lourdes : opencv/xdotool/camoufox).

URL via env FORGE_BROWSER_URL (défaut http://localhost:8080). Timeouts courts. Zéro dépendance.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "http://localhost:8080"
DEFAULT_TAB = "forge"  # source de vérité unique du tab par défaut (réutilisé par modules.evasion)


def base_url():
    return os.environ.get("FORGE_BROWSER_URL", DEFAULT_URL).rstrip("/")


def _qs(params):
    """Encode les params en query string : None filtré, bool -> 'true'/'false'."""
    clean = {}
    for k, v in (params or {}).items():
        if v is None:
            continue
        clean[k] = "true" if v is True else "false" if v is False else v
    return urllib.parse.urlencode(clean)


def _req(method, path, params=None, timeout=30):
    """Tous les endpoints n'acceptent que des query params (aucun body). Non-levant :
    un 4xx/5xx (HTTPError) ou une erreur réseau (URLError) renvoie (status, corps)."""
    qs = _qs(params)
    url = base_url() + path + (("?" + qs) if qs else "")
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status = r.status
            body = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", "replace") if e.fp else str(e)
    except urllib.error.URLError as e:
        return 0, str(e.reason)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def health(timeout=2):
    """True si le service répond (2xx). Ne lève jamais : _req() renvoie (0, reason) sur erreur réseau."""
    st, _ = _req("GET", "/health", timeout=timeout)
    return 200 <= st < 300


def capture_start(types=None, tab=DEFAULT_TAB, timeout=30):
    """Arme la capture des requêtes (mécanisme /capture-start)."""
    return _req("POST", "/capture-start", {"types": types, "tab": tab}, timeout=timeout)


def capture_dump(url_contains=None, tab=DEFAULT_TAB, timeout=30):
    """Récupère les requêtes capturées (mécanisme /capture-dump)."""
    return _req("POST", "/capture-dump", {"url_contains": url_contains, "tab": tab}, timeout=timeout)


def xhr(url, types=None, url_contains=None, tab=DEFAULT_TAB, timeout=45):
    """OBSERVATION (recon) : /xhr n'existe pas côté service. On arme la capture, on navigue,
    puis on dump les requêtes vues. Renvoie (status, requêtes capturées)."""
    capture_start(types=types, tab=tab, timeout=timeout)
    goto(url, tab=tab, timeout=timeout)
    return capture_dump(url_contains=url_contains, tab=tab, timeout=timeout)


def vision_click_os(strategy="turnstile", threshold=0.55, tab=DEFAULT_TAB, timeout=60):
    """Clic OS xdotool sur la case Turnstile interactive (template match)."""
    return _req("POST", "/vision-click-os", {"strategy": strategy, "threshold": threshold,
                                             "tab": tab}, timeout=timeout)


def intercept_modify(find, replace, pattern, target="url", tab=DEFAULT_TAB, timeout=45):
    """Arme la réécriture find->replace dans une requête en vol (url|body). 'pattern' (glob URL)
    est REQUIS par l'API. La preuve cross-account se récupère ensuite via /intercept-dump."""
    return _req("POST", "/intercept-modify", {"pattern": pattern, "find": find, "replace": replace,
                                              "target": target, "tab": tab}, timeout=timeout)


def goto(url, tab=DEFAULT_TAB, wait=5, timeout=45):
    return _req("POST", "/goto", {"url": url, "wait": wait, "tab": tab}, timeout=timeout)


def content(max_length=50000, tab=DEFAULT_TAB, timeout=30):
    return _req("GET", "/content", {"max_length": max_length, "tab": tab}, timeout=timeout)


def set_user_agent(user_agent, force=False, timeout=30):
    return _req("POST", "/set-user-agent", {"user_agent": user_agent, "force": force}, timeout=timeout)

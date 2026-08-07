# SPDX-License-Identifier: AGPL-3.0-or-later
"""FRANCHISSEMENT DE CHALLENGE — traduction PURE entre la session NAVIGATEUR (qui passe le défi
Cloudflare/DataDome) et le matériel de session GOUVERNÉ (`forge.session`) que le reste du moteur
attache à ses requêtes HTTP brutes.

POURQUOI CE MODULE EXISTE
-------------------------
Mesuré sur une évaluation réelle : la cible était derrière Cloudflare, `curl` rendait
`403 cf-mitigated: challenge`, et `evasion.turnstile` FRANCHISSAIT pourtant le défi (25 tirs,
`{'found': True, 'clicked': True, 'method': 'os/xdotool'}`). Le moteur a émis 1573 actions et atteint
**9 URLs distinctes** (accueil, favicon, URLs de défi) : le contenu du site n'a JAMAIS été vu.
La capacité de franchissement EXISTAIT — elle n'était pas ROUTÉE. Ce module est la route : il
convertit ce que le navigateur détient (cookies de clearance + User-Agent EXACT) en matériel
`forge.session.Session`, que `Oracle._http` fusionne déjà, scope-guardé, sur chaque requête in-scope.

LE PIÈGE, NOMMÉ
---------------
Un `cf_clearance` est lié à l'UA **et** à l'IP qui l'ont obtenu. Le rejouer avec l'UA par défaut
d'urllib le rend INOPÉRANT — on croit avoir routé la clearance, on reprend un 403. C'est pourquoi
`material_for_host` refuse de produire du matériel sans l'UA EXACT du navigateur : cookies et UA
voyagent ENSEMBLE ou pas du tout.

CE QUE CE MODULE NE FAIT PAS
----------------------------
Aucun réseau, aucun état global, aucun import de module d'attaque : il ne fait que PARSER des charges
utiles déjà reçues (réponses du service browser) et JUGER une réponse HTTP. Le scope-guard n'est PAS
ici — il vit dans `SessionStore.adopt_clearance` (le seul point où du matériel s'attache à un hôte).
SECRET : les helpers d'évidence ne rendent que des NOMS de cookies et des compteurs, jamais une valeur.
"""
import re

from .challenge import looks_like_challenge

# --- Cookies de FRANCHISSEMENT connus (minuscules) -------------------------------------------------
# Sert UNIQUEMENT à ÉTIQUETER l'évidence (« quels cookies de clearance ai-je récoltés ? ») et à
# décider si une récolte vaut la peine d'être adoptée. La récolte elle-même n'est PAS restreinte à
# cette liste : un WAF peut nommer son cookie n'importe comment, et se limiter à un allowlist rendrait
# la route silencieusement inopérante sur le prochain fournisseur. Le VRAI filtre est le DOMAINE du
# cookie (cf. `cookies_for_host`) + le scope-guard du store.
CLEARANCE_COOKIE_NAMES = frozenset({
    "cf_clearance", "__cf_bm", "__cfduid", "cf_chl_rc_m",            # Cloudflare
    "datadome",                                                      # DataDome
    "incap_ses", "visid_incap", "nlbi",                              # Imperva/Incapsula
    "_abck", "bm_sz", "ak_bmsc", "bm_sv",                            # Akamai Bot Manager
    "reese84",                                                       # Kasada/F5 Distributed Cloud
    "awswaf-token", "aws-waf-token",                                 # AWS WAF
})

# --- En-têtes de RÉPONSE qui SIGNENT un challenge managé (minuscules) ------------------------------
# STRICTEMENT des marqueurs de challenge — jamais un simple `server: cloudflare` (une app derrière
# Cloudflare répond 403 pour ses propres raisons ; ce 403-là est un verdict, pas une cécité).
_CHALLENGE_HEADER_NAMES = (
    "cf-mitigated", "cf-chl-bypass", "cf-chl-out", "x-datadome-cid", "x-datadome-captcha",
    "x-iinfo", "x-cdn",
)
_CHALLENGE_HEADER_VALUES = ("challenge", "captcha", "managed_challenge", "interactive")


def _iter_header_items(headers):
    """(nom, valeur) depuis un dict, une liste de tuples, ou un objet `email.message.Message`
    (`resp.headers`). Ne lève JAMAIS : une forme inattendue rend une séquence vide."""
    if headers is None:
        return []
    try:
        if isinstance(headers, dict):
            return list(headers.items())
        if hasattr(headers, "items"):                    # email.message.Message / Headers
            return list(headers.items())
        return [(k, v) for k, v in headers]              # liste de paires
    except Exception:                                    # noqa: BLE001 (entrée hostile)
        return []


def response_is_challenge(status, body="", headers=None):
    """True si une réponse HTTP est un CHALLENGE MANAGÉ — c'est-à-dire « je n'ai PAS vu l'application ».

    DÉLIBÉRÉMENT PLUS STRICT que `challenge.looks_like_challenge` : celui-ci traite tout 403/429/503
    comme un challenge (bon signal pour BASCULER la recon sur la voie navigateur, mauvais signal pour
    faire taire un oracle). Ici, un **403 NU est un verdict applicatif légitime** et l'oracle DOIT
    conclure dessus. On n'exige donc qu'UNE de ces deux preuves EXPLICITES :

      - un en-tête de challenge (`cf-mitigated: challenge` — exactement ce qui a été MESURÉ sur la
        cible réelle ; le corps, lui, est VIDE sur ce chemin car `Oracle._http` rend `""` sur HTTPError,
        donc la voie en-tête n'est pas un luxe, c'est la seule qui marche sur un 403) ;
      - un interstitiel de challenge dans le CORPS (« Just a moment », `/cdn-cgi/challenge-platform`,
        DataDome…) — on réutilise la liste de `challenge.py` (source unique, aucune dérive) en passant
        `status=None` pour NEUTRALISER la branche par code de statut.

    Pur, ne lève jamais. Un doute -> False : on préfère laisser un oracle conclure que le faire taire
    à tort (l'inverse fabriquerait des `skipped` de complaisance)."""
    for name, value in _iter_header_items(headers):
        low_n = str(name).lower().strip()
        if low_n in _CHALLENGE_HEADER_NAMES:
            if low_n in ("x-iinfo", "x-cdn"):            # Incapsula : présence seule = pas concluant
                if any(v in str(value).lower() for v in _CHALLENGE_HEADER_VALUES):
                    return True
                continue
            return True
    return looks_like_challenge(None, body or "")        # status=None -> AUCUNE branche par code


# --- récolte de la session NAVIGATEUR (parsing pur des charges du service browser) ------------------
def _domain_covers(domain, host):
    """True si un `domain` de cookie couvre `host` (le point de tête est optionnel, RFC 6265 §5.1.3).
    Un cookie SANS domaine déclaré est accepté (il appartient au contexte qu'on vient de naviguer) ;
    un cookie explicitement lié à un AUTRE domaine est REFUSÉ."""
    d = str(domain or "").strip().lower().lstrip(".")
    h = str(host or "").strip().lower()
    if not d:
        return True                                      # pas de domaine déclaré -> contexte courant
    if not h:
        return False
    return h == d or h.endswith("." + d)


def _iter_cookie_records(payload):
    """Enregistrements de cookie {name, value, domain} depuis les formes que le service browser peut
    rendre : liste de dicts, `{"cookies": [...]}`, ou dict plat `{nom: valeur}`. Ne lève jamais."""
    out = []
    try:
        node = payload
        if isinstance(node, dict):
            for key in ("cookies", "result", "data", "items"):
                if isinstance(node.get(key), (list, dict)):
                    node = node[key]
                    break
        if isinstance(node, dict):                       # dict plat {nom: valeur} (pas de domaine)
            for k, v in node.items():
                if isinstance(v, (str, int, float)):
                    out.append({"name": str(k), "value": str(v), "domain": ""})
            return out
        if isinstance(node, list):
            for it in node:
                if not isinstance(it, dict):
                    continue
                name = it.get("name") or it.get("key")
                if not name:
                    continue
                out.append({"name": str(name), "value": str(it.get("value", "")),
                            "domain": str(it.get("domain", "") or "")})
    except Exception:                                    # noqa: BLE001 (charge arbitraire du service)
        return []
    return out


def cookies_for_host(payload, host):
    """dict {nom: valeur} des cookies du navigateur qui APPARTIENNENT à `host` (domaine couvrant).
    Un cookie d'un tiers (`.doubleclick.net`, un domaine d'auth externe) est ÉCARTÉ ici — première
    barrière ; la seconde (autoritative) est le scope-guard de `SessionStore.adopt_clearance`.
    Ne lève jamais."""
    out = {}
    for rec in _iter_cookie_records(payload):
        if not rec["name"] or not _domain_covers(rec["domain"], host):
            continue
        out[rec["name"]] = rec["value"]
    return out


_UA_RX = re.compile(r"[A-Za-z]")


def user_agent_from(payload):
    """User-Agent EXACT du navigateur depuis une réponse `/evaluate navigator.userAgent` : str direct
    OU dict {result|value|output|data}. `""` si illisible. Ne lève jamais."""
    node = payload
    if isinstance(node, dict):
        for key in ("result", "value", "output", "data", "content"):
            if isinstance(node.get(key), str):
                node = node[key]
                break
    if not isinstance(node, str):
        return ""
    ua = node.strip().strip('"').strip()
    # garde-fou : une réponse d'erreur du service ("", "null", un JSON d'erreur) n'est PAS un UA.
    if len(ua) < 16 or not _UA_RX.search(ua) or ua.lower() in ("null", "undefined", "none"):
        return ""
    return ua


def material_for_host(cookie_payload, ua_payload, host):
    """Matériel de session `{"cookies": {...}, "headers": {"User-Agent": ...}}` prêt pour
    `SessionStore.adopt_clearance`, ou **None** si la récolte est inutilisable.

    REFUS DÉLIBÉRÉ (le piège nommé en tête de module) :
      - pas de cookie appartenant à `host`  -> None (rien à router) ;
      - pas d'UA navigateur lisible          -> None. Un `cf_clearance` rejoué sous l'UA d'urllib est
        INOPÉRANT : produire le matériel quand même donnerait l'ILLUSION d'une route ouverte et le
        moteur reprendrait un 403 en croyant être passé. Mieux vaut rendre None et que l'appelant
        dise `skipped` (« je n'ai pas pu vérifier ») que de faire semblant.
    Pur, ne lève jamais."""
    cookies = cookies_for_host(cookie_payload, host)
    if not cookies:
        return None
    ua = user_agent_from(ua_payload)
    if not ua:
        return None
    return {"cookies": cookies, "headers": {"User-Agent": ua}}


def clearance_names(material):
    """NOMS (triés) des cookies RECONNUS comme cookies de franchissement dans `material`. Vue SÛRE
    pour l'évidence d'un finding : des noms, jamais une valeur. Ne lève jamais."""
    cookies = (material or {}).get("cookies") or {}
    return sorted(n for n in cookies if str(n).lower() in CLEARANCE_COOKIE_NAMES)


def cookie_names(material):
    """NOMS (triés) de TOUS les cookies récoltés. Vue SÛRE : des noms, jamais une valeur."""
    return sorted((material or {}).get("cookies") or {})

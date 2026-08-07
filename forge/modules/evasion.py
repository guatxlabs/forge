# SPDX-License-Identifier: AGPL-3.0-or-later
"""Modules d'évasion — atteindre les cibles derrière Cloudflare/WAF via browser-automation.

Le plus gros déblocage offensif réel : beaucoup de programmes ne tiennent que sur Cloudflare/
WAF qui bloque curl. Ces modules parlent au service browser-automation (port 8080) :
  - evasion.xhr            : OBSERVATION des requêtes via la session browser (capture-start/dump). exploit=False
  - evasion.turnstile      : franchir le Turnstile interactif (vision-click-os). exploit=False (enabler d'accès)
  - evasion.idor_intercept : arme l'interception IDOR via intercept-modify (preuve via /intercept-dump). exploit=True
  - evasion.discover       : DÉCOUVERTE backed-browser — franchit le challenge managé PUIS extrait les
                             endpoints du rendu (DOM/JS/XHR) IN-SCOPE et émet le MÊME
                             DISCOVERY_ENDPOINT_MARKER que recon.js_endpoints. exploit=False, non destructif.

Auto-neutralisation (`available`) si le service ne répond pas. Tout reste gaté par le ROE.
Rappel : passer Cloudflare ≠ une faille — c'est un enabler à chaîner vers un impact (IDOR/ATO).

ROUTAGE DU FRANCHISSEMENT (le verrou qui comptait) — franchir le défi ne servait à RIEN tant que
le reste du moteur tirait en HTTP brut : mesuré sur une évaluation réelle, `evasion.turnstile` a
réussi son clic 25 fois pendant que les modules HTTP reprenaient un `403 cf-mitigated: challenge`
— 1573 actions, **9 URLs distinctes atteintes**, contenu du site jamais vu. `evasion.turnstile` et
`evasion.discover` RÉCOLTENT désormais la session navigateur (cookies de clearance + User-Agent
EXACT — indissociables : un `cf_clearance` rejoué sous l'UA d'urllib est inopérant) vers le
`SessionStore` gouverné via `_adopt_clearance`. Les ~40 modules HTTP en profitent SANS ÊTRE MODIFIÉS
(`Oracle._http` fusionne déjà le matériel scope-guardé). Échec du franchissement -> l'hôte est marqué
CHALLENGED et les modules en aval rendent `skipped`, jamais `tested`.

evasion.discover est la RÉPONSE au trou « WAF -> recon curl challengé -> 0 endpoint -> 0 oracle » :
sur une cible IN-SCOPE protégée, il pilote le browser gouverné (session authentifiée SECRÈTE vivant
DANS le service, jamais lue/loggée/reportée ici), passe le challenge, et RE-VALIDE fail-closed chaque
endpoint découvert contre le périmètre AVANT de l'émettre — cartographie de reachability autorisée,
navigate/extract SEULE, bornée (une page, N endpoints). Hors-scope -> AUCUN appel browser. Service
absent -> status=skipped (offline-safe).
"""
import re
import time
import urllib.parse

from .oracle import Oracle
from .registry import register, Module
from .recon_surface import PassiveSurface, JsEndpoints, _host_only
from .. import browser_client as bc
from .. import clearance
from .. import session as _session
from .. import techniques


class _EvasionBase(Module):
    # Sonde de santé memoïsée (TTL court) : `available` reste une property reflétant la
    # joignabilité réelle du service browser, MAIS sans refaire un appel réseau à CHAQUE lecture.
    # Avant : cmd_modules lisait `.available` sur tous les modules d'évasion -> autant de health()
    # bloquants (jusqu'au timeout) => ~6s au boot. Le cache (clé = base_url courante) coalesce les
    # lectures rapprochées ; un changement d'URL (env FORGE_BROWSER_URL) re-sonde immédiatement.
    _HEALTH_TTL = 5.0                            # secondes — assez court pour rester fidèle à l'état réel
    _health_cache = {}                           # {base_url: (expiry_monotonic, ok_bool)} — partagé par classe

    @classmethod
    def _health_cached(cls):
        url = bc.base_url()
        now = time.monotonic()
        hit = cls._health_cache.get(url)
        if hit is not None and now < hit[0]:
            return hit[1]
        ok = bc.health()                         # un seul probe réseau par fenêtre TTL/URL
        cls._health_cache[url] = (now + cls._HEALTH_TTL, ok)
        return ok

    @property
    def available(self):
        return self._health_cached()             # service browser joignable ? (memoïsé TTL court)

    # =============================================================================================
    #  ROUTAGE DU FRANCHISSEMENT — faire PROFITER au reste du moteur ce que le navigateur a obtenu.
    #
    #  Sans ça, franchir le défi ne servait à RIEN : `evasion.turnstile` cliquait la case avec succès
    #  (mesuré : 25 tirs, `{'found': True, 'clicked': True, 'method': 'os/xdotool'}`) pendant que les
    #  ~40 modules HTTP continuaient de tirer en clair et reprenaient un `403 cf-mitigated: challenge`.
    #  Bilan mesuré de cette évaluation : 1573 actions, **9 URLs distinctes atteintes**, contenu du
    #  site JAMAIS vu, 2410 findings dont 0 vulnérable. On récolte donc la session navigateur vers le
    #  `SessionStore` gouverné : les modules HTTP en profitent SANS ÊTRE MODIFIÉS (`Oracle._http`
    #  fusionne déjà le matériel scope-guardé sous les en-têtes de l'appelant).
    # =============================================================================================
    @staticmethod
    def _browser_material(url, tab):
        """Matériel de session RÉCOLTÉ sur le navigateur pour l'hôte de `url` (cookies + User-Agent
        EXACT), ou None. Deux lectures du service, jamais fatales. Aucun secret ne sort d'ici : le
        dict rendu est consommé par `adopt_clearance` et n'est JAMAIS journalisé/reporté tel quel."""
        try:
            _st, cookie_payload = bc.cookies()
        except Exception:                                # noqa: BLE001 (service hostile/absent)
            cookie_payload = None
        try:
            _st, ua_payload = bc.evaluate("navigator.userAgent", tab=tab)
        except Exception:                                # noqa: BLE001
            ua_payload = None
        return clearance.material_for_host(cookie_payload, ua_payload, _host_only(url))

    def _adopt_clearance(self, url, tab):
        """RÉCOLTE la session navigateur et l'INSTALLE dans le `SessionStore` lié par le moteur.
        Renvoie un dict de télémétrie SÛR (booléens, NOMS de cookies, raison) — jamais une valeur.

        Le scope-guard est celui de `SessionStore.adopt_clearance` (`is_in_scope` fait foi) : un
        cookie de clearance ne peut PHYSIQUEMENT pas s'attacher à un hôte hors périmètre. Hors moteur
        (appel direct dev/test) aucun store n'est lié -> no-op total, aucune erreur."""
        store = _session.current()
        if store is None:
            return {"adopted": False, "why": "aucun SessionStore lié (appel direct hors moteur)"}
        material = self._browser_material(url, tab)
        if material is None:
            return {"adopted": False,
                    "why": ("aucun cookie navigateur pour cet hôte, ou User-Agent illisible — un "
                            "cookie de clearance est lié à l'UA qui l'a obtenu : sans l'UA EXACT il "
                            "serait INOPÉRANT, on refuse donc de le router (pas de fausse route)")}
        adopted = store.adopt_clearance(url, material)
        return {"adopted": adopted,
                "why": ("" if adopted else "hôte hors périmètre — adoption refusée (scope-guard)"),
                "cookies": clearance.cookie_names(material),
                "clearance_cookies": clearance.clearance_names(material)}

    @staticmethod
    def _plain_http_reach(url):
        """PREUVE DE PORTÉE, pas d'intention : re-tire `url` par le chemin de tir du RESTE du moteur
        (`Oracle._http` — le chokepoint que ~40 modules partagent), matériel adopté compris. Renvoie
        (status, is_challenge, taille_du_corps).

        On mesure ici EXACTEMENT ce qui compte : le moteur voit-il enfin le site ? Un test qui
        vérifierait « le cookie est bien copié » ne prouverait rien.

        NOTE — on n'emprunte PAS `PassiveSurface._http_get` : celui-ci pose un défaut
        `User-Agent: forge-surface` quand l'appelant n'en fournit pas, et ce défaut BAT (setdefault)
        l'UA récolté, ce qui rendrait la clearance inopérante. Cf. le rapport de mission."""
        st, body, hdrs = Oracle._http(url, timeout=15, maxlen=200000)
        if st is None:
            return None, False, 0
        return st, clearance.response_is_challenge(st, body, hdrs), len(body or "")


@register("evasion.xhr")
class EvasionXhr(_EvasionBase):
    kind = "evasion.xhr"
    exploit = False
    mitre = "T1190"
    description = ("Observation des requêtes XHR via la session browser-automation "
                  "(capture-start/dump) — contournement WAF/DataDome.")

    def dry(self, action):
        return (f"POST {bc.base_url()}/capture-start ; POST /goto {{url:{action.target}}} ; "
                f"POST /capture-dump   # observation des requêtes via session browser (bypass WAF)")

    def fire(self, action):
        p = action.params
        st, resp = bc.xhr(action.target, types=p.get("types"),
                          url_contains=p.get("url_contains"), tab=p.get("tab", bc.DEFAULT_TAB))
        return [self.finding(
            target=action.target, title=f"Observation requêtes via browser (HTTP {st})",
            severity="INFO", category="access", mitre="T1190", status="tested",
            tool="browser-automation:/capture-dump", evidence=str(resp)[:1500], poc=self.dry(action))]


@register("evasion.turnstile")
class EvasionTurnstile(_EvasionBase):
    """Franchit le Turnstile interactif ET **ROUTE** le franchissement vers le reste du moteur.

    Le module cliquait la case avec succès puis JETAIT le résultat : la session qui passait le défi
    vivait dans le service browser, et les modules HTTP continuaient de reprendre un 403. Il RÉCOLTE
    désormais cookies + User-Agent EXACT vers le `SessionStore` gouverné (scope-guardé), puis VÉRIFIE
    la portée par un tir HTTP BRUT sur la cible — le chemin qu'empruntent les autres modules.

    NE JAMAIS FAIRE SEMBLANT : si la vérification ne rend pas du CONTENU (200 hors challenge), le
    finding est `status='skipped'` (« je n'ai pas pu vérifier »), l'hôte est marqué CHALLENGED, et les
    modules en aval s'abstiennent de conclure. Jamais `tested` sur un franchissement non prouvé."""

    kind = "evasion.turnstile"
    exploit = False                              # franchir une case ≠ exploit ; enabler d'accès
    mitre = "T1556"
    description = ("Franchit le Cloudflare Turnstile interactif via vision-click-os (détection template "
                  "+ clic OS X11) PUIS route cookies+User-Agent vers la session gouvernée — enabler d'accès.")

    def dry(self, action):
        return (f"POST {bc.base_url()}/goto {{url:{action.target}}} ; "
                f"POST /vision-click-os {{strategy:turnstile}} ; GET /cookies ; "
                f"POST /evaluate {{script:navigator.userAgent}}"
                f"   # 1 essai, IP propre ; puis récolte de la clearance vers la session gouvernée")

    def fire(self, action):
        tab = action.params.get("tab", bc.DEFAULT_TAB)
        url = PassiveSurface._url(action.target)         # scheme garanti (cible hôte nu -> https://)
        bc.goto(action.target, tab=tab)
        st, resp = bc.vision_click_os(strategy=action.params.get("strategy", "turnstile"),
                                      threshold=action.params.get("threshold", 0.55), tab=tab)
        # (1) RÉCOLTE : la clearance rejoint le store gouverné (scope-guardé) -> les modules en profitent.
        harvest = self._adopt_clearance(url, tab)
        # (2) PREUVE DE PORTÉE : le moteur voit-il enfin le site en HTTP brut ? (pas « le cookie est copié »)
        reach_st, reach_challenge, reach_len = self._plain_http_reach(url)
        reached = reach_st is not None and 200 <= reach_st < 400 and not reach_challenge
        store = _session.current()
        if not reached and store is not None:
            store.mark_challenged(url)                   # aucun module en aval ne conclura sur cet hôte
        evidence = (
            f"vision-click-os: {str(resp)[:900]} ; clearance_adoptée={harvest['adopted']}"
            f"{' (' + harvest['why'] + ')' if harvest.get('why') else ''} ; "
            f"cookies_récoltés={harvest.get('cookies') or '—'} ; "
            f"cookies_de_clearance={harvest.get('clearance_cookies') or 'aucun reconnu'} ; "
            f"portée_HTTP_brut=HTTP {reach_st} challenge={reach_challenge} corps={reach_len}o "
            f"(re-tir par le chemin partagé des modules) ; SECRET: aucune valeur de cookie ni d'UA ici")
        return [self.finding(
            target=action.target,
            title=("Turnstile franchi ET routé — le moteur atteint la cible en HTTP brut" if reached
                   else "Franchissement Turnstile NON confirmé — le moteur ne voit toujours pas la cible"),
            severity="INFO", category="access", mitre="T1556",
            status=("tested" if reached else "skipped"),
            tool="browser-automation:/vision-click-os", evidence=evidence, poc=self.dry(action))]


@register("evasion.idor_intercept")
class EvasionIdorIntercept(_EvasionBase):
    kind = "evasion.idor_intercept"
    exploit = True                               # tamper d'une requête en vol -> exige allow_exploit
    mitre = "T1190"                              # tamper d'identifiant en vol (CWE-639)
    description = ("Arme l'interception IDOR en vol via browser intercept-modify "
                  "(substitution d'identifiant) — preuve via /intercept-dump (CWE-639).")

    def dry(self, action):
        p = action.params
        return (f"POST {bc.base_url()}/intercept-modify "
                f"{{pattern:{p.get('pattern', '?')}, find:{p.get('find', '?')}, "
                f"replace:{p.get('replace', '?')}, target:{p.get('target', 'url')}}}"
                f"   # ARME l'interception IDOR ; preuve via /intercept-dump")

    def fire(self, action):
        p = action.params
        if not p.get("find") or not p.get("replace") or not p.get("pattern"):
            return [self.finding(
                target=action.target, title="IDOR intercept non testé — params manquants",
                severity="INFO", category="CWE-639", status="tested",
                tool="browser-automation:/intercept-modify",
                evidence="Requiert params.pattern (glob URL), params.find et params.replace (la variable à substituer).",
                poc=self.dry(action))]
        st, resp = bc.intercept_modify(p["find"], p["replace"], pattern=p["pattern"],
                                       target=p.get("target", "url"), tab=p.get("tab", bc.DEFAULT_TAB))
        return [self.finding(
            target=action.target, title="Interception IDOR armée — preuve à confirmer via /intercept-dump",
            severity="INFO", category="CWE-639", mitre="T1190", status="tested",
            tool="browser-automation:/intercept-modify",
            evidence=f"HTTP {st} — {str(resp)[:1200]} (interception ARMÉE ; confirmer cross-account via /intercept-dump)",
            poc=self.dry(action))]


@register("evasion.discover")
class EvasionDiscover(_EvasionBase, PassiveSurface):
    """DÉCOUVERTE d'endpoints BACKED-BROWSER derrière un WAF/challenge managé (Cloudflare & co).

    Le trou comblé : sur une cible protégée, la recon HTTP simple est challengée -> 0 endpoint ->
    la chaîne discovery->oracle propose 0 oracle -> toute la largeur d'oracles ne tire jamais. Ici,
    UNIQUEMENT pour une cible IN-SCOPE autorisée, on pilote le browser-automation gouverné pour
    franchir le challenge (turnstile/vision-click-os) et OBSERVER le trafic (capture-start/dump),
    puis on extrait les endpoints du rendu — liens/forms du DOM, routes référencées dans le JS
    (MÊMES regex que recon.js_endpoints, anti-drift) et URLs XHR/fetch capturées — RESTREINTS
    fail-closed aux hôtes in-scope. Chaque endpoint est émis avec le MÊME titre-marqueur
    (techniques.DISCOVERY_ENDPOINT_MARKER) que recon.js_endpoints : le cerveau le détecte et CHAÎNE
    les oracles de vérification dessus (edge e). C'est de la cartographie de reachability autorisée.

    Garde-fous DURS (hérités de PassiveSurface + la sonde de santé de _EvasionBase) :
      - SCOPE-GUARD : cible hors périmètre -> refus fail-closed SANS AUCUN appel browser ; et chaque
        endpoint découvert est RE-VALIDÉ contre le périmètre injecté (_host_in_scope) avant émission.
      - NON DESTRUCTIF : navigate + lecture/extraction SEULE (exploit=False, destructive=False).
      - SESSION SECRÈTE : la session authentifiée vit DANS le service browser ; on n'en lit QUE des
        URLs (jamais les en-têtes/cookies), jamais journalisée/reportée — l'évidence ne contient que
        des URLs d'endpoints in-scope, jamais le dump réseau brut.
      - DÉGRADATION : service browser indisponible -> `available=False` (engine SKIP) ET, en appel
        direct, un finding `status='skipped'` (offline-safe, aucun crash).
      - BORNÉ : une seule page navigée (MAX_PAGES), candidats bruts plafonnés (MAX_RAW), findings
        par-endpoint plafonnés (MAX_ENDPOINTS hérité) — anti-runaway.
    """

    kind = "evasion.discover"
    exploit = False               # navigate + extract only -> jamais d'exploitation
    destructive = False           # lecture seule : aucun état muté
    cls = "evasion"               # famille évasion (brain : proposé sur cible PROTÉGÉE)
    mitre = techniques.mitre_for("evasion.discover")   # T1594 (source de vérité : techniques.py)
    category = "recon"            # cartographie de surface (comme recon.js_endpoints) — pas une vuln
    tool = "forge/modules/evasion.py:evasion.discover"
    description = ("Découverte d'endpoints derrière WAF via browser-automation : franchit le challenge "
                   "managé puis extrait DOM/JS/XHR in-scope, émis avec le marqueur de découverte (T1594).")

    MAX_PAGES = 1                 # borne dure de navigation : la seule cible (no runaway)
    MAX_RAW = 500                 # borne des candidats bruts avant filtrage in-scope
    # MAX_ENDPOINTS (findings par-endpoint émis) hérité de PassiveSurface (25).

    _A_HREF = re.compile(r'<a\b[^>]+href=["\']([^"\']+)["\']', re.I)
    _FORM_ACTION = re.compile(r'<form\b[^>]+action=["\']([^"\']+)["\']', re.I)

    def dry(self, action):
        tab = action.params.get("tab", bc.DEFAULT_TAB)
        return (f"POST {bc.base_url()}/capture-start ; POST /goto {{url:{self._url(action.target)}}} ; "
                f"POST /vision-click-os {{strategy:turnstile}} ; GET /content ; POST /capture-dump"
                f"   # découverte d'endpoints IN-SCOPE derrière WAF (navigate/extract only, tab={tab})")

    def fire(self, action):
        page = action.target
        tab = action.params.get("tab", bc.DEFAULT_TAB)

        # (1) SCOPE-GUARD fail-closed — cible hors périmètre : refus DUR, AUCUNE navigation browser.
        if not self._target_allowed(action):
            return [self._skipped(
                page, "evasion.discover non exécuté — cible hors périmètre (fail-closed)",
                "Cible hors in-scope ; AUCUN appel browser émis (le scope-guard interdit la sortie du périmètre).",
                self.dry(action))]

        # (2) DÉGRADATION GRACIEUSE — service browser-automation injoignable : status=skipped (offline-safe).
        if not self._health_cached():
            return [self._skipped(
                page, "evasion.discover non exécuté — service browser-automation indisponible",
                "Le service browser (port 8080) ne répond pas ; dégradation gracieuse (aucune découverte).",
                self.dry(action))]

        url = self._url(page)
        # (3) NAVIGATION + FRANCHISSEMENT DU CHALLENGE (non destructif). Capture armée AVANT le goto
        #     pour observer le trafic XHR/fetch. La session gouvernée (cookies/DataDome) vit DANS le
        #     service browser : on ne la lit/logge/reporte JAMAIS ici.
        bc.capture_start(tab=tab)
        bc.goto(url, tab=tab)
        try:                                     # franchir le Turnstile interactif — best-effort, jamais fatal
            bc.vision_click_os(strategy=action.params.get("strategy", "turnstile"),
                               threshold=action.params.get("threshold", 0.55), tab=tab)
        except Exception:                        # noqa: BLE001
            pass

        # (3b) ROUTAGE DU FRANCHISSEMENT — la découverte trouvait les endpoints, puis les ORACLES
        #      chaînés dessus retiraient en HTTP brut et reprenaient un 403 : la cartographie était
        #      juste, la vérification aveugle. On récolte donc la clearance (cookies + UA EXACT) vers
        #      le store gouverné AVANT d'émettre les endpoints, pour que les oracles de la vague
        #      suivante tirent avec le matériel qui passe. Scope-guardé ; SECRET (noms seuls).
        harvest = self._adopt_clearance(url, tab)

        # (4) EXTRACTION du rendu : DOM (liens/forms) + routes JS + XHR/fetch capturés — hôtes IN-SCOPE seuls.
        _cst, content = bc.content(tab=tab)
        _dst, captured = bc.capture_dump(tab=tab)
        html = self._as_text(content)
        if not html and not captured:
            # NE PAS FAIRE SEMBLANT : rendu vide = challenge non franchi. On MARQUE l'hôte pour que les
            # modules en aval rendent `skipped` au lieu d'un `tested` qui affirmerait « rien trouvé ».
            store = _session.current()
            if store is not None:
                store.mark_challenged(url)
            return [self._skipped(
                page, "evasion.discover non concluant — rendu vide après navigation",
                "Aucun contenu rendu ni requête capturée (challenge non franchi / IP flaggée / page vide) ; "
                "hôte marqué CHALLENGED — les modules en aval s'abstiendront de conclure.",
                self.dry(action))]

        harvest_ev = (f"clearance_adoptée={harvest['adopted']}"
                      f"{' (' + harvest['why'] + ')' if harvest.get('why') else ''} ; "
                      f"cookies_de_clearance={harvest.get('clearance_cookies') or 'aucun reconnu'}")
        endpoints = self._extract(action, url, html, captured)
        if not endpoints:
            return [self._finding(
                page, "evasion.discover — aucun endpoint in-scope extrait",
                "Navigation OK (challenge franchi) mais aucun endpoint in-scope dans le DOM/JS/trafic. "
                + harvest_ev,
                self.dry(action))]

        # ÉVIDENCE : UNIQUEMENT des URLs d'endpoints in-scope + des NOMS de cookies (jamais le matériel
        # de session lui-même, jamais le dump réseau brut).
        evidence = (f"{len(endpoints)} endpoint(s) in-scope découvert(s) via browser (challenge franchi) ; "
                    f"{harvest_ev} : " + ", ".join(endpoints[:20]))
        summary = self._finding(
            page, f"evasion.discover — {len(endpoints)} endpoint(s) in-scope via browser", evidence,
            self.dry(action))
        # Chaque endpoint émis avec le MÊME marqueur que recon.js_endpoints -> le cerveau chaîne les oracles.
        return [summary] + self._endpoint_findings(action, endpoints, techniques.DISCOVERY_ENDPOINT_MARKER)

    # --- extraction (in-scope-locked, bornée, jamais de matériel de session) ---
    def _extract(self, action, base_url, html, captured):
        """Endpoints IN-SCOPE depuis DOM (liens/forms) + routes JS + URLs XHR/fetch capturées.
        Restreint fail-closed aux hôtes in-scope, dédupliqué, borné à MAX_RAW candidats. Ne lit
        JAMAIS le matériel de session (uniquement des URLs de requêtes/DOM) : le secret ne peut
        physiquement pas entrer dans un finding."""
        raw = []
        html = html or ""
        # DOM : liens <a href> + actions de formulaire <form action>
        for rx in (self._A_HREF, self._FORM_ACTION):
            raw += rx.findall(html)
        # routes/URLs JS — MÊMES regex que recon.js_endpoints (anti-drift de la surface découverte)
        for rx in (JsEndpoints._PATH_API, JsEndpoints._PATH_ANY):
            raw += rx.findall(html)
        for u in JsEndpoints._URL.findall(html):
            raw.append(u.rstrip('\\",\')'))
        # URLs XHR/fetch capturées — URL SEULE (jamais les en-têtes/cookies de la requête)
        raw += self._capture_urls(captured)

        inscope, seen = [], set()
        for cand in raw[:self.MAX_RAW]:                     # borne anti-runaway sur les candidats bruts
            absu = urllib.parse.urljoin(base_url, str(cand).strip())
            if not absu.lower().startswith("http"):
                continue
            if absu in seen:
                continue
            seen.add(absu)
            if self._host_in_scope(action, _host_only(absu)):   # verrou STRICT fail-closed
                inscope.append(absu)
        return inscope

    @staticmethod
    def _capture_urls(captured):
        """Liste d'URLs depuis la réponse /capture-dump, robuste aux formes du service. N'extrait QUE
        le champ URL de chaque requête (JAMAIS les en-têtes/cookies — le matériel de session reste
        secret). Ne lève jamais."""
        out = []

        def _url_of(item):
            if isinstance(item, str):
                return item
            if isinstance(item, dict):
                for k in ("url", "URL", "request_url", "documentURL"):
                    v = item.get(k)
                    if isinstance(v, str) and v:
                        return v
                req = item.get("request")
                if isinstance(req, dict) and isinstance(req.get("url"), str):
                    return req["url"]
            return None

        def _walk(node):
            if isinstance(node, list):
                for it in node:
                    u = _url_of(it)
                    if u:
                        out.append(u)
                    elif isinstance(it, (list, dict)):
                        _walk(it)
            elif isinstance(node, dict):
                for key in ("requests", "captured", "entries", "xhr", "data", "items", "network", "results"):
                    if isinstance(node.get(key), (list, dict)):
                        _walk(node[key])
                u = _url_of(node)                           # dict {url:...} unique
                if u:
                    out.append(u)

        try:
            _walk(captured)
        except Exception:                                    # noqa: BLE001
            return []
        return out

    @staticmethod
    def _as_text(resp):
        """Corps HTML rendu depuis /content : str direct OU dict {content|html|body|text}. '' sinon."""
        if isinstance(resp, str):
            return resp
        if isinstance(resp, dict):
            for k in ("content", "html", "body", "text"):
                if isinstance(resp.get(k), str):
                    return resp[k]
        return ""

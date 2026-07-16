"""Base commune des modules-oracles à PREUVE (`Oracle`) — factorise le squelette répété par les
quatre vérificateurs à preuve : `access_control.idor`, `ssrf.callback`, `auth.takeover`,
`cors.credentials`.

Contrat commun (le « pas de preuve => tested » est ici la loi, pas une convention par module) :
  - PREUVE obtenue  -> `proof(proven=True, ...)`  -> status='vulnerable' (sévérité HIGH/CRITICAL) ;
  - PAS de preuve    -> `proof(proven=False, ...)` -> status='tested' (jamais 'vulnerable' à l'aveugle) ;
  - config manquante -> `skip(...)`               -> finding INFO 'tested', AUCUN réseau émis.

Ce que la base fournit (chaque oracle concret se réduit à : métadonnées + logique de sonde/jugement) :
  - `proof(...)` / `skip(...)` : construction UNIFORME de Finding qui estampille kind/mitre/cwe/category/
    tool/fix et applique le toggle de statut (preuve => vulnerable, sinon tested) ;
  - `_http(...)` : le CÂBLAGE urllib partagé (Request + urlopen + gestion HTTPError/transport). Chaque
    oracle garde son `_fetch` (le seam monkeypatché par les tests) mais l'adosse à `_http` ;
  - `_curl(...)` : PoC curl rejouable (un `-H` par en-tête), partagé par IDOR/SSRF/ATO.

Aucune capacité n'est élargie ici : les flags exploit/destructive/web_allowed restent déclarés par
chaque module concret et restent gardés par le ROE.
"""
import urllib.error
import urllib.parse
import urllib.request

from ._scopeguard import ScopeGuardMixin
from .registry import Module
from .. import pin as _pin
from .. import session as _session
from .. import throttle as _throttle

_MAX_REDIRECTS = 5               # borne du suivi de redirection scope-checké opt-in (anti-boucle)
_MAX_BACKOFF = 3                 # borne des ré-essais 429/503 (back-off exponentiel, JAMAIS infini)
_BACKOFF_BASE = 0.5             # délai initial du back-off (s) si pas de Retry-After
_BACKOFF_CAP = 8.0             # plafond du délai de back-off / d'un Retry-After honoré (s)


def _is_throttled(err):
    """True si une HTTPError est une réponse de THROTTLING/WAF (429 Too Many Requests / 503). Ne lève jamais."""
    try:
        return err.code in (429, 503)
    except Exception:            # noqa: BLE001
        return False


def _retry_after(err, fallback):
    """Délai de back-off (s) : `Retry-After` (secondes entières) s'il est lisible, sinon `fallback`.
    Une date HTTP (format non-numérique) est ignorée -> fallback. Borné à `_BACKOFF_CAP`. Ne lève jamais."""
    ra = None
    try:
        ra = err.headers.get("Retry-After")
    except Exception:            # noqa: BLE001
        ra = None
    delay = fallback
    if ra:
        try:
            delay = float(int(str(ra).strip()))
        except (TypeError, ValueError):
            delay = fallback
    return max(0.0, min(delay, _BACKOFF_CAP))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Handler qui NE SUIT PAS les redirections : `redirect_request` -> None fait remonter la 3xx
    telle quelle (HTTPError avec le header Location intact). Indispensable à l'oracle open-redirect
    (lire la cible de redirection SANS émettre de requête vers l'hôte attaquant hors-scope) et,
    plus généralement, garde-fou de SÛRETÉ : une redirection vers un hôte hors périmètre ne doit
    JAMAIS être suivie automatiquement (le scope-guard resterait aveugle à l'I/O sortante). C'est le
    comportement PAR DÉFAUT de tout fetch d'oracle (`_http(follow_redirects=False)`)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401,N802
        return None


def _host_of(url):
    """Hôte (lowercase) d'une URL, '' si illisible. Ne lève jamais."""
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except Exception:            # noqa: BLE001
        return ""


def _redirect_target(cur_url, location, store):
    """URL absolue du PROCHAIN saut de redirection SI le suivi est autorisé, sinon None (fail-closed).

    Refuse (None -> la 3xx remonte telle quelle, AUCUNE requête vers la cible) si :
      - pas de `Location` ou schéma non http(s) ;
      - AUCUN périmètre gouverné lié (dev/test/offline) — on ne suit jamais à l'aveugle ;
      - destination HORS périmètre — le matériel secret et le réseau ne peuvent PHYSIQUEMENT pas
        quitter le périmètre déclaré, même via une redirection dérivée à runtime (c'était la faille :
        un hôte in-scope 302-ant vers 127.0.0.1/interne recevait sinon la session gouvernée)."""
    if not location:
        return None
    nxt = urllib.parse.urljoin(cur_url, str(location))
    if not nxt.lower().startswith(("http://", "https://")):
        return None
    scope = getattr(store, "scope", None) if store is not None else None
    if scope is None or not scope.is_in_scope(nxt):
        return None
    return nxt


class Oracle(Module):
    """Base des oracles à preuve. Un oracle concret déclare ses métadonnées (kind/mitre/cwe/fix/tool)
    et surcharge une petite méthode de sonde/jugement — toute la plomberie Finding/HTTP vit ici."""

    web_allowed = True          # interaction web (réseau) -> gardée par le ROE (commun aux 4 oracles)
    available = True            # urllib stdlib -> toujours disponible
    cwe = ""                    # CWE canonique de l'oracle (ex "CWE-918") : sert de category ET de cwe
    fix = ""                    # remédiation par défaut de l'oracle (le fix explicite d'un finding prime)
    tool = ""                   # chaîne de provenance estampillée sur les findings
    MAXLEN = 200000             # troncature du corps lu par `_fetch_body` (cas commun ; surchargée par oracle)

    # --- construction UNIFORME de Finding (le coeur factorisé) ---
    def proof(self, *, target, proven, title, severity, evidence, poc, fix=None):
        """Finding sur le CHEMIN DE PREUVE. Estampille category=self.cwe, cwe=self.cwe, mitre=self.mitre,
        tool=self.tool, fix (self.fix par défaut, override par argument). `proven` applique le contrat :
        True -> status='vulnerable', False -> status='tested' (jamais vulnerable sans preuve)."""
        return self.finding(
            _proven=bool(proven),                        # marqueur de PREUVE sanctionné (cf. Module.finding)
            target=target, title=title, severity=severity,
            category=self.cwe, cwe=self.cwe, mitre=self.mitre,
            fix=self.fix if fix is None else fix,
            status="vulnerable" if proven else "tested",
            tool=self.tool, evidence=evidence, poc=poc)

    def skip(self, *, target, title, evidence, poc, severity="INFO"):
        """Finding 'non testé / config manquante' : category=self.cwe, status='tested', tool=self.tool,
        et AUCUN mitre/cwe/fix estampillé (le schema dérivera cwe depuis category + fix depuis le mapping).
        Sert aussi aux refus fail-closed (ex : write IDOR non autorisé) — INFO, aucun réseau émis."""
        return self.finding(
            target=target, title=title, severity=severity,
            category=self.cwe, status="tested", tool=self.tool,
            evidence=evidence, poc=poc)

    # --- seam réseau bas-niveau : UN SEUL saut, SANS suivi auto de redirection ---
    @staticmethod
    def _raw_open(req, timeout=15):
        """Ouvre UNE requête via un opener local `_NoRedirect` : AUCUNE redirection n'est suivie
        automatiquement (une 3xx remonte en `HTTPError`, `Location` intact). C'est le POINT DE PATCH
        RÉSEAU unique des tests (au lieu de `urlopen`) ET le garde-fou de sûreté : le suivi de
        redirection est TOUJOURS explicite et scope-checké dans `_http`, jamais délégué à urllib à
        l'aveugle (qui re-poste les en-têtes — dont le matériel de session — vers l'hôte cible)."""
        return urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)

    @staticmethod
    def _pinned_open(req, pin_ip, timeout=15):
        """ANTI-REBINDING END-TO-END : comme `_raw_open` (opener no-follow, une 3xx remonte en HTTPError)
        MAIS la connexion TCP est établie vers `pin_ip` (l'IP ÉPINGLÉE par le ROE au fire-time) AU LIEU de
        re-résoudre le hostname de `req` — la couche connexion urllib re-résolvait sinon, rouvrant la
        fenêtre de DNS-rebinding entre la résolution du ROE et le connect.

        La logique de connexion PAR-IP (sous-classes HTTPConnection/HTTPSConnection + handlers, SNI/cert
        préservés) vit en SOURCE UNIQUE dans `pin.build_pinned_opener` (partagée avec recon_surface). On y
        passe `override_ip=pin_ip` (l'appelant fournit l'IP explicitement) + `_NoRedirect` (aucun suivi
        auto). TLS NON affaibli : `self.host` reste l'HÔTE D'ORIGINE -> `Host:` header ET, en HTTPS, SNI +
        validation du certificat restent l'hôte d'origine (jamais l'IP). On ne change QUE la CIBLE du connect."""
        opener = _pin.build_pinned_opener(override_ip=pin_ip, extra_handlers=(_NoRedirect,))
        return opener.open(req, timeout=timeout)

    # --- câblage HTTP partagé (les `_fetch` concrets adaptent la forme du tuple retourné) ---
    @staticmethod
    def _http(url, *, headers=None, timeout=15, method="GET", data=None, maxlen=200000,
              follow_redirects=False):
        """Requête urllib partagée -> (status, body, resp_headers).

        - succès        : (r.status, corps décodé tronqué à maxlen, r.headers) ;
        - HTTPError     : (e.code, "", e.headers | None) — corps vide, en-têtes si disponibles ;
        - erreur transport (réseau hostile) : (None, "", None) — on ne crashe jamais.
        Chaque oracle en dérive sa propre forme (content-type, dict d'en-têtes…) dans son `_fetch`.

        `follow_redirects` — DÉFAUT False (garde-fou de SÛRETÉ) : une 3xx N'EST PAS suivie et remonte
        telle quelle (HTTPError, `Location` intact — ce que lisent les oracles open-redirect/OAuth/
        cache-poison). En suivant à l'aveugle, urllib RE-POSTERAIT les en-têtes de la requête — dont le
        matériel de session SECRET — vers l'hôte de destination : un hôte in-scope 302-ant vers
        127.0.0.1/interne exfiltrerait ainsi cookie/Authorization gouvernés HORS périmètre. Le suivi est
        donc OPT-IN et scope-checké : à True, chaque saut est re-validé (`_redirect_target` — arrêt au
        1er `Location` HORS périmètre ou sans scope gouverné lié) et, sur un saut CROSS-ORIGIN, le
        matériel secret de l'appelant (Cookie/Authorization) est RETIRÉ avant de re-tirer ; la session
        gouvernée est re-fusionnée scope-guardée POUR LE NOUVEL hôte (jamais celle de l'hôte précédent).

        SESSION GOUVERNÉE : si un `SessionStore` est lié (par le moteur autour de fire()), le matériel
        d'authentification SECRET applicable à l'URL COURANTE — et UNIQUEMENT si elle est IN-SCOPE
        (scope-guard du store) — est fusionné SOUS les en-têtes de l'appelant dans la requête sortante.
        Il n'est JAMAIS renvoyé ni exposé : l'appelant bâtit ses PoC depuis SES propres en-têtes
        (`_curl`), pas depuis la requête. Sans store lié (dev/test/offline) -> aucun matériel injecté."""
        caller_headers = dict(headers or {})
        payload = data.encode("utf-8") if isinstance(data, str) else data
        store = _session.current()
        bucket = _throttle.current()             # THROTTLE lié par l'engine autour de fire() ; None => no-op
        cur_url, cur_method, cur_payload = url, method, payload
        for _hop in range(_MAX_REDIRECTS + 1):
            req_headers = dict(caller_headers)
            if store is not None:                    # scope-guard PAR-URL : {} si url courante hors-scope
                for k, v in store.headers_for(cur_url).items():
                    req_headers.setdefault(k, v)     # les en-têtes explicites de l'appelant priment
            # BACK-OFF 429/503 borné : re-tente la MÊME requête après Retry-After / back-off exponentiel,
            # SANS consommer un hop de redirection. Le throttle (min-interval) s'applique avant CHAQUE tir.
            backoff_left, backoff_delay, e = _MAX_BACKOFF, _BACKOFF_BASE, None
            while True:
                if bucket is not None:
                    bucket.wait()                    # respect du débit (rate) avant chaque requête sortante
                req = urllib.request.Request(cur_url, headers=req_headers, method=cur_method, data=cur_payload)
                # ANTI-REBINDING : le ROE a épinglé l'IP de CET hôte au fire-time (moteur -> pin.using).
                # Si un pin s'applique à `cur_url`, on se connecte PAR-IP (Host/SNI/cert = hôte d'origine) ;
                # sinon (pas de pin lié, ou hôte non épinglé -> ex redirect cross-origin) résolution NORMALE
                # (byte-identique à l'historique, et c'est `_raw_open` que les tests monkeypatchent).
                pin_ip = _pin.ip_for(cur_url)
                try:
                    resp = (Oracle._pinned_open(req, pin_ip, timeout=timeout) if pin_ip
                            else Oracle._raw_open(req, timeout=timeout))
                    with resp as r:
                        return r.status, r.read(maxlen).decode("utf-8", "replace"), r.headers
                except urllib.error.HTTPError as he:
                    e = he
                    if backoff_left > 0 and _is_throttled(he):
                        _throttle._sleep(_retry_after(he, backoff_delay))   # attendre (Retry-After ou exp)
                        backoff_left -= 1
                        backoff_delay = min(backoff_delay * 2, _BACKOFF_CAP)
                        continue                     # RE-tente (budget borné : jamais infini)
                    break                            # succès impossible : gérer redirection/throttling ci-dessous
                except Exception:                # noqa: BLE001  (réseau hostile : on ne crashe pas)
                    return None, "", None
            # e est une HTTPError (3xx no-follow, ou 4xx/5xx dont un 429/503 persistant après back-off).
            if follow_redirects and 300 <= e.code < 400:
                loc = None
                try:
                    loc = e.headers.get("Location")
                except Exception:            # noqa: BLE001
                    loc = None
                nxt = _redirect_target(cur_url, loc, store)
                if nxt is not None:
                    follow = True
                    if _host_of(nxt) != _host_of(cur_url):
                        # saut CROSS-ORIGIN : on NE re-poste JAMAIS le secret de l'appelant vers le
                        # nouvel hôte ; la session gouvernée du nouvel hôte (scope-guardée) sera
                        # re-fusionnée au tour suivant via headers_for(nxt).
                        caller_headers = {k: v for k, v in caller_headers.items()
                                          if k.lower() not in ("cookie", "authorization")}
                        # ANTI-REBINDING (résidu T8 fermé) : le ROE n'a épinglé QUE l'hôte de la cible
                        # d'origine. Sous un contexte de pin gouverné, un hôte cross-host N'EST PAS épinglé
                        # -> la couche connexion RE-RÉSOUDRAIT (fenêtre de rebinding). On RÉSOUT le nouvel
                        # hôte sous les MÊMES règles fail-closed que le ROE (`Scope.safe_pinned_ip` :
                        # privé/out_scope/timeout/inconnu => None) et on l'ÉPINGLE ; None => on REFUSE de
                        # suivre (la 3xx remonte telle quelle). Hors contexte gouverné (dev/test/offline) =>
                        # aucun pin lié => suivi NORMAL byte-identique (le scope-guard hostname a déjà gaté nxt).
                        if _pin.current() is not None and _pin.ip_for(nxt) is None:
                            scope = getattr(store, "scope", None) if store is not None else None
                            safe_ip = scope.safe_pinned_ip(nxt) if scope is not None else None
                            if safe_ip is None:
                                follow = False           # fail-closed : hôte dérivé non épinglable
                            else:
                                _pin.bind(nxt, safe_ip)  # épingle l'hôte dérivé -> connexion PAR-IP au tour suivant
                    if follow:
                        if e.code not in (307, 308):     # 301/302/303 -> GET sans corps (convention)
                            cur_method, cur_payload = "GET", None
                        cur_url = nxt
                        continue
            # THROTTLING PERSISTANT (429/503 après back-off) : marque le bucket -> l'engine surface un
            # marqueur « rate-limited » au run (au lieu d'empties silencieux). Puis la réponse telle quelle.
            if _is_throttled(e) and bucket is not None:
                bucket.mark_blocked()
            # pas de suivi (défaut, hors-scope, sans scope lié, ou budget épuisé) : réponse telle quelle.
            try:
                return e.code, "", e.headers
            except Exception:            # noqa: BLE001
                return e.code, "", None
        return None, "", None                # budget de redirections épuisé (défense en profondeur)

    # --- fetch (status, body) PARTAGÉ (seam `_fetch` monkeypatché par les tests) ---
    @classmethod
    def _fetch_body(cls, url, headers=None, timeout=15, method="GET", data=None):
        """(status, body) — adosse le câblage urllib partagé (Oracle._http), en tronquant le corps à
        `cls.MAXLEN` (100000/200000/300000 selon l'oracle). Source UNIQUE des ~10 `_fetch` (st, body)
        recopiés dans ssrf/tokenapi/rce/business_logic/xxe/race/rfi/injection/exposure/takeover : ils ne
        divergeaient QUE par le maxlen. Le SessionStore gouverné (scope-guardé) est fusionné par `_http`
        UNIQUEMENT sur des URL in-scope. Exposé aussi sous le nom `_fetch` (seam patché par les tests)."""
        st, body, _ = Oracle._http(url, headers=headers, timeout=timeout, method=method,
                                   data=data, maxlen=cls.MAXLEN)
        return st, body

    # Nom historique du seam : les modules concrets appellent `self._fetch(...)` et les tests le
    # monkeypatchent par classe. Résout vers la méthode hoistée ci-dessus (par héritage/alias).
    _fetch = _fetch_body

    @staticmethod
    def _content_type(headers):
        """Content-Type NORMALISÉ (type/sous-type minuscule, paramètres retirés) depuis un mapping
        d'en-têtes (ou None). '' si absent/illisible. Source unique de l'extraction recopiée dans
        access_control (cadre la comparaison différentielle : html vs json ≠ même objet). Ne lève jamais."""
        ct = ""
        if headers is not None:
            try:
                ct = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
            except Exception:            # noqa: BLE001
                ct = ""
        return ct

    # --- PoC curl partagé (IDOR / SSRF / ATO) — un drapeau -H par en-tête (commande rejouable) ---
    @staticmethod
    def _curl(url, headers, method="GET", data=None):
        """PoC curl valide : un `-H` par en-tête (jamais un repr de dict), `-X` si non-GET,
        `--data` si corps, URL quotée en dernier. Sortie identique pour IDOR/SSRF/ATO."""
        parts = ["curl", "-sS"]
        if method and method.upper() != "GET":
            parts += ["-X", method.upper()]
        for k, v in (headers or {}).items():
            parts += ["-H", f"'{k}: {v}'"]
        if data is not None:
            parts += ["--data", f"'{data}'"]
        parts.append(f"'{url}'")
        return " ".join(parts)


class ScopeGuardedOracle(ScopeGuardMixin, Oracle):
    """Base des oracles à VÉRIFICATION qui portent un SCOPE-GUARD NATIF fail-closed (défense en
    profondeur : l'engine gate déjà en Couche 2, on re-valide localement AVANT tout réseau) + une
    DÉGRADATION GRACIEUSE uniforme (`status='skipped'` quand le réseau/outil optionnel est absent,
    pour que les tests offline passent). Ce mixin ne porte AUCUNE capacité élargie : exploit/
    destructive restent déclarés par chaque module concret et gardés par le ROE.

    Le scope-guard (`_scope`/`_in_scope`) vit dans `ScopeGuardMixin` (source UNIQUE à auditer)."""

    def _scope_refused(self, action):
        """Refus fail-closed : cible hors périmètre -> Finding `skipped` INFO, AUCUNE requête émise.
        Le matériel secret et le réseau ne peuvent physiquement pas quitter le périmètre déclaré."""
        return self.degraded(
            target=action.target,
            title=f"{self.kind} non testé — cible hors périmètre (scope-guard fail-closed)",
            evidence="La cible n'appartient pas au périmètre in-scope ; aucune requête émise (fail-closed).",
            poc=self.dry(action))

    def degraded(self, *, target, title, evidence, poc):
        """Finding de DÉGRADATION GRACIEUSE (`status='skipped'`) : scope-refus, outil optionnel absent
        ou réseau indisponible. Estampille kind/mitre/cwe/tool/fix comme un finding normal (INFO)."""
        return self.finding(
            target=target, title=title, severity="INFO",
            category=self.cwe, cwe=self.cwe, mitre=self.mitre,
            fix=self.fix, status="skipped", tool=self.tool,
            evidence=evidence, poc=poc)

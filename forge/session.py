# SPDX-License-Identifier: AGPL-3.0-or-later
"""Support de SESSION authentifiée GOUVERNÉE — matériel de requête SECRET attaché aux requêtes
IN-SCOPE uniquement.

Les vulnérabilités à fort impact sur une infra protégée sont AUTHENTIFIÉES (contrôle d'accès /
logique métier) : les modules recon/oracle doivent donc pouvoir évaluer des surfaces qui exigent une
session. Ce module porte un matériel de session OPTIONNEL, par-scope ou par-cible (cookies, en-têtes
de requête, jeton bearer), que ces modules attachent quand ils émettent une requête — sous trois
garanties DURES :

  (1) SECRET — le matériel de session n'est JAMAIS sérialisé dans le ledger, journalisé, ni inclus dans
      un finding ou un rapport. `Session`/`SessionStore` se RÉDIGENT eux-mêmes (repr/str n'exposent que
      des compteurs), le matériel est injecté UNIQUEMENT dans les en-têtes de la requête SORTANTE
      (jamais renvoyé, jamais recopié dans un PoC/evidence — les modules construisent leurs PoC depuis
      LEURS propres en-têtes, pas depuis la requête fusionnée), et il n'entre JAMAIS dans
      `action.params` (que le moteur peut exposer) ni dans le graphe d'engagement.
  (2) SCOPE-GUARDÉ — une session n'est attachée QU'AUX requêtes dont l'hôte est IN-SCOPE (le scope ROE
      fait foi). `headers_for(url)` renvoie {} pour toute URL hors-scope : le matériel secret ne peut
      PHYSIQUEMENT pas quitter le périmètre déclaré — même vers une URL dérivée à runtime par un module
      (un collecteur SSRF, un asset découvert). Les REDIRECTIONS HTTP ne peuvent pas non plus exfiltrer
      le secret : le seam de fetch des oracles (`Oracle._http`) NE SUIT PAS les redirections par défaut ;
      le suivi est opt-in et scope-checké (chaque saut re-validé, arrêt au 1er `Location` hors périmètre,
      matériel secret RETIRÉ sur tout saut cross-origin) — jamais un re-post aveugle des en-têtes vers
      l'hôte de destination.
  (3) OFFLINE-SAFE — sans session configurée, le store est INERTE (headers_for -> {}), no-op total :
      zéro changement de comportement, la suite offline reste verte.

Liaison : le moteur construit un `SessionStore` depuis le scope (+ matériel par-cible) et le LIE autour
de chaque `fire()` de module via `using(store)` (contexte thread-local restauré en sortie). Les
chokepoints HTTP partagés (`Oracle._http`, `PassiveSurface._http_get`) consultent `current()` et
fusionnent les en-têtes de session scope-guardés SOUS ceux de l'appelant. Zéro dépendance (stdlib).

FRANCHISSEMENT DE CHALLENGE (`adopt_clearance`) — le matériel de session n'est plus seulement DÉCLARÉ
par l'opérateur : il peut aussi être RÉCOLTÉ à runtime sur la session navigateur qui vient de franchir
un défi Cloudflare/DataDome (`forge.clearance` + `modules/evasion.py`). Mêmes trois garanties, sans
exception — le scope-guard vaut identiquement pour un cookie de clearance et pour un cookie d'auth.
L'adoption FUSIONNE (elle n'écrase pas) : l'authentification déclarée par l'opérateur survit."""
import base64
import contextlib
import fnmatch
import json
import re
import threading
import time

from .roe import Scope


def _has_header(headers, name):
    """True si `name` (insensible à la casse) est déjà présent dans le dict d'en-têtes."""
    low = name.lower()
    return any(str(k).lower() == low for k in headers)


class Session:
    """Matériel de requête SECRET pour UN principal authentifié (cookies / en-têtes / bearer).

    Accepte un dict (ou kwargs) :
      - `headers` : dict d'en-têtes de requête bruts (ex {"Authorization": "Bearer …", "X-CSRF": "…"}) ;
      - `cookies` : dict {nom: valeur} OU chaîne 'a=b; c=d' ;
      - `bearer` / `token` : jeton -> en-tête 'Authorization: Bearer <jeton>'.
    Se rédige : repr/str n'exposent QUE des compteurs, jamais les valeurs secrètes."""

    def __init__(self, data=None, **kw):
        d = dict(data or {})
        d.update(kw)
        self._headers = {str(k): str(v) for k, v in (d.get("headers") or {}).items()}
        self._cookies = self._parse_cookies(d.get("cookies"))
        bearer = d.get("bearer") or d.get("token") or ""
        self._bearer = str(bearer)

    @staticmethod
    def _parse_cookies(cookies):
        """dict {nom: valeur} depuis un dict OU une chaîne 'a=b; c=d'. Ne lève jamais."""
        if not cookies:
            return {}
        if isinstance(cookies, dict):
            return {str(k): str(v) for k, v in cookies.items()}
        out = {}
        for part in str(cookies).split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip()
            if k:
                out[k] = v.strip()
        return out

    def is_empty(self):
        return not (self._headers or self._cookies or self._bearer)

    def with_fallback(self, other):
        """Nouvelle `Session` fusionnée : le matériel de `self` (DÉCLARÉ par l'opérateur) PRIME, celui
        de `other` (RÉCOLTÉ à runtime — cf. `SessionStore.adopt_clearance`) ne comble QUE les trous.

        POURQUOI UNE FUSION ET NON UN REMPLACEMENT. Adopter du matériel de franchissement en ÉCRASANT
        la session de l'hôte DÉTRUIRAIT l'authentification de l'opérateur : les oracles de contrôle
        d'accès (IDOR/ATO) redeviendraient anonymes et rendraient « rien trouvé » — le mode d'échec
        le plus cher du dépôt (un rapport propre et vide, indiscernable d'une cible saine). On fusionne
        donc au grain du COOKIE (et non de l'en-tête `Cookie` entier) : `sid` de l'opérateur ET
        `cf_clearance` du navigateur partent ensemble dans la MÊME requête.

        Précédence, cohérente avec tout le dépôt (« l'explicite prime ») : en-têtes de `self` d'abord
        (comparaison insensible à la casse — jamais de doublon `User-Agent`/`user-agent`), cookies de
        `self` par NOM (les noms de cookie, eux, sont sensibles à la casse : RFC 6265), bearer de `self`
        s'il existe. Corollaire ASSUMÉ : un opérateur qui fixe SON `User-Agent` garde le sien, même si
        cela rend une clearance liée à l'UA du navigateur inopérante — on ne renverse jamais un choix
        explicite dans son dos. Pur : ne mute NI `self` NI `other`."""
        if other is None:
            return self
        headers = dict(self._headers)
        for k, v in other._headers.items():
            if not _has_header(headers, k):
                headers[k] = v
        cookies = dict(other._cookies)
        cookies.update(self._cookies)                    # les cookies de l'opérateur priment par NOM
        return Session({"headers": headers, "cookies": cookies,
                        "bearer": self._bearer or other._bearer})

    def request_headers(self):
        """En-têtes de requête à INJECTER (copie fraîche à chaque appel) : en-têtes bruts + `Cookie`
        (si cookies) + `Authorization: Bearer` (si bearer). N'écrase jamais un `Cookie`/`Authorization`
        déjà présent dans `headers` (l'explicite prime — comparaison insensible à la casse)."""
        h = dict(self._headers)
        if self._cookies and not _has_header(h, "Cookie"):
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
        if self._bearer and not _has_header(h, "Authorization"):
            h["Authorization"] = f"Bearer {self._bearer}"
        return h

    # --- rédaction : JAMAIS de valeur secrète dans une représentation lisible/loggable ---
    def __repr__(self):
        return (f"<forge.Session headers={len(self._headers)} cookies={len(self._cookies)} "
                f"bearer={'yes' if self._bearer else 'no'}>")

    __str__ = __repr__


def _coerce(x):
    """None | dict | Session -> Session | None (fail-closed : type inattendu -> None)."""
    if x is None:
        return None
    if isinstance(x, Session):
        return x
    if isinstance(x, dict):
        return Session(x)
    return None


class SessionStore:
    """Résout le matériel de session pour une URL, SOUS scope-guard. `headers_for(url)` renvoie {}
    pour toute URL hors-scope (le secret ne quitte JAMAIS le périmètre) ou sans session applicable.

    Sélection de session (la plus spécifique gagne) : hôte exact > motif glob (fnmatch) > défaut global.
    Le scope-guard passe TOUJOURS AVANT la sélection : même un `per_host` mal configuré sur un hôte
    hors-scope ne peut rien fuiter (is_in_scope fait foi)."""

    def __init__(self, scope, default=None, per_host=None):
        self.scope = scope
        self._default = _coerce(default)
        self._per_host = {}
        # ÉTAT DE FRANCHISSEMENT PAR-HÔTE (aucun secret : {hôte canonique: 'cleared'|'challenged'}).
        # C'est le canal par lequel « le défi n'a PAS été franchi » remonte jusqu'aux modules qui
        # n'ont PAS de corps de réponse à inspecter (sonde de TIMING du smuggling) pour qu'ils rendent
        # `skipped` (« je n'ai pas pu vérifier ») au lieu de `tested` (« j'ai vérifié, rien trouvé »).
        self._clearance = {}
        for host, sess in (per_host or {}).items():
            self.add_host_session(host, sess)

    @classmethod
    def from_scope(cls, scope):
        """Construit depuis le scope : `scope.session` (défaut global) + `scope.sessions` (map par-hôte).
        Robuste si ces attributs manquent (store inerte -> headers_for renvoie toujours {})."""
        return cls(scope, default=getattr(scope, "session", None),
                   per_host=getattr(scope, "sessions", None) or {})

    def add_host_session(self, host, data):
        """Enregistre/écrase le matériel de session pour un hôte (canonicalisé). Ignoré si vide/None."""
        s = _coerce(data)
        if s is not None and not s.is_empty():
            self._per_host[Scope._host(host)] = s

    def _match(self, host):
        """Session la plus spécifique pour un hôte canonique : exacte > glob (fnmatch) > défaut global."""
        if host in self._per_host:
            return self._per_host[host]
        for pat, sess in self._per_host.items():
            if fnmatch.fnmatch(host, pat):
                return sess
        return self._default

    def inherit(self, src, dst):
        """Porte la session gouvernée À TRAVERS la CHAÎNE de découverte : fait hériter à l'hôte DÉRIVÉ
        `dst` (origine IP, sous-domaine, endpoint résolu à runtime depuis `src`) la session PAR-HÔTE de
        `src`, pour que les oracles chaînés sur `dst` soient authentifiés. Retourne True si un héritage
        a été posé.

        GARDE-FOUS (fail-closed, SECRET) :
          - SCOPE-GUARD : no-op si `dst` est hors-scope (le matériel ne peut PHYSIQUEMENT pas partir hors
            du périmètre déclaré — is_in_scope fait foi, comme session_for) ;
          - n'ÉCRASE JAMAIS une session déjà configurée pour `dst` (l'explicite prime) ;
          - n'hérite QUE d'une session PAR-HÔTE de `src` (pas du défaut global, qui couvre déjà tout
            in-scope via _match) ni d'une session vide -> évite d'aliaser inutilement ;
          - SECRET : ne journalise/retourne aucun matériel ; l'aliasing reste interne au store."""
        if self.scope is None or not self.scope.is_in_scope(dst):
            return False
        dh = Scope._host(dst)
        if not dh or dh in self._per_host:               # déjà une session explicite pour dst -> ne pas écraser
            return False
        s = self._match(Scope._host(src))
        if s is None or s is self._default or s.is_empty():
            return False                                 # rien à hériter (pas de session par-hôte de src)
        self._per_host[dh] = s
        return True

    def session_for(self, url):
        """La `Session` à attacher pour `url`, ou None. SCOPE-GUARD DUR : hors-scope -> None (le
        matériel secret ne peut physiquement pas partir vers un hôte non autorisé par le ROE)."""
        if self.scope is None or not self.scope.is_in_scope(url):
            return None
        s = self._match(Scope._host(url))
        if s is None or s.is_empty():
            return None
        return s

    def headers_for(self, url):
        """En-têtes de session à injecter pour `url` (scope-guardés), ou {} (jamais None)."""
        s = self.session_for(url)
        return s.request_headers() if s is not None else {}

    # =============================================================================================
    #  FRANCHISSEMENT DE CHALLENGE — router vers les modules HTTP ce que le NAVIGATEUR a obtenu.
    #
    #  Le trou mesuré : sur une cible derrière Cloudflare, `evasion.turnstile` FRANCHIT le défi (clic
    #  OS confirmé) pendant que le reste du moteur continue de tirer en HTTP brut et reprend un
    #  403 `cf-mitigated: challenge`. 1573 actions, 9 URLs distinctes atteintes, contenu du site jamais
    #  vu. La capacité existait ; elle n'était pas ROUTÉE. `adopt_clearance` EST la route : le matériel
    #  du navigateur (cookies de clearance + User-Agent EXACT) rejoint le store, et les ~40 modules
    #  qui passent par `Oracle._http` en profitent SANS ÊTRE MODIFIÉS.
    # =============================================================================================
    CLEARED = "cleared"                 # défi franchi ET matériel adopté pour cet hôte
    CHALLENGED = "challenged"           # défi CONSTATÉ et NON franchi -> aucun module ne peut conclure
    UNKNOWN = "unknown"                 # rien d'observé -> comportement historique (l'oracle conclut)

    def adopt_clearance(self, url, material):
        """ADOPTE pour l'hôte de `url` du matériel de FRANCHISSEMENT récolté à runtime (cookies de
        clearance + User-Agent exact du navigateur). Retourne True si l'adoption a eu lieu.

        GARDE-FOUS (fail-closed, SECRET) :
          - SCOPE-GUARD DUR, identique à `session_for` : hors-scope -> no-op + False. Un `cf_clearance`
            qui partirait vers un tiers serait une FUITE DE SESSION vers un hôte non autorisé ; le
            matériel ne peut PHYSIQUEMENT pas quitter le périmètre déclaré (`is_in_scope` fait foi) ;
          - L'EXISTANT PRIME et SURVIT : on fusionne sous la session RÉSOLUE pour cet hôte
            (`_match` : exacte > glob > DÉFAUT GLOBAL). Poser une session par-hôte sans fusionner
            masquerait le défaut global pour cet hôte (`_match` s'arrête au par-hôte) et ferait perdre
            l'authentification de l'opérateur en silence — cf. `Session.with_fallback` ;
          - matériel vide/illisible -> no-op + False (jamais d'adoption fantôme).
        SECRET : ne journalise/retourne aucun matériel — juste un booléen."""
        if self.scope is None or not self.scope.is_in_scope(url):
            return False
        host = Scope._host(url)
        if not host:
            return False
        harvested = _coerce(material)
        if harvested is None or harvested.is_empty():
            return False
        existing = self._match(host)                     # inclut le défaut global (ne pas le perdre)
        self._per_host[host] = (existing.with_fallback(harvested) if existing is not None
                                else harvested)
        self._clearance[host] = self.CLEARED
        return True

    def mark_challenged(self, url):
        """ENREGISTRE qu'un challenge managé a été CONSTATÉ sur l'hôte de `url` et NON franchi.
        Retourne True si l'état a été posé. Scope-guardé (on ne suit que le périmètre déclaré) et
        SANS SECRET : on ne stocke qu'un hostname et un mot. C'est ce que lisent les modules qui n'ont
        pas de corps de réponse à juger, pour rendre `skipped` plutôt qu'un `tested` mensonger."""
        if self.scope is None or not self.scope.is_in_scope(url):
            return False
        host = Scope._host(url)
        if not host:
            return False
        self._clearance[host] = self.CHALLENGED
        return True

    def clearance_state(self, url):
        """`'cleared'` | `'challenged'` | `'unknown'` pour l'hôte de `url`. `'unknown'` est le défaut
        et signifie « rien d'observé » : les modules gardent alors leur comportement historique."""
        host = Scope._host(url)
        return self._clearance.get(host, self.UNKNOWN) if host else self.UNKNOWN

    def clearance_census(self):
        """Recensement SÛR {hôte: état} du franchissement (hostnames + verdicts, aucun secret)."""
        return dict(self._clearance)

    def hosts_with_session(self):
        """Résumé SÛR (aucun secret) : hôtes portant une session par-hôte + présence d'un défaut global."""
        return {"per_host": sorted(self._per_host), "has_default": self._default is not None}

    def __repr__(self):
        return (f"<forge.SessionStore per_host={len(self._per_host)} "
                f"default={'yes' if self._default is not None else 'no'}>")

    __str__ = __repr__


# =================================================================================================
#  CONTEXTE D'AUTHENTIFICATION PAR-ENGAGEMENT (R5) — comptes de test LABELLISÉS de l'opérateur +
#  idor_targets structurés, qui alimentent les oracles de contrôle d'accès (IDOR d'abord).
# =================================================================================================
class AuthAccount:
    """Un compte de test de l'opérateur, LABELLISÉ (`attacker` / `victim` / …). Enrobe `Session` pour
    réutiliser exactement le parsing headers/cookies/bearer ET la rédaction (repr/str n'exposent que
    des compteurs — le matériel secret ne fuit pas dans une représentation lisible).

    Le compte est FOURNI par l'opérateur (ses propres comptes de test sur une cible in-scope) — jamais
    récolté/volé. Son seul usage : REJOUER une requête authentifiée (headers de session) contre une
    ressource possédée par un AUTRE compte de l'opérateur pour prouver un accès cross-compte."""

    def __init__(self, data=None, **kw):
        d = dict(data or {})
        d.update(kw)
        self.label = str(d.get("label") or "").strip()
        self._session = Session(d)                    # réutilise headers/cookies/bearer + rédaction

    def headers(self):
        """En-têtes de requête à INJECTER (copie fraîche) — bruts + Cookie + Authorization: Bearer."""
        return self._session.request_headers()

    def is_empty(self):
        return self._session.is_empty()

    def expires_at(self):
        """Échéance (epoch s) LISIBLE du matériel de ce compte, ou None (INCONNU — cookie opaque).
        SECRET : rend un entier, jamais un fragment de jeton."""
        return headers_expiry(self.headers())

    def is_expired(self, now=None):
        """True seulement si l'échéance est lisible ET dépassée (cf. `headers_expired`)."""
        return headers_expired(self.headers(), now=now)

    def as_param(self):
        """Forme consommée par l'oracle IDOR : {label, headers}. SECRET — les headers portent le
        matériel d'auth (jamais journalisé tel quel ; le PoC/evidence est rédigé à la source)."""
        return {"label": self.label, "headers": self.headers()}

    # --- rédaction : JAMAIS de valeur secrète dans une représentation lisible/loggable ---
    def __repr__(self):
        return f"<forge.AuthAccount label={self.label!r} {self._session!r}>"

    __str__ = __repr__


# =================================================================================================
#  PÉREMPTION DU MATÉRIEL D'AUTHENTIFICATION — lire la date d'expiration AUTO-DÉCLARÉE d'un jeton.
#
#  POURQUOI. Le matériel d'auth ARME les oracles de contrôle d'accès (`access_control.idor`,
#  `auth.takeover`, `access_control.privesc`). Une session qui expire en cours de campagne ne produit
#  PAS d'erreur : les conjonctions de preuve s'effondrent toutes à False et l'oracle rend « rien
#  trouvé » — un rapport PROPRE et VIDE qui ressemble à « la cible est saine ». C'est le mode d'échec
#  le plus cher du projet. Ces helpers donnent le premier des deux signaux qui le rendent VISIBLE :
#  la PÉREMPTION LISIBLE DANS LE JETON LUI-MÊME, connue AVANT d'émettre la moindre requête.
#  (Le second signal — « la cible répond au compte authentifié comme à l'anonyme » — vit dans
#  `modules/oracle.py` : il se lit sur les sondes DÉJÀ tirées, sans requête supplémentaire.)
#
#  CE QUE CE CODE NE FAIT PAS. Aucune vérification de SIGNATURE : on ne valide pas le jeton, on LIT
#  une date auto-déclarée. C'est suffisant et c'est le bon niveau : le jeton est celui de l'opérateur
#  (pas d'adversaire à contrer ici), et un `exp` dépassé signifie que le SERVEUR le refusera. Un
#  jeton illisible/non-JWT (cookie de session opaque) rend `None` = INCONNU — jamais « expiré » :
#  on n'accuse JAMAIS sans preuve, l'inconnu retombe sur la détection au tir.
#  SECRET : ces fonctions ne rendent QU'UN ENTIER (epoch) ou un booléen. Jamais le jeton, jamais un
#  fragment de jeton — rien d'ici ne peut atterrir dans un log, un finding ou le ledger.
# =================================================================================================
# Un JWT commence TOUJOURS par le base64url de `{"` -> `eyJ`. Discriminant simple et sûr : on ne
# tente de décoder QUE ce qui a la forme d'un JWT, jamais un cookie opaque quelconque.
_JWT_RX = re.compile(r"eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")

# Grâce (s) appliquée AVANT de déclarer un matériel périmé : notre horloge peut être EN AVANCE sur
# celle du serveur. La grâce pousse la déclaration PLUS TARD (jamais plus tôt) — on préfère rater une
# péremption de 30 s (la détection au tir la rattrape) que d'accuser à tort un jeton encore valide.
_EXPIRY_GRACE = 60.0


def _b64url_json(seg):
    """dict depuis un segment base64url (padding restauré), ou None. Ne lève JAMAIS."""
    try:
        raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
        obj = json.loads(raw.decode("utf-8", "replace"))
    except Exception:            # noqa: BLE001  (jeton arbitraire : tout échec = « illisible »)
        return None
    return obj if isinstance(obj, dict) else None


def jwt_expiry(token):
    """`exp` (epoch secondes, int) du PAYLOAD d'un JWT, ou None si absent/illisible/non-JWT.
    AUCUNE vérification de signature (cf. le bloc ci-dessus). Ne lève JAMAIS."""
    payload = _b64url_json(str(token or "").split(".")[1]) if str(token or "").count(".") >= 2 else None
    exp = (payload or {}).get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return None                                  # `exp` absent ou non numérique -> INCONNU
    return int(exp)


def material_expiry(values):
    """La PLUS PROCHE échéance (epoch) parmi les JWT trouvés dans des chaînes arbitraires (valeurs
    d'en-tête, de cookie, bearer nu), ou None si aucune n'est lisible. Le jeton peut être ENROBÉ
    (`Bearer <jwt>`, `sid=<jwt>; other=1`) : on extrait les sous-chaînes de forme JWT. Ne lève JAMAIS."""
    best = None
    for v in values or ():
        for tok in _JWT_RX.findall(str(v or "")):
            exp = jwt_expiry(tok)
            if exp is not None and (best is None or exp < best):
                best = exp
    return best


def headers_expiry(headers):
    """Échéance la plus proche du matériel porté par un dict d'EN-TÊTES DE REQUÊTE (la forme que les
    oracles manipulent : `Authorization`, `Cookie`, en-têtes maison). None = INCONNU."""
    return material_expiry((headers or {}).values())


def headers_expired(headers, now=None, grace=_EXPIRY_GRACE):
    """True SEULEMENT si le matériel porte une échéance LISIBLE et DÉPASSÉE (grâce d'horloge incluse).
    INCONNU (cookie opaque, pas de JWT) -> False : jamais d'accusation sans preuve."""
    exp = headers_expiry(headers)
    if exp is None:
        return False
    return (time.time() if now is None else float(now)) >= exp + float(grace)


class AuthContext:
    """Contexte d'authentification PAR-ENGAGEMENT (R5) : comptes de test LABELLISÉS de l'opérateur +
    `idor_targets` structurés {url, owner, marker}. Alimente les oracles de contrôle d'accès.

    - `accounts`      : liste d'`AuthAccount` non vides (attacker/victim/…) ;
    - `idor_targets`  : liste de dicts {url (in-scope), owner (ex 'victim'), marker (chaîne prouvant la
                        donnée de la victime)} ; l'oracle rejoue chaque `url` avec la session de
                        l'ATTAQUANT et flag si le marqueur (ou un 2xx là où l'anon est refusé) revient.

    Consommé par DEUX oracles de contrôle d'accès qui partagent ces MÊMES `accounts` (R5 : `access_
    control.idor` ; R5b : `auth.takeover`/ATO) — l'engine injecte comptes + idor_targets dans les deux,
    aucun chemin parallèle. SECRET : `ledger_summary()`/`repr` n'exposent QUE des labels + des
    compteurs, jamais un secret. INERTE si absent (`from_scope` -> None -> aucun changement)."""

    def __init__(self, accounts=None, idor_targets=None):
        self.accounts = [a for a in (accounts or [])
                         if isinstance(a, AuthAccount) and not a.is_empty()]
        self.idor_targets = list(idor_targets or [])

    @classmethod
    def from_scope(cls, scope):
        """Construit depuis `scope.auth` (bloc optionnel). Rend None (INERTE) si le bloc est absent,
        illisible, ou ne porte NI compte NI cible exploitable — l'oracle retombe alors sur son chemin
        historique (« config manquante »), byte-identique. Fail-closed : une entrée non-dict est
        ignorée (jamais une exception -> jamais un contexte fabriqué)."""
        raw = getattr(scope, "auth", None)
        if not isinstance(raw, dict):
            return None
        accounts = []
        for a in (raw.get("accounts") or []):
            if isinstance(a, dict):
                acc = AuthAccount(a)
                if not acc.is_empty():                # un compte sans matériel d'auth n'aide en rien
                    accounts.append(acc)
        targets = []
        for t in (raw.get("idor_targets") or []):
            if isinstance(t, dict) and t.get("url"):
                targets.append({
                    "url": str(t.get("url")),
                    "owner": str(t.get("owner") or ""),
                    "marker": "" if t.get("marker") is None else str(t.get("marker")),
                })
        if not accounts and not targets:
            return None                               # rien d'exploitable -> INERTE
        return cls(accounts=accounts, idor_targets=targets)

    def account(self, label):
        """Le compte portant `label` (insensible à la casse), ou None."""
        lo = str(label or "").strip().lower()
        for a in self.accounts:
            if a.label.lower() == lo:
                return a
        return None

    def attacker(self):
        """Le compte ATTAQUANT : celui labellisé 'attacker' si présent, sinon le 1er compte (convention)."""
        return self.account("attacker") or (self.accounts[0] if self.accounts else None)

    def accounts_as_params(self):
        """Les comptes sous la forme {label, headers} consommée par l'oracle IDOR (SECRET — rédigé à
        la source lors de la construction du finding)."""
        return [a.as_param() for a in self.accounts]

    def is_empty(self):
        return not self.accounts and not self.idor_targets

    def ledger_summary(self):
        """Vue SÛRE pour le ledger/log d'un run qui a UTILISÉ le contexte : labels des comptes + nombre
        de cibles idor. AUCUN secret (jamais un header/cookie/bearer/URL complète d'un marqueur)."""
        return {"accounts": [a.label for a in self.accounts],
                "idor_targets": len(self.idor_targets)}

    def expired_labels(self, now=None):
        """LABELS des comptes dont le matériel porte une échéance LISIBLE et DÉPASSÉE. Vue SÛRE
        (des labels et rien d'autre) destinée au ledger et à la ligne d'avancement du run : c'est ce
        qui rend une session morte VISIBLE avant que le rapport ne soit vide."""
        return [a.label for a in self.accounts if a.is_expired(now=now)]

    def expiry_census(self, now=None):
        """Recensement SÛR {label: 'expired'|'valid'|'unknown'} — 'unknown' = matériel sans échéance
        lisible (cookie opaque), le cas majoritaire hors JWT. Aucun secret (labels + verdicts)."""
        out = {}
        for a in self.accounts:
            exp = a.expires_at()
            out[a.label] = "unknown" if exp is None else ("expired" if a.is_expired(now=now) else "valid")
        return out

    def __repr__(self):
        return (f"<forge.AuthContext accounts={len(self.accounts)} "
                f"idor_targets={len(self.idor_targets)}>")

    __str__ = __repr__


def attacker_headers_from_params(accounts):
    """En-têtes du compte ATTAQUANT parmi les comptes SÉRIALISÉS `{label, headers}` : le compte
    labellisé 'attacker' si présent, sinon le 1er (convention). None si aucun compte ; `{}` si le
    compte n'a pas d'en-têtes.

    SOURCE UNIQUE de la sélection « attaquant = labellisé-ou-premier » côté oracles : les deux
    consommateurs (`IdorDifferential`, `AuthTakeover`) travaillent sur la forme sérialisée produite par
    `AuthContext.accounts_as_params()` et déléguaient jusqu'ici à deux copies BYTE-IDENTIQUES de cette
    logique (leur docstring disait « Miroir EXACT »). Single-sourcé ici pour que la sélection de compte
    — surface sensible à la sécurité — n'existe qu'à UN endroit. Pur, ne lève jamais."""
    if not accounts:
        return None
    for a in accounts:
        if str(a.get("label", "")).strip().lower() == "attacker":
            return a.get("headers", {}) or {}
    return accounts[0].get("headers", {}) or {}


def attacker_label_from_params(accounts):
    """LABEL du compte ATTAQUANT parmi les comptes SÉRIALISÉS `{label, headers}` — MIROIR EXACT de la
    sélection de `attacker_headers_from_params` (labellisé 'attacker' sinon le 1er). `""` si aucun
    compte ou compte sans label.

    Même raison d'être que son jumeau : la sélection de compte est une surface sensible et ne doit
    exister qu'à UN endroit. Sert à NOMMER le compte dans un finding de dégradation (« matériel du
    compte 'attacker' inutilisable ») — un LABEL, jamais un secret. Pur, ne lève jamais."""
    if not accounts:
        return ""
    for a in accounts:
        if str(a.get("label", "")).strip().lower() == "attacker":
            return str(a.get("label", "")).strip()
    return str(accounts[0].get("label", "")).strip()


# --- liaison ambiante (thread-local) : le moteur LIE le store autour de chaque fire() --------------
_local = threading.local()


def current():
    """Le `SessionStore` actuellement lié (ou None hors d'un `using(...)`)."""
    return getattr(_local, "store", None)


def bind(store):
    """Lie `store` comme store courant du thread. Préférer `using(...)` (restauration automatique)."""
    _local.store = store


@contextlib.contextmanager
def using(store):
    """Lie `store` pour la durée du bloc puis restaure l'état précédent (réentrant, exception-safe)."""
    prev = current()
    bind(store)
    try:
        yield store
    finally:
        bind(prev)

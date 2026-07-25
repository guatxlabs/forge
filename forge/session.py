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
fusionnent les en-têtes de session scope-guardés SOUS ceux de l'appelant. Zéro dépendance (stdlib)."""
import contextlib
import fnmatch
import threading

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

    def as_param(self):
        """Forme consommée par l'oracle IDOR : {label, headers}. SECRET — les headers portent le
        matériel d'auth (jamais journalisé tel quel ; le PoC/evidence est rédigé à la source)."""
        return {"label": self.label, "headers": self.headers()}

    # --- rédaction : JAMAIS de valeur secrète dans une représentation lisible/loggable ---
    def __repr__(self):
        return f"<forge.AuthAccount label={self.label!r} {self._session!r}>"

    __str__ = __repr__


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

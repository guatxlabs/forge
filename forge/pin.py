# SPDX-License-Identifier: AGPL-3.0-only
"""Épinglage d'IP au fire-time (anti-rebinding END-TO-END) — LIÉ autour d'un `fire()` gouverné par
l'engine et HONORÉ par les chokepoints de CONNEXION (`Oracle._http`, `httpflow._timed`).

CONTEXTE — la boucle est bouclée avec le ROE. `roe.py` résout la cible UNE SEULE FOIS au POINT DE TIR,
rend le verdict CONTRE l'IP résolue (privé / out_scope), et ÉPINGLE cette/ces IP sur
`Decision.pinned_ips`. Le moteur expose la liste au module (`action.params["_pinned_ips"]`) ET lie CE
contexte (`using(target, ips)`). Les chokepoints consultent `ip_for(url)` : si l'hôte de l'URL de
connexion CORRESPOND à l'hôte épinglé, ils SE CONNECTENT à l'IP épinglée AU LIEU de re-résoudre le DNS.
Cela ferme la fenêtre de DNS-rebinding sub-ms entre la résolution du ROE (decide/fire) et le connect
réel du module (que la couche connexion urllib/socket re-résolvait sinon).

TLS PRÉSERVÉ — connecter par-IP N'AFFAIBLIT JAMAIS la vérification : le `Host:` header reste l'HÔTE
D'ORIGINE et, en HTTPS, le SNI + la validation du certificat restent l'HÔTE D'ORIGINE (jamais validés
contre l'IP). Voir `Oracle._pinned_open` / `httpflow._timed`.

HELPER DE CONNEXION PARTAGÉ (`build_pinned_opener`) — la logique « dialer l'IP épinglée AU LIEU de
re-résoudre » (sous-classes `HTTPConnection`/`HTTPSConnection` + handlers) vit ICI, en source UNIQUE,
et est réutilisée par `Oracle._pinned_open` (oracle.py, no-follow) ET `PassiveSurface._http_get`
(recon_surface.py, follow), au lieu d'être dupliquée. Elle consulte `ip_for(host)` PAR CONNEXION (donc
un saut de redirection vers un hôte NON épinglé se résout normalement) avec un `override_ip` optionnel
(pour les appelants qui passent explicitement une IP, ex tests / oracle single-hop).

INVARIANTS :
  - contexte ABSENT / `ips` vide      => `ip_for()` renvoie None => résolution DNS NORMALE
    (BYTE-IDENTIQUE au comportement historique). L'épinglage est ADDITIF.
  - hôte NON épinglé (ex : cible d'une REDIRECTION cross-origin, hôte différent) => `ip_for()` None. Un
    saut vers le MÊME hôte reste épinglé. Pour une REDIRECTION CROSS-HOST, l'appelant gouverné (Oracle.
    _http) RÉSOUT le nouvel hôte sous les MÊMES règles fail-closed (`Scope.safe_pinned_ip`) et l'ÉPINGLE
    via `bind()`, ou REFUSE de suivre — fermant le résidu de re-résolution. Hors contexte gouverné =>
    suivi normal (byte-identique).
  - jamais d'exception (fail-safe) : une entrée malformée => aucun pin (ne casse pas le fire).
Zéro dépendance (stdlib). Même idiome que `throttle`/`session` (contexte thread-local restauré en sortie)."""
import http.client
import socket
import threading
import urllib.request

from .roe import Scope                      # Scope._host : normalisation d'hôte canonique (source unique)

_state = threading.local()                  # contexte courant (par thread) : map {host: ip} ou None


def pick(ips):
    """Première IP littérale NON VIDE de `ips` (list/tuple/str), sinon None. Ne lève jamais.
    Le ROE a déjà VÉTOÉ le tir si l'UNE des IP résolues était privée/out_scope -> toute IP épinglée est
    sûre ; on retient la 1re (déterministe, suffisant : elles pointent le même hôte gouverné)."""
    if not ips:
        return None
    if isinstance(ips, str):
        ips = [ips]
    for cand in ips:
        try:
            s = str(cand).strip()
        except Exception:                   # noqa: BLE001
            continue
        if s:
            return s
    return None


def current():
    """Map {host: ip} liée au thread, ou None (hors contexte -> aucun pin). Ne lève jamais."""
    return getattr(_state, "map", None)


def ip_for(url):
    """IP épinglée pour l'hôte de `url` si un pin est lié pour CET hôte, sinon None (résolution normale).
    L'hôte est normalisé via `Scope._host` (même canon que le ROE) -> matching cohérent. Ne lève jamais."""
    m = current()
    if not m:
        return None
    try:
        return m.get(Scope._host(url))
    except Exception:                       # noqa: BLE001 (URL illisible -> pas de pin, jamais de crash)
        return None


def bind(url, ip):
    """Ajoute/écrase le pin {host(url): ip} DANS le contexte thread-local COURANT (s'il existe). Sert à
    épingler un hôte DÉRIVÉ à runtime — la cible d'une REDIRECTION CROSS-HOST — sous les mêmes règles
    fail-closed que le ROE (l'appelant a d'abord obtenu `ip` via `Scope.safe_pinned_ip`). No-op si aucun
    contexte n'est lié (hors fire gouverné) ou si host/ip vide. La mutation est locale au `using` courant
    (le dict est jeté au `__exit__` -> aucune fuite entre fires). Ne lève jamais."""
    m = current()
    if m is None or not ip:
        return
    try:
        host = Scope._host(url)
    except Exception:                       # noqa: BLE001
        return
    if host:
        m[host] = str(ip)


def build_pinned_opener(override_ip=None, extra_handlers=()):
    """Opener urllib dont CHAQUE connexion HTTP/HTTPS DIALE l'IP ÉPINGLÉE de SON PROPRE hôte
    (`ip_for(host)`) — ou `override_ip` quand l'hôte ne porte pas de pin thread-local — AU LIEU de
    re-résoudre le DNS. Ferme la fenêtre de DNS-rebinding au niveau de la CONNEXION. Source UNIQUE
    partagée par `Oracle._pinned_open` et `PassiveSurface._http_get` (plus de duplication).

    - Un hôte SANS pin ET sans override => `ip_for or override` = None => résolution NORMALE
      (BYTE-IDENTIQUE) : une redirection cross-host vers un hôte non épinglé se résout normalement.
    - TLS JAMAIS AFFAIBLI : le `Host:` header reste l'hôte d'origine (self.host) et, en HTTPS,
      `server_hostname` (SNI + validation du certificat) reste l'HÔTE D'ORIGINE via le `_context`
      VÉRIFIÉ du handler standard — le certificat n'est JAMAIS validé contre l'IP. Seule la CIBLE du
      connect TCP change.
    - `extra_handlers` : handlers additionnels (ex : `_NoRedirect` pour le suivi fail-closed d'oracle).
    - `override_ip` : IP à dialer si l'hôte n'a pas de pin thread-local (appelants single-hop/tests qui
      passent l'IP explicitement). Ne lève jamais à la construction."""
    def _dial(host):                        # IP à dialer : pin thread-local de l'hôte, sinon override, sinon None
        return ip_for(host) or override_ip

    class _PinHTTPConnection(http.client.HTTPConnection):
        def connect(self):                                # dial l'IP épinglée de self.host, garde le Host header
            dst = _dial(self.host) or self.host
            self.sock = socket.create_connection((dst, self.port), self.timeout, self.source_address)
            if self._tunnel_host:
                self._tunnel()

    class _PinHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):                                # dial l'IP épinglée ; SNI/cert = hôte d'origine
            dst = _dial(self.host) or self.host
            sock = socket.create_connection((dst, self.port), self.timeout, self.source_address)
            if self._tunnel_host:
                self.sock = sock
                self._tunnel()
                server_hostname = self._tunnel_host
            else:
                server_hostname = self.host               # HÔTE D'ORIGINE -> SNI + validation certificat
            self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)

    class _PinHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, r):
            return self.do_open(_PinHTTPConnection, r)

    class _PinHTTPSHandler(urllib.request.HTTPSHandler):  # hérite le _context VÉRIFIÉ (check_hostname on)
        def https_open(self, r):
            return self.do_open(_PinHTTPSConnection, r)

    return urllib.request.build_opener(*extra_handlers, _PinHTTPHandler, _PinHTTPSHandler)


class using:
    """Context manager : lie l'IP épinglée `ip` (1re non vide de `ips`) à l'hôte de `target` le temps
    d'un `fire()`. `ips` vide/None -> lie None (no-op, résolution normale). Restaure le contexte
    précédent en sortie (réentrance sûre). Ne lève jamais à la construction."""

    def __init__(self, target, ips):
        ip = pick(ips)
        host = ""
        try:
            host = Scope._host(target)
        except Exception:                   # noqa: BLE001
            host = ""
        self.map = {host: ip} if (host and ip) else None

    def __enter__(self):
        self.prev = getattr(_state, "map", None)
        _state.map = self.map
        return self.map

    def __exit__(self, *a):
        _state.map = self.prev
        return False

"""Scope-guard fail-closed — implémentation CANONIQUE et UNIQUE (source de vérité).

Le scope-guard fail-closed était recopié VERBATIM dans quatre bases de modules
(`ScopeGuardedOracle`, `PentestConnector`, `ExternalToolModule`, `PassiveSurface`), et
`_bound_allow_exploit` dans deux d'entre elles. Ce mixin porte l'implémentation unique — une
SEULE surface à auditer pour cette logique SÛRETÉ-CRITIQUE (miroir de la gate ROE de l'engine :
défense en profondeur, on re-valide localement AVANT tout réseau ; sans scope injecté -> permissif
dev/test, l'engine injecte TOUJOURS le périmètre en production et gate en amont).

Le mixin n'ajoute AUCUNE capacité élargie : exploit/destructive restent déclarés par chaque module
concret et gardés par le ROE.
"""

import urllib.parse

from .. import session as _session
from ..roe import Scope


def web_url_candidates(target):
    """URLs HTTP à essayer, DANS L'ORDRE, pour une cible qui peut être un hôte nu, un `host:port` ou
    une URL complète. Point de NORMALISATION unique (partagé par security_headers + PassiveSurface) :
    une cible sans scheme ne doit JAMAIS être passée telle quelle à urllib (`unknown url type`).

    - cible AVEC scheme (`http://`, `https://`, …) -> renvoyée TELLE QUELLE (candidat unique).
      BYTE-IDENTIQUE pour les cibles URL / endpoint déjà formées (aucune régression).
    - `host` / `host:port` nu -> préfixé d'un scheme, http+https ordonnés par vraisemblance :
        * port 80  -> [http]            ; port 443 -> [https] (le bon scheme est certain) ;
        * autre port EXPLICITE -> [http, https] (un port non standard est le plus souvent http clair,
          ex. une console interne sur :7100) ;
        * AUCUN port -> [https, http] (défaut web https, repli http).
    Pur, ne lève JAMAIS. Ne renvoie jamais [] pour une cible non vide."""
    s = str(target).strip()
    if not s:
        return []
    if "://" in s:
        return [s]
    try:                                          # urlsplit ne peuple .port qu'avec un netloc (préfixe //)
        port = urllib.parse.urlsplit("//" + s).port
    except (ValueError, TypeError):               # netloc/port malformé -> traiter comme sans port
        port = None
    if port == 80:
        return ["http://" + s]
    if port == 443:
        return ["https://" + s]
    if port is not None:
        return ["http://" + s, "https://" + s]
    return ["https://" + s, "http://" + s]


class ScopeGuardMixin:
    """Scope-guard fail-closed partagé (`_scope`/`_in_scope`/`_in_scope_flat`) + lecture du scope
    gouverné lié (`_bound_allow_exploit`). Mixin pur (hérite de `object`) : à placer en PREMIÈRE base
    pour primer sur `Module`."""

    @staticmethod
    def _scope(action):
        """(enforce, Scope) reconstruit depuis le périmètre injecté par l'engine (in_scope/out_scope
        dans action.params). `enforce` distingue « périmètre fourni » (production) de « appelé sans
        scope » (dev/test) — sans scope on n'élargit jamais le périmètre (permissif dev, gate ROE amont)."""
        enforce = "in_scope" in action.params or "out_scope" in action.params
        sc = Scope({"in_scope": action.params.get("in_scope", []),
                    "out_scope": action.params.get("out_scope", [])})
        return enforce, sc

    def _in_scope(self, action, target):
        """Appartenance PLATE (miroir exact de la gate ROE) pour la cible requêtée. Sans scope injecté
        -> permissif (l'engine injecte TOUJOURS le périmètre en production, et gate en amont)."""
        enforce, sc = self._scope(action)
        return True if not enforce else sc.is_in_scope(target)

    # Alias historique : PassiveSurface (recon_surface) réfère cette gate sous le nom `_in_scope_flat`.
    _in_scope_flat = _in_scope

    @staticmethod
    def _bound_allow_exploit():
        """(scope, armed) depuis le SessionStore lié — (None, False) si aucun. `armed` = allow_exploit OU
        allow_high_impact. Non lié -> (None, False) : défère au ROE de l'engine (ne se sur-refuse pas)."""
        store = _session.current()
        scope = getattr(store, "scope", None) if store is not None else None
        if scope is None:
            return None, False
        return scope, bool(getattr(scope, "allow_exploit", False)
                           or getattr(scope, "allow_high_impact", False))

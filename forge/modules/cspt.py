"""Oracle À PREUVE du Client-Side Path Traversal (CSPT) — `cspt.redirect`.

CE QU'IL PROUVE, ET COMMENT
---------------------------
Le front concatene une valeur qu'il ne maitrise pas dans une URL d'API :

    fetch(`/api/users/${idVenantDeLURL}`)

Le navigateur normalise les `../` AVANT d'emettre la requete. Un `../../../canari` fait donc
partir un GET vers `/canari` — et il part AVEC les jetons d'authentification et anti-CSRF que
le front ajoute lui-meme. C'est ce qui en fait un contournement de CSRF (le whitepaper
CSPT2CSRF de Doyensec le montre sur Mattermost et Rocket.Chat), et non une simple traversee.
`encodeURIComponent('..') === '..'` : l'encodage ne protege pas.

LA PREUVE EST UN DIFFERENTIEL DE PROFONDEUR DE CHEMIN, pas une simple presence :

  * sonde TEMOIN    `param=<canari>`             -> requete observee vers `/api/users/<canari>`
  * sonde TRAVERSAL `param=../../../<canari>`    -> requete observee vers `/<canari>`

PREUVE = les deux requetes existent ET celle de la sonde traversal porte STRICTEMENT MOINS de
segments de chemin. C'est ce qui distingue une normalisation reelle d'un serveur qui se
contenterait de refleter la valeur. Sans le temoin, on ne saurait pas d'ou l'on est parti :
un chemin court pourrait etre le chemin normal de l'application.

POURQUOI IL FAUT LE NAVIGATEUR
-------------------------------
La normalisation des `../` est faite par le NAVIGATEUR, pas par le serveur. Aucune sonde HTTP
ne peut l'observer : `urllib` enverrait le chemin tel quel. On arme donc la capture reseau du
service navigateur gouverne, on navigue, et on lit les requetes REELLEMENT emises.

GARDES
------
  * `exploit=True` : la sonde fait emettre a l'application une requete vers un point de service
    qu'elle n'avait pas prevu. Le ROE doit exiger `allow_exploit` avant de tirer.
  * `destructive=False` : la cible du detournement est un CANARI INEXISTANT (12 hex sous un
    prefixe `forgecspt`). Il rend 404 et ne mute rien. On ne detourne JAMAIS vers un point de
    service reel de l'application — ce serait agir en son nom.
  * SCOPE fail-closed : hors perimetre -> `skipped`, aucune navigation.
  * DEGRADATION : navigateur absent ou sonde qui n'aboutit pas -> `skipped`, JAMAIS un negatif.
    Une sonde qui n'a pas abouti ne conclut pas.
  * SESSION SECRETE : la session authentifiee vit DANS le service. On ne lit d'elle aucun
    en-tete ni cookie ; l'evidence ne porte que des CHEMINS et le canari.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse

from .oracle import ScopeGuardedOracle
from .registry import register
from .. import browser_client as bc
from .. import techniques

_CANARY_PREFIX = "forgecspt"
DEFAULT_DEPTH = 3          # `../` * 3 : remonte assez pour sortir d'un prefixe /api/v1/x usuel
MAX_DEPTH = 8              # borne declaree — jamais de fan-out silencieux


def _ok(status):
    """True si le service navigateur a repondu 2xx (`browser_client` rend 0 sur erreur reseau)."""
    return bool(status) and 200 <= int(status) < 300


def canary(target, param):
    """Canari DETERMINISTE (donc rejouable) et propre a la cible : `forgecspt` + 12 hex.

    Inexistant par construction : il ne peut correspondre a aucune route de l'application, ce
    qui garantit que sa presence dans une requete vient de NOTRE sonde et de rien d'autre.
    """
    seed = "{}|{}|forge-cspt".format(target, param)
    return _CANARY_PREFIX + hashlib.sha256(seed.encode()).hexdigest()[:12]


def paths_containing(dump, token):
    """Chemins des requetes capturees qui portent `token`.

    Le schema exact de `/capture-dump` n'est pas fige : on serialise et on extrait les URL par
    motif, ce qui reste correct si le service ajoute ou renomme des champs. Defensif a dessein
    — un oracle qui casse au premier changement de schema ne sert personne.
    """
    blob = dump if isinstance(dump, str) else json.dumps(dump, ensure_ascii=False)
    out = []
    for m in re.finditer(r'https?://[^\s"\'<>\\]+', blob):
        url = m.group(0)
        if token not in url:
            continue
        path = urllib.parse.urlparse(url).path
        if path and path not in out:
            out.append(path)
    return out


def depth(path):
    """Nombre de segments non vides d'un chemin. `/a/b/c` -> 3, `/c` -> 1."""
    return len([s for s in path.split("/") if s])


# --- Enregistrement de la technique (contrat « declare-une-fois -> derive-partout ») ------------
# `cls="cspt"` : meme classe que le module de SURFACE `recon.client_sinks`, qui fournit les
# candidats. C'est `cls` qui relie l'oracle a la classe pour `coverage_gaps()` (planner.py:370).
# CWE-22 faute de CWE propre au CSPT ; l'impact reel est souvent CWE-352 (contournement de CSRF),
# ce que `fix` enonce explicitement.
techniques.register_kind(techniques._k(
    "cspt.redirect", "CSPT", True, depends_on=("recon.client_sinks",),
    cls="cspt", cwe="CWE-22", mitre="T1190", exploit=True,
    attck_tactic="Initial Access", phase="access", capability="active",
    proof_required=True))


@register("cspt.redirect")
class CsptRedirect(ScopeGuardedOracle):
    kind = "cspt.redirect"
    exploit = True               # fait emettre a l'app une requete qu'elle n'avait pas prevue
    destructive = False          # canari INEXISTANT : 404, aucun etat mute
    web_allowed = True
    available = True             # stdlib + service navigateur (teste au tir)
    category = "cspt"
    cwe = "CWE-22"
    mitre = techniques.mitre_for("cspt.redirect") or "T1190"
    tool = "forge/modules/cspt.py:cspt.redirect"
    description = ("PROUVE un Client-Side Path Traversal par DIFFERENTIEL DE PROFONDEUR : le meme "
                   "canari est envoye avec et sans `../`, et l'on compare les chemins REELLEMENT "
                   "emis par le navigateur. Preuve = le chemin de la sonde traversal porte "
                   "strictement moins de segments — la normalisation a bien eu lieu et la requete "
                   "authentifiee est partie ailleurs.")
    fix = ("Valider le segment cote CLIENT avant de le concatener dans une URL d'API (rejeter '..' "
           "et '/'), et surtout RE-VERIFIER l'autorisation cote SERVEUR sur le point de service "
           "reellement atteint : la requete detournee porte les jetons legitimes, donc une "
           "protection CSRF fondee sur le seul jeton ne la distingue pas d'une requete normale.")

    # --- seams navigateur (patchables — memes conventions que xss.execution) --------------------
    @staticmethod
    def _browser_available():
        """Seam : le service navigateur repond-il ? Absent -> degradation `skipped`."""
        return bc.health()

    @staticmethod
    def _probe(url, token, tab=bc.DEFAULT_TAB):
        """Seam : arme la capture, navigue, rend (abouti, chemins portant le canari).

        `abouti=False` -> la sonde n'a pas abouti : l'appelant NE CONCLUT PAS. C'est la
        difference entre « pas de CSPT » et « pas teste ».
        """
        bc.goto("about:blank", tab=tab, wait=0)      # document neuf : pas de capture residuelle
        st, dump = bc.xhr(url, url_contains=token, tab=tab)
        if not _ok(st):
            return False, []
        return True, paths_containing(dump, token)

    @staticmethod
    def _reset(tab=bc.DEFAULT_TAB):
        """Hygiene : ne laisse pas la page sondee chargee dans le navigateur gouverne."""
        try:
            bc.goto("about:blank", tab=tab, wait=0)
        except Exception:            # noqa: BLE001
            pass

    @staticmethod
    def _inject(base, param, value):
        """URL de sonde. PERCENT-encodage sauf pour `.` et `/` : `../` DOIT rester lisible par le
        code client. C'est tout l'interet du vecteur — `encodeURIComponent('..')` vaut deja `'..'`,
        donc l'encoder ne changerait rien pour un front conforme, mais le %2F casserait les
        implementations qui decodent une seule fois."""
        enc = param + "=" + urllib.parse.quote(value, safe="./")
        return base + ("&" if "?" in base else "?") + enc

    def dry(self, action):
        param = action.params.get("param", "id")
        d = min(int(action.params.get("depth", DEFAULT_DEPTH)), MAX_DEPTH)
        tok = canary(str(action.target), param)
        return (f"# 2 navigations sur {action.target} avec capture reseau :\n"
                f"#   temoin    {param}={tok}\n"
                f"#   traversal {param}={'../' * d}{tok}\n"
                f"# PREUVE = le chemin emis par la 2e porte STRICTEMENT MOINS de segments. "
                f"Canari INEXISTANT (404), aucun etat mute.")

    def fire(self, action):
        target = str(action.target)
        if not self._in_scope(action, target):
            return [self.skip(target=target, title="CSPT non sonde — cible hors perimetre (fail-closed)",
                              evidence="Aucune navigation emise.", poc=self.dry(action))]

        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=target, title="CSPT non sonde — parametre non fourni",
                evidence=("`params.param` est REQUIS : c'est le champ dont la valeur est concatenee "
                          "dans une URL d'API. `recon.client_sinks` fournit les candidats."),
                poc=self.dry(action))]

        if not self._browser_available():
            return [self.degraded(
                target=target, title="CSPT non verifie — service navigateur indisponible",
                evidence=("La normalisation des `../` est faite par le NAVIGATEUR : aucune sonde "
                          "HTTP ne peut l'observer. Sans lui, on ne conclut pas."),
                poc=self.dry(action))]

        d = min(max(int(action.params.get("depth", DEFAULT_DEPTH)), 1), MAX_DEPTH)
        tok = canary(target, param)

        ok_t, paths_t = self._probe(self._inject(target, param, tok), tok)
        ok_x, paths_x = self._probe(self._inject(target, param, ("../" * d) + tok), tok)
        self._reset()

        if not (ok_t and ok_x):
            return [self.degraded(
                target=target, title="CSPT non verifie — une sonde n'a pas abouti",
                evidence=f"temoin_abouti={ok_t}, traversal_abouti={ok_x} ; aucune conclusion tiree.",
                poc=self.dry(action))]

        if not paths_t:
            return [self.proof(
                target=target, proven=False, severity="INFO",
                title="Pas de CSPT — le parametre n'alimente aucune requete reseau",
                evidence=(f"Sonde temoin `{param}={tok}` : le canari n'apparait dans AUCUNE requete "
                          f"emise. Ce parametre n'est pas concatene dans une URL d'API — verifier "
                          f"le candidat fourni par `recon.client_sinks`, ou le nom du parametre."),
                poc=self.dry(action))]

        if not paths_x:
            return [self.proof(
                target=target, proven=False, severity="INFO",
                title="Pas de CSPT — la valeur traversee ne part pas",
                evidence=(f"Temoin observe sur {paths_t} ; avec `{'../' * d}` en tete, aucune requete "
                          f"ne porte le canari : la valeur est validee ou encodee avant construction "
                          f"de l'URL. C'est un vrai negatif."),
                poc=self.dry(action))]

        base_depth = min(depth(p) for p in paths_t)
        trav_depth = min(depth(p) for p in paths_x)
        if trav_depth < base_depth:
            return [self.proof(
                target=target, proven=True, severity="HIGH",
                title=(f"CSPT CONFIRME — chemin remonte de {base_depth} a {trav_depth} segment(s) "
                       f"via `{param}`"),
                evidence=(f"Sonde temoin `{param}={tok}` -> {paths_t} ({base_depth} segments). "
                          f"Sonde traversal `{param}={'../' * d}{tok}` -> {paths_x} "
                          f"({trav_depth} segments). Le navigateur a NORMALISE les `../` avant "
                          f"emission : la requete est partie vers un autre point de service, en "
                          f"portant les jetons d'authentification et anti-CSRF ajoutes par le front. "
                          f"Canari INEXISTANT (404) : aucun etat mute, aucune action au nom d'autrui. "
                          f"IMPACT A INSTRUIRE : viser un point de service reel et mutant "
                          f"transformerait ceci en CSRF (CWE-352) — a ne faire qu'avec l'accord "
                          f"explicite du programme."),
                poc=self.dry(action))]

        return [self.proof(
            target=target, proven=False, severity="INFO",
            title="Pas de CSPT — aucune remontee de chemin observee",
            evidence=(f"Temoin {paths_t} ({base_depth} segments) ; traversal {paths_x} "
                      f"({trav_depth} segments). Le chemin emis n'a pas perdu de segment : les `../` "
                      f"ont ete encodes ou neutralises avant construction de l'URL. Vrai negatif."),
            poc=self.dry(action))]

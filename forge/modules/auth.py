"""auth.takeover — oracle ATO/auth-bypass à PREUVE (T1212 / CWE-287, CWE-640).

L'« account takeover théorique » est un classique vétoé. Cet oracle exige une PREUVE concrète :
après le flux de bypass/reset (réinitialisation de mot de passe, token prévisible, confusion de
session…), on s'authentifie et on lit un endpoint « whoami » (profil/session) — si l'identité
renvoyée est celle de la VICTIME (et non celle de l'attaquant), c'est un takeover prouvé. Sinon
-> `tested` (jamais `vulnerable` sur une intuition).

Mécanique générique (data-driven, aucune cible en dur) :
  1. l'attaquant exécute l'étape de bypass (params.bypass : method/url/body/headers) — ex: POST reset ;
  2. avec la session/headers obtenus (params.attacker_session_headers, éventuellement enrichis par
     l'étape 1 via un token extrait), on GET params.whoami_url ;
  3. PREUVE = le corps whoami contient l'identifiant VICTIME (params.victim_marker) ET PAS celui de
     l'attaquant (params.attacker_marker, optionnel) -> takeover confirmé.

exploit=True (prend le contrôle du compte d'autrui) -> exige allow_exploit. destructive selon le flux
(un reset de mot de passe MUTE le compte victime) : exposé via params.destructive (défaut True pour le
reset). web_allowed via le ROE. Bâti sur la base `Oracle` (Finding + HTTP + curl partagés).
"""
import urllib.parse

from .oracle import Oracle
from .registry import register
from .. import techniques


@register("auth.takeover")
class AuthTakeover(Oracle):
    kind = "auth.takeover"
    exploit = True                       # obtient la session/identité d'autrui -> allow_exploit
    destructive = True                   # un reset/forge de credential MUTE le compte victime -> allow_destructive
    web_allowed = True
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("auth.takeover")   # source de vérité : forge/techniques.py (T1212)
    cwe = "CWE-287"                      # category + cwe des findings (via Oracle.proof/skip)
    tool = "forge/modules/auth.py:auth.takeover"
    fix = ("Renforcer l'authentification et le flux de reset : tokens de réinitialisation aléatoires "
           "(CSPRNG), à usage unique, liés au compte et à durée de vie courte ; invalider/relancer "
           "toutes les sessions après un reset ; MFA sur les actions sensibles ; ne jamais dériver "
           "l'identité d'un état contrôlable côté client (CWE-287/640).")
    description = ("Oracle ATO/auth-bypass à PREUVE : après le flux de bypass, le whoami renvoie-t-il "
                  "l'identité de la VICTIME ? Sinon tested (pas de takeover théorique). CWE-287/640.")

    @staticmethod
    def _fetch(url, headers=None, timeout=15, method="GET", data=None):
        """(status, body, headers_dict) — adosse le câblage urllib partagé (Oracle._http).
        Seam monkeypatché par les tests."""
        st, body, h = Oracle._http(url, headers=headers, timeout=timeout, method=method, data=data, maxlen=200000)
        return st, body, (dict(h) if h is not None else {})

    def dry(self, action):
        p = action.params
        bp = p.get("bypass", {})
        return (f"# 1) {str(bp.get('method', 'POST')).upper()} {bp.get('url', '<bypass>')} "
                f"(flux de bypass attaquant)\n"
                f"# 2) GET {p.get('whoami_url', '<whoami>')} avec la session attaquant\n"
                f"# PREUVE = whoami contient le marqueur VICTIME ({p.get('victim_marker', '<victime>')}) "
                f"-> takeover ; sinon tested")

    def fire(self, action):
        p = action.params
        whoami = p.get("whoami_url")
        victim = p.get("victim_marker")
        sess = dict(p.get("attacker_session_headers", {}))
        if not whoami or not victim:
            return [self.skip(
                target=action.target, title="ATO non testé — config manquante",
                evidence=("Requiert params.whoami_url (endpoint profil/session) et params.victim_marker "
                          "(identifiant unique de la victime attendu dans le whoami). "
                          "Optionnel : params.bypass (étape de bypass), params.attacker_marker."),
                poc=self.dry(action))]
        # le flag destructif réel suit le flux : un GET-only n'est pas destructif, un reset l'est.
        # On NE modifie PAS self.destructive (déclaration de capacité, lue par le ROE avant fire) — c'est
        # le module qui est gardé `destructive=True` par prudence (un reset MUTE la victime).
        bp = p.get("bypass")
        if bp and bp.get("url"):
            self._fetch(bp["url"], headers=bp.get("headers", {}),
                        method=str(bp.get("method", "POST")).upper(),
                        data=(urllib.parse.urlencode(bp["body"]) if isinstance(bp.get("body"), dict)
                              else bp.get("body")))
        ws, wbody, _ = self._fetch(whoami, headers=sess)
        attacker = p.get("attacker_marker")
        # PREUVE NETTE : whoami accordé (2xx), contient le marqueur VICTIME, et — si fourni — PAS celui
        # de l'attaquant (sinon on regarde juste sa propre session : faux positif classique).
        is_victim = (ws in (200, 206) and victim in (wbody or "")
                     and (attacker is None or attacker not in (wbody or "")))
        return [self.proof(
            target=whoami, proven=is_victim,
            title=("ATO CONFIRMÉ — la session attaquant lit l'identité de la VICTIME"
                   if is_victim else "ATO non confirmé — whoami ne renvoie pas l'identité victime"),
            severity=("CRITICAL" if is_victim else "INFO"),
            evidence=(f"whoami HTTP {ws} ; victim_marker_présent={victim in (wbody or '')} ; "
                      f"attacker_marker_absent={attacker is None or attacker not in (wbody or '')} "
                      f"(extrait={(wbody or '')[:120]!r})"),
            poc=self._curl(whoami, sess))]

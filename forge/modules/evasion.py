"""Modules d'évasion — atteindre les cibles derrière Cloudflare/WAF via browser-automation.

Le plus gros déblocage offensif réel : beaucoup de programmes ne tiennent que sur Cloudflare/
WAF qui bloque curl. Ces modules parlent au service browser-automation (port 8080) :
  - evasion.xhr            : OBSERVATION des requêtes via la session browser (capture-start/dump). exploit=False
  - evasion.turnstile      : franchir le Turnstile interactif (vision-click-os). exploit=False (enabler d'accès)
  - evasion.idor_intercept : arme l'interception IDOR via intercept-modify (preuve via /intercept-dump). exploit=True

Auto-neutralisation (`available`) si le service ne répond pas. Tout reste gaté par le ROE.
Rappel : passer Cloudflare ≠ une faille — c'est un enabler à chaîner vers un impact (IDOR/ATO).
"""
import time

from .registry import register, Module
from .. import browser_client as bc


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
    kind = "evasion.turnstile"
    exploit = False                              # franchir une case ≠ exploit ; enabler d'accès
    mitre = "T1556"
    description = ("Franchit le Cloudflare Turnstile interactif via vision-click-os "
                  "(détection template + clic OS X11) — enabler d'accès.")

    def dry(self, action):
        return (f"POST {bc.base_url()}/goto {{url:{action.target}}} ; "
                f"POST /vision-click-os {{strategy:turnstile}}   # 1 essai, IP propre")

    def fire(self, action):
        bc.goto(action.target, tab=action.params.get("tab", bc.DEFAULT_TAB))
        st, resp = bc.vision_click_os(strategy=action.params.get("strategy", "turnstile"),
                                      threshold=action.params.get("threshold", 0.55),
                                      tab=action.params.get("tab", bc.DEFAULT_TAB))
        return [self.finding(
            target=action.target, title="Tentative de franchissement Turnstile (vision-click-os)",
            severity="INFO", category="access", mitre="T1556", status="tested",
            tool="browser-automation:/vision-click-os", evidence=str(resp)[:1500], poc=self.dry(action))]


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

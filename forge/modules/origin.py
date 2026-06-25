"""origin.find — trouver l'IP d'origine derrière un CDN/WAF (porté de secpipe/origin_detection).

Le gros levier : si l'origine réelle est joignable hors-Cloudflare, on contourne TOUT le WAF.
Pipeline : subfinder (sous-domaines) → résolution DNS → drop des IP en plage Cloudflare →
VÉRIFICATION (httpx avec en-tête Host) que l'IP sert bien le site AVANT de flaguer HIGH.

Ce module incarne le pattern d'or de secpipe : « pas de finding sans preuve » (vérifier
l'exploitabilité avant d'élever la sévérité) → évite les findings aspirationnels que les
règles du workspace vétoent. exploit=False (découverte). Réseau -> gaté par le ROE.

SÛRETÉ — re-validation fail-closed du périmètre : un sous-domaine peut résoudre vers une IP
hors-scope (infra tierce/mutualisée/takeover). Le ROE gate le DOMAINE de l'action, pas les IP
résolues à runtime. AVANT chaque connexion httpx, on revérifie `Scope.is_in_scope(ip)` (le
scope est injecté dans action.params par l'engine, miroir de l'injection IDOR engine.py:130-134).
Une IP hors-scope -> finding INFO, AUCUNE connexion. Pas de scope dans les params -> fail-closed
(rien n'est en scope), on ne connecte pas : on n'élargit jamais le périmètre par omission.
"""
import socket

from .registry import register, Module
from .. import runner
from ..roe import Scope

# sous-ensemble des plages Cloudflare (dérive dans le temps — rafraîchir périodiquement)
CF_RANGES = [
    "104.16.0.0/12", "172.64.0.0/13", "131.0.72.0/22", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "173.245.48.0/20", "103.21.244.0/22", "141.101.64.0/18",
]


def _in_cf(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(c) for c in CF_RANGES)


@register("origin.find")
class OriginFind(Module):
    kind = "origin.find"
    exploit = False
    mitre = "T1590.005"
    description = ("Trouve l'IP d'origine derrière un CDN/WAF (subfinder→DNS→drop-CF→"
                  "vérif Host-header) — bypass WAF si l'origine est joignable.")
    SUB, SUB_IMG = "subfinder", "projectdiscovery/subfinder"
    HX, HX_IMG = "httpx", "projectdiscovery/httpx"

    @property
    def available(self):
        return (runner.available(self.SUB, self.SUB_IMG, prefer_docker=True)
                and runner.available(self.HX, self.HX_IMG, prefer_docker=True))

    def dry(self, action):
        return (f"subfinder -d {action.target} -silent | resolve | drop-CF | "
                f"httpx -H 'Host: {action.target}' (vérifie l'origine avant flag HIGH)")

    def fire(self, action):
        domain = action.target
        # Scope reconstruit depuis les params injectés par l'engine (miroir IDOR engine.py:130-134).
        # Quand le scope EST fourni (chemin de production : l'engine injecte TOUJOURS in_scope/out_scope),
        # on applique un filtre FAIL-CLOSED sur chaque IP résolue : in_scope vide => is_in_scope()==False
        # => aucune connexion. `enforce` distingue « scope fourni » de « module appelé en direct sans
        # scope » (dev/test) — le seul chemin qui touche le réseau est l'engine, qui injecte toujours.
        enforce = "in_scope" in action.params or "out_scope" in action.params
        guard = Scope({"in_scope": action.params.get("in_scope", []),
                       "out_scope": action.params.get("out_scope", [])})
        rc, out, err = runner.tool(self.SUB, self.SUB_IMG, ["-d", domain, "-silent"], timeout=120, prefer_docker=True)
        failed = self.tool_failed(action, rc, out, err, "subfinder", category="origin-exposure")
        if failed:
            return [failed]
        subs = [s.strip() for s in (out or "").splitlines() if s.strip()] or [domain]

        seen, candidates = set(), []
        for s in subs:
            try:
                ip = socket.gethostbyname(s)
            except OSError:
                continue
            if ip in seen or _in_cf(ip):
                continue
            seen.add(ip)
            candidates.append((s, ip))

        findings = []
        for s, ip in candidates:
            # FAIL-CLOSED : l'IP résolue est-elle bien dans le périmètre autorisé ? Un sous-domaine
            # peut pointer vers de l'infra tierce/mutualisée -> on ne s'y connecte JAMAIS. Finding INFO,
            # on passe à la candidate suivante (jamais de httpx hors-scope).
            if enforce and not guard.is_in_scope(ip):
                findings.append(self.finding(
                    target=ip,
                    title="IP résolue HORS-SCOPE — connexion refusée (fail-closed)",
                    severity="INFO", category="origin-exposure", mitre="T1590.005",
                    status="tested", tool="subfinder",
                    evidence=(f"{s} -> {ip} hors du périmètre autorisé (in_scope) — "
                              f"aucune requête httpx émise (infra tierce/mutualisée possible)."),
                    poc=f"# {ip} hors-scope : ne pas connecter ; ajouter au scope si autorisé"))
                continue
            # VÉRIFICATION avant flag : l'IP sert-elle le site avec l'en-tête Host ?
            rc2, vo, ve = runner.tool(self.HX, self.HX_IMG,
                                      ["-u", f"http://{ip}", "-H", f"Host: {domain}",
                                       "-status-code", "-silent", "-no-color"], timeout=30, prefer_docker=True)
            verified = any(code in (vo or "") for code in ("[200]", "[301]", "[302]", "[403]"))
            # Distinguer l'échec d'outil (httpx indisponible/timeout) d'un vrai négatif : un rc2!=0
            # sans hit n'est PAS la preuve que l'origine ne sert pas le site — on ne flague pas HIGH,
            # mais on étiquette explicitement « verif non concluante » sans interrompre la boucle.
            tool_ko = (rc2 != 0 and not verified)
            findings.append(self.finding(
                target=ip,
                title=("Origine exposée derrière CDN (VÉRIFIÉE) — bypass WAF" if verified
                       else "IP hors-CDN — verif non concluante: httpx indisponible/timeout" if tool_ko
                       else "IP hors-CDN (origine non confirmée)"),
                severity=("HIGH" if verified else "INFO"),
                category="origin-exposure", mitre="T1590.005",
                status=("vulnerable" if verified else "tested"),
                tool="subfinder+httpx",
                evidence=(f"{s} -> {ip} ; host-header check={verified} ; "
                          + (f"verif non concluante (rc={rc2}): {((ve or vo) or '').strip()[:200]}"
                             if tool_ko else (vo or "").strip()[:200])),
                poc=f"curl -sI -H 'Host: {domain}' http://{ip}"))
        if not findings:
            findings.append(self.finding(
                target=domain, title="Aucune origine hors-CDN trouvée", severity="INFO",
                category="origin-exposure", status="tested", tool="subfinder+httpx", poc=self.dry(action)))
        return findings

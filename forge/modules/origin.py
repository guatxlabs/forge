"""origin.find — trouver l'IP d'origine derrière un CDN/WAF (porté de secpipe/origin_detection).

Le gros levier : si l'origine réelle est joignable hors-Cloudflare, on contourne TOUT le WAF.
Pipeline : candidats d'hôtes (subfinder + PRÉFIXES PASSIFS révélateurs d'origine) → résolution DNS →
drop des IP en plage Cloudflare → VÉRIFICATION (httpx avec en-tête Host) que l'IP sert bien le site
AVANT de flaguer HIGH.

STRENGTHEN (reachability autorisée, méthodes PASSIVES / low-noise) : au-delà des sous-domaines de
subfinder, on ajoute une liste de PRÉFIXES couramment révélateurs de l'origine (`origin.`, `direct.`,
`cpanel.`, `mail.`, `dev.`, `staging.`…) + le domaine nu. Ce sont de simples CANDIDATS de chaînes
(génération hors-ligne, ZÉRO scan actif) résolus par le MÊME seam DNS (socket.gethostbyname) — donc
low-noise. Un IP hors-CF vers lequel PLUSIEURS hôtes convergent est un candidat d'origine plus solide
(compte de convergence dans l'evidence). Cela élargit la découverte sans bruit actif ni élargissement
de périmètre : chaque IP résolue reste RE-VALIDÉE fail-closed contre le scope avant toute connexion.

Ce module incarne le pattern d'or de secpipe : « pas de finding sans preuve » (vérifier
l'exploitabilité avant d'élever la sévérité) → évite les findings aspirationnels que les
règles du workspace vétoent. exploit=False (découverte). Réseau -> gaté par le ROE.

DÉGRADATION GRACIEUSE : subfinder indisponible/en échec (rc!=0) -> finding `status='skipped'`
(offline-safe), on ne tente PAS de résolution DNS passive à sa place (éviterait le seam et
frapperait le réseau réel). httpx indisponible/timeout sur une candidate -> finding `skipped`
(verif non concluante), jamais de faux HIGH.

SÛRETÉ — re-validation fail-closed du périmètre : un sous-domaine peut résoudre vers une IP
hors-scope (infra tierce/mutualisée/takeover). Le ROE gate le DOMAINE de l'action, pas les IP
résolues à runtime. AVANT chaque connexion httpx, on revérifie `Scope.is_in_scope(ip)` (le
scope est injecté dans action.params par l'engine, miroir de l'injection IDOR engine.py:130-134).
Une IP hors-scope -> finding INFO, AUCUNE connexion. Pas de scope dans les params -> fail-closed
(rien n'est en scope), on ne connecte pas : on n'élargit jamais le périmètre par omission.
"""
import re
import socket

from .registry import register, Module
from .. import runner
from ..roe import Scope
from .toolspec import check_extra_args, safe_value

# sous-ensemble des plages Cloudflare (dérive dans le temps — rafraîchir périodiquement)
CF_RANGES = [
    "104.16.0.0/12", "172.64.0.0/13", "131.0.72.0/22", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "173.245.48.0/20", "103.21.244.0/22", "141.101.64.0/18",
]

# Préfixes de sous-domaine couramment révélateurs de l'IP d'origine (bypass CDN). PASSIF : on ne fait
# que GÉNÉRER des noms d'hôtes candidats (résolus ensuite par le seam DNS) — aucun scan actif.
ORIGIN_PREFIXES = (
    "origin", "origin-www", "www-origin", "direct", "direct-connect", "cpanel", "whm",
    "webmail", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh", "vpn", "remote",
    "dev", "development", "staging", "stage", "test", "uat", "preprod", "old", "legacy",
    "backend", "api", "internal", "portal", "admin", "cdn-origin", "server", "host",
)


def _in_cf(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(c) for c in CF_RANGES)


def _passive_candidates(domain):
    """Hôtes candidats PASSIFS (génération de chaînes, ZÉRO réseau) : domaine nu + préfixes
    couramment révélateurs d'origine. Résolus ensuite via le même seam DNS (socket.gethostbyname)."""
    return [domain] + [f"{p}.{domain}" for p in ORIGIN_PREFIXES]


# M7 — corrélation de CONTENU. Un code de statut seul (surtout 403) ne prouve PAS qu'une IP sert le site :
# vhost par défaut, shared-hosting, WAF deny-by-default renvoient couramment 200/403 à un Host arbitraire.
# On EXIGE une corrélation de contenu positive (title normalisé identique à la baseline CDN) avant de
# promouvoir un finding en HIGH/vulnerable. Ces helpers parsent la sortie httpx (`-status-code -title`).
_HTTPX_BRACKET = re.compile(r"\[([^\]]*)\]")
_STATUS_RE = re.compile(r"\d{3}(?:,\d{3})*")


def _httpx_fields(text):
    """Extrait (status, title) de la 1re ligne httpx `-status-code -title -silent -no-color`
    (ex. `http://1.2.3.4 [200] [Example Domain]`). Le premier groupe `[...]` purement numérique est
    le statut (1er code si chaîne de redirections `[301,200]`) ; le premier groupe non numérique est le
    title. Champs absents -> chaînes vides. PURE, sans réseau."""
    raw = (text or "").strip()
    line = raw.splitlines()[0] if raw else ""
    status, title = "", ""
    for g in _HTTPX_BRACKET.findall(line):
        gg = g.strip()
        if not gg:
            continue
        if _STATUS_RE.fullmatch(gg):
            if not status:
                status = gg.split(",")[0]
        elif not title:
            title = gg
    return status, title


def _norm_title(t):
    """Normalise un title pour comparaison : espaces compactés + casefold. Vide -> ''."""
    return " ".join((t or "").split()).casefold()


@register("origin.find")
class OriginFind(Module):
    kind = "origin.find"
    exploit = False
    mitre = "T1590.005"
    description = ("Trouve l'IP d'origine derrière un CDN/WAF (subfinder + préfixes passifs → DNS → "
                  "drop-CF → vérif Host-header) — bypass WAF si l'origine est joignable. Params UI : "
                  "sources (-sources), timeout (-timeout), rate (-rl), extra_args (allowlist) — tunent subfinder.")
    SUB, SUB_IMG = "subfinder", "projectdiscovery/subfinder"
    HX, HX_IMG = "httpx", "projectdiscovery/httpx"

    # SCHÉMA servi à l'UI — tune l'énumération subfinder de l'étape 1. Rendu par modules-form.js.
    PARAMS_SCHEMA = [
        {"name": "sources", "type": "text", "label": "sources subfinder (-sources)", "flag": "-sources"},
        {"name": "timeout", "type": "number", "label": "timeout par source (-timeout s)", "flag": "-timeout"},
        {"name": "rate", "type": "number", "label": "rate-limit subfinder (-rl req/s)", "flag": "-rl"},
        {"name": "extra_args", "type": "list", "label": "extra args subfinder (allowlist)", "flag": ""},
    ]
    # ALLOWLIST des drapeaux subfinder acceptés en argument libre — tout flag hors liste est REFUSÉ.
    # EXCLUS : -o/-oJ/-oD (écriture fichier), -config/-pc (lecture fichier de config/provider arbitraire).
    FLAG_ALLOWLIST = ("-all", "-recursive", "-nW", "-sources", "-rl", "-timeout", "-max-time", "-silent")

    @property
    def available(self):
        return (runner.available(self.SUB, self.SUB_IMG, prefer_docker=True)
                and runner.available(self.HX, self.HX_IMG, prefer_docker=True))

    def _subfinder_args(self, domain, params):
        """Argv subfinder de l'étape 1 : défaut `-d <domain> -silent` (BYTE-IDENTIQUE sans params) +
        knobs optionnels (sources/timeout/rate) + extra_args VALIDÉS (le gate fire() refuse en amont)."""
        p = params or {}
        argv = ["-d", domain, "-silent"]
        sources = p.get("sources")
        if sources is not None and safe_value(str(sources)):
            argv += ["-sources", str(sources)]
        timeout = p.get("timeout")
        if timeout not in (None, "") and safe_value(str(timeout)):
            argv += ["-timeout", str(timeout)]
        rate = p.get("rate")
        if rate not in (None, "") and safe_value(str(rate)):
            argv += ["-rl", str(rate)]
        _, extra = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)
        return argv + extra

    def dry(self, action):
        return (f"subfinder -d {action.target} -silent + préfixes passifs (origin./direct./cpanel.…) "
                f"| resolve | drop-CF | httpx -H 'Host: {action.target}' (vérifie l'origine avant flag HIGH)")

    def _skipped(self, action, title, evidence):
        """Dégradation gracieuse : outil (subfinder/httpx) ou réseau indisponible -> finding
        INFO `status='skipped'` (offline-safe), jamais de crash ni de faux positif."""
        return self.finding(
            target=action.target, title=title, severity="INFO", category="origin-exposure",
            mitre="T1590.005", status="skipped", tool="subfinder+httpx",
            evidence=(evidence or "")[:500], poc=self.dry(action))

    def fire(self, action):
        domain = action.target
        # EXTRA_ARGS gouvernés : un drapeau subfinder libre hors allowlist (ou non-liste) -> refus fail-closed.
        bad_extra, _ = check_extra_args(action.params.get("extra_args"), self.FLAG_ALLOWLIST)
        if bad_extra is not None:
            return [self._skipped(action, f"origin.find non exécuté — argument libre refusé ({bad_extra})",
                                  "Aucun processus lancé (fail-closed).")]
        # Scope reconstruit depuis les params injectés par l'engine (miroir IDOR engine.py:130-134).
        # Quand le scope EST fourni (chemin de production : l'engine injecte TOUJOURS in_scope/out_scope),
        # on applique un filtre FAIL-CLOSED sur chaque IP résolue : in_scope vide => is_in_scope()==False
        # => aucune connexion. `enforce` distingue « scope fourni » de « module appelé en direct sans
        # scope » (dev/test) — le seul chemin qui touche le réseau est l'engine, qui injecte toujours.
        enforce = "in_scope" in action.params or "out_scope" in action.params
        guard = Scope({"in_scope": action.params.get("in_scope", []),
                       "out_scope": action.params.get("out_scope", [])})
        rc, out, err = runner.tool(self.SUB, self.SUB_IMG, self._subfinder_args(domain, action.params),
                                   timeout=120, prefer_docker=True)
        # DÉGRADATION : subfinder indisponible/en échec -> skipped. On NE bascule PAS en résolution DNS
        # passive « à sa place » : cela frapperait le réseau réel hors du seam d'énumération (et
        # masquerait la panne). Le module se neutralise proprement (offline-safe).
        if rc != 0:
            reason = {127: "outil indisponible", 124: "timeout"}.get(rc, f"échec (rc={rc})")
            return [self._skipped(action, f"subfinder — {reason}",
                                  ((err or out) or "").strip() or reason)]
        subs = [s.strip() for s in (out or "").splitlines() if s.strip()] or [domain]

        # STRENGTHEN : fusionne les sous-domaines subfinder + les candidats PASSIFS révélateurs
        # d'origine (génération hors-ligne). Dédup des noms d'hôtes en préservant l'ordre (subfinder
        # d'abord). Chaque hôte est ensuite résolu par le seam DNS et re-validé fail-closed.
        hostnames, seen_h = [], set()
        for h in list(subs) + _passive_candidates(domain):
            h = h.strip().casefold()
            if h and h not in seen_h:
                seen_h.add(h)
                hostnames.append(h)

        seen_ip, candidates, ip_sources = set(), [], {}
        for s in hostnames:
            try:
                ip = socket.gethostbyname(s)
            except OSError:
                continue
            ip_sources.setdefault(ip, []).append(s)          # convergence : combien d'hôtes -> cet IP
            if ip in seen_ip or _in_cf(ip):
                continue
            seen_ip.add(ip)
            candidates.append((s, ip))

        # M7 — BASELINE CDN de corrélation de contenu : title du site tel que SERVI PAR LE CDN. Une IP
        # candidate n'est promue HIGH que si SON contenu (title) MATCHE cette baseline. Résolue PARESSEUSE-
        # MENT (None -> fetch au 1er candidat IN-SCOPE réellement vérifié) pour ne JAMAIS émettre de requête
        # si aucun candidat ne passe le scope-guard. Baseline vide/indisponible => aucune corrélation
        # possible => AUCUN HIGH (fail-closed : on préfère un faux négatif à un faux HIGH).
        base_title = None                                     # None = pas encore résolue (lazy)

        def _baseline_title():
            nonlocal base_title
            if base_title is None:
                rcb, bo, _be = runner.tool(self.HX, self.HX_IMG,
                                           ["-u", f"http://{domain}", "-title", "-status-code",
                                            "-silent", "-no-color"], timeout=30, prefer_docker=True)
                _bt = _httpx_fields(bo or "")[1] if rcb == 0 else ""
                base_title = _norm_title(_bt)
            return base_title

        findings = []
        for s, ip in candidates:
            converge = len(ip_sources.get(ip, [s]))           # nb d'hôtes convergeant vers cet IP (confiance)
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
            # VÉRIFICATION avant flag : l'IP sert-elle le site avec l'en-tête Host ? On demande AUSSI le
            # title (`-title`) pour la corrélation de contenu M7.
            rc2, vo, ve = runner.tool(self.HX, self.HX_IMG,
                                      ["-u", f"http://{ip}", "-H", f"Host: {domain}",
                                       "-status-code", "-title", "-silent", "-no-color"], timeout=30, prefer_docker=True)
            ip_status, ip_title = _httpx_fields(vo or "")
            # M7 — 403 RETIRÉ du set « joignable » (un WAF deny-by-default le renvoie à tout Host : jamais
            # une preuve). Seuls 200/301/302 comptent comme joignables.
            reachable = ip_status in ("200", "301", "302")
            # M7 — CORRÉLATION DE CONTENU : promotion HIGH SEULEMENT si le title de l'IP MATCHE la baseline
            # CDN (non vide des deux côtés). Un match de statut seul ne suffit plus.
            base = _baseline_title()
            content_ok = bool(base) and _norm_title(ip_title) == base
            verified = reachable and content_ok
            reachable_only = reachable and not content_ok      # joignable mais contenu NON corrélé
            # Distinguer l'échec d'outil (httpx indisponible/timeout) d'un vrai négatif : un rc2!=0
            # sans statut joignable n'est PAS la preuve que l'origine ne sert pas le site — pas de HIGH.
            # DÉGRADATION : verif non concluante par outil indisponible -> `status='skipped'`.
            tool_ko = (rc2 != 0 and not reachable)
            if verified:
                sev, st = "HIGH", "vulnerable"
                title = "Origine exposée derrière CDN (VÉRIFIÉE, contenu corrélé) — bypass WAF"
            elif reachable_only:
                # joignable mais aucune corrélation de contenu -> NE PAS promouvoir en HIGH (M7). MEDIUM :
                # piste à confirmer manuellement (vhost par défaut / shared-hosting / WAF non exclus).
                sev, st = "MEDIUM", "tested"
                title = "IP hors-CDN joignable — contenu NON corrélé à la baseline (origine NON confirmée)"
            elif tool_ko:
                sev, st = "INFO", "skipped"
                title = "IP hors-CDN — verif non concluante: httpx indisponible/timeout"
            else:
                sev, st = "INFO", "tested"
                title = "IP hors-CDN (origine non confirmée)"
            findings.append(self.finding(
                _proven=bool(verified),                  # PREUVE concrète (statut joignable + contenu corrélé)
                target=ip,
                title=title,
                severity=sev,
                category="origin-exposure", mitre="T1590.005",
                fix=("Restreindre l'accès à l'IP d'origine au seul CDN/WAF : allowlist des plages IP du "
                     "fournisseur (ex: Cloudflare) au niveau pare-feu/groupe de sécurité et refuser tout "
                     "trafic direct, afin de rendre l'origine non joignable hors du CDN (et de fermer le "
                     "contournement de WAF)."),
                status=st,
                tool="subfinder+httpx",
                evidence=(f"{s} -> {ip} (convergence: {converge} hôte(s)) ; statut={ip_status or 'n/a'} "
                          f"joignable={reachable} ; title-match baseline={content_ok} "
                          f"(ip_title={ip_title!r}) ; "
                          + (f"verif non concluante (rc={rc2}): {((ve or vo) or '').strip()[:160]}"
                             if tool_ko else (vo or "").strip()[:160])),
                poc=f"curl -sI -H 'Host: {domain}' http://{ip}"))
        if not findings:
            findings.append(self.finding(
                target=domain, title="Aucune origine hors-CDN trouvée", severity="INFO",
                category="origin-exposure", status="tested", tool="subfinder+httpx", poc=self.dry(action)))
        return findings

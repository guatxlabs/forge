"""web.security_headers — oracle d'AUDIT des en-têtes HTTP de sécurité (durcissement).

Une revue manuelle de la console Forge a montré que des en-têtes de durcissement manquaient et
qu'aucun scanner générique (nuclei medium+, ni même toutes sévérités) ne le signalait, et qu'AUCUN
module Forge dédié ne le couvrait. Ce module comble ce trou : il récupère la réponse HTTP de la cible
et émet un finding INFORMATIF par en-tête manquant / faible.

DISCIPLINE DE PREUVE (comme les autres modules Forge) : une observation de configuration est un fait
`tested` (INFO/LOW), JAMAIS `vulnerable`. Il n'y a pas d'exploitation ici — c'est de la cartographie
de durcissement. exploit=False, destructive=False, web_allowed=True (gardé par le ROE), available=True
(urllib stdlib -> toujours disponible). Bâti sur la base `ScopeGuardedOracle` : scope-guard fail-closed
natif + dégradation gracieuse (`skipped`) quand le réseau est indisponible — on ne signale JAMAIS « tous
les en-têtes manquants » sur un échec réseau (ce serait un faux positif massif).

Contrôles (un finding par écart) :
  - Content-Security-Policy absent (INFO) — note si présent SEULEMENT en `<meta>` (plus faible) ;
  - clickjacking : X-Frame-Options absent ET CSP sans `frame-ancestors` (LOW) ;
  - X-Content-Type-Options: nosniff absent (INFO) ;
  - Referrer-Policy absent (INFO) ;
  - Strict-Transport-Security absent — UNIQUEMENT sur cible HTTPS (INFO ; N/A en http clair) ;
  - Permissions-Policy absent (INFO) ;
  - Set-Cookie sans Secure / HttpOnly / SameSite — par cookie (LOW) ;
  - fuite de version Server / X-Powered-By (INFO).
"""
from ._scopeguard import web_url_candidates
from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import techniques


@register("web.security_headers")
class SecurityHeaders(ScopeGuardedOracle):
    kind = "web.security_headers"
    exploit = False                      # observation de configuration : aucune exploitation
    destructive = False                  # lecture seule (un GET)
    web_allowed = True                   # interaction réseau -> gardée par le ROE
    available = True                     # urllib stdlib -> toujours disponible
    mitre = techniques.mitre_for("web.security_headers")   # source de vérité : forge/techniques.py
    cwe = "CWE-693"                      # Protection Mechanism Failure (umbrella en-têtes manquants)
    tool = "forge/modules/security_headers.py:web.security_headers"
    fix = ("Configurer les en-têtes de réponse de sécurité au niveau du serveur / reverse-proxy : "
           "Content-Security-Policy, X-Frame-Options (ou CSP frame-ancestors), "
           "X-Content-Type-Options: nosniff, Referrer-Policy, Strict-Transport-Security (HTTPS), "
           "Permissions-Policy, et flags de cookie Secure/HttpOnly/SameSite (CWE-693).")
    description = ("Audit des en-têtes HTTP de sécurité (CSP, X-Frame-Options, nosniff, Referrer-Policy, "
                  "HSTS sur https, Permissions-Policy) et des cookies non sécurisés (Secure/HttpOnly/"
                  "SameSite). Émet un finding INFO/LOW par écart, status=tested (jamais vulnerable). CWE-693.")

    # SCHÉMA servi à l'UI (source unique) — rendu par modules-form.js via `forge modules --json`.
    PARAMS_SCHEMA = [
        {"name": "host", "type": "text", "label": "Host header (override anti-rebinding, ex localhost)"},
    ]

    # --- seam réseau (monkeypatché par les tests) : (status, body, headers) ---
    @staticmethod
    def _fetch(url, headers=None, timeout=15):
        """(status, body, headers) — adosse le câblage urllib partagé (Oracle._http). `headers` est
        l'objet HTTPMessage brut (accès insensible à la casse + get_all pour Set-Cookie multiples), ou
        None sur échec réseau. Le seam est GET (les en-têtes de réponse portent toute la preuve)."""
        st, body, h = Oracle._http(url, headers=headers, timeout=timeout, method="GET", maxlen=200000)
        return st, body, h

    @staticmethod
    def _url_for(action):
        """URL HTTP la plus vraisemblable à sonder pour la cible (hôte nu / host:port / URL déjà formée).
        Délègue au helper de normalisation partagé (jamais de cible sans scheme passée à urllib). Une URL
        déjà formée est renvoyée telle quelle (PoC byte-identique)."""
        cands = web_url_candidates(action.target)
        return cands[0] if cands else str(action.target)

    def _curl(self, action, url):
        host = (action.params or {}).get("host")
        h = f" -H 'Host: {host}'" if host else ""
        return (f"curl -sSI{h} '{url}'  "
                f"# lire les en-têtes de sécurité (CSP/X-Frame-Options/nosniff/Referrer-Policy/HSTS/"
                f"Permissions-Policy) + flags de cookie")

    def dry(self, action):
        return self._curl(action, self._url_for(action))

    # --- helpers d'analyse (purs) ---
    @staticmethod
    def _hget(headers, name):
        """Valeur d'un en-tête (insensible à la casse), '' si absent/illisible. Ne lève jamais."""
        if headers is None:
            return ""
        try:
            return (headers.get(name) or "").strip()
        except Exception:            # noqa: BLE001
            return ""

    @staticmethod
    def _cookies(headers):
        """Liste des valeurs Set-Cookie (toutes, pas seulement la 1re). [] si aucune. Ne lève jamais."""
        if headers is None:
            return []
        try:
            return [c for c in headers.get_all("Set-Cookie") or [] if c]
        except Exception:            # noqa: BLE001
            v = SecurityHeaders._hget(headers, "Set-Cookie")
            return [v] if v else []

    def _gap(self, action, title, severity, evidence, cwe, poc=None):
        """Finding d'ÉCART de durcissement — status='tested' (fait de config, jamais 'vulnerable').
        Estampille cwe (par-écart), mitre/tool/fix du module, et le PoC curl rejouable. `poc` (l'URL
        RÉELLEMENT sondée) est fourni par fire() ; à défaut on retombe sur `dry()` (candidat le + probable)."""
        return self.finding(
            target=action.target, title=title, severity=severity,
            category=cwe, cwe=cwe, mitre=self.mitre, status="tested",
            tool=self.tool, fix=self.fix, evidence=evidence,
            poc=poc if poc is not None else self.dry(action))

    def fire(self, action):
        # SCOPE-GUARD fail-closed (défense en profondeur ; l'engine gate déjà en amont).
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]

        req_headers = dict((action.params or {}).get("headers", {}))
        host = (action.params or {}).get("host")
        if host:
            req_headers.setdefault("Host", host)          # override anti-rebinding (ex Host: localhost)

        # NORMALISATION : une cible hôte nu / host:port n'a PAS de scheme -> la passer telle quelle à
        # urllib lèverait `unknown url type`. On essaie les candidats (http/https ordonnés par
        # vraisemblance, cf. web_url_candidates) et on GARDE la 1re réponse. Une URL déjà formée n'a
        # qu'un candidat (byte-identique). AUCUN candidat joignable -> dégradation `skipped` visible.
        candidates = web_url_candidates(action.target) or [str(action.target)]
        url = candidates[0]
        st = body = headers = None
        for cand in candidates:
            st, body, headers = self._fetch(cand, headers=req_headers or None)
            url = cand
            if st is not None:
                break
        poc = self._curl(action, url)

        # ÉCHEC RÉSEAU : status None (transport mort) -> dégradation gracieuse, JAMAIS « tout manquant ».
        if st is None:
            return [self.degraded(
                target=action.target,
                title=f"{self.kind} non testé — réponse HTTP indisponible",
                evidence="Aucune réponse HTTP (réseau/transport indisponible) ; audit des en-têtes impossible.",
                poc=poc)]

        # `gap` LIE le PoC (l'URL réellement sondée) à chaque finding d'écart émis ci-dessous.
        def gap(title, severity, evidence, cwe):
            return self._gap(action, title, severity, evidence, cwe, poc=poc)

        is_https = str(url).lower().startswith("https://")
        body = body or ""
        csp = self._hget(headers, "Content-Security-Policy")
        xfo = self._hget(headers, "X-Frame-Options")
        xcto = self._hget(headers, "X-Content-Type-Options")
        refpol = self._hget(headers, "Referrer-Policy")
        hsts = self._hget(headers, "Strict-Transport-Security")
        permpol = self._hget(headers, "Permissions-Policy")
        server = self._hget(headers, "Server")
        powered = self._hget(headers, "X-Powered-By")
        csp_low = csp.lower()
        findings = []

        # 1) Content-Security-Policy — INFO. Note si présent SEULEMENT en <meta> (plus faible que l'en-tête).
        if not csp:
            meta = ("http-equiv" in body.lower()
                    and "content-security-policy" in body.lower())
            note = (" (présent uniquement en <meta http-equiv> — plus faible : ignoré pour "
                    "frame-ancestors et par certains agents)") if meta else ""
            findings.append(gap(
                f"Content-Security-Policy absent{' (meta seulement)' if meta else ''}", "INFO",
                f"En-tête HTTP Content-Security-Policy absent{note}. HTTP {st}.", "CWE-693"))

        # 2) Clickjacking — X-Frame-Options absent ET CSP sans frame-ancestors -> LOW.
        if not xfo and "frame-ancestors" not in csp_low:
            findings.append(gap(
                "Clickjacking — X-Frame-Options absent (et pas de CSP frame-ancestors)", "LOW",
                f"X-Frame-Options absent et CSP ne contient pas 'frame-ancestors' (HTTP {st}) : "
                f"la page peut être enframée (clickjacking).", "CWE-1021"))

        # 3) X-Content-Type-Options: nosniff — INFO.
        if xcto.lower() != "nosniff":
            findings.append(gap(
                "X-Content-Type-Options: nosniff absent", "INFO",
                f"X-Content-Type-Options != 'nosniff' (valeur observée: {xcto or 'absent'!r}, HTTP {st}) : "
                f"MIME sniffing possible.", "CWE-693"))

        # 4) Referrer-Policy — INFO.
        if not refpol:
            findings.append(gap(
                "Referrer-Policy absent", "INFO",
                f"En-tête Referrer-Policy absent (HTTP {st}) : fuite potentielle du Referer complet.",
                "CWE-693"))

        # 5) Strict-Transport-Security — UNIQUEMENT sur https (N/A en http clair : pas de faux positif).
        if is_https and not hsts:
            findings.append(gap(
                "Strict-Transport-Security absent (HTTPS)", "INFO",
                f"Cible HTTPS sans en-tête Strict-Transport-Security (HTTP {st}) : "
                f"downgrade/MITM SSL-strip non atténué.", "CWE-693"))

        # 6) Permissions-Policy — INFO (durcissement optionnel).
        if not permpol:
            findings.append(gap(
                "Permissions-Policy absent", "INFO",
                f"En-tête Permissions-Policy absent (HTTP {st}) : APIs navigateur (caméra, micro, "
                f"géoloc…) non restreintes explicitement.", "CWE-693"))

        # 7) Cookies non sécurisés — par cookie, LOW.
        for raw in self._cookies(headers):
            attrs = [a.strip().lower() for a in raw.split(";")[1:]]
            name = raw.split("=", 1)[0].strip()
            missing = [flag for flag, present in (
                ("Secure", "secure" in attrs),
                ("HttpOnly", "httponly" in attrs),
                ("SameSite", any(a.startswith("samesite") for a in attrs)),
            ) if not present]
            if missing:
                findings.append(gap(
                    f"Cookie non sécurisé — {name} (manque {', '.join(missing)})", "LOW",
                    f"Set-Cookie '{name}' sans {', '.join(missing)} (HTTP {st}). "
                    f"Cookie brut: {raw[:200]}", "CWE-614"))

        # 8) Fuite de version serveur — INFO.
        leaks = [f"{k}: {v}" for k, v in (("Server", server), ("X-Powered-By", powered))
                 if v and any(c.isdigit() for c in v)]
        if leaks:
            findings.append(gap(
                "Fuite de version (Server / X-Powered-By)", "INFO",
                f"En-tête(s) révélant une version logicielle : {'; '.join(leaks)} (HTTP {st}).",
                "CWE-200"))

        # Cible durcie : AUCUN écart -> aucun finding (pas de bruit sur une réponse conforme).
        return findings

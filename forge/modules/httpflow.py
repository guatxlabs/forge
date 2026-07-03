"""LOT INJECTION/PROTOCOLE (flux HTTP) — trois oracles de VÉRIFICATION à PREUVE MINIMALE & BÉNIGNE
(`request_smuggling.probe`, `cache_poisoning.probe`, `header_injection.probe`).

Ces oracles CONFIRMENT une faiblesse au niveau du PROTOCOLE/flux HTTP avec une preuve MINIMALE et
NON DESTRUCTIVE — détection pour test autorisé, jamais de poisoning d'un autre utilisateur :

  - request_smuggling.probe : désync HTTP CL.TE/TE.CL par sonde de TIMING différentielle. Une variante
                              ambiguë (Content-Length vs Transfer-Encoding incohérents) fait HANG un
                              back-end vulnérable (il attend un terminateur de chunk) là où la baseline
                              répond vite -> désync. La sonde est AUTO-CONTENUE sur NOTRE PROPRE connexion
                              (fermée ensuite) : aucun préfixe pendant n'est laissé pour se FUSIONNER à la
                              requête d'un autre user (pas d'empoisonnement de file). CWE-444.
  - cache_poisoning.probe   : un en-tête NON CLÉ (unkeyed : `X-Forwarded-Host`…) portant un marqueur
                              BÉNIGN se REFLÈTE dans une réponse CACHEABLE (différentiel vs un contrôle
                              sans l'en-tête) -> web cache poisoning. Sonde SEULE : un cache-buster UNIQUE
                              cloisonne notre réponse sous une clé que personne d'autre ne requête (jamais
                              de persistance d'entrée nuisible pour de vrais users) et le marqueur est
                              bénin (un hostname, pas une charge). CWE-525.
  - header_injection.probe  : injection d'en-tête / Host header par marqueur BÉNIGN — deux voies :
                              (a) CRLF response-splitting (CWE-113) : un en-tête BÉNIGN injecté via CRLF
                                  dans un paramètre réfléchi APPARAÎT comme en-tête de réponse réel ;
                              (b) host header poisoning (CWE-644, ex reset-password) : un marqueur d'hôte
                                  injecté (`Host`/`X-Forwarded-Host`) est REFLÉTÉ dans le corps/`Location`
                                  (différentiel vs contrôle). Non destructif (marqueur inerte, jamais de
                              Set-Cookie/session tamperé). CWE-113/CWE-644.

GARDE-FOUS (chaque oracle les respecte, prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : cible hors périmètre -> `skipped`, AUCUNE requête émise (défense en
      profondeur : l'engine gate déjà en Couche 2, on re-valide localement AVANT tout réseau).
  (2) PREUVE MINIMALE & BÉNIGNE : promotion `vulnerable` UNIQUEMENT sur preuve concrète (hang de timing /
      réflexion unkeyed cacheable / en-tête injecté matérialisé). Sinon `tested` (pas de verdict aveugle).
  (3) NON DESTRUCTIF : sondes de vérification (exploit=False, destructive=False) — jamais de poisoning
      d'un autre user (probe self-contained / cache-buster unique / marqueur inerte).
  (4) SESSION SECRÈTE : le matériel d'auth gouverné est fusionné par `Oracle._http` UNIQUEMENT sur URL
      in-scope et n'est JAMAIS journalisé/rapporté.
  (5) DÉGRADATION GRACIEUSE : réseau/transport indisponible -> `skipped` (offline-safe).

Bâtis sur `ClientFlowOracle` (clientflow.py, `_fetch` header-aware -> (status, body, pairs)) pour les deux
oracles qui inspectent les en-têtes de réponse, et sur `ScopeGuardedOracle` (+ un seam `_timed`
monkeypatchable) pour la sonde de timing du smuggling. Aucune capacité élargie.
"""
import hashlib
import re
import socket
import ssl
import time
import urllib.parse

from .oracle import ScopeGuardedOracle
from .clientflow import ClientFlowOracle
from .registry import register
from .. import techniques


# =================================================================================================
#  request_smuggling.probe — désync CL.TE/TE.CL par sonde de TIMING différentielle — CWE-444
# =================================================================================================
@register("request_smuggling.probe")
class RequestSmugglingProbe(ScopeGuardedOracle):
    kind = "request_smuggling.probe"
    exploit = False                      # sonde de TIMING de vérification (non destructive) -> non-exploit
    destructive = False                  # AUTO-CONTENUE : aucun poisoning de file d'un autre user
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # stdlib socket/ssl
    mitre = techniques.mitre_for("request_smuggling.probe")   # source de vérité : techniques.py (T1190)
    cwe = "CWE-444"                                       # HTTP Request/Response Smuggling
    tool = "forge/modules/httpflow.py:request_smuggling.probe"
    fix = ("Normaliser le parsing HTTP entre front-end et back-end : rejeter les requêtes qui portent À "
           "LA FOIS Content-Length et Transfer-Encoding (ou des en-têtes dupliqués/obfusqués), préférer "
           "HTTP/2 de bout en bout, et s'assurer que les deux extrémités s'accordent sur la frontière de "
           "message ; désactiver la réutilisation de connexion en amont si nécessaire (CWE-444).")
    description = ("Oracle Request-Smuggling à PREUVE de TIMING : une variante CL.TE/TE.CL ambiguë HANG un "
                   "back-end vulnérable (vs baseline rapide). Sonde AUTO-CONTENUE (aucun poisoning d'autrui). "
                   "Non destructif. Sinon tested. CWE-444.")

    @staticmethod
    def _craft(variant, host, path):
        """Bytes d'une requête AUTO-CONTENUE. `baseline` = GET normal. `clte`/`tecl` = Content-Length et
        Transfer-Encoding INCOHÉRENTS (self-contained, terminés proprement) : un back-end vulnérable HANG
        en attendant un terminateur qu'on retient SUR NOTRE connexion (fermée ensuite) — jamais de préfixe
        pendant fusionné à la requête d'un autre user. BÉNIN (corps inerte)."""
        if variant == "clte":
            body = "0\r\n\r\n"                    # TE:chunked dit « fini » ; CL dit « il reste des octets »
            return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body) + 4}\r\n"
                    f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body}").encode()
        if variant == "tecl":
            body = "1\r\nZ\r\n0\r\n\r\n"          # CL:4 tronque ; TE:chunked attend plus
            return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n"
                    f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body}").encode()
        return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()

    @staticmethod
    def _timed(action, variant, timeout):
        """(elapsed_seconds, status) — status ∈ {"ok","timeout","error"}. Envoie la requête AUTO-CONTENUE
        sur NOTRE PROPRE connexion raw-socket et mesure le délai jusqu'à la première réponse. « timeout » =
        connecté mais aucune réponse (signal de HANG = désync) ; « error » = pas de connexion (offline).
        Connexion isolée puis FERMÉE : aucun empoisonnement de file d'un autre user. Seam monkeypatché
        par les tests (zéro réseau réel)."""
        parsed = urllib.parse.urlsplit(action.target)
        host = parsed.hostname
        if not host:
            return (0.0, "error")
        tls = parsed.scheme == "https"
        port = parsed.port or (443 if tls else 80)
        path = parsed.path or "/"
        raw = RequestSmugglingProbe._craft(variant, host, path)
        t0 = time.monotonic()
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=min(timeout, 10))
            if tls:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            sock.settimeout(timeout)
            sock.sendall(raw)
            data = sock.recv(64)
            return (time.monotonic() - t0, "ok" if data else "timeout")
        except socket.timeout:
            return (time.monotonic() - t0, "timeout")
        except OSError:
            return (time.monotonic() - t0, "error")
        finally:
            try:
                if sock is not None:
                    sock.close()
            except OSError:
                pass

    def dry(self, action):
        return (f"# sonde de TIMING sur {action.target} : baseline (GET) vs CL.TE vs TE.CL (Content-Length "
                f"et Transfer-Encoding incohérents) — PREUVE = une variante ambiguë HANG (back-end attend un "
                f"terminateur) là où la baseline répond vite ; sonde AUTO-CONTENUE, aucun poisoning ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        try:
            timeout = max(3, min(int(action.params.get("timeout") or 8), 30))
        except (TypeError, ValueError):
            timeout = 8
        try:
            delay_gap = max(1.0, float(action.params.get("delay_gap") or 5.0))
        except (TypeError, ValueError):
            delay_gap = 5.0

        base_el, base_status = self._timed(action, "baseline", timeout)
        seen = base_status in ("ok", "timeout")
        hung, notes = [], [f"baseline:{base_status}({round(base_el, 3)}s)"]
        for v in ("clte", "tecl"):
            el, status = self._timed(action, v, timeout)
            if status in ("ok", "timeout"):
                seen = True
            # HANG = connecté mais timeout (le back-end attend) OU réponse bien plus lente que la baseline
            # RAPIDE. Exige une baseline OK comme référence (sinon aucune conclusion -> tested).
            timed_out = status == "timeout"
            slower = status == "ok" and base_status == "ok" and (el - base_el) >= delay_gap
            if base_status == "ok" and (timed_out or slower):
                hung.append(v)
            notes.append(f"{v}:{status}({round(el, 3)}s)")

        # (5) DÉGRADATION GRACIEUSE : aucune connexion établie du tout (tout « error ») -> skipped (offline).
        if not seen:
            return [self.degraded(
                target=action.target,
                title="Request-Smuggling non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune connexion établie (baseline ni variantes) ; transport indisponible ; offline-safe.",
                poc=self.dry(action))]

        proven = bool(hung) and base_status == "ok"
        return [self.proof(
            target=action.target, proven=proven,
            title=("Request-Smuggling CONFIRMÉ — désync détectée par différentiel de TIMING (CL.TE/TE.CL)"
                   if proven else "Request-Smuggling non confirmé — aucun hang différentiel (pas de verdict aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"variantes en hang={hung or 'aucune'} ; seuil_délai={delay_gap}s ; détail={' '.join(notes)} ; "
                      f"sonde AUTO-CONTENUE sur notre propre connexion (fermée) — aucun préfixe pendant, aucun "
                      f"poisoning de file d'un autre user ; non destructif ; session gouvernée non journalisée"),
            poc=(f"# baseline (GET) vs CL.TE/TE.CL (Content-Length vs Transfer-Encoding incohérents) sur "
                 f"{action.target} ; PREUVE = HANG d'une variante ambiguë (timeout) vs baseline rapide "
                 f"({hung or '—'}) ; requête auto-contenue, jamais de préfixe smuggé vers un autre user"))]


# =================================================================================================
#  cache_poisoning.probe — réflexion d'un en-tête NON CLÉ dans une réponse CACHEABLE — CWE-525
# =================================================================================================
# En-têtes typiquement NON CLÉS (unkeyed) par les caches — leur valeur influence pourtant la réponse.
_UNKEYED_HEADERS = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Scheme", "X-Forwarded-Server", "Forwarded"]
# En-têtes de réponse où un reflet est significatif (en plus du corps).
_REFLECT_RESP_HEADERS = ("Location", "Content-Location", "Link", "Refresh", "Set-Cookie")


@register("cache_poisoning.probe")
class CachePoisoningProbe(ClientFlowOracle):
    kind = "cache_poisoning.probe"
    mitre = techniques.mitre_for("cache_poisoning.probe")     # source de vérité : techniques.py (T1190)
    cwe = "CWE-525"                                      # Information Exposure Through Caching / Web Cache Poisoning
    tool = "forge/modules/httpflow.py:cache_poisoning.probe"
    fix = ("Inclure dans la CLÉ de cache TOUS les en-têtes qui influencent la réponse (ou ne jamais "
           "réfléchir un en-tête non clé comme `X-Forwarded-Host` dans le corps/les liens absolus/les "
           "redirections) ; utiliser `Vary` correctement, normaliser l'en-tête Host côté origine, et ne "
           "pas mettre en cache les réponses qui dépendent d'entrées non clés (CWE-525).")
    description = ("Oracle Cache-Poisoning à PREUVE : un en-tête NON CLÉ (X-Forwarded-Host…) portant un "
                   "marqueur BÉNIGN se reflète dans une réponse CACHEABLE (diff vs contrôle). Cache-buster "
                   "unique (jamais de persistance nuisible). Sinon tested. CWE-525.")

    @classmethod
    def _marker(cls, target):
        """Marqueur d'hôte BÉNIGN déterministe-par-cible (hostname inerte, pas une charge) et un cache-buster
        UNIQUE cloisonnant la réponse sous une clé que personne d'autre ne requête (probe-only)."""
        h = hashlib.sha256(f"{target}|forge-cache".encode()).hexdigest()
        return f"forge{h[:10]}.forge-cache.test", f"forgecb{h[10:20]}"

    @staticmethod
    def _reflected_in(pairs, body, marker):
        """'corps' | nom d'en-tête de réponse | '' — où le marqueur est réfléchi (corps ou en-tête)."""
        if marker in (body or ""):
            return "corps"
        for name in _REFLECT_RESP_HEADERS:
            for v in ClientFlowOracle._get_all(pairs, name):
                if marker in (v or ""):
                    return name
        return ""

    def _cacheable(self, pairs):
        """(bool, preuve) — la réponse est-elle CACHEABLE d'après ses en-têtes ? no-store/no-cache/private
        -> False ; public/max-age>0/Age/X-Cache(hit|miss)/CF-Cache-Status -> True. Conservateur."""
        cc = (self._get(pairs, "Cache-Control") or "").lower()
        if "no-store" in cc or "no-cache" in cc or "private" in cc:
            return False, cc or "no-cache"
        if "public" in cc:
            return True, cc
        m = re.search(r"max-age=(\d+)", cc)
        if m and int(m.group(1)) > 0:
            return True, cc
        if self._get(pairs, "Age") is not None:
            return True, f"Age:{self._get(pairs, 'Age')}"
        xc = " ".join(v for v in (self._get(pairs, "X-Cache"), self._get(pairs, "CF-Cache-Status"),
                                  self._get(pairs, "X-Cache-Hits"), self._get(pairs, "X-Served-By")) if v)
        if xc and re.search(r"(?i)hit|miss", xc):
            return True, xc
        return False, cc or "—"

    def _url(self, action, buster):
        sep = "&" if "?" in action.target else "?"
        return f"{action.target}{sep}{urllib.parse.urlencode({'forgecb': buster})}"

    def dry(self, action):
        marker, buster = self._marker(action.target)
        return (f"# envoie {action.target}?forgecb={buster} avec X-Forwarded-Host: {marker} (marqueur "
                f"BÉNIGN) et compare à un contrôle SANS l'en-tête — PREUVE = {marker} réfléchi dans une "
                f"réponse CACHEABLE uniquement via l'en-tête non clé ; cache-buster unique (probe-only) ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        marker, buster = self._marker(action.target)
        user_headers = dict(action.params.get("headers", {}))
        headers = list(action.params.get("unkeyed_headers") or _UNKEYED_HEADERS)

        # contrôle : requête SANS en-tête non clé (buster distinct) -> le marqueur ne doit PAS y apparaître
        # (anti-faux-positif : confirme que tout reflet vient bien de l'en-tête non clé injecté).
        c_st, c_body, c_pairs = self._fetch(self._url(action, buster + "ctl"), headers=dict(user_headers))
        control_reflects = bool(self._reflected_in(c_pairs, c_body, marker))
        seen_network = c_st is not None

        proven, hdr_used, where_reflected, cache_ev, reflected_uncacheable = False, "", "", "", False
        for h in headers:
            probe_headers = dict(user_headers)
            probe_headers[h] = marker
            st, body, pairs = self._fetch(self._url(action, buster), headers=probe_headers)
            if st is not None:
                seen_network = True
            loc = self._reflected_in(pairs, body, marker)
            if loc and not control_reflects:
                cacheable, cev = self._cacheable(pairs)
                if cacheable:
                    proven, hdr_used, where_reflected, cache_ev = True, h, loc, cev
                    break
                # réfléchi mais NON cacheable : réel mais pas du poisoning -> mémorisé, reste `tested`.
                reflected_uncacheable = True
                hdr_used, where_reflected, cache_ev = h, loc, cev

        # (5) DÉGRADATION GRACIEUSE : aucune réponse (réseau indisponible) -> skipped (offline-safe).
        if not seen_network:
            return [self.degraded(
                target=action.target,
                title="Cache-Poisoning non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]
        return [self.proof(
            target=action.target, proven=proven,
            title=("Cache-Poisoning CONFIRMÉ — en-tête NON CLÉ réfléchi dans une réponse CACHEABLE"
                   if proven else "Cache-Poisoning non confirmé — pas de réflexion unkeyed cacheable (pas de verdict aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"en-tête non clé={hdr_used or '—'} ; reflet={where_reflected or 'aucun'} ; "
                      f"cacheable={cache_ev or '—'} ; reflet_non_cacheable={reflected_uncacheable} ; "
                      f"réflexion_contrôle(sans en-tête)={control_reflects} (si vrai -> non concluant) ; "
                      f"marqueur BÉNIGN (hostname inerte) + cache-buster unique (aucune persistance nuisible "
                      f"pour de vrais users) ; non destructif ; session gouvernée non journalisée"),
            poc=(f"# curl -H 'X-Forwarded-Host: {marker}' '{self._url(action, buster)}' vs contrôle sans "
                 f"l'en-tête\n# PREUVE = {marker} réfléchi ({where_reflected or '—'}) dans une réponse "
                 f"CACHEABLE via l'en-tête non clé ; cache-buster unique, probe-only"))]


# =================================================================================================
#  header_injection.probe — CRLF response-splitting (CWE-113) + host header poisoning (CWE-644)
# =================================================================================================
_CRLF_HEADER_NAME = "Forge-Split"                        # en-tête BÉNIGN témoin d'une injection CRLF réussie
# En-têtes d'hôte injectables pour le host poisoning (le marqueur d'hôte BÉNIGN y est placé).
_HOST_HEADERS = ["X-Forwarded-Host", "Host", "X-Host", "X-Forwarded-Server", "Forwarded"]


@register("header_injection.probe")
class HeaderInjectionProbe(ClientFlowOracle):
    kind = "header_injection.probe"
    mitre = techniques.mitre_for("header_injection.probe")    # source de vérité : techniques.py (T1190)
    cwe = "CWE-113"                                      # Improper Neutralization of CRLF in HTTP Headers (+ CWE-644 host)
    tool = "forge/modules/httpflow.py:header_injection.probe"
    fix = ("Neutraliser CR/LF dans toute valeur écrite dans un en-tête de réponse (ne jamais réfléchir une "
           "entrée utilisateur non filtrée dans un header/`Location`) ; pour le Host : utiliser une "
           "allowlist d'hôtes de confiance côté serveur et construire les URLs absolues (liens de reset, "
           "redirections) à partir d'une valeur CONFIGURÉE, jamais de l'en-tête Host/X-Forwarded-Host du "
           "client (CWE-113 / CWE-644).")
    description = ("Oracle Header/Host-Injection à PREUVE BÉNIGNE : CRLF response-splitting (un en-tête "
                   "bénin injecté apparaît dans la réponse, CWE-113) OU host poisoning (marqueur d'hôte "
                   "reflété dans le corps/Location, CWE-644). Non destructif. Sinon tested. CWE-113/644.")

    @staticmethod
    def _reflected_in(pairs, body, marker):
        """'corps' | nom d'en-tête de réponse | '' — où le marqueur d'hôte est réfléchi."""
        if marker in (body or ""):
            return "corps"
        for name in ("Location", "Content-Location", "Link", "Refresh"):
            for v in ClientFlowOracle._get_all(pairs, name):
                if marker in (v or ""):
                    return name
        return ""

    def dry(self, action):
        param = action.params.get("param")
        mhost = self._marker(action.target, "host", "hostinj") + ".forge-hh.test"
        crlf = (f"CRLF: injecte {param}=…%0d%0a{_CRLF_HEADER_NAME}:<token> -> l'en-tête bénin apparaît "
                f"dans la réponse (CWE-113)" if param else "CRLF: (params.param requis pour tester)")
        return (f"# {crlf} ; HOST: injecte X-Forwarded-Host/Host: {mhost} -> reflet dans le corps/Location "
                f"(CWE-644, diff vs contrôle) ; marqueur BÉNIGN, non destructif ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        method = str(action.params.get("method", "GET")).upper()
        param = action.params.get("param")
        user_headers = dict(action.params.get("headers", {}))
        seen_network = False

        # --- (b) HOST HEADER POISONING (CWE-644) — ne requiert AUCUN param ---
        mhost = self._marker(action.target, "host", "hostinj") + ".forge-hh.test"
        sep = "&" if "?" in action.target else "?"
        ctl_url = action.target
        # contrôle : requête SANS en-tête d'hôte injecté -> le marqueur d'hôte ne doit PAS y apparaître.
        c_st, c_body, c_pairs = self._fetch(ctl_url, headers=dict(user_headers))
        if c_st is not None:
            seen_network = True
        control_reflects_host = bool(self._reflected_in(c_pairs, c_body, mhost))
        host_confirmed, host_hdr, host_where = False, "", ""
        for hh in _HOST_HEADERS:
            probe_headers = dict(user_headers)
            probe_headers[hh] = mhost
            st, body, pairs = self._fetch(action.target, headers=probe_headers)
            if st is not None:
                seen_network = True
            loc = self._reflected_in(pairs, body, mhost)
            if loc and not control_reflects_host:
                host_confirmed, host_hdr, host_where = True, hh, loc
                break

        # --- (a) CRLF RESPONSE SPLITTING (CWE-113) — requiert un paramètre réfléchi ---
        crlf_confirmed, crlf_token = False, ""
        if param:
            crlf_token = self._marker(action.target, param, "crlf")
            # valeur BÉNIGNE : un CRLF suivi d'un en-tête témoin inerte ; si l'app l'écrit sans filtrer,
            # l'en-tête `Forge-Split: <token>` se MATÉRIALISE dans la réponse.
            payload = f"forge\r\n{_CRLF_HEADER_NAME}: {crlf_token}\r\n\r\nforge"
            _, st, _body, pairs = self._send_h(action, param, payload, method)
            if st is not None:
                seen_network = True
            got = self._get(pairs, _CRLF_HEADER_NAME)
            crlf_confirmed = bool(got and crlf_token in got)

        # (5) DÉGRADATION GRACIEUSE : aucune réponse (réseau indisponible) -> skipped (offline-safe).
        if not seen_network:
            return [self.degraded(
                target=action.target,
                title="Header-Injection non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]

        proven = crlf_confirmed or host_confirmed
        which = ", ".join(t for t in (
            ("CRLF response-splitting (CWE-113)" if crlf_confirmed else ""),
            ("host header poisoning (CWE-644)" if host_confirmed else "")) if t) or "aucune"
        return [self.proof(
            target=action.target, proven=proven,
            title=("Header-Injection CONFIRMÉE — " + which if proven
                   else "Header-Injection non confirmée — ni CRLF ni host poisoning (pas de verdict aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"voie(s)={which} ; CRLF: en-tête témoin '{_CRLF_HEADER_NAME}' matérialisé={crlf_confirmed} ; "
                      f"HOST: en-tête={host_hdr or '—'} reflet={host_where or 'aucun'} "
                      f"réflexion_contrôle={control_reflects_host} (si vrai -> non concluant) ; marqueur BÉNIGN "
                      f"inerte (aucun Set-Cookie/session tamperé) ; non destructif ; session gouvernée non journalisée"),
            poc=(f"# CRLF: {action.params.get('param', '<param>')}=…%0d%0a{_CRLF_HEADER_NAME}:<token> ; "
                 f"HOST: -H 'X-Forwarded-Host: {mhost}' sur {action.target}\n"
                 f"# PREUVE = en-tête bénin '{_CRLF_HEADER_NAME}' matérialisé OU marqueur d'hôte reflété "
                 f"(diff vs contrôle) ; marqueur inerte"))]

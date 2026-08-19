# SPDX-License-Identifier: AGPL-3.0-or-later
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
import statistics
import time
import urllib.parse

from ._scopeguard import web_url_candidates
from .oracle import ScopeGuardedOracle
from .clientflow import ClientFlowOracle
from .registry import register
from .. import pin as _pin
from .. import session as _session
from .. import techniques
from .. import throttle


# =================================================================================================
#  request_smuggling.probe — désync CL.TE/TE.CL par sonde de TIMING différentielle — CWE-444
# =================================================================================================
# ANTI-FAUX-POSITIF : un HANG mesuré UNE seule fois peut n'être qu'un à-coup réseau transitoire (GC,
# congestion, perte de paquet). On EXIGE que le hang se REPRODUISE sur une MAJORITÉ d'échantillons
# répétés avant toute promotion `vulnerable`. La baseline est elle aussi ré-échantillonnée (médiane)
# pour une référence stable. `_SMUGGLE_MIN_HANGS`/`_SMUGGLE_SAMPLES` sont le quorum (≥2/3).
_SMUGGLE_SAMPLES = 3
_SMUGGLE_MIN_HANGS = 2


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
        # NORMALISATION scheme-less : une cible hôte nu / host:port n'a pas de netloc pour urlsplit
        # (hostname=None -> "error" et cible non testée). On la préfixe d'un scheme via le helper partagé
        # (cf. web_url_candidates) AVANT de parser : `host:port` devient testable. URL déjà formée ->
        # candidat unique = la cible telle quelle (byte-identique à l'historique).
        cands = web_url_candidates(action.target)
        parsed = urllib.parse.urlsplit(cands[0] if cands else str(action.target))
        host = parsed.hostname
        if not host:
            return (0.0, "error")
        tls = parsed.scheme == "https"
        port = parsed.port or (443 if tls else 80)
        path = parsed.path or "/"
        raw = RequestSmugglingProbe._craft(variant, host, path)
        # ANTI-REBINDING : le ROE a résolu+épinglé l'IP de la cible au fire-time (action.params["_pinned_ips"]).
        # On établit la connexion TCP vers l'IP ÉPINGLÉE au lieu de re-résoudre le hostname ici (fenêtre de
        # DNS-rebinding). Le `Host:` de la requête crafted reste `host` (voir _craft) et, en TLS, le SNI reste
        # `host` (server_hostname ci-dessous) : la validation du certificat n'est PAS affaiblie. Pin absent =>
        # `connect_host = host` (résolution normale, byte-identique à l'historique).
        connect_host = _pin.pick(action.params.get("_pinned_ips")) or host
        # DÉBIT — ce module NE PASSE PAS par `Oracle._http` : il ouvre son propre raw socket, donc il
        # échappait AUX DEUX étages de débit. Mesuré sous un plafond de run actif à 5 req/s :
        # **10 requêtes en 5 ms** avant que la cadence ne s'installe. Un plafond que l'on peut
        # contourner en ouvrant sa propre socket n'est pas un plafond.
        #
        # L'ATTENTE EST AVANT `t0`, ET C'EST TOUT L'ENJEU : ce qui suit MESURE le délai jusqu'à la
        # première réponse, et un délai anormal EST le signal de désync. Dormir dans la fenêtre
        # mesurée ferait passer le frein pour un hang — l'oracle rendrait « désynchronisation
        # confirmée » sur son propre throttle.
        _b = throttle.current()
        if _b is not None:
            _b.wait()
        t0 = time.monotonic()
        sock = None
        try:
            sock = socket.create_connection((connect_host, port), timeout=min(timeout, 10))
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

        # ÉCHANTILLONNAGE RÉPÉTÉ (anti-faux-positif) : chaque mesure est prise `_SMUGGLE_SAMPLES` fois.
        def _samples(variant):
            els, sts = [], []
            for _ in range(_SMUGGLE_SAMPLES):
                el, st = self._timed(action, variant, timeout)
                els.append(el)
                sts.append(st)
            return els, sts

        seen = False
        # BASELINE ré-échantillonnée -> référence STABLE : status = "ok" si une MAJORITÉ des échantillons
        # répond ; élapsed représentatif = médiane des échantillons OK (repli : médiane de tous). Un
        # à-coup isolé ne fausse plus la référence.
        base_els, base_sts = _samples("baseline")
        if any(s in ("ok", "timeout") for s in base_sts):
            seen = True
        base_ok = [e for e, s in zip(base_els, base_sts) if s == "ok"]
        if len(base_ok) >= _SMUGGLE_MIN_HANGS:
            base_status = "ok"
        elif any(s == "timeout" for s in base_sts):
            base_status = "timeout"
        else:
            base_status = "error"
        base_el = statistics.median(base_ok or base_els)

        hung, notes = [], [f"baseline:{base_status}(md {round(base_el, 3)}s /{_SMUGGLE_SAMPLES})"]
        for v in ("clte", "tecl"):
            els, sts = _samples(v)
            if any(s in ("ok", "timeout") for s in sts):
                seen = True
            # HANG d'un ÉCHANTILLON = connecté mais timeout (le back-end attend) OU réponse bien plus lente
            # que la baseline RAPIDE. Exige une baseline OK comme référence (sinon aucune conclusion).
            hang_count = 0
            for el, status in zip(els, sts):
                timed_out = status == "timeout"
                slower = status == "ok" and base_status == "ok" and (el - base_el) >= delay_gap
                if base_status == "ok" and (timed_out or slower):
                    hang_count += 1
            # PROMOTION seulement si le hang se REPRODUIT (quorum ≥ `_SMUGGLE_MIN_HANGS`) : un unique
            # à-coup réseau transitoire (1/N) NE promeut PAS -> pas de faux HIGH sur un échantillon isolé.
            if hang_count >= _SMUGGLE_MIN_HANGS:
                hung.append(v)
            notes.append(f"{v}:{hang_count}/{_SMUGGLE_SAMPLES}hang(md {round(statistics.median(els), 3)}s)")

        # (5) DÉGRADATION GRACIEUSE : aucune connexion établie du tout (tout « error ») -> skipped (offline).
        if not seen:
            return [self.degraded(
                target=action.target,
                title="Request-Smuggling non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune connexion établie (baseline ni variantes) ; transport indisponible ; offline-safe.",
                poc=self.dry(action))]

        # (5b) NE PAS FAIRE SEMBLANT — cet oracle ne juge QUE des TIMINGS : il n'a aucun corps ni
        # en-tête à inspecter, donc aucun moyen propre de voir qu'un WAF s'est interposé. Or derrière
        # un challenge managé, c'est le WAF qui répond : la baseline comme les variantes mesurent le
        # temps de réponse du WAF, jamais celui du back-end — « aucun hang différentiel » ne dit alors
        # RIEN sur la désync. Le store gouverné porte cet état (posé par evasion.* quand le
        # franchissement échoue, ou par un oracle HTTP qui a vu la signature) : CHALLENGED -> skipped.
        store = _session.current()
        if store is not None and store.clearance_state(action.target) == store.CHALLENGED:
            return [self.degraded(
                target=action.target,
                title="Request-Smuggling non testé — challenge/WAF managé interposé (timing non concluant)",
                evidence=("L'hôte est marqué CHALLENGED (défi managé constaté et NON franchi) : les mesures "
                          "de timing portent sur le WAF, pas sur le back-end — aucun verdict de désync n'est "
                          "possible. `skipped` (« pas vérifié »), jamais `tested` (« rien trouvé »). "
                          "Router le franchissement (evasion.turnstile/evasion.discover) puis rejouer."),
                poc=self.dry(action))]

        proven = bool(hung) and base_status == "ok"
        return [self.proof(
            target=action.target, proven=proven,
            title=("Request-Smuggling CONFIRMÉ — désync détectée par différentiel de TIMING (CL.TE/TE.CL)"
                   if proven else "Request-Smuggling non confirmé — aucun hang différentiel (pas de verdict aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"variantes en hang={hung or 'aucune'} ; seuil_délai={delay_gap}s ; "
                      f"quorum={_SMUGGLE_MIN_HANGS}/{_SMUGGLE_SAMPLES} échantillons (anti à-coup transitoire) ; "
                      f"détail={' '.join(notes)} ; sonde AUTO-CONTENUE sur notre propre connexion (fermée) — "
                      f"aucun préfixe pendant, aucun poisoning de file d'un autre user ; non destructif ; "
                      f"session gouvernée non journalisée"),
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

    @staticmethod
    def _base_url(target):
        """Base URL NORMALISÉE au scheme pour `target` (hôte nu / host:port / URL déjà formée). Délègue au
        helper partagé (cf. web_url_candidates) : une cible sans scheme n'est JAMAIS passée à urllib. URL
        déjà formée -> candidat unique = la cible (byte-identique)."""
        cands = web_url_candidates(target)
        return cands[0] if cands else str(target)

    def _url(self, base, buster):
        sep = "&" if "?" in base else "?"
        return f"{base}{sep}{urllib.parse.urlencode({'forgecb': buster})}"

    def dry(self, action):
        marker, buster = self._marker(action.target)
        base = self._base_url(action.target)
        return (f"# envoie {self._url(base, buster)} avec X-Forwarded-Host: {marker} (marqueur "
                f"BÉNIGN) et compare à un contrôle SANS l'en-tête — PREUVE = {marker} réfléchi dans une "
                f"réponse CACHEABLE uniquement via l'en-tête non clé ; cache-buster unique (probe-only) ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        marker, buster = self._marker(action.target)
        user_headers = dict(action.params.get("headers", {}))
        headers = list(action.params.get("unkeyed_headers") or _UNKEYED_HEADERS)

        # NORMALISATION scheme-less : une cible hôte nu / host:port n'a PAS de scheme -> la passer telle
        # quelle à urllib lèverait `unknown url type`. La requête de CONTRÔLE essaie les candidats
        # (http/https ordonnés par vraisemblance, cf. web_url_candidates) et FIXE la base sur la 1re
        # joignable — toutes les sondes suivantes réutilisent cette base. URL déjà formée -> 1 candidat
        # (byte-identique). AUCUN candidat joignable -> dégradation `skipped` visible (offline-safe).
        candidates = web_url_candidates(action.target) or [str(action.target)]
        base = candidates[0]

        # contrôle : requête SANS en-tête non clé (buster distinct) -> le marqueur ne doit PAS y apparaître
        # (anti-faux-positif : confirme que tout reflet vient bien de l'en-tête non clé injecté).
        c_st, c_body, c_pairs = None, "", []
        for cand in candidates:
            c_st, c_body, c_pairs = self._fetch(self._url(cand, buster + "ctl"), headers=dict(user_headers))
            base = cand
            if c_st is not None:
                break
        # NE PAS FAIRE SEMBLANT : si le CONTRÔLE revient du WAF (challenge managé), tout le
        # différentiel qui suit compare deux réponses de WAF -> aucun verdict de cache poisoning
        # n'est possible. `skipped`, jamais `tested`. (Signature STRICTE : un 403 nu reste un verdict.)
        blocked = self._challenge_degraded(action, action.target, c_st, c_body, c_pairs)
        if blocked is not None:
            return [blocked]
        control_reflects = bool(self._reflected_in(c_pairs, c_body, marker))
        seen_network = c_st is not None

        proven, hdr_used, where_reflected, cache_ev, reflected_uncacheable = False, "", "", "", False
        for h in headers:
            probe_headers = dict(user_headers)
            probe_headers[h] = marker
            st, body, pairs = self._fetch(self._url(base, buster), headers=probe_headers)
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
            poc=(f"# curl -H 'X-Forwarded-Host: {marker}' '{self._url(base, buster)}' vs contrôle sans "
                 f"l'en-tête\n# PREUVE = {marker} réfléchi ({where_reflected or '—'}) dans une réponse "
                 f"CACHEABLE via l'en-tête non clé ; cache-buster unique, probe-only"))]


# =================================================================================================
#  header_injection.probe — CRLF response-splitting (CWE-113) + host header poisoning (CWE-644)
# =================================================================================================
_CRLF_HEADER_NAME = "Forge-Split"                        # en-tête BÉNIGN témoin d'une injection CRLF réussie
# En-têtes d'hôte injectables pour le host poisoning (le marqueur d'hôte BÉNIGN y est placé).
_HOST_HEADERS = ["X-Forwarded-Host", "Host", "X-Host", "X-Forwarded-Server", "Forwarded"]

# =================================================================================================
#  CONTRE-MESURE « CANONICALISATION D'URL » — le reflet d'hôte le plus banal du web n'est PAS une vuln.
#
#  MESURÉ (banc de détection multi-applications, `docs/BENCH_DETECTION.md` § D4) : **5 HIGH FAUX** —
#  4 sur DVWA (Apache 2.4, un par répertoire découvert) + 1 sur VAmPI (Werkzeug 2.2) — tous produits
#  par le MÊME phénomène : une requête sur un répertoire SANS slash final reçoit une redirection de
#  canonicalisation dont le `Location` est reconstruit à partir de l'en-tête `Host` de la requête.
#
#      curl -H 'Host: evil.example' http://.../docs -> 301  Location: http://evil.example/docs/
#      curl -H 'Host: evil.example' http://.../ui   -> 308  Location: http://evil.example/ui/
#
#  DEUX STACKS INDÉPENDANTES, donc pas un bug d'application : c'est le comportement PAR DÉFAUT d'à
#  peu près tout serveur web (RFC 3986 § 6 : normalisation de l'URI de référence). Aucune des quatre
#  applications du banc ne déclarait cette classe dans sa vérité terrain.
#
#  POURQUOI LE CONTRÔLE EXISTANT NE POUVAIT PAS RATTRAPER. `control_reflects_host` compare avec le
#  VRAI `Host` — où le marqueur ne peut par construction jamais apparaître : le contrôle rend
#  toujours False, et la conjonction `loc and not control_reflects_host` promeut toujours.
#
#  POURQUOI PAS `Oracle.path_discrimination()`. Vérifié en loopback contre les deux stacks fautives :
#  elle rend `verdict=True` (« la cible DISCRIMINE ») sur les deux — ses chemins de contrôle
#  reçoivent un 404 parfaitement normal. Elle répond à « la cible sert-elle un 200 sur n'importe quel
#  chemin deviné ? », pas à « ce reflet d'hôte est-il une décision applicative ? ». Famille
#  différente : elle ne peut ni couvrir ce cas ni entrer en concurrence avec lui. Ce qui EST partagé —
#  et réutilisé tel quel — c'est le VOCABULAIRE de la retenue (`proof(proven=False)` -> INFO).
#
#  CE QUI RESTE DÉTECTÉ (on ne fabrique pas l'excès inverse). Le discriminant est le CHEMIN de la
#  destination, parce que c'est lui qui distingue une normalisation d'une DÉCISION :
#    - `Location` dont le chemin est celui de la requête (au slash final près) -> canonicalisation ;
#    - `Location` vers un AUTRE chemin (`/reset`, `/login`, `/`)            -> décision applicative ;
#    - marqueur dans le CORPS (lien de reset absolu, lien canonique, `<base href>`) -> le vecteur qui
#      PAIE (empoisonnement de lien de réinitialisation) — toujours promu ;
#    - marqueur dans un AUTRE en-tête (`Link`, `Refresh`, `Content-Location`)      -> toujours promu.
#  Le corps AUTO-GÉNÉRÉ d'une redirection recopie son propre `Location` (« The document has moved
#  <a href="…">here</a> ») : cet ÉCHO est neutralisé avant la recherche d'un reflet RÉSIDUEL, sinon
#  la même redirection par défaut repasserait par la porte du corps.
# =================================================================================================


def _same_path(a, b):
    """Deux chemins d'URL désignent-ils la MÊME ressource, au slash final près ? (`/docs` ≡ `/docs/`,
    et `''` ≡ `/` — la racine). Pur, ne lève jamais."""
    na = (str(a or "").rstrip("/")) or "/"
    nb = (str(b or "").rstrip("/")) or "/"
    return na == nb


# =================================================================================================
#  CONTRE-MESURE « ÉCHO DÉCORATIF » — la garde ci-dessus n'a fermé QU'UNE PORTE SUR DEUX.
#
#  MESURÉ (rejeu du banc, `docs/BENCH_DETECTION.md` § D14) : **4 HIGH FAUX de plus sur DVWA**, sur
#  les MÊMES répertoires qu'en D4, à un caractère près — la variante à SLASH FINAL, où Apache ne
#  redirige plus : il sert l'index, et son pied de page recopie le `Host` reçu.
#
#      curl -H 'Host: evil.forge-hh.test' http://127.0.0.1:8081/docs/  ->  200, AUCUN `Location`
#        <address>Apache/2.4.25 (Debian) Server at evil.forge-hh.test Port 80</address>
#        occurrences du marqueur dans le corps : 1        `href` PORTEUR : 0
#
#  `ServerSignature On` est le défaut Debian : TOUTE page auto-générée (index de répertoire, page
#  d'erreur) recopie l'en-tête `Host`. Aucune des quatre applications du banc ne déclare cette classe
#  dans sa vérité terrain. La garde de D4 ne regardait QUE le `Location` ; dès que le marqueur est
#  dans le CORPS, `_reflected_in` rendait `"corps"` sans autre examen et la seule garde restante
#  était `control_reflects_host` — celle que D4 a elle-même démontrée structurellement incapable
#  (elle compare avec le VRAI `Host`, où le marqueur ne peut PAR CONSTRUCTION jamais apparaître).
#
#  LE DISCRIMINANT — CE QUE LE CORPS FAIT DU `Host`, PAS LE FAIT QU'IL LE CONTIENNE.
#  Ce qui rend un host poisoning PAYABLE, c'est qu'une URL soit CONSTRUITE depuis l'en-tête : le
#  lien de réinitialisation absolu qui part par e-mail, le `<base href>`, le `<script src>`, l'entrée
#  de cache. Le marqueur y occupe alors l'AUTORITÉ d'une URI (RFC 3986 § 3.2 : l'autorité SUIT
#  « // » et PRÉCÈDE « / ? # »). Un pied de page, un titre, un message d'erreur le portent comme du
#  TEXTE : rien n'est construit, rien n'est suivi, rien n'est chargé. Le banc l'avait déjà chiffré
#  sans le nommer — « href porteur : 0 ».
#
#  CE QUI RESTE DÉTECTÉ (on ne fabrique pas l'excès inverse) — le corps promeut dès qu'UNE SEULE
#  occurrence est PORTEUSE, même noyée dans dix échos inertes :
#    - `<a href="https://<marqueur>/account/reset?token=…">`   -> lien de reset (le vecteur qui paie)
#    - `<base href="//<marqueur>/">`, `<script src="http://<marqueur>/x.js">`, `<form action=…>`
#    - `<meta http-equiv=refresh content="0;url=https://<marqueur>/">`, JSON `{"url":"https://…"}`
#    - texte nu `<marqueur>/reset?token=…` (lien d'e-mail sans balise) : suivi d'un chemin/une query
#  Et les VOIES HORS CORPS sont intactes : `Location` applicatif, `Link`, `Refresh`,
#  `Content-Location`, CRLF response-splitting — la mesure ne portait que sur le corps.
#
#  L'abstention est NOMMÉE dans l'évidence (une abstention muette serait le défaut symétrique).
# =================================================================================================

# Autorité d'URI — le marqueur SUIT « // » (avec userinfo optionnel : `//user:pw@<marqueur>`)…
_URL_AUTHORITY_BEFORE_RX = re.compile(r'//(?:[^\s"\'<>/?#]*@)?$')
# …ou PRÉCÈDE un délimiteur de chemin/query/fragment (port optionnel) : `<marqueur>:8443/reset?x`.
_URL_AUTHORITY_AFTER_RX = re.compile(r'^(?::\d{1,5})?[/?#]')
# Fenêtre de contexte AMONT bornée : une autorité est collée à son « // » (userinfo compris). Borner
# évite un balayage du corps entier par occurrence — et tout risque de backtracking pathologique.
_URL_AUTHORITY_LOOKBEHIND = 128


def _host_echo_split(body, marker):
    """(porteur, inerte) — deux EXTRAITS DE CONTEXTE (ou '') disant COMMENT le marqueur d'hôte
    apparaît dans le corps :

      - `porteur` : au moins une occurrence occupe l'AUTORITÉ d'une URI -> une URL est CONSTRUITE
        depuis l'en-tête `Host` (lien de reset, `<base href>`, `src`, entrée de cache) -> vrai
        empoisonnement, à PROMOUVOIR ;
      - `inerte`  : le marqueur n'est présent que comme TEXTE (signature serveur `<address>`, titre,
        message) -> écho décoratif, RIEN n'est construit -> ne promeut pas, mais est NOMMÉ.

    Les deux peuvent être non vides : un corps peut porter un vrai lien ET un pied de page. La
    décision se prend alors sur `porteur` (fail-open vers la DÉTECTION, jamais vers le silence).
    Pur, ne lève jamais."""
    text = body or ""
    if not marker or marker not in text:
        return "", ""
    carrying = inert = ""
    i = text.find(marker)
    while i >= 0:
        before = text[max(0, i - _URL_AUTHORITY_LOOKBEHIND):i]
        after = text[i + len(marker):i + len(marker) + 16]
        snip = " ".join(text[max(0, i - 60):i + len(marker) + 40].split())
        if _URL_AUTHORITY_BEFORE_RX.search(before) or _URL_AUTHORITY_AFTER_RX.match(after):
            carrying = carrying or snip
        else:
            inert = inert or snip
        if carrying and inert:
            break
        i = text.find(marker, i + 1)
    return carrying, inert


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
        """'corps' | nom d'en-tête de réponse | '' — où le marqueur d'hôte est réfléchi.

        « Réfléchi DANS LE CORPS » veut dire qu'une URL y est CONSTRUITE depuis l'en-tête `Host`
        (`_host_echo_split`), pas qu'il s'y trouve recopié en toutes lettres : un pied de page
        auto-généré (`ServerSignature On`, défaut Debian) recopie le `Host` sur TOUTE page sans que
        rien ne soit construit — cf. le bloc de doctrine « écho décoratif » ci-dessus. Un écho
        purement inerte laisse donc la place à l'examen des EN-TÊTES, qui suit."""
        if _host_echo_split(body, marker)[0]:
            return "corps"
        for name in ("Location", "Content-Location", "Link", "Refresh"):
            for v in ClientFlowOracle._get_all(pairs, name):
                if marker in (v or ""):
                    return name
        return ""

    @classmethod
    def _is_canonical_redirect(cls, status, req_url, location, marker):
        """La 3xx observée est-elle la CANONICALISATION D'URL par défaut du serveur (cf. le bloc de
        doctrine ci-dessus) plutôt qu'une décision de l'application ?

        VRAI ssi les trois tiennent : (1) statut de redirection, (2) le `Location` pointe vers l'hôte
        MARQUEUR (le serveur a bien recopié notre en-tête), et (3) son chemin est celui de la requête
        AU SLASH FINAL PRÈS — donc la même ressource, seule l'autorité a changé. Aucune application ne
        « décide » cela : c'est la normalisation d'URI du serveur.

        FAUX dès que le chemin DIFFÈRE : `/account` -> `/login`, `/x` -> `/`, ou tout `Location`
        applicatif. Là, l'application a CHOISI une destination en s'appuyant sur un en-tête contrôlé
        par le client — c'est l'empoisonnement exploitable, et il reste promu. Pur, ne lève jamais."""
        try:
            if status is None or not (300 <= int(status) < 400):
                return False
        except (TypeError, ValueError):
            return False
        loc = str(location or "")
        if not marker or marker not in loc:
            return False
        try:
            lp = urllib.parse.urlsplit(loc)
            rp = urllib.parse.urlsplit(str(req_url or ""))
        except ValueError:            # URL hostile : on NE conclut PAS à la canonicalisation
            return False
        # L'hôte de destination doit être EXACTEMENT le marqueur : `http://<marker>.evil/…` n'est pas
        # une recopie, c'est une construction — on la laisse au chemin de promotion (fail-open vers la
        # DÉTECTION, jamais vers le silence).
        if (lp.hostname or "") != marker:
            return False
        return _same_path(lp.path, rp.path)

    @classmethod
    def _host_reflection(cls, status, req_url, pairs, body, marker):
        """(où, canonicalisation_seule) — où le marqueur d'hôte est réfléchi, et si ce reflet n'est
        QUE la canonicalisation d'URL par défaut du serveur (auquel cas `où` est vide : rien à promouvoir).

        Sur une canonicalisation constatée, l'ÉCHO est neutralisé des DEUX côtés — l'en-tête `Location`
        lui-même, et sa recopie dans le corps auto-généré de la page de redirection — puis on cherche un
        reflet RÉSIDUEL. Un résidu (corps applicatif, `Link`, `Refresh`…) est un VRAI reflet et repart
        sur le chemin de promotion : la neutralisation retire l'écho, jamais la preuve."""
        loc = cls._get(pairs, "Location") or ""
        if not cls._is_canonical_redirect(status, req_url, loc, marker):
            return cls._reflected_in(pairs, body, marker), False
        rest = [(k, v) for k, v in (pairs or []) if str(k).lower() != "location"]
        residual = cls._reflected_in(rest, (body or "").replace(loc, ""), marker)
        return residual, (not residual)

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

        # NORMALISATION scheme-less : une cible hôte nu / host:port n'a PAS de scheme -> la passer telle
        # quelle à urllib lèverait `unknown url type`. La requête de CONTRÔLE essaie les candidats
        # (http/https ordonnés par vraisemblance, cf. web_url_candidates) et FIXE la base sur la 1re
        # joignable ; les sondes host + la sonde CRLF (`_send_h(base=...)`) la réutilisent. URL déjà
        # formée -> 1 candidat (byte-identique). Aucun candidat joignable -> dégradation `skipped`.
        candidates = web_url_candidates(action.target) or [str(action.target)]
        base = candidates[0]

        # --- (b) HOST HEADER POISONING (CWE-644) — ne requiert AUCUN param ---
        mhost = self._marker(action.target, "host", "hostinj") + ".forge-hh.test"
        # contrôle : requête SANS en-tête d'hôte injecté -> le marqueur d'hôte ne doit PAS y apparaître.
        c_st, c_body, c_pairs = None, "", []
        for cand in candidates:
            c_st, c_body, c_pairs = self._fetch(cand, headers=dict(user_headers))
            base = cand
            if c_st is not None:
                break
        if c_st is not None:
            seen_network = True
        # NE PAS FAIRE SEMBLANT : contrôle rendu par le WAF -> les sondes host/CRLF qui suivent ne
        # toucheront jamais l'application. `skipped`, jamais `tested` (signature STRICTE).
        blocked = self._challenge_degraded(action, action.target, c_st, c_body, c_pairs)
        if blocked is not None:
            return [blocked]
        control_reflects_host = bool(self._reflected_in(c_pairs, c_body, mhost))
        host_confirmed, host_hdr, host_where = False, "", ""
        canonical_hdr = ""                # en-tête dont le SEUL reflet était une canonicalisation d'URL
        inert_hdr, inert_ctx = "", ""     # en-tête dont le SEUL reflet était un ÉCHO DÉCORATIF (corps)
        for hh in _HOST_HEADERS:
            probe_headers = dict(user_headers)
            probe_headers[hh] = mhost
            st, body, pairs = self._fetch(base, headers=probe_headers)
            if st is not None:
                seen_network = True
            # CANONICALISATION ÉCARTÉE (cf. doctrine ci-dessus) : une redirection de répertoire dont le
            # `Location` reflète l'hôte est le comportement PAR DÉFAUT du serveur, pas une vulnérabilité.
            # On NE `break` PAS dessus : un autre en-tête d'hôte peut, lui, produire un vrai reflet.
            loc, canonical = self._host_reflection(st, base, pairs, body, mhost)
            if canonical and not canonical_hdr:
                canonical_hdr = hh
            # ÉCHO DÉCORATIF ÉCARTÉ (cf. doctrine « écho décoratif ») : le corps recopie le `Host` en
            # TEXTE sans construire d'URL. On ne `break` pas non plus — un autre en-tête peut porter,
            # lui, un lien réellement construit ; et si l'un d'eux le fait, `loc` gagne (fail-open).
            if not loc and not inert_hdr:
                _carrying, _inert = _host_echo_split(body, mhost)
                if _inert:
                    inert_hdr, inert_ctx = hh, _inert
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
            _, st, _body, pairs = self._send_h(action, param, payload, method, base=base)
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
        # La canonicalisation écartée est NOMMÉE dans l'évidence : l'opérateur doit voir CE QUI a été
        # observé ET pourquoi ça n'a pas promu (une abstention muette serait le défaut symétrique).
        canon_note = (f"canonicalisation d'URL ÉCARTÉE (en-tête {canonical_hdr}) : la cible a répondu une "
                      f"REDIRECTION vers le MÊME chemin sur l'hôte injecté (comportement par défaut de "
                      f"quasi tout serveur web, mesuré sur Apache 2.4 ET Werkzeug 2.2) — normalisation "
                      f"d'URI, pas une décision applicative ; aucun reflet RÉSIDUEL hors l'écho du "
                      f"Location. Un `Location` vers un AUTRE chemin, ou le marqueur dans le corps/un "
                      f"autre en-tête, aurait promu"
                      if canonical_hdr and not host_confirmed else "")
        # Idem pour l'écho DÉCORATIF : ce qui a été OBSERVÉ, et pourquoi ça n'a pas promu.
        inert_note = (f"écho DÉCORATIF ÉCARTÉ (en-tête {inert_hdr}) : le corps recopie le `Host` en "
                      f"TEXTE INERTE ({inert_ctx[:160]}) — signature/pied de page auto-généré "
                      f"(`ServerSignature On` est le défaut Debian d'Apache, mesuré sur DVWA) ; AUCUNE "
                      f"URL n'est CONSTRUITE depuis l'en-tête (0 occurrence en position d'autorité "
                      f"d'URI : ni href/src/action, ni lien absolu). Un lien de réinitialisation "
                      f"absolu, un `<base href>`, une ressource chargée depuis l'hôte injecté — ou le "
                      f"marqueur dans `Location`/`Link`/`Refresh` — auraient promu"
                      if inert_hdr and not host_confirmed else "")
        return [self.proof(
            target=action.target, proven=proven,
            title=("Header-Injection CONFIRMÉE — " + which if proven
                   else "Header-Injection non confirmée — ni CRLF ni host poisoning (pas de verdict aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"voie(s)={which} ; CRLF: en-tête témoin '{_CRLF_HEADER_NAME}' matérialisé={crlf_confirmed} ; "
                      f"HOST: en-tête={host_hdr or '—'} reflet={host_where or 'aucun'} "
                      f"réflexion_contrôle={control_reflects_host} (si vrai -> non concluant) ; "
                      + (canon_note + " ; " if canon_note else "")
                      + (inert_note + " ; " if inert_note else "")
                      + "marqueur BÉNIGN "
                      "inerte (aucun Set-Cookie/session tamperé) ; non destructif ; session gouvernée non journalisée"),
            poc=(f"# CRLF: {action.params.get('param', '<param>')}=…%0d%0a{_CRLF_HEADER_NAME}:<token> ; "
                 f"HOST: -H 'X-Forwarded-Host: {mhost}' sur {base}\n"
                 f"# PREUVE = en-tête bénin '{_CRLF_HEADER_NAME}' matérialisé OU marqueur d'hôte reflété "
                 f"(diff vs contrôle) ; marqueur inerte"))]

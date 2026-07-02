"""Modules PASSIFS de cartographie de surface d'attaque — énumération en lecture seule, verrouillée
au périmètre, NON destructive et sans exploitation.

Cinq modules, calqués sur le pattern de `recon.py` (wrappers d'outils) et `origin.py` (re-validation
fail-closed du périmètre sur les hôtes DÉCOUVERTS à runtime) :

  - recon.subdomains  : énumère les sous-domaines des racines IN-SCOPE via sources passives
                        (certificate transparency crt.sh + passive DNS optionnel), STRICTEMENT
                        verrouillé aux racines déclarées (T1590).
  - recon.dns         : résout A/AAAA/CNAME/MX/TXT/NS des hôtes in-scope (dnspython > dig > socket) (T1590.002).
  - recon.js_endpoints: récupère les pages in-scope et extrait routes/URLs d'API référencées dans
                        leur JavaScript — cartographie de surface, jamais appelée (T1594).
  - recon.urls        : découverte passive d'URLs historiques (Wayback CDX / CommonCrawl) pour les
                        hôtes in-scope, filtrée aux racines déclarées (T1596).
  - recon.tech        : fingerprint techno depuis les réponses HTTP (Server/X-Powered-By/cookies/
                        meta), enrichi par httpx -tech-detect si disponible (T1592.002).

DISCIPLINE (héritée de recon.py + origin.py + la base Oracle) :
  - exploit=False, destructive=False : lecture/énumération seule — AUCUNE exploitation, aucune mutation.
  - ROE / scope-guard : la cible (`action.target`) est gatée en amont par l'engine (Couche 2,
    in-scope fail-closed). En profondeur, CHAQUE hôte découvert ou dérivé à runtime est RE-VALIDÉ
    fail-closed contre le périmètre (miroir de `origin.find`) : l'engine injecte `in_scope`/`out_scope`
    dans `action.params` ; tout hôte hors périmètre est ÉCARTÉ (jamais émis, jamais requêté). Sans
    scope injecté (appel direct dev/test), on ne connecte pas hors des racines fournies.
  - Dégradation gracieuse : source/outil optionnel ou réseau indisponible -> finding `status='skipped'`
    (INFO) au lieu d'un crash — la suite de tests offline reste verte.
  - Modèle à preuve : findings de surface informatifs (`status='tested'`, sévérité INFO) ; jamais de
    promotion en `vulnerable` (pas de preuve d'exploitabilité — c'est de la cartographie).

Zéro dépendance obligatoire (stdlib : urllib/socket/re/json) ; dnspython/dig/httpx sont OPTIONNELS
et leur absence dégrade proprement. Tout accès réseau passe par un seam monkeypatchable
(`_http_get` / `_resolve_all`) : les tests unitaires mockent le réseau (hermétiques).
"""
import json
import re
import shutil
import socket
import urllib.error
import urllib.parse
import urllib.request

from .registry import register, Module
from .. import runner
from .. import session as _session
from .. import techniques
from ..roe import Scope


# --- helpers de périmètre (hôte canonique / racine / containment hiérarchique) ----------------------
def _host_only(value):
    """Hôte canonique (scheme/port/path/userinfo retirés, casefold) — délègue à Scope._host."""
    return Scope._host(value)


def _root_of(pattern):
    """Racine enregistrable approx. d'un motif de scope : hôte canonique, wildcard `*.` retiré.
    (`https://*.app.test:443/x` -> `app.test`). Sert à verrouiller les hôtes découverts aux racines."""
    h = _host_only(pattern)
    return h[2:] if h.startswith("*.") else h


def _under(host, root):
    """True si `host` est la racine `root` ou un sous-domaine de `root` (containment hiérarchique)."""
    return bool(root) and (host == root or host.endswith("." + root))


class PassiveSurface(Module):
    """Base des modules passifs de surface : plomberie Finding + HTTP + périmètre partagée.

    Un module concret déclare ses métadonnées (kind/mitre/tool/description) et surcharge `fire()`
    (et `dry()`). Tout accès réseau passe par `_http_get` (seam monkeypatché par les tests)."""

    exploit = False          # énumération : jamais d'exploitation
    destructive = False      # lecture seule : aucune mutation
    web_allowed = True       # interaction web (réseau) -> gardée par le ROE
    available = True         # stdlib (urllib/socket) -> toujours disponible ; dégrade à runtime
    category = "recon"       # catégorie de finding (comme recon.httpx) ; pas de CWE (surface, pas vuln)
    mitre = ""
    tool = ""

    # --- périmètre : lecture du scope injecté + gardes fail-closed ---
    @staticmethod
    def _scope(action):
        """(enforce, Scope) reconstruit depuis les params injectés par l'engine. `enforce` distingue
        « scope fourni » (chemin de production) de « appelé en direct sans scope » (dev/test)."""
        enforce = "in_scope" in action.params or "out_scope" in action.params
        sc = Scope({"in_scope": action.params.get("in_scope", []),
                    "out_scope": action.params.get("out_scope", [])})
        return enforce, sc

    def _roots(self, action):
        return [r for r in (_root_of(p) for p in action.params.get("in_scope", [])) if r]

    def _out_roots(self, action):
        return [r for r in (_root_of(p) for p in action.params.get("out_scope", [])) if r]

    def _in_scope_flat(self, action, host):
        """Appartenance PLATE (miroir exact de la gate ROE de l'engine) pour un hôte requêté :
        l'engine n'a fait tirer l'action que si `is_in_scope(target)` — on applique la même règle.
        Sans scope injecté (dev/test) -> permissif (l'engine injecte TOUJOURS en production)."""
        enforce, sc = self._scope(action)
        if not enforce:
            return True
        return sc.is_in_scope(host)

    def _target_allowed(self, action):
        return self._in_scope_flat(action, action.target)

    def _host_in_scope(self, action, host):
        """Verrou STRICT des hôtes DÉCOUVERTS aux racines déclarées : un hôte est conservé s'il est
        (sous-)domaine d'une racine in-scope ET n'est pas exclu par out_scope. Repli sur la gate plate
        pour les entrées in_scope explicites (hôte exact / glob). Fail-closed : sans scope -> écarté."""
        h = _host_only(host)
        if not h:
            return False
        if any(_under(h, r) for r in self._out_roots(action)):
            return False                                    # exclusion out_scope l'emporte
        if any(_under(h, r) for r in self._roots(action)):
            return True                                     # sous-domaine d'une racine déclarée
        enforce, sc = self._scope(action)
        return bool(enforce) and sc.is_in_scope(h)          # hôte/glob in_scope explicite

    # --- HTTP partagé (seam monkeypatché par les tests — aucun réseau réel en test) ---
    @staticmethod
    def _http_get(url, headers=None, timeout=20, maxlen=500000):
        """GET urllib partagé -> (status, body, headers_dict).
        - succès       : (r.status, corps décodé tronqué, dict d'en-têtes minuscule-insensible) ;
        - HTTPError    : (code, "", en-têtes|{}) ;
        - transport KO : (None, "", {}) — réseau indisponible, on ne crashe jamais (offline-safe).

        SESSION GOUVERNÉE : si un `SessionStore` est lié (moteur, autour de fire()), le matériel d'auth
        SECRET applicable à `url` — et UNIQUEMENT si `url` est IN-SCOPE (scope-guard du store) — est
        fusionné SOUS les en-têtes de l'appelant. Jamais renvoyé, jamais exposé dans un finding (les
        findings recon dérivent de la RÉPONSE). Sans store lié -> aucune modification (byte-à-byte)."""
        req_headers = dict(headers or {"User-Agent": "forge-surface"})
        store = _session.current()
        if store is not None:                            # scope-guard PAR-URL : {} si url hors-scope
            for k, v in store.headers_for(url).items():
                req_headers.setdefault(k, v)             # les en-têtes explicites de l'appelant priment
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(maxlen).decode("utf-8", "replace")
                return r.status, body, {k: v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            try:
                return e.code, "", {k: v for k, v in e.headers.items()}
            except Exception:                               # noqa: BLE001
                return e.code, "", {}
        except Exception:                                   # noqa: BLE001  (transport hostile)
            return None, "", {}

    @staticmethod
    def _url(target):
        """Assure un scheme (défaut https) pour une cible nue (`app.test` -> `https://app.test`)."""
        return target if "://" in str(target) else "https://" + str(target)

    # --- construction de Finding (informatif de surface / dégradation skipped) ---
    def _finding(self, target, title, evidence, poc, status="tested", severity="INFO"):
        return self.finding(
            target=target, title=title, severity=severity, category=self.category,
            mitre=self.mitre, status=status, tool=self.tool,
            evidence=(evidence or "")[:1800], poc=poc)

    def _skipped(self, target, title, evidence, poc):
        """Dégradation gracieuse : source/outil/réseau indisponible -> INFO `status='skipped'`."""
        return self._finding(target, title, evidence, poc, status="skipped")

    def dry(self, action):
        raise NotImplementedError

    def fire(self, action):
        raise NotImplementedError


# =================================================================================================
@register("recon.subdomains")
class SubdomainEnum(PassiveSurface):
    kind = "recon.subdomains"
    mitre = techniques.mitre_for("recon.subdomains")        # T1590 (source de vérité : techniques.py)
    tool = "forge/modules/recon_surface.py:recon.subdomains"
    description = ("Énumération PASSIVE de sous-domaines (certificate transparency crt.sh + passive "
                   "DNS optionnel), STRICTEMENT verrouillée aux racines in-scope. Découverte informative (T1590).")
    MAX_HOSTS = 500

    def _sources(self, domain, action):
        """(nom, url) des sources passives à interroger. crt.sh (CT) par défaut ; passive DNS via un
        gabarit d'URL optionnel `params.passive_dns_url` (contenant `{domain}`)."""
        srcs = [("crt.sh", f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json")]
        tmpl = action.params.get("passive_dns_url")
        if tmpl:
            try:
                srcs.append(("passive_dns", tmpl.format(domain=domain)))
            except Exception:                               # noqa: BLE001
                pass
        return srcs

    def dry(self, action):
        return (f"# passif : crt.sh CT + passive DNS pour %.{action.target} ; "
                f"filtrer STRICTEMENT aux racines in-scope (hôtes hors périmètre jamais émis)")

    def fire(self, action):
        domain = action.target
        if not self._target_allowed(action):
            return [self._skipped(domain, "recon.subdomains non exécuté — cible hors périmètre (fail-closed)",
                                  "La cible n'appartient pas au périmètre in-scope ; aucune requête émise.",
                                  self.dry(action))]
        discovered, reached, tried = set(), 0, []
        for name, url in self._sources(domain, action):
            tried.append(name)
            st, body, _ = self._http_get(url, timeout=action.params.get("timeout", 20))
            if st is None:
                continue                                    # source injoignable -> on tente la suivante
            reached += 1
            discovered |= self._parse(body)
        if reached == 0:
            return [self._skipped(domain, "recon.subdomains non concluant — sources passives injoignables",
                                  f"Aucune source atteinte ({', '.join(tried) or 'aucune'}) — réseau/source indisponible.",
                                  self.dry(action))]
        # VERROU périmètre : ne garder que les (sous-)domaines des racines déclarées, hors out_scope.
        in_scope_hosts = sorted(h for h in discovered if self._host_in_scope(action, h))
        filtered = len(discovered) - len(in_scope_hosts)
        findings = [self._finding(
            domain, f"Sous-domaines découverts (passif) : {len(in_scope_hosts)} in-scope",
            (f"{len(in_scope_hosts)} sous-domaine(s) in-scope via {', '.join(tried)} "
             f"({filtered} hors périmètre écarté(s), jamais émis). "
             f"Exemples : {', '.join(in_scope_hosts[:40]) or '—'}"),
            self.dry(action))]
        for h in in_scope_hosts[:self.MAX_HOSTS]:           # un finding informatif par hôte (enrichit le graphe)
            findings.append(self._finding(
                h, f"Sous-domaine in-scope : {h}",
                f"Découvert via source(s) passive(s) {', '.join(tried)} ; racine {domain}.",
                f"# hôte passif in-scope ; vérifier : dig +short {h}"))
        return findings

    @staticmethod
    def _parse(body):
        """Extrait un set d'hôtes d'une réponse crt.sh (JSON array OU objets ligne-à-ligne) ou d'un
        flux texte passive-DNS générique (un hôte par ligne/jeton). Robuste, ne lève jamais."""
        hosts = set()
        if not body:
            return hosts

        def _add(v):
            for line in str(v).splitlines():
                h = line.strip().lstrip("*.").casefold()
                if h and "." in h and "@" not in h and "/" not in h and " " not in h:
                    hosts.add(h)

        parsed = None
        try:
            parsed = json.loads(body)
        except ValueError:
            rows = []                                        # crt.sh « legacy » : un objet JSON / ligne
            for line in body.splitlines():
                line = line.strip().rstrip(",")
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    rows = None
                    break
            parsed = rows
        if isinstance(parsed, list):
            for e in parsed:
                if isinstance(e, dict):
                    for key in ("name_value", "common_name", "name", "hostname"):
                        if e.get(key):
                            _add(e[key])
                elif isinstance(e, str):
                    _add(e)
            return hosts
        for tok in re.split(r"[\s,]+", body):                # flux texte générique
            _add(tok)
        return hosts


# =================================================================================================
@register("recon.dns")
class DnsRecords(PassiveSurface):
    kind = "recon.dns"
    mitre = techniques.mitre_for("recon.dns")               # T1590.002
    tool = "forge/modules/recon_surface.py:recon.dns"
    description = ("Résolution DNS (A/AAAA/CNAME/MX/TXT/NS) des hôtes in-scope. Backend dnspython > "
                   "dig > socket (A/AAAA seul) ; résolution impossible -> skipped (T1590.002).")
    RTYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")

    def _hosts(self, action):
        """Cible + hôtes additionnels (`params.hosts`), dédupliqués en préservant l'ordre."""
        raw = [action.target] + [h for h in (action.params.get("hosts") or []) if h]
        seen, out = set(), []
        for h in raw:
            if h not in seen:
                seen.add(h)
                out.append(h)
        return out

    def dry(self, action):
        return f"# résolution {'/'.join(self.RTYPES)} pour {action.target} (dnspython | dig | socket)"

    def fire(self, action):
        if not self._target_allowed(action):
            return [self._skipped(action.target, "recon.dns non exécuté — cible hors périmètre (fail-closed)",
                                  "Cible hors in-scope ; aucune résolution émise.", self.dry(action))]
        findings = []
        for host in self._hosts(action):
            if not self._in_scope_flat(action, host):        # verrou fail-closed sur la liste d'hôtes
                findings.append(self._skipped(
                    host, f"recon.dns — hôte hors périmètre écarté : {host}",
                    "Hôte hors in-scope ; non résolu (fail-closed).", self.dry(action)))
                continue
            records, backend, ok = self._resolve_all(host, self.RTYPES)
            if not ok:
                findings.append(self._skipped(
                    host, f"recon.dns non concluant — résolution indisponible ({host})",
                    f"Backend '{backend}' indisponible ou échec (réseau ou outil DNS absent).", self.dry(action)))
                continue
            lines = []
            for rt in self.RTYPES:
                vals = records.get(rt) or []
                if vals:
                    lines.append(f"{rt}: {', '.join(vals[:12])}")
            evidence = f"backend={backend} ; " + (" | ".join(lines) if lines else "aucun enregistrement")
            findings.append(self._finding(
                host, f"Enregistrements DNS — {host}", evidence,
                f"dig +short A/AAAA/CNAME/MX/TXT/NS {host}"))
        return findings

    @staticmethod
    def _resolve_all(host, rtypes):
        """(records: dict[str,list[str]], backend: str, ok: bool). ok=False => résolution impossible
        (réseau/outil) -> l'appelant émet `skipped`. Backends, dans l'ordre : dnspython > dig > socket.
        Seam monkeypatché par les tests (aucun réseau réel en test). Ne lève jamais."""
        # 1) dnspython (optionnel) — tous les types d'enregistrement
        try:
            import dns.resolver as _dnsr                     # noqa: WPS433
            records, any_ok = {}, False
            for rt in rtypes:
                try:
                    ans = _dnsr.resolve(host, rt, lifetime=8)
                    records[rt] = [x.to_text().strip() for x in ans]
                    if records[rt]:
                        any_ok = True
                except Exception:                            # noqa: BLE001 (NXDOMAIN/NoAnswer/timeout par type)
                    records[rt] = []
            return records, "dnspython", any_ok
        except ImportError:
            pass
        except Exception:                                    # noqa: BLE001
            pass
        # 2) dig (optionnel) — tous les types via +short
        if shutil.which("dig"):
            records, any_ok = {}, False
            for rt in rtypes:
                rc, out, _ = runner.tool("dig", None, ["+short", rt, host], timeout=15)
                if rc == 127:                                # dig disparu entre-temps -> repli socket
                    break
                vals = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
                records[rt] = vals
                if vals:
                    any_ok = True
            else:
                return records, "dig", any_ok
        # 3) socket (toujours présent) — A/AAAA uniquement
        records = {rt: [] for rt in rtypes}
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
                ip = sockaddr[0]
                if fam == socket.AF_INET and ip not in records["A"]:
                    records["A"].append(ip)
                elif fam == socket.AF_INET6 and ip not in records["AAAA"]:
                    records["AAAA"].append(ip)
            return records, "socket", bool(records["A"] or records["AAAA"])
        except Exception:                                    # noqa: BLE001 (réseau/NXDOMAIN)
            return records, "socket", False


# =================================================================================================
@register("recon.js_endpoints")
class JsEndpoints(PassiveSurface):
    kind = "recon.js_endpoints"
    mitre = techniques.mitre_for("recon.js_endpoints")      # T1594
    tool = "forge/modules/recon_surface.py:recon.js_endpoints"
    description = ("Récupère les pages in-scope et extrait routes/URLs d'API référencées dans leur "
                   "JavaScript (cartographie de surface). Endpoints jamais appelés (T1594).")
    MAX_JS = 12
    _SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
    _URL = re.compile(r'https?://[^\s"\'`<>()\\]{4,}')
    _PATH_API = re.compile(r'''["'`](/(?:api|v\d+|graphql|gql|rest|internal|admin|auth|oauth|'''
                           r'''user|users|account|accounts|session)[a-zA-Z0-9_\-./]*)["'`]''')
    _PATH_ANY = re.compile(r'["\'`](/[a-zA-Z0-9_\-./]{2,})["\'`]')

    def dry(self, action):
        return (f"# GET {action.target} + fichiers JS in-scope ; extraire routes/URLs d'API par regex "
                f"(cartographie — jamais appelées)")

    def fire(self, action):
        page = action.target
        if not self._target_allowed(action):
            return [self._skipped(page, "recon.js_endpoints non exécuté — cible hors périmètre (fail-closed)",
                                  "Cible hors in-scope ; aucune requête émise.", self.dry(action))]
        st, html, _ = self._http_get(self._url(page), timeout=action.params.get("timeout", 20))
        if st is None:
            return [self._skipped(page, "recon.js_endpoints non concluant — page injoignable",
                                  "La page in-scope n'a pu être récupérée (réseau indisponible).", self.dry(action))]
        texts = [html or ""]
        # fichiers JS référencés (<script src>) — UNIQUEMENT même périmètre in-scope (verrou STRICT
        # fail-closed sur l'hôte : jamais récupérer un JS hors des racines déclarées), bornés.
        js_urls = []
        for src in self._SCRIPT_SRC.findall(html or ""):
            absu = urllib.parse.urljoin(self._url(page), src)
            if absu.startswith("http") and self._host_in_scope(action, _host_only(absu)):
                js_urls.append(absu)
        for ju in js_urls[:self.MAX_JS]:
            jst, jbody, _ = self._http_get(ju, timeout=action.params.get("timeout", 20))
            if jst is not None and jbody:
                texts.append(jbody)
        # extraction : routes/paths + URLs absolues (classées in-scope vs externes, jamais appelées).
        paths, ext_urls, inscope_urls = set(), set(), set()
        for t in texts:
            for rx in (self._PATH_API, self._PATH_ANY):
                for p in rx.findall(t):
                    paths.add(p)
            for u in self._URL.findall(t):
                u = u.rstrip('\\",\')')
                (inscope_urls if self._host_in_scope(action, _host_only(u)) else ext_urls).add(u)
        sorted_paths = sorted(paths)
        if not (sorted_paths or inscope_urls or ext_urls):
            return [self._finding(page, "recon.js_endpoints — aucun endpoint extrait",
                                  "Aucune route/URL d'API détectée dans le JS de la page.", self.dry(action))]
        evidence = (f"routes/paths ({len(paths)}) : {', '.join(sorted_paths[:60]) or '—'} || "
                    f"URLs in-scope ({len(inscope_urls)}) : {', '.join(sorted(inscope_urls)[:20]) or '—'} || "
                    f"URLs externes non appelées ({len(ext_urls)}) : {', '.join(sorted(ext_urls)[:10]) or '—'}")
        return [self._finding(
            page, f"Endpoints extraits du JS : {len(paths) + len(inscope_urls)} in-scope",
            evidence, self.dry(action))]


# =================================================================================================
@register("recon.urls")
class HistoricalUrls(PassiveSurface):
    kind = "recon.urls"
    mitre = techniques.mitre_for("recon.urls")              # T1596
    tool = "forge/modules/recon_surface.py:recon.urls"
    description = ("Découverte PASSIVE d'URLs historiques (Wayback CDX / CommonCrawl) pour les hôtes "
                   "in-scope, filtrée aux racines déclarées. Aucune URL n'est requêtée (T1596).")
    MAX_URLS = 800

    def _sources(self, domain, action):
        limit = action.params.get("limit", 2000)
        srcs = [("wayback",
                 f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(domain)}/*"
                 f"&output=json&fl=original&collapse=urlkey&limit={limit}")]
        cc = action.params.get("commoncrawl_url")            # gabarit optionnel avec `{domain}`
        if cc:
            try:
                srcs.append(("commoncrawl", cc.format(domain=domain)))
            except Exception:                                # noqa: BLE001
                pass
        return srcs

    def dry(self, action):
        return (f"# passif : Wayback CDX / CommonCrawl pour {action.target}/* "
                f"(filtré STRICTEMENT aux racines in-scope)")

    def fire(self, action):
        domain = action.target
        if not self._target_allowed(action):
            return [self._skipped(domain, "recon.urls non exécuté — cible hors périmètre (fail-closed)",
                                  "Cible hors in-scope ; aucune requête émise.", self.dry(action))]
        found, reached, tried = set(), 0, []
        for name, url in self._sources(domain, action):
            tried.append(name)
            st, body, _ = self._http_get(url, timeout=action.params.get("timeout", 25))
            if st is None:
                continue
            reached += 1
            found |= self._parse(body)
        if reached == 0:
            return [self._skipped(domain, "recon.urls non concluant — archives injoignables",
                                  f"Aucune source atteinte ({', '.join(tried) or 'aucune'}) — réseau indisponible.",
                                  self.dry(action))]
        in_scope_urls = sorted(u for u in found if self._host_in_scope(action, _host_only(u)))
        filtered = len(found) - len(in_scope_urls)
        return [self._finding(
            domain, f"URLs historiques (passif) : {len(in_scope_urls)} in-scope",
            (f"{len(in_scope_urls)} URL(s) in-scope via {', '.join(tried)} "
             f"({filtered} hors périmètre écartée(s)). Exemples : {', '.join(in_scope_urls[:40]) or '—'}"),
            self.dry(action))]

    @staticmethod
    def _parse(body):
        """URLs d'une réponse Wayback CDX (JSON : lignes de listes, 1ère = en-tête) ou d'un flux texte
        (une URL par ligne). Robuste, ne lève jamais."""
        urls = set()
        if not body:
            return urls
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        if isinstance(data, list):
            for row in data:
                if isinstance(row, list) and row:
                    v = str(row[0]).strip()
                    if v.lower() == "original":              # ligne d'en-tête CDX
                        continue
                    if v.startswith("http"):
                        urls.add(v)
                elif isinstance(row, str) and row.strip().startswith("http"):
                    urls.add(row.strip())
            return urls
        for line in body.splitlines():                       # flux texte générique
            line = line.strip()
            if line.startswith("http"):
                urls.add(line)
        return urls


# =================================================================================================
@register("recon.tech")
class TechFingerprint(PassiveSurface):
    kind = "recon.tech"
    mitre = techniques.mitre_for("recon.tech")              # T1592.002
    tool = "forge/modules/recon_surface.py:recon.tech"
    description = ("Fingerprint techno depuis les réponses HTTP (Server/X-Powered-By/cookies/meta) ; "
                   "enrichi par httpx -tech-detect si disponible. Passif, in-scope seulement (T1592.002).")
    HX, HX_IMG = "httpx", "projectdiscovery/httpx"
    _HEADER_SIGS = {
        "server": "Server", "x-powered-by": "X-Powered-By", "via": "Via", "x-generator": "X-Generator",
        "x-aspnet-version": "ASP.NET", "x-aspnetmvc-version": "ASP.NET MVC",
        "x-drupal-cache": "Drupal", "x-drupal-dynamic-cache": "Drupal", "x-shopify-stage": "Shopify",
        "x-vercel-id": "Vercel", "x-served-by": "Varnish/Fastly", "cf-ray": "Cloudflare",
        "x-amz-cf-id": "AWS CloudFront", "x-envoy-upstream-service-time": "Envoy",
    }
    _VALUE_HEADERS = ("server", "x-powered-by", "via", "x-generator")
    _COOKIE_SIGS = {
        "phpsessid": "PHP", "jsessionid": "Java/JSP", "asp.net_sessionid": "ASP.NET",
        "aspxauth": "ASP.NET", "laravel_session": "Laravel", "_rails": "Ruby on Rails",
        "connect.sid": "Node/Express", "csrftoken": "Django", "sessionid": "Django",
    }
    _BODY_SIGS = [
        ("wp-content", "WordPress"), ("wp-includes", "WordPress"),
        ('name="generator" content="drupal', "Drupal"), ("__next_data__", "Next.js"),
        ("/_nuxt/", "Nuxt.js"), ("ng-version", "Angular"), ("data-reactroot", "React"),
        ("__react", "React"),
    ]

    def dry(self, action):
        return (f"# GET {action.target} -> analyse Server/X-Powered-By/cookies/meta "
                f"(+ httpx -tech-detect si disponible)")

    def fire(self, action):
        target = action.target
        if not self._target_allowed(action):
            return [self._skipped(target, "recon.tech non exécuté — cible hors périmètre (fail-closed)",
                                  "Cible hors in-scope ; aucune requête émise.", self.dry(action))]
        techs, evidence_bits = set(), []
        st, body, headers = self._http_get(self._url(target), timeout=action.params.get("timeout", 20))
        if st is not None:
            low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
            for hk, label in self._HEADER_SIGS.items():
                if hk in low:
                    techs.add(f"{label}={low[hk]}" if hk in self._VALUE_HEADERS else label)
            setc = low.get("set-cookie", "").lower()
            for ck, label in self._COOKIE_SIGS.items():
                if ck in setc:
                    techs.add(label)
            bl = (body or "").lower()
            for sig, label in self._BODY_SIGS:
                if sig in bl:
                    techs.add(label)
            evidence_bits.append(
                f"HTTP {st} ; Server={low.get('server', '—')} ; X-Powered-By={low.get('x-powered-by', '—')}")
        # enrichissement OPTIONNEL par httpx -tech-detect (si binaire/docker présent et non désactivé).
        if action.params.get("use_httpx", True) and runner.available(self.HX, self.HX_IMG, prefer_docker=True):
            rc, out, _ = runner.tool(
                self.HX, self.HX_IMG,
                ["-u", self._url(target), "-tech-detect", "-silent", "-json", "-no-color"],
                timeout=60, prefer_docker=True)
            if rc == 0 and out:
                evidence_bits.append("httpx: " + out.strip()[:400])
                for line in out.splitlines():
                    try:
                        j = json.loads(line)
                    except ValueError:
                        continue
                    for t in (j.get("tech") or j.get("technologies") or []):
                        techs.add(str(t))
        if st is None and not techs:                         # aucune réponse HTTP ET pas de httpx -> dégradé
            return [self._skipped(target, "recon.tech non concluant — cible injoignable et httpx indisponible",
                                  "Aucune réponse HTTP et pas de httpx pour le fingerprint (dégradation).",
                                  self.dry(action))]
        return [self._finding(
            target, f"Fingerprint techno : {len(techs)} signature(s)",
            (", ".join(sorted(techs)) or "aucune signature détectée")
            + (" || " + " ; ".join(evidence_bits) if evidence_bits else ""),
            self.dry(action))]

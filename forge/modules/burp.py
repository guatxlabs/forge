"""Connecteur Burp Suite (`burp.scan`) — PILOTE la REST API de Burp, ne fabrique aucun payload.

Forge n'ajoute pas de capacité offensive : il PARLE à la REST API de Burp Suite Professional/
Enterprise (un outil de pentest STANDARD que l'opérateur exécute déjà), lance un scan sur les URL
in-scope, sonde l'état, rapatrie les `issues` et les MAPPE en Finding(s). C'est de la GOUVERNANCE
+ de l'AUDIT autour d'un outil existant : Burp produit les résultats, Forge les normalise et les
journalise derrière la gate ROE.

Transport : REST stdlib (urllib). POST {BURP_API_URL}/v0.1/scan {urls, scope, ...} -> Location/id ;
GET {BURP_API_URL}/v0.1/scan/{id} -> {scan_status, scan_metrics, issue_events|issues}.
Config via env : BURP_API_URL (ex http://127.0.0.1:1337/{BURP_API_KEY}), BURP_API_KEY.

SCAN AUTHENTIFIÉ GOUVERNÉ (LOT INTÉGRATION) — les vulns à fort impact vivent DERRIÈRE le login. Ce
connecteur pilote donc un scan ACTIF AUTHENTIFIÉ en réutilisant la SESSION gouvernée de l'opérateur
(cookies / en-têtes / bearer portés par `forge.session.SessionStore`, lié par le moteur autour de
fire()). Le matériel de session est injecté DANS LA SEULE requête de lancement sortante vers le Burp
REST de l'opérateur (`request_headers`), pour que Burp attache ces en-têtes à ses requêtes in-scope
et audite les surfaces derrière authentification. Quatre garde-fous DURS :

  (1) SCOPE-GUARD — défense en profondeur AU-DELÀ du ROE : on ne soumet à Burp QUE les URL in-scope
      (le scope du store fait foi). Une URL hors-scope (dérivée à runtime, chaînée, découverte) est
      ÉCARTÉE ; si AUCUNE URL in-scope ne subsiste, le scan est REFUSÉ (status=skipped) sans le
      moindre I/O vers Burp. Le matériel de session ne peut PHYSIQUEMENT pas quitter le périmètre
      (headers_for renvoie {} hors-scope).
  (2) SESSION SECRÈTE — le matériel d'auth n'entre JAMAIS dans un finding, un PoC/dry, ni le ledger.
      Il ne part que dans la requête de lancement (vers le Burp LOCAL de l'opérateur). L'evidence des
      issues est RÉDIGÉE : toute valeur de session éventuellement renvoyée par Burp (requête rejouée)
      est remplacée par `<redacted-session>`. dry()/notes n'exposent QUE des compteurs.
  (3) NON DESTRUCTIF par défaut — le scan reste intrusif mais non destructif par contrat. Les options
      de scan INTRUSIVES/agressives (audit actif « all/aggressive/intrusive ») ne sont activées QUE si
      l'opt-in exploit gouverné est armé (scope.allow_exploit). Sinon elles sont SUPPRIMÉES et un
      finding ne peut JAMAIS être élevé à exploit/destructif (au plus `reported_by_tool`, comme nuclei).
  (4) DÉGRADATION GRACIEUSE — Burp REST injoignable => status=skipped (offline-safe), jamais un plantage.

Gouvernance (héritée automatiquement de l'engine/ROE autour de fire(), NON contournée) :
  - exploit=False : un active-scan web n'est pas un exploit ciblé (pas d'accès à l'objet d'autrui ;
    la promotion en `vulnerable` reste réservée aux oracles à preuve de Forge — ici on émet
    `reported_by_tool`, comme nuclei).
  - destructive=False : le scan est intrusif mais non destructif par contrat.
  - web_allowed=True : c'est une activité de SCAN WEB (recon/scan actif) sur des URL in-scope.

`available` SONDE l'API à fire-time (GET /v0.1/, jamais figé au catalogue).
"""
import json
import os
import time
import urllib.error
import urllib.request

from .registry import register, Module
from .. import session as _session
from .. import techniques
from ..schema import extract_cwe

# mapping sévérité Burp -> sévérité Forge (Burp: high/medium/low/info[rmation])
_SEV = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW",
        "info": "INFO", "information": "INFO", "false_positive": "INFO"}

# Classes d'issue Burp bien connues (PortSwigger) -> CWE canonique. Sert de repli quand l'issue ne
# porte pas explicitement un « CWE-NNN » : le CWE rejoint alors la table ATT&CK (mitre_for_cwe) et la
# remédiation par défaut (schema.default_fix_for). Ordre = plus spécifique d'abord.
_NAME_CWE = (
    ("sql injection", "CWE-89"),
    ("os command injection", "CWE-78"),
    ("command injection", "CWE-78"),
    ("server-side template injection", "CWE-1336"),
    ("server-side request forgery", "CWE-918"),
    ("ssrf", "CWE-918"),
    ("xml external entity", "CWE-611"),
    ("xxe", "CWE-611"),
    ("cross-site scripting", "CWE-79"),
    ("xss", "CWE-79"),
    ("cross-site request forgery", "CWE-352"),
    ("csrf", "CWE-352"),
    ("file path traversal", "CWE-22"),
    ("path traversal", "CWE-22"),
    ("directory traversal", "CWE-22"),
    ("open redirection", "CWE-601"),
    ("open redirect", "CWE-601"),
    ("xpath injection", "CWE-643"),
    ("ldap injection", "CWE-90"),
)
# Champs d'issue susceptibles de contenir un identifiant « CWE-NNN » explicite (classifications HTML,
# description, remédiation…). On les scanne AVANT de retomber sur la map par nom.
_CWE_FIELDS = ("cwe", "vulnerability_classifications", "classifications",
               "description", "remediation", "issue_background", "name")

# Jetons de nom de configuration de scan considérés INTRUSIFS/agressifs -> gatés derrière allow_exploit.
_INTRUSIVE_TOKENS = ("all", "active", "intrusive", "aggressive", "exploit")
# Config nommée que Forge ajoute quand l'opérateur opte pour l'audit intrusif (allow_exploit armé).
_INTRUSIVE_CONFIG = "Audit checks - all"


def _cfg(action=None):
    p = (action.params if action is not None else None) or {}
    return {
        "url": (p.get("burp_api_url") or os.environ.get("BURP_API_URL", "http://127.0.0.1:1337")).rstrip("/"),
        "key": p.get("burp_api_key") or os.environ.get("BURP_API_KEY", "") or None,
    }


def _base(cfg):
    """Burp préfixe l'API par la clé dans le path : {url}/{key}. Sans clé -> {url} nu."""
    return f"{cfg['url']}/{cfg['key']}" if cfg.get("key") else cfg["url"]


def _req(method, url, body=None, timeout=30):
    """Requête REST stdlib. Renvoie (status, parsed_json|texte, headers). Ne lève pas sur 4xx/5xx.
    status=0 => transport injoignable (URLError) : le service Burp est absent (dégradation gracieuse)."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, _maybe_json(raw), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else str(e)
        return e.code, _maybe_json(raw), dict(getattr(e, "headers", {}) or {})
    except urllib.error.URLError as e:
        return 0, str(e.reason), {}


def _maybe_json(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _as_list(v):
    """None|str CSV|list -> list[str] non vides (trim). Robuste : jamais None, ne lève pas."""
    if not v:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [s.strip() for s in str(v).split(",") if s.strip()]


def _truthy(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _is_intrusive_config(name):
    """True si un nom de config nommée dénote un audit INTRUSIF/agressif (gaté derrière allow_exploit)."""
    n = str(name).lower()
    return any(tok in n for tok in _INTRUSIVE_TOKENS)


def _secret_values(authed):
    """Ensemble des VALEURS secrètes dérivées du matériel de session injecté (à rédiger de l'evidence).

    Inclut la valeur brute de chaque en-tête + les valeurs de cookie individuelles (name=value ET
    la valeur seule) + le jeton bearer nu. Garantit que même un echo partiel par Burp (une requête
    rejouée qui ne montre que la valeur du cookie) est neutralisé."""
    out = set()
    for k, v in (authed or {}).items():
        if not v:
            continue
        out.add(v)
        lk = str(k).lower()
        if lk == "cookie":
            for part in str(v).split(";"):
                part = part.strip()
                if "=" in part:
                    _, cv = part.split("=", 1)
                    cv = cv.strip()
                    if cv:
                        out.add(cv)
                elif part:
                    out.add(part)
        elif lk == "authorization":
            toks = str(v).split()
            if len(toks) == 2:                       # "Bearer <token>"
                out.add(toks[1])
    return out


def _redact(text, secrets):
    """Remplace toute valeur secrète par `<redacted-session>` (plus longues d'abord : anti-artefact)."""
    if not secrets:
        return text
    for s in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(s, "<redacted-session>")
    return text


def _issue_cwe(iss):
    """CWE canonique d'une issue Burp : « CWE-NNN » explicite (classifications/description) puis repli
    sur la map de noms bien connus. "" si indéterminable. Pur, ne lève pas."""
    if not isinstance(iss, dict):
        return ""
    for f in _CWE_FIELDS:
        val = iss.get(f)
        if val:
            c = extract_cwe(val if isinstance(val, str) else json.dumps(val))
            if c:
                return c
    name = str(iss.get("name") or (iss.get("issue_type") or {}).get("name") or "").lower()
    for needle, cwe in _NAME_CWE:
        if needle in name:
            return cwe
    return ""


@register("burp.scan")
class BurpScan(Module):
    kind = "burp.scan"
    exploit = False                                   # scan actif web -> pas un exploit ciblé
    destructive = False                               # intrusif mais non destructif par contrat
    web_allowed = True                                # activité de scan web in-scope -> plancher web
    mitre = "T1595.002"                               # Active Scanning: Vulnerability Scanning
    description = ("Pilote la REST API de Burp Suite : lance un scan actif (authentifié via la session "
                  "gouvernée, scope-locké), sonde l'état, rapatrie les issues et les mappe en Finding(s).")

    _POLL_INTERVAL = 2.0
    _MAX_POLLS = 60                                   # ~120s par défaut (borné, surchargé par params)

    @property
    def available(self):
        # SONDE À FIRE-TIME : l'API Burp répond-elle ? GET racine versionnée (jamais au catalogue).
        cfg = _cfg()
        st, _body, _h = _req("GET", f"{_base(cfg)}/v0.1/", timeout=2)
        return st != 0                                # 0 = injoignable (URLError) ; tout HTTP = up

    # --- résolution scope / session gouvernée (via le store lié par le moteur autour de fire()) -----
    @staticmethod
    def _bound():
        """(store, scope, allow_exploit) depuis le SessionStore lié — (None, None, False) si aucun."""
        store = _session.current()
        scope = getattr(store, "scope", None) if store is not None else None
        allow_exploit = bool(getattr(scope, "allow_exploit", False)) if scope is not None else False
        return store, scope, allow_exploit

    def _scan_urls(self, action):
        p = action.params or {}
        urls = p.get("urls") or [action.target]
        return [u for u in urls if u]

    @staticmethod
    def _in_scope_urls(scope, urls):
        """(kept, refused) : partitionne les URL selon le scope. scope=None -> tout gardé (dev/offline)."""
        if scope is None:
            return list(urls), []
        kept = [u for u in urls if scope.is_in_scope(u)]
        refused = [u for u in urls if u not in kept]
        return kept, refused

    def _authed_headers(self, store, urls):
        """Matériel de session à injecter pour l'ensemble des URL in-scope (union, scope-guardé par le
        store : headers_for renvoie {} hors-scope). {} sans store/session (offline-safe)."""
        authed = {}
        if store is not None:
            for u in urls:
                for k, v in store.headers_for(u).items():
                    authed.setdefault(k, v)
        return authed

    def _scan_configs(self, action, allow_exploit):
        """(configs, suppressed) : configurations de scan NOMMÉES (crawl+audit) depuis params, filtrées
        par la gouvernance non-destructive. `suppressed`=True si une option intrusive a été retirée
        faute d'opt-in exploit. Sans opt-in : les configs intrusives sont ÉCARTÉES et l'audit actif
        n'est PAS ajouté (non-destructif par défaut)."""
        p = action.params or {}
        names = _as_list(p.get("scan_configs") or p.get("scan_config"))
        intrusive = _truthy(p.get("intrusive") or p.get("active_audit"))
        suppressed = False
        if not allow_exploit:
            kept = [n for n in names if not _is_intrusive_config(n)]
            if len(kept) != len(names) or intrusive:
                suppressed = True                    # intrusif demandé mais non opt-in -> supprimé
            names, intrusive = kept, False
        if intrusive and _INTRUSIVE_CONFIG not in names:
            names.append(_INTRUSIVE_CONFIG)
        configs = [{"name": n, "type": "NamedConfiguration"} for n in names]
        return configs, suppressed

    def _scan_body(self, urls, authed, configs, action):
        """Corps POST /v0.1/scan. Le matériel de session (authed) n'est présent QUE ICI (requête
        sortante vers le Burp de l'opérateur) — jamais recopié dans un finding/dry/ledger."""
        p = action.params or {}
        body = {"urls": urls,
                "scope": {"type": "SimpleScope", "include": [{"rule": u} for u in urls]}}
        excl = _as_list(p.get("exclude"))
        if excl:
            body["scope"]["exclude"] = [{"rule": u} for u in excl]
        if configs:
            body["scan_configurations"] = configs
        if authed:
            # SESSION (SECRET) : Burp attache ces en-têtes à ses requêtes in-scope -> audit authentifié.
            body["request_headers"] = [{"name": k, "value": v} for k, v in authed.items()]
        pool = p.get("resource_pool")
        if pool:
            body["resource_pool"] = str(pool)
        return body

    @staticmethod
    def _auth_note(authed, suppressed_intrusive):
        """Note de posture SÛRE (aucune valeur secrète — que des compteurs/flags) pour dry()/evidence."""
        parts = [f"authenticated={'yes' if authed else 'no'}"]
        if authed:
            parts.append(f"session_headers={len(authed)}(redacted)")
        if suppressed_intrusive:
            parts.append("intrusive_suppressed=governance")
        return " ".join(parts)

    def dry(self, action):
        cfg = _cfg(action)
        store, scope, allow_exploit = self._bound()
        urls = self._scan_urls(action)
        kept, _refused = self._in_scope_urls(scope, urls)
        authed = self._authed_headers(store, kept)
        configs, suppressed = self._scan_configs(action, allow_exploit)
        cfgnames = [c["name"] for c in configs]
        return (f"# POST {_base(cfg)}/v0.1/scan {{urls: {kept}, configs: {cfgnames}, "
                f"{self._auth_note(authed, suppressed)}}} -> id ; "
                f"GET /v0.1/scan/{{id}} (poll) -> issues -> Findings   "
                f"# pilote la REST API de Burp (scan actif in-scope, session rédigée)")

    def fire(self, action):
        cfg = _cfg(action)
        store, scope, allow_exploit = self._bound()
        urls = self._scan_urls(action)
        if not urls:
            return [self.finding(
                target=action.target, title="Burp non lancé — aucune URL", severity="INFO",
                category="burp", status="tested", tool="burp-rest",
                evidence="Requiert params.urls (in-scope) ou action.target.", poc=self.dry(action))]

        # (1) SCOPE-GUARD (défense en profondeur) — n'envoyer à Burp QUE les URL in-scope.
        kept, refused = self._in_scope_urls(scope, urls)
        if not kept:
            return [self.finding(
                target=action.target, title="Burp — cible hors scope, scan refusé", severity="INFO",
                category="burp", mitre=self.mitre, status="skipped", tool="burp-rest",
                evidence=(f"scope-guard: {len(refused)} URL hors périmètre refusée(s), "
                          f"aucun I/O émis vers Burp"), poc=self.dry(action))]
        urls = kept

        # (2) SESSION gouvernée (SECRET, scope-guardée par le store) — injectée UNIQUEMENT dans le body.
        authed = self._authed_headers(store, urls)
        secrets = _secret_values(authed)

        # (3) NON-DESTRUCTIF — configs de scan filtrées par la gouvernance (intrusif => opt-in exploit).
        configs, suppressed = self._scan_configs(action, allow_exploit)

        body = self._scan_body(urls, authed, configs, action)
        st, resp, headers = _req("POST", f"{_base(cfg)}/v0.1/scan", body=body)

        # (4) DÉGRADATION GRACIEUSE — Burp REST injoignable (transport) -> status=skipped (offline-safe).
        if st == 0:
            return [self.finding(
                target=action.target, title="Burp REST injoignable — scan sauté", severity="INFO",
                category="burp", mitre=self.mitre, status="skipped", tool="burp-rest",
                evidence=_redact(f"Burp REST API injoignable: {str(resp)[:300]} "
                                 f"{self._auth_note(authed, suppressed)}", secrets),
                poc=self.dry(action))]
        if st >= 400:
            return [self.finding(
                target=action.target, title=f"Burp — échec lancement scan (HTTP {st})", severity="INFO",
                category="burp", status="tested", tool="burp-rest",
                evidence=_redact(str(resp)[:500], secrets), poc=self.dry(action))]

        scan_id = self._scan_id(resp, headers)
        if scan_id is None:
            return [self.finding(
                target=action.target, title="Burp — id de scan introuvable", severity="INFO",
                category="burp", status="tested", tool="burp-rest",
                evidence=_redact(f"HTTP {st} body={str(resp)[:300]} location={headers.get('Location')}", secrets),
                poc=self.dry(action))]

        issues, status_txt = self._poll(cfg, scan_id, action)
        return self._map_issues(action, scan_id, status_txt, issues, secrets, authed, suppressed)

    @staticmethod
    def _scan_id(body, headers):
        """L'id de scan : champ JSON `scan_id`/`id`, sinon dernier segment de l'en-tête Location."""
        if isinstance(body, dict):
            for k in ("scan_id", "id", "task_id"):
                if body.get(k) is not None:
                    return body[k]
        loc = headers.get("Location") or headers.get("location")
        if loc:
            return loc.rstrip("/").rsplit("/", 1)[-1]
        return None

    def _poll(self, cfg, scan_id, action):
        """Poll GET /v0.1/scan/{id} jusqu'à succeeded/failed ou épuisement du budget de polls."""
        p = action.params or {}
        max_polls = int(p.get("max_polls") or self._MAX_POLLS)
        interval = float(p.get("poll_interval") or self._POLL_INTERVAL)
        last_body, status_txt = None, "unknown"
        for _ in range(max(1, max_polls)):
            st, body, _h = _req("GET", f"{_base(cfg)}/v0.1/scan/{scan_id}")
            last_body = body
            if isinstance(body, dict):
                status_txt = str(body.get("scan_status") or body.get("status") or "unknown").lower()
                if status_txt in ("succeeded", "failed", "completed", "paused", "abandoned"):
                    break
            time.sleep(interval)
        return self._extract_issues(last_body), status_txt

    @staticmethod
    def _extract_issues(body):
        """Issues Burp : soit `issue_events[].issue`, soit une liste `issues` directe."""
        if not isinstance(body, dict):
            return []
        if isinstance(body.get("issue_events"), list):
            out = []
            for ev in body["issue_events"]:
                iss = ev.get("issue") if isinstance(ev, dict) else None
                if iss:
                    out.append(iss)
            return out
        if isinstance(body.get("issues"), list):
            return body["issues"]
        return []

    def _map_issues(self, action, scan_id, status_txt, issues, secrets, authed, suppressed_intrusive):
        authnote = self._auth_note(authed, suppressed_intrusive)
        if not issues:
            return [self.finding(
                target=action.target, title=f"Burp scan terminé ({status_txt}) — aucune issue",
                severity="INFO", category="burp", mitre=self.mitre, status="tested",
                tool=f"burp-rest:scan/{scan_id}",
                evidence=f"scan_id={scan_id} status={status_txt} {authnote}", poc=self.dry(action))]
        findings = []
        for iss in issues:
            name = (iss.get("name") or (iss.get("issue_type") or {}).get("name")
                    or iss.get("type_index") or "issue")
            sev_raw = str(iss.get("severity", "info")).lower()
            sev = _SEV.get(sev_raw, "INFO")
            # severity/cwe/mitre mapping via forge/techniques.py (source de vérité) : le CWE de l'issue
            # rejoint la tactique ATT&CK et la remédiation par défaut (Finding.__post_init__).
            cwe = _issue_cwe(iss)
            mitre = techniques.mitre_for_cwe(cwe) or self.mitre
            where = iss.get("origin", "") + (iss.get("path") or "")
            # SECRET : l'issue peut rejouer une requête contenant notre session -> RÉDACTION avant evidence.
            raw = _redact(json.dumps(iss), secrets)[:1200]
            findings.append(self.finding(
                target=(where or action.target),
                title=f"Burp: {name}",
                severity=sev, category="burp", cwe=cwe, mitre=mitre,
                # même politique anti-sur-classement que nuclei : l'outil signale, Forge ne prouve pas
                # l'exploitabilité ici -> reported_by_tool (jamais `vulnerable`, jamais exploit/destructif).
                status=("reported_by_tool" if sev in ("HIGH", "CRITICAL", "MEDIUM") else "tested"),
                tool=f"burp-rest:scan/{scan_id}",
                evidence=_redact(f"severity={sev_raw} confidence={iss.get('confidence', '?')} "
                                 f"cwe={cwe or '?'} {authnote} {raw}", secrets),
                poc=self.dry(action)))
        return findings

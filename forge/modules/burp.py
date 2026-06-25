"""Connecteur Burp Suite (`burp.scan`) — PILOTE la REST API de Burp, ne fabrique aucun payload.

Forge n'ajoute pas de capacité offensive : il PARLE à la REST API de Burp Suite Professional/
Enterprise (un outil de pentest STANDARD que l'opérateur exécute déjà), lance un scan sur les URL
in-scope, sonde l'état, rapatrie les `issues` et les MAPPE en Finding(s). C'est de la GOUVERNANCE
+ de l'AUDIT autour d'un outil existant : Burp produit les résultats, Forge les normalise et les
journalise derrière la gate ROE.

Transport : REST stdlib (urllib). POST {BURP_API_URL}/v0.1/scan {urls, scope} -> Location/id ;
GET {BURP_API_URL}/v0.1/scan/{id} -> {scan_status, scan_metrics, issue_events|issues}.
Config via env : BURP_API_URL (ex http://127.0.0.1:1337/{BURP_API_KEY}), BURP_API_KEY.

Gouvernance (héritée automatiquement de l'engine/ROE autour de fire(), NON contournée) :
  - exploit=False : un active-scan web n'est pas un exploit ciblé (pas d'accès à l'objet d'autrui ;
    la promotion en `vulnerable` reste réservée aux oracles à preuve de Forge — ici on émet
    `reported_by_tool`, comme nuclei).
  - destructive=False : le scan est intrusif mais non destructif par contrat (pas de suppression/
    altération volontaire de données ; reste gaté ROE de toute façon).
  - web_allowed=True : c'est une activité de SCAN WEB (recon/scan actif) sur des URL in-scope —
    elle relève du plancher web, contrairement au connecteur MSF (lancement opérateur opt-in).
    Choix justifié : le scan Burp est cadré (URL in-scope, gate ROE, pas d'exploitation d'objet),
    donc acceptable sur la surface web au même titre que nuclei.

`available` SONDE l'API à fire-time (GET /v0.1/, jamais figé au catalogue).
"""
import json
import os
import time
import urllib.error
import urllib.request

from .registry import register, Module

# mapping sévérité Burp -> sévérité Forge (Burp: high/medium/low/info[rmation])
_SEV = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW",
        "info": "INFO", "information": "INFO", "false_positive": "INFO"}


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
    """Requête REST stdlib. Renvoie (status, parsed_json|texte, headers). Ne lève pas sur 4xx/5xx."""
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


@register("burp.scan")
class BurpScan(Module):
    kind = "burp.scan"
    exploit = False                                   # scan actif web -> pas un exploit ciblé
    destructive = False                               # intrusif mais non destructif par contrat
    web_allowed = True                                # activité de scan web in-scope -> plancher web
    mitre = "T1595.002"                               # Active Scanning: Vulnerability Scanning
    description = ("Pilote la REST API de Burp Suite : lance un scan sur les URL in-scope, "
                  "sonde l'état, rapatrie les issues et les mappe en Finding(s).")

    _POLL_INTERVAL = 2.0
    _MAX_POLLS = 60                                   # ~120s par défaut (borné, surchargé par params)

    @property
    def available(self):
        # SONDE À FIRE-TIME : l'API Burp répond-elle ? GET racine versionnée (jamais au catalogue).
        cfg = _cfg()
        st, _body, _h = _req("GET", f"{_base(cfg)}/v0.1/", timeout=2)
        return st != 0                                # 0 = injoignable (URLError) ; tout HTTP = up

    def _scan_urls(self, action):
        p = action.params or {}
        urls = p.get("urls") or [action.target]
        return [u for u in urls if u]

    def dry(self, action):
        cfg = _cfg(action)
        urls = self._scan_urls(action)
        return (f"# POST {_base(cfg)}/v0.1/scan {{urls: {urls}}} -> id ; "
                f"GET /v0.1/scan/{{id}} (poll) -> issues -> Findings   "
                f"# pilote la REST API de Burp (scan actif in-scope)")

    def fire(self, action):
        cfg = _cfg(action)
        urls = self._scan_urls(action)
        if not urls:
            return [self.finding(
                target=action.target, title="Burp non lancé — aucune URL", severity="INFO",
                category="burp", status="tested", tool="burp-rest",
                evidence="Requiert params.urls (in-scope) ou action.target.", poc=self.dry(action))]

        st, body, headers = _req("POST", f"{_base(cfg)}/v0.1/scan",
                                 body={"urls": urls, "scope": {"include": [{"rule": u} for u in urls]}})
        if st == 0 or st >= 400:
            return [self.finding(
                target=action.target, title=f"Burp — échec lancement scan (HTTP {st})", severity="INFO",
                category="burp", status="tested", tool="burp-rest",
                evidence=str(body)[:500], poc=self.dry(action))]

        scan_id = self._scan_id(body, headers)
        if scan_id is None:
            return [self.finding(
                target=action.target, title="Burp — id de scan introuvable", severity="INFO",
                category="burp", status="tested", tool="burp-rest",
                evidence=f"HTTP {st} body={str(body)[:300]} location={headers.get('Location')}",
                poc=self.dry(action))]

        issues, status_txt = self._poll(cfg, scan_id, action)
        return self._map_issues(action, scan_id, status_txt, issues)

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

    def _map_issues(self, action, scan_id, status_txt, issues):
        if not issues:
            return [self.finding(
                target=action.target, title=f"Burp scan terminé ({status_txt}) — aucune issue",
                severity="INFO", category="burp", mitre=self.mitre, status="tested",
                tool=f"burp-rest:scan/{scan_id}",
                evidence=f"scan_id={scan_id} status={status_txt}", poc=self.dry(action))]
        findings = []
        for iss in issues:
            name = iss.get("name") or iss.get("issue_type", {}).get("name") or iss.get("type_index") or "issue"
            sev_raw = str(iss.get("severity", "info")).lower()
            sev = _SEV.get(sev_raw, "INFO")
            where = iss.get("origin", "") + (iss.get("path") or "")
            findings.append(self.finding(
                target=(where or action.target),
                title=f"Burp: {name}",
                severity=sev, category="burp", mitre=self.mitre,
                # même politique anti-sur-classement que nuclei : l'outil signale, Forge ne prouve
                # pas l'exploitabilité ici -> reported_by_tool (pas `vulnerable`).
                status=("reported_by_tool" if sev in ("HIGH", "CRITICAL", "MEDIUM") else "tested"),
                tool=f"burp-rest:scan/{scan_id}",
                evidence=(f"severity={sev_raw} confidence={iss.get('confidence', '?')} "
                          f"{json.dumps(iss)[:1200]}"),
                poc=self.dry(action)))
        return findings

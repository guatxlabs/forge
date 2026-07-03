# SPDX-License-Identifier: AGPL-3.0-only
"""Parseurs par format — chacun transforme un fichier de scan en `list[Finding]` orientés preuve.

Contrat commun (voir `_base.make_finding`) : RECON/DÉCOUVERTE -> `status="tested"` ;
scanner à auto-déclaration (nuclei/burp) -> `status="reported_by_tool"` ; JAMAIS `vulnerable`.
CWE/ATT&CK dérivés quand disponibles ; toute valeur passe par `redact()`. Zéro exécution, zéro I/O
réseau — pur parsing. Un XML illisible lève `ValueError` (message clair) ; les parseurs JSON sont
tolérants (lignes illisibles ignorées).

Les fonctions acceptent `(text, *, mapping=None)` — `mapping` n'est consommé que par les parseurs
génériques (colonnes personnalisées). Les autres l'ignorent (signature uniforme pour le dispatch).
"""
import csv
import json

from . import _base
from ._base import (host_of, iter_json_objects, looks_like_host, make_finding,
                    first_cwe, cwe_in, el_text, strip_html, safe_xml_root, norm_severity)


# --- nmap XML ---------------------------------------------------------------------------------------
def parse_nmap(text, *, mapping=None):
    """nmap `-oX` : un finding RECON (status=tested, ATT&CK T1046) par port OUVERT. Cible = hostname
    si présent, sinon adresse IPv4/IPv6 de l'hôte."""
    root = safe_xml_root(text)  # durci anti-XXE / billion-laughs ; lève ValueError si illisible
    out = []
    for host in root.findall("host"):
        addr = ""
        for ad in host.findall("address"):
            if ad.get("addrtype") in ("ipv4", "ipv6"):
                addr = ad.get("addr") or addr
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else ""
        target = hostname or addr or "unknown"
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            portid = p.get("portid", "")
            proto = p.get("protocol", "tcp")
            svc = p.find("service")
            sname = svc.get("name", "") if svc is not None else ""
            sprod = svc.get("product", "") if svc is not None else ""
            sver = svc.get("version", "") if svc is not None else ""
            detail = " ".join(x for x in (f"{proto}/{portid}", sname, sprod, sver) if x).strip()
            out.append(make_finding(
                target=target, tool="nmap", status="tested", severity="INFO",
                category="Recon", mitre="T1046",
                title=f"Port ouvert {portid}/{proto} ({sname or 'unknown'}) sur {target}",
                evidence=detail, poc=f"nmap -p {portid} {target}"))
    return out


# --- nuclei JSON / JSONL ----------------------------------------------------------------------------
def parse_nuclei(text, *, mapping=None):
    """nuclei `-json`/`-jsonl` : chaque hit -> `reported_by_tool` (l'outil s'auto-déclare, pas une
    preuve Forge). Sévérité de `info.severity` ; CWE de `info.classification.cwe-id` (-> ATT&CK dérivé)."""
    out = []
    for o in iter_json_objects(text):
        info = o.get("info") if isinstance(o.get("info"), dict) else {}
        tid = o.get("template-id") or o.get("templateID") or o.get("template_id") or info.get("name") or "nuclei"
        name = info.get("name") or tid
        sev = info.get("severity") or o.get("severity") or "info"
        matched = o.get("matched-at") or o.get("matched_at") or o.get("host") or o.get("url") or o.get("input") or ""
        target = o.get("host") or host_of(matched) or matched
        classif = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cwe = first_cwe(classif.get("cwe-id") or classif.get("cwe_id"))
        cve = classif.get("cve-id") or classif.get("cve_id")
        parts = [f"template={tid}"]
        if o.get("matcher-name"):
            parts.append("matcher=" + str(o.get("matcher-name")))
        if o.get("type"):
            parts.append("type=" + str(o.get("type")))
        if matched:
            parts.append("matched-at=" + str(matched))
        if cve:
            parts.append("cve=" + (",".join(cve) if isinstance(cve, list) else str(cve)))
        if o.get("extracted-results"):
            parts.append("extracted=" + json.dumps(o.get("extracted-results"))[:300])
        out.append(make_finding(
            target=target or "unknown", tool="nuclei", status="reported_by_tool",
            severity=sev, cwe=cwe, category=(cwe or "Scanner"),
            title=f"[nuclei] {name} ({tid})",
            evidence="; ".join(parts),
            poc=f"nuclei -id {tid} -u {target or matched}"))
    return out


# --- Burp Suite XML export --------------------------------------------------------------------------
def parse_burp(text, *, mapping=None):
    """Export XML Burp (`<issues><issue>…`) : chaque issue -> `reported_by_tool`. Sévérité de
    `<severity>` (Information/Low/Medium/High) ; CWE extrait de `<vulnerabilityClassifications>`
    (ou du background). L'HTML des corps est nettoyé et rédigé."""
    root = safe_xml_root(text)  # durci anti-XXE / billion-laughs ; lève ValueError si illisible
    out = []
    for iss in root.iter("issue"):
        name = el_text(iss.find("name")) or "Burp issue"
        hostel = iss.find("host")
        host = el_text(hostel) if hostel is not None else ""
        path = el_text(iss.find("path"))
        sev = el_text(iss.find("severity")) or "Information"
        conf = el_text(iss.find("confidence"))
        cwe = cwe_in(el_text(iss.find("vulnerabilityClassifications"))) or cwe_in(el_text(iss.find("issueBackground")))
        detail = strip_html(el_text(iss.find("issueDetail")))
        url = (host or "") + (path or "")
        out.append(make_finding(
            target=host_of(host) or host or "unknown", tool="burp", status="reported_by_tool",
            severity=sev, cwe=cwe, category=(cwe or "Scanner"),
            title=f"[burp] {name}",
            evidence=" ".join(x for x in (f"url={url}" if url else "",
                                          f"confidence={conf}" if conf else "", detail) if x).strip(),
            poc=(f"curl -sS '{url}'" if url else "")))
    return out


# --- httpx JSON / JSONL -----------------------------------------------------------------------------
def parse_httpx(text, *, mapping=None):
    """httpx `-json` : joignabilité HTTP -> RECON (status=tested, ATT&CK T1595). Un finding par entrée."""
    out = []
    for o in iter_json_objects(text):
        url = o.get("url") or o.get("input") or ""
        host = o.get("host") or host_of(url) or o.get("input") or url
        sc = o.get("status_code") or o.get("status-code") or o.get("status")
        title = o.get("title") or ""
        webserver = o.get("webserver") or o.get("server") or ""
        tech = o.get("tech") or o.get("technologies") or o.get("technology") or []
        techs = ", ".join(tech) if isinstance(tech, list) else str(tech)
        out.append(make_finding(
            target=host_of(url) or host or "unknown", tool="httpx", status="tested",
            severity="INFO", category="Recon", mitre="T1595",
            title=f"Service HTTP actif {url or host} (status {sc})",
            evidence=" ".join(x for x in (f"url={url}", f"status={sc}",
                                          f"server={webserver}" if webserver else "",
                                          f"tech={techs}" if techs else "",
                                          f"title={title}" if title else "") if x).strip(),
            poc=f"httpx -u {url or host}"))
    return out


# --- ffuf JSON --------------------------------------------------------------------------------------
def parse_ffuf(text, *, mapping=None):
    """ffuf `-o result.json` : contenu découvert -> RECON (status=tested, ATT&CK T1595.003). Lit
    `results[]` (ou, en repli, du JSONL de résultats)."""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        results = [o for o in iter_json_objects(text) if ("url" in o or "status" in o) and "results" not in o]
    out = []
    for r in results or []:
        if not isinstance(r, dict):
            continue
        url = r.get("url") or ""
        host = r.get("host") or host_of(url)
        status = r.get("status")
        length = r.get("length")
        words = r.get("words")
        inp = r.get("input") if isinstance(r.get("input"), dict) else {}
        fuzz = inp.get("FUZZ", "")
        out.append(make_finding(
            target=host_of(url) or host or "unknown", tool="ffuf", status="tested",
            severity="INFO", category="Recon", mitre="T1595.003",
            title=f"Contenu découvert {url} (status {status})",
            evidence=" ".join(x for x in (f"url={url}", f"status={status}", f"length={length}",
                                          f"words={words}", f"FUZZ={fuzz}" if fuzz else "") if x).strip(),
            poc=(f"curl -sS '{url}'" if url else "")))
    return out


# --- subfinder / amass — liste d'hôtes (texte OU JSONL) ---------------------------------------------
def parse_hosts(text, *, mapping=None):
    """subfinder/amass : sous-domaines découverts -> RECON (status=tested, ATT&CK T1590). Tolère le
    texte nu (un hôte par ligne, `host,source` accepté) ET le JSONL (subfinder `-oJ` {"host":…},
    amass `-json` {"name":…,"domain":…}). Déduplique."""
    out = []
    seen = set()
    got_json = False
    for o in iter_json_objects(text):
        got_json = True
        h = o.get("host") or o.get("name") or o.get("subdomain") or ""
        src = o.get("source") or o.get("sources") or o.get("input") or o.get("domain") or ""
        h = str(h).strip()
        if h and h not in seen:
            seen.add(h)
            out.append(make_finding(
                target=h, tool="subfinder/amass", status="tested", severity="INFO",
                category="Recon", mitre="T1590",
                title=f"Sous-domaine découvert {h}",
                evidence=f"host={h}" + (f" source={src}" if src else ""),
                poc=f"dig +short {h}"))
    if got_json:
        return out
    for line in (text or "").splitlines():
        h = line.strip()
        if not h or h.startswith("#"):
            continue
        h = h.replace(",", " ").split()[0]  # tolère "host,source" / "host source"
        if not looks_like_host(h) or h in seen:
            continue
        seen.add(h)
        out.append(make_finding(
            target=h, tool="subfinder/amass", status="tested", severity="INFO",
            category="Recon", mitre="T1590",
            title=f"Sous-domaine découvert {h}", evidence=f"host={h}", poc=f"dig +short {h}"))
    return out


# --- Générique JSON / CSV (mapping de colonnes) -----------------------------------------------------
_GEN_TARGET = ("target", "host", "hostname", "url", "ip", "address", "asset", "domain", "fqdn", "endpoint")
_GEN_TITLE = ("title", "name", "template", "template-id", "message", "summary", "issue", "finding", "vuln", "check", "rule")
_GEN_SEV = ("severity", "risk", "level", "criticality", "impact", "priority")
_GEN_CWE = ("cwe", "cwe-id", "cwe_id", "weakness")
_GEN_EV = ("evidence", "description", "detail", "details", "matched", "matched-at", "info", "notes", "data", "proof", "output")


def _pick(d, keys, mapping, field):
    """Valeur d'un champ logique : `mapping[field]` (override explicite) sinon 1er alias connu
    (casse-insensible). '' si aucun."""
    if mapping and field in mapping:
        col = mapping[field]
        for dk in d:
            if dk.lower() == str(col).lower():
                return d[dk]
    lowered = {k.lower(): k for k in d}
    for k in keys:
        if k in lowered:
            return d[lowered[k]]
    return ""


def parse_generic_rows(rows, mapping=None):
    """Transforme une liste de dicts en findings. Preuve : sévérité>INFO ou CWE présent ->
    `reported_by_tool`, sinon `tested` (jamais `vulnerable`). `mapping` remappe target/title/
    severity/cwe/evidence (ex {"target":"host"})."""
    out = []
    for d in rows:
        if not isinstance(d, dict):
            continue
        target = str(_pick(d, _GEN_TARGET, mapping, "target") or "").strip()
        title = str(_pick(d, _GEN_TITLE, mapping, "title") or "").strip()
        sev = norm_severity(_pick(d, _GEN_SEV, mapping, "severity"))
        cwe = first_cwe(_pick(d, _GEN_CWE, mapping, "cwe"))
        ev = _pick(d, _GEN_EV, mapping, "evidence")
        ev = ev if isinstance(ev, str) else json.dumps(ev)
        if not ev:
            ev = json.dumps({k: d[k] for k in list(d)[:12]})[:2000]
        status = "reported_by_tool" if (sev != "INFO" or cwe) else "tested"
        out.append(make_finding(
            target=target or "unknown", tool="import:generic", status=status,
            severity=sev, cwe=cwe, category=(cwe or "Imported"),
            title=(title or "Imported finding"), evidence=ev))
    return out


def parse_generic_json(text, *, mapping=None):
    """JSON générique : tableau `[{...}]`, JSONL, ou enveloppe `{"findings":[...]}` /
    `{"results":[...]}` / `{"vulnerabilities":[...]}` / `{"issues":[...]}` / `{"items":[...]}`."""
    rows = []
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        for k in ("findings", "results", "vulnerabilities", "issues", "data", "items"):
            if isinstance(data.get(k), list):
                rows = data[k]
                break
        else:
            rows = [data]
    else:
        rows = list(iter_json_objects(text))
    return parse_generic_rows(rows, mapping)


def parse_generic_csv(text, *, mapping=None):
    """CSV générique : en-tête -> colonnes ; mapping/aliases identiques au JSON générique."""
    rows = list(csv.DictReader(_base.io.StringIO(text)))
    return parse_generic_rows(rows, mapping)


# --- Registre de dispatch ---------------------------------------------------------------------------
PARSERS = {
    "nmap": parse_nmap,
    "nuclei": parse_nuclei,
    "burp": parse_burp,
    "httpx": parse_httpx,
    "ffuf": parse_ffuf,
    "hosts": parse_hosts,
    "generic-json": parse_generic_json,
    "generic-csv": parse_generic_csv,
}

# Alias de format tolérés (résolus vers un parseur canonique). "auto" est traité par le dispatch.
ALIASES = {
    "nmap-xml": "nmap", "xml-nmap": "nmap",
    "burp-xml": "burp", "burpsuite": "burp",
    "subfinder": "hosts", "amass": "hosts", "hostlist": "hosts", "subdomains": "hosts",
    "json": "generic-json", "generic": "generic-json", "generic_json": "generic-json",
    "csv": "generic-csv", "generic_csv": "generic-csv",
}

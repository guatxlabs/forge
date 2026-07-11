# SPDX-License-Identifier: AGPL-3.0-only
"""Socle des importateurs de scans — helpers PURS, sans effet de bord (stdlib only).

Ce module absorbe la propriété « ingest les sorties d'outils existants » de Faraday/Trickest/
reNgine (80+ formats) MAIS SOUS la gouvernance de Forge :
  - PUR DATA : aucune exécution, aucune requête réseau — on LIT un fichier déjà produit ;
  - ORIENTÉ PREUVE : un finding importé n'est JAMAIS `vulnerable`. Un scanner qui s'auto-déclare
    (nuclei/burp) devient `reported_by_tool` (sa sévérité sert à prioriser, pas à confirmer) ; une
    sortie de RECON/DÉCOUVERTE (nmap/httpx/ffuf/subfinder) devient `tested`. La promotion en
    `vulnerable` reste réservée aux oracles à preuve de Forge — jamais à un import ;
  - REDACTED : tout secret présent dans le fichier (Authorization/Bearer, api_key, cookie, clé
    privée, JWT…) est masqué AVANT d'entrer dans un finding (jamais ré-émis ni journalisé) ;
  - DÉRIVÉ : la taxonomie (vuln_class/cwe/mitre) est dérivée de `forge/techniques.py` quand
    possible (ex : CWE -> ATT&CK via `mitre_for_cwe`) — même source unique que le reste de Forge.

Le scope-guard (ne pas ingérer un asset HORS périmètre) vit dans `scope_filter` (utilisé par la
CLI et l'endpoint console) : il réutilise `roe.Scope` (LE scope-guard unique), pas une re-copie.
"""
import io
import json
import re
import xml.etree.ElementTree as ET

from ..schema import Finding, SEVERITIES
from .. import techniques
from ..redact import redact_secrets as _redact_secrets

# --- Rédaction de secrets ---------------------------------------------------------------------------
# DÉLÉGATION à la surface UNIQUE et auditée `forge.redact` (cf. son docstring). Cette ancienne
# implémentation locale RATAIT la plupart des tokens cloud (gh_/xox…/AIza…/sk-…/glpat-) : un secret que
# le rapport masquait FUYAIT par ce chemin d'ingest. `redact()` garde son nom/sa signature publics
# (make_finding, l'API `importers`, la CLI l'utilisent) mais N'est plus qu'un WRAPPER FIN qui préserve
# le contrat de coercition local (non-`str`/vide -> `""`/`str(text)`, jamais `None`).


def redact(text):
    """Masque les secrets d'une chaîne (jamais None) — DÉLÈGUE à `forge.redact.redact_secrets` (surface
    unique). PUR — favorise la sûreté (sur-masquage OK)."""
    if not text:
        return "" if text is None else str(text)
    return _redact_secrets(str(text))


# --- Normalisation de sévérité ----------------------------------------------------------------------
_SEV_MAP = {
    "": "INFO", "info": "INFO", "informational": "INFO", "information": "INFO", "none": "INFO",
    "unknown": "INFO", "note": "INFO", "log": "INFO",
    "low": "LOW", "minor": "LOW",
    "medium": "MEDIUM", "moderate": "MEDIUM", "warning": "MEDIUM", "warn": "MEDIUM",
    "high": "HIGH", "important": "HIGH", "major": "HIGH", "error": "HIGH",
    "critical": "CRITICAL", "crit": "CRITICAL", "blocker": "CRITICAL",
}


def norm_severity(s):
    """Sévérité canonique (INFO/LOW/MEDIUM/HIGH/CRITICAL). Tout inconnu -> INFO (fail-safe)."""
    return _SEV_MAP.get(str(s or "").strip().lower(), "INFO")


def _sev_rank(sev):
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


# --- Extraction d'hôte / CWE / texte ----------------------------------------------------------------
# Hôte plausible : IPv4 OU domaine (au moins un point) — exige un point pour éviter de prendre un mot
# quelconque pour un hôte (robustesse de la détection « liste d'hôtes » et du scope-check).
_HOST_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9-]{2,})$")
_CWE_RX = re.compile(r"(?i)cwe[-_ ]?(\d+)")


def host_of(value):
    """Hôte nu d'une URL/host:port (scheme/userinfo/port/chemin retirés). '' si vide. PUR."""
    s = str(value or "").strip()
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):
        s = s[1:].split("]", 1)[0]
    elif s.count(":") == 1:
        s = s.split(":", 1)[0]
    return s


def looks_like_host(s):
    """True si `s` ressemble à un hôte (IPv4/domaine). Sert à détecter une liste d'hôtes nue."""
    return bool(_HOST_RE.match(str(s or "").strip()))


def first_cwe(value):
    """Premier identifiant CWE canonique ('CWE-79') dérivé d'une valeur (str/int/list). '' si aucun."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    s = str(value).strip()
    if not s:
        return ""
    m = _CWE_RX.search(s)
    if m:
        return "CWE-" + m.group(1)
    return "CWE-" + s if s.isdigit() else ""


def cwe_in(text):
    """Cherche un CWE dans un texte libre (HTML de classification Burp, etc.). '' si absent."""
    m = _CWE_RX.search(str(text or ""))
    return "CWE-" + m.group(1) if m else ""


def el_text(el):
    """Texte d'un élément ElementTree, strippé ('' si None)."""
    return (el.text or "").strip() if el is not None else ""


def strip_html(s):
    """Retire les balises HTML et compacte les espaces (pour les corps HTML Burp)."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", str(s or ""))).strip()


def _doctype_is_dangerous(low, start):
    """Vrai si la déclaration DOCTYPE commençant à `start` (dans `low`, minuscule) porte un SOUS-ENSEMBLE
    INTERNE (`[…]`, seul endroit où des `<!ENTITY>` peuvent vivre -> billion-laughs) OU un DTD EXTERNE
    (`SYSTEM`/`PUBLIC` -> XXE par entité externe). On ne scanne QUE la déclaration DOCTYPE (jusqu'à son
    `>` de fin, profondeur 0), donc du texte de corps contenant littéralement « <!ENTITY » (ex: CDATA
    Burp) ne peut PAS provoquer de faux positif. Un DOCTYPE nu (`<!DOCTYPE nmaprun>`, ce que nmap émet)
    n'est PAS dangereux (ni `[`, ni SYSTEM/PUBLIC)."""
    i, n = start, len(low)
    while i < n:
        c = low[i]
        if c == "[":                       # sous-ensemble interne -> peut déclarer des entités
            return True
        if c == ">":                       # fin de la déclaration DOCTYPE (aucun `[` rencontré)
            head = low[start:i]
            return (" system" in head) or (" public" in head)
        i += 1
    return True                            # DOCTYPE non terminé -> suspect (malformé) -> refus


def safe_xml_root(text):
    """Parse un XML NON FIABLE (nmap/Burp) en le DURCISSANT contre XXE et les bombes d'expansion
    d'entités (« billion laughs »), SANS dépendance externe (stdlib only — pas de defusedxml).

    Défense : on REFUSE toute déclaration DOCTYPE portant un sous-ensemble interne (`[…]` — le seul lieu
    d'un `<!ENTITY>`, donc d'un billion-laughs) ou un DTD externe (`SYSTEM`/`PUBLIC` — XXE). SANS DTD, il
    n'existe aucune entité personnalisée : le document est sûr (seules les entités prédéfinies amp/lt/gt/
    quot/apos subsistent, inoffensives). Un `<!DOCTYPE nmaprun>` nu — ce que nmap émet — reste accepté.
    Lève `ValueError` sur XML illisible OU sur une DTD/entité refusée (message clair pour l'appelant)."""
    s = text if isinstance(text, str) else str(text)
    low = s.lower()
    dt = low.find("<!doctype")
    if dt != -1 and _doctype_is_dangerous(low, dt + len("<!doctype")):
        raise ValueError("DTD/entité XML refusée (durcissement anti-XXE / anti-billion-laughs)")
    try:
        return ET.fromstring(s)
    except ET.ParseError as e:
        raise ValueError(f"XML illisible: {e}")


def iter_json_objects(text):
    """Itère les objets JSON d'un texte, tolérant aux DEUX formes courantes des scanners :
    un tableau JSON complet `[{...},{...}]` OU du JSON-Lines (un objet par ligne). Ne lève jamais
    (les lignes illisibles sont ignorées). Un dict racine est émis tel quel (objet unique)."""
    t = (text or "").strip()
    if not t:
        return
    try:
        data = json.loads(t)
    except ValueError:
        data = None
    if data is not None:
        if isinstance(data, list):
            for x in data:
                if isinstance(x, dict):
                    yield x
            return
        if isinstance(data, dict):
            yield data
            return
    for line in t.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            x = json.loads(line)
        except ValueError:
            continue
        if isinstance(x, dict):
            yield x


# --- Construction d'un finding importé (orienté preuve, rédigé) -------------------------------------
_ALLOWED_STATUS = ("tested", "reported_by_tool", "skipped")


def make_finding(*, target, title, tool, status="tested", severity="INFO",
                 cwe="", mitre="", category="", evidence="", poc=""):
    """Construit un `Finding` IMPORTÉ, orienté preuve et RÉDIGÉ.

    - `status` est CLAMPÉ à {tested, reported_by_tool, skipped} : un import ne peut JAMAIS produire
      `vulnerable` (invariant preuve). Un statut hors de cet ensemble est ramené à `reported_by_tool`
      si une sévérité/preuve d'outil est présente, sinon `tested`.
    - `cwe` est canonicalisé ('79' -> 'CWE-79') ; `mitre` est dérivé du CWE via la table unique
      (`techniques.mitre_for_cwe`) s'il n'est pas fourni.
    - `title`/`evidence`/`poc` passent par `redact()` — aucun secret ne peut entrer dans un finding.
    """
    sev = norm_severity(severity)
    cwe = first_cwe(cwe) if cwe else ""
    if cwe and not mitre:
        mitre = techniques.mitre_for_cwe(cwe) or ""
    if not category:
        category = cwe or ""
    if status not in _ALLOWED_STATUS:
        status = "reported_by_tool" if (_sev_rank(sev) > 0 or cwe) else "tested"
    return Finding(
        target=(str(target or "").strip() or "unknown"),
        title=(redact(title)[:300] or f"{tool} finding"),
        severity=sev, category=category, cwe=cwe, mitre=mitre,
        status=status, tool=tool,
        evidence=redact(evidence)[:4000], poc=redact(poc)[:2000])


# --- Détection de format ----------------------------------------------------------------------------
def _classify_obj(o):
    """Classe UN objet JSON (échantillon) vers un format, ou None. Ordre : nuclei (marqueur template)
    avant httpx (url+status) avant liste d'hôtes (subfinder/amass)."""
    if not isinstance(o, dict):
        return None
    if o.get("template-id") or o.get("templateID") or o.get("template_id"):
        return "nuclei"
    info = o.get("info")
    if isinstance(info, dict) and ("matched-at" in o or "matcher-name" in o or "template" in o):
        return "nuclei"
    if ("url" in o or "input" in o) and any(k in o for k in ("status_code", "status-code", "webserver", "scheme", "a")):
        return "httpx"
    if ("host" in o and "url" not in o) or ("name" in o and "domain" in o):
        return "hosts"
    return None


def detect_format(text, filename=""):
    """Devine le format d'un fichier de scan (ou None si indétectable -> l'appelant exige --format).

    XML (nmap/burp) par sniff de balise ; JSON complet (ffuf via `results`+`config`, nuclei via
    `template-id`, sinon générique) ; JSON-Lines (échantillon du 1er objet) ; texte nu (liste d'hôtes
    si toutes les lignes ressemblent à des hôtes) ; CSV (en-tête à virgules). PUR, ne lève jamais."""
    t = (text or "").lstrip()
    if not t:
        return None
    if t.startswith("<"):
        low = t[:4000].lower()
        if "<nmaprun" in low:
            return "nmap"
        if "burpversion" in low or "<issues" in low or "<issue>" in low:
            return "burp"
        return None
    # JSON complet
    try:
        data = json.loads(t)
    except ValueError:
        data = None
    if isinstance(data, dict):
        if isinstance(data.get("results"), list) and ("commandline" in data or "config" in data):
            return "ffuf"
        f = _classify_obj(data)
        if f:
            return f
        for k in ("findings", "results", "vulnerabilities", "issues", "items"):
            if isinstance(data.get(k), list):
                return "generic-json"
        return "generic-json"
    if isinstance(data, list):
        for x in data:
            if isinstance(x, dict):
                return _classify_obj(x) or "generic-json"
        return "generic-json"
    # JSON-Lines : échantillonne le 1er objet.
    for line in t.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except ValueError:
            break  # 1re ligne non-JSON -> pas du JSONL
        if isinstance(o, dict):
            return _classify_obj(o) or "generic-json"
        break
    # texte nu : liste d'hôtes ?
    lines = [l.strip() for l in t.splitlines() if l.strip() and not l.strip().startswith("#")]
    if lines and all(looks_like_host(l.replace(",", " ").split()[0]) for l in lines[:64]):
        return "hosts"
    # CSV : en-tête à virgules.
    if lines and "," in lines[0]:
        return "generic-csv"
    return None


__all__ = [
    "redact", "norm_severity", "make_finding", "host_of", "looks_like_host", "first_cwe",
    "cwe_in", "el_text", "strip_html", "iter_json_objects", "detect_format", "safe_xml_root",
    "ET", "io", "json",
]

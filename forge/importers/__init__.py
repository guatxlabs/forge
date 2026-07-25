# SPDX-License-Identifier: AGPL-3.0-or-later
"""Importateurs de scans — ingérer les sorties d'outils EXISTANTS en findings Forge orientés preuve.

Point d'entrée MIGRATION-SUPERSET : un hunter venant de Faraday/Trickest/reNgine/Osmedeus peut verser
ses fichiers de scan déjà produits (nmap XML, nuclei JSON/JSONL, export Burp XML, httpx JSON, ffuf
JSON, listes d'hôtes subfinder/amass, ou un JSON/CSV générique mappé) DANS Forge, SOUS la gouvernance :

  - PUR DATA, ZÉRO exécution : on parse un fichier, on ne lance aucun outil ni requête réseau ;
  - ORIENTÉ PREUVE : un finding importé n'est JAMAIS `vulnerable`. Un scanner à auto-déclaration
    (nuclei/burp) -> `reported_by_tool` (sévérité conservée pour prioriser) ; RECON/DÉCOUVERTE
    (nmap/httpx/ffuf/subfinder) -> `tested`. La promotion `vulnerable` reste aux oracles de Forge ;
  - REDACTED : les secrets du fichier (Authorization/Bearer, api_key, cookie, JWT, clé privée…) sont
    masqués avant d'entrer dans un finding — jamais ré-émis ni journalisés ;
  - SCOPE-GUARD : `scope_filter` respecte le périmètre — les findings d'assets HORS scope sont JETÉS
    (défaut) ou MARQUÉS (status=skipped) — via `roe.Scope` (le scope-guard unique, pas une re-copie).

API publique :
  - `detect_format(text, filename="")`            -> nom de format ou None ;
  - `parse(fmt, text, mapping=None)`              -> list[Finding] ;
  - `parse_file(path, fmt="auto", mapping=None)`  -> (fmt, list[Finding]) ;
  - `parse_auto(text, filename="", mapping=None)` -> (fmt, list[Finding]) ;
  - `scope_filter(findings, scope, flag_out_of_scope=False)` -> (findings, counts) ;
  - `FORMATS`, `redact`, `make_finding`.
"""
from pathlib import Path

from ._base import (redact, make_finding, norm_severity, detect_format, host_of,
                    looks_like_host, first_cwe)
from .parsers import PARSERS, ALIASES

FORMATS = list(PARSERS)


def normalize_format(fmt):
    """Résout un nom de format (alias inclus) vers un parseur canonique. 'auto'/'' -> 'auto'.
    Lève ValueError sur un format inconnu (message listant les formats supportés)."""
    f = (fmt or "auto").strip().lower()
    if f in ("", "auto"):
        return "auto"
    f = ALIASES.get(f, f)
    if f not in PARSERS:
        raise ValueError(f"format inconnu '{fmt}' (supportés: {', '.join(FORMATS)}, auto)")
    return f


def parse(fmt, text, mapping=None):
    """Parse `text` avec le parseur du format `fmt` (alias résolus). Lève ValueError si `fmt` est
    'auto' (utiliser `parse_auto`) ou inconnu, ou si un XML est illisible."""
    f = normalize_format(fmt)
    if f == "auto":
        raise ValueError("format 'auto' : utiliser parse_auto()/parse_file(fmt='auto')")
    return PARSERS[f](text, mapping=mapping) or []


def parse_auto(text, filename="", mapping=None):
    """Détecte le format puis parse. Lève ValueError si le format n'est pas détectable."""
    fmt = detect_format(text, filename)
    if fmt is None:
        raise ValueError("format non détecté automatiquement — préciser --format")
    return fmt, parse(fmt, text, mapping=mapping)


def parse_file(path, fmt="auto", mapping=None):
    """Lit `path` et parse. `fmt='auto'` -> auto-détection (via contenu + nom de fichier).
    Retourne (format_effectif, list[Finding]). Lève ValueError sur format/contenu invalide."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if normalize_format(fmt) == "auto":
        return parse_auto(text, filename=str(path), mapping=mapping)
    f = normalize_format(fmt)
    return f, parse(f, text, mapping=mapping)


def scope_filter(findings, scope, flag_out_of_scope=False):
    """Applique le SCOPE-GUARD aux findings importés via `roe.Scope` (le scope-guard UNIQUE de Forge).

    - un finding dont la cible est IN-SCOPE est conservé tel quel ;
    - un finding HORS scope est JETÉ (défaut) — l'asset n'appartient pas au périmètre d'engagement ;
    - avec `flag_out_of_scope=True`, il est CONSERVÉ mais NEUTRALISÉ (status='skipped', titre + evidence
      marqués « HORS-SCOPE ») — visible pour l'audit, jamais compté comme un finding actif.
    Retourne (findings_retenus, counts={parsed,in_scope,out_of_scope,emitted}). Le scope-guard est
    fail-closed (scope in_scope vide => rien n'est en scope) — cohérent avec le reste de Forge."""
    kept, in_n, out_n = [], 0, 0
    for f in findings:
        if scope.is_in_scope(f.target):
            in_n += 1
            kept.append(f)
        else:
            out_n += 1
            if flag_out_of_scope:
                f.title = "[HORS-SCOPE] " + f.title
                f.evidence = ("[hors périmètre d'engagement — non ingéré comme actif] " + (f.evidence or ""))[:4000]
                f.status = "skipped"
                kept.append(f)
    return kept, {"parsed": len(findings), "in_scope": in_n, "out_of_scope": out_n, "emitted": len(kept)}


__all__ = [
    "FORMATS", "PARSERS", "normalize_format", "parse", "parse_auto", "parse_file",
    "detect_format", "scope_filter", "redact", "make_finding", "norm_severity",
    "host_of", "looks_like_host", "first_cwe",
]

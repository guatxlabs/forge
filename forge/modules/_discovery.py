# SPDX-License-Identifier: AGPL-3.0-or-later
"""Helpers PARTAGÉS de DÉCOUVERTE DE SERVICE (host:port chaînable).

Utilisés par TOUS les modules de recon qui trouvent des PORTS OUVERTS : les modules écrits à la main
(`recon.nmap`/`recon.httpx` dans recon.py) ET les wrappers spec-driven (`recon.naabu`/`recon.masscan`
du catalogue, via toolspec.py). Centralise, en un seul point :
  - l'ANCRAGE d'un `host:port` découvert sur l'hôte DÉJÀ gaté par le ROE (jamais un autre hôte) ;
  - l'ÉMISSION d'un finding de découverte porteur du marqueur `DISCOVERY_SERVICE_MARKER` -> le port
    devient un NŒUD du graphe que le cerveau CHAÎNE (fingerprint/oracles/scanners de contenu) ;
  - la CONFIRMATION HTTP d'un port ouvert (sonde GET) — là où un scanner de ports (naabu/masscan) ou la
    sonde brute de nmap ne dit rien du protocole applicatif, un vrai GET obtient un STATUS HTTP tandis
    qu'un service NON-HTTP (VNC/SSH…) casse le parse -> None -> jamais surfacé (zéro bruit) ;
  - l'EXTRACTION de ports depuis la sortie hétérogène des outils (naabu `host:port`, masscan
    `Discovered open port N/tcp on host`) et un finding d'INVENTAIRE de la surface ouverte.

Zéro dépendance (stdlib) — cohérent avec le cœur Forge. Toutes les fonctions sont PURES (hormis
`http_probe`, qui SONDE) et ne lèvent JAMAIS.
"""
import ipaddress
import re
import urllib.parse

from .oracle import Oracle
from .. import techniques
from .. import resource_profile

# Ports web STANDARD : déjà couverts par l'hôte de base (recon/oracles semés dessus) -> on n'émet PAS
# de cible `host:port` redondante pour eux. Seuls les ports NON standard ont besoin d'être surfacés
# comme NOUVELLE surface chaînable.
_STANDARD_WEB_PORTS = frozenset({80, 443})
_MAX_DISCOVERED_SERVICES = 25            # borne le fan-out (un scan -p- ne doit pas exploser le plan)
_MAX_PROBED_PORTS = 25                   # borne les sondes de CONFIRMATION HTTP (un -p- peut ouvrir bcp de ports)
_MAX_DISCOVERED_ENDPOINTS = 25           # borne le fan-out d'un CRAWL (katana/gospider/gau) — style ≤25/≤32

# Extraction de ports depuis la sortie hétérogène des scanners de ports (déjà PARSÉE en « hits ») :
#  - masscan : « Discovered open port 8000/tcp on 127.0.0.1 » ;
#  - naabu   : « 127.0.0.1:8000 » (host:port par ligne).
_MASSCAN_PORT_RX = re.compile(r"open port (\d{1,5})/", re.IGNORECASE)
_HOSTPORT_RX = re.compile(r":(\d{1,5})\s*$")


def bare_host(target):
    """Hôte nu (scheme/userinfo/path/port retirés) d'une cible. Miroir simplifié de `Scope._host` :
    sert à ANCRER un `host:port` découvert sur l'hôte DÉJÀ gaté par le ROE (jamais un autre hôte).
    Pur, ne lève jamais."""
    s = str(target).strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):                            # IPv6 littéral [::1]:port -> garde l'adresse
        return s.split("]", 1)[0].lstrip("[")
    if s.count(":") == 1:                            # host:port (pas IPv6 nu)
        s = s.split(":", 1)[0]
    return s


def is_ip_literal(host):
    """True si `host` est une adresse IP LITTÉRALE (v4/v6), pas un nom de domaine. Pur, ne lève jamais.
    Sert au garde-fou des modules d'ARCHIVE WEB (gau/Wayback) : les archives sont indexées par NOM de
    domaine — une IP nue n'a jamais d'archive utile (que du bruit) -> skip propre."""
    try:
        ipaddress.ip_address(str(host).strip())
        return True
    except ValueError:
        return False


def http_probe(url, timeout=5):
    """Sonde de CONFIRMATION HTTP d'un port ouvert -> status (int) ou None. GET avec Host correct via le
    câblage urllib partagé (`Oracle._http`) : un port qui parle HTTP renvoie un STATUS (200/401/421…),
    un service NON-HTTP (VNC…) casse le parse HTTP -> None. Seam par DÉFAUT ; les modules l'exposent via
    `_fetch` (monkeypatchable par les tests). Ne lève jamais (sonde qui lève -> traitée non-HTTP)."""
    try:
        st, _body, _h = Oracle._http(url, timeout=timeout, method="GET", maxlen=2048)
        return st
    except Exception:            # noqa: BLE001  (réseau/protocole hostile : jamais un crash)
        return None


def http_confirmed_ports(fetch, host, ports):
    """Sous-ensemble de `ports` (ouverts) qui parlent RÉELLEMENT HTTP, prouvé par une sonde GET (Host
    correct) via `fetch` (le seam `_fetch` du module). Un service NON-HTTP (VNC 5900…) casse le parse
    HTTP -> None -> jamais confirmé -> ZÉRO bruit. Sonde BORNÉE (`_MAX_PROBED_PORTS`). Ancrée sur l'hôte
    DÉJÀ gaté par le ROE (`host`) : la sonde ne peut PHYSIQUEMENT pas quitter le périmètre. Pur (hormis
    la sonde), ne lève jamais."""
    # Cap de sondes RÉSOLU par profil (`discovery_max_fanout`) : `balanced` == 25 == _MAX_PROBED_PORTS
    # (byte-identique) ; `low`=8 (moins de sondes = plus léger), `full`=50. Défaut-classe préservé.
    max_probe = resource_profile.resolve("discovery_max_fanout", default=_MAX_PROBED_PORTS)
    out, seen, n = [], set(), 0
    for p in ports:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            continue
        if pi in seen:
            continue
        seen.add(pi)
        if n >= max_probe:
            break
        n += 1
        try:
            st = fetch(f"http://{host}:{pi}")
        except Exception:            # noqa: BLE001  (réseau/protocole hostile : jamais un crash)
            st = None
        if st is not None:           # une RÉPONSE HTTP (quel que soit le code) => le port parle HTTP
            out.append(pi)
    return out


def service_discovery_findings(module, action, ports, tool):
    """Un finding de DÉCOUVERTE par port web NON standard (target = `host:port`, marqueur
    DISCOVERY_SERVICE_MARKER) -> le port devient un NŒUD du graphe que le cerveau chaîne (actions web
    de base + scanners de contenu + modules web explicites via _directive_actions) sur cette nouvelle
    surface. Ancré sur l'hôte DÉJÀ gaté par le ROE (`bare_host(action.target)`) : jamais un autre hôte
    -> la re-gate ROE de la vague suivante le laisse passer s'il est in-scope (host in-scope => host:port
    in-scope) et le VÉTOe sinon. Ports 80/443 et le port propre de la cible ignorés (déjà couverts).
    Borné + dédupliqué. Pur, ne lève jamais."""
    host = bare_host(action.target)
    tgt_netloc = str(action.target).split("://")[-1].split("/", 1)[0]
    # Cap de fan-out RÉSOLU par profil : `balanced` == 25 == _MAX_DISCOVERED_SERVICES (byte-identique) ;
    # `low`=8, `full`=50. Borne les NŒUDS de service ajoutés au graphe (un -p- ne doit pas l'exploser).
    max_services = resource_profile.resolve("discovery_max_fanout", default=_MAX_DISCOVERED_SERVICES)
    out, seen = [], set()
    for port in ports:
        try:
            p = int(port)
        except (TypeError, ValueError):
            continue
        if p in _STANDARD_WEB_PORTS or p in seen or not (0 < p < 65536):
            continue
        hp = f"{host}:{p}"
        if hp == tgt_netloc:                         # déjà la cible courante -> pas de nœud self-référent
            continue
        seen.add(p)
        out.append(module.finding(
            target=hp, title=f"{techniques.DISCOVERY_SERVICE_MARKER} : {hp}",
            severity="INFO", category="recon", mitre=getattr(module, "mitre", ""), status="tested",
            tool=tool,
            evidence=(f"Service web découvert sur le port non standard {p} ({hp}) via {tool} — "
                      f"nouvelle surface web chaînable (fingerprint/oracles/scanners à la vague suivante)."),
            poc=f"# {tool} : service web exposé sur {hp}"))
        if len(out) >= max_services:
            break
    return out


def _looks_http_url(u):
    """True si `u` est une URL http(s) ABSOLUE (candidat d'endpoint chaînable). Pur, ne lève jamais."""
    return str(u).strip().lower().startswith(("http://", "https://"))


def _has_query_param(u):
    """True si l'URL porte au moins un paramètre de query `?k=` (donc INJECTABLE via param) — valeurs
    VIDES INCLUSES (`keep_blank_values` : `?QUERY=` est injectable, il ne doit pas être dé-priorisé/coupé
    par le cap comme s'il était sans paramètre). Pur."""
    try:
        return bool(urllib.parse.parse_qsl(urllib.parse.urlsplit(str(u)).query, keep_blank_values=True))
    except Exception:            # noqa: BLE001
        return False


def endpoint_discovery_findings(module, action, urls, tool):
    """Convertit les URLs CRAWLÉES (katana/gospider/gau) en findings de DÉCOUVERTE D'ENDPOINT
    chaînables : chaque URL http(s) IN-SCOPE devient un NŒUD du graphe (target=URL, marqueur
    DISCOVERY_ENDPOINT_MARKER) que le cerveau CHAÎNE vers les oracles à injection (edge e — il en
    extrait le paramètre de query et SONDE RÉELLEMENT au lieu d'émettre « config manquante »), AU
    LIEU d'un simple finding texte par-URL rattaché à l'hôte (jamais vérifié).

    Garde-fous :
      - RE-VALIDÉ fail-closed contre le périmètre injecté (`module._scope`) : une URL dont l'hôte
        sort du scope n'est JAMAIS émise (le matériel/réseau ne peut physiquement pas fuir) ;
      - INJECTABLES D'ABORD : les URLs porteuses d'un paramètre de query (`?k=v`) sont priorisées
        (tri STABLE) avant celles sans query -> le cap ne sacrifie pas la surface injectable ;
      - dédupliqué (ordre préservé), borné à `_MAX_DISCOVERED_ENDPOINTS` (un crawl volumineux ne
        doit pas exploser le plan). Pur, ne lève jamais."""
    enforce, sc = module._scope(action)
    seen, cleaned = set(), []
    for u in urls:
        s = str(u).strip().rstrip('\\",\')')
        if not _looks_http_url(s) or s in seen:
            continue
        if enforce and not sc.is_in_scope(s):        # fail-closed : jamais un endpoint hors périmètre
            continue
        seen.add(s)
        cleaned.append(s)
    cleaned.sort(key=lambda u: 0 if _has_query_param(u) else 1)   # stable : injectables d'abord
    # Cap d'endpoints crawlés RÉSOLU par le MÊME levier que recon_surface.MAX_ENDPOINTS (`crawl_max_endpoints`) :
    # `balanced` == 25 == _MAX_DISCOVERED_ENDPOINTS (byte-identique) ; `low`=10, `full`=50.
    max_endpoints = resource_profile.resolve("crawl_max_endpoints", default=_MAX_DISCOVERED_ENDPOINTS)
    out = []
    for u in cleaned[:max_endpoints]:
        out.append(module.finding(
            target=u, title=f"{techniques.DISCOVERY_ENDPOINT_MARKER} : {u}",
            severity="INFO", category="recon", mitre=getattr(module, "mitre", ""), status="tested",
            tool=tool,
            evidence=(f"Endpoint in-scope découvert par {tool} ({u}) — nouvelle surface chaînable : le "
                      f"cerveau y branche les oracles à injection (paramètre de query -> sonde réelle)."),
            poc=f"# {tool} : endpoint in-scope à vérifier -> {u}"))
    return out


def ports_from_hits(hits):
    """Ports (int) extraits des HITS déjà parsés d'un scanner de ports — tolère les DEUX formats
    (masscan `Discovered open port N/tcp on host`, naabu `host:port`). Dé-dupliqué, ordre préservé.
    Pur, ne lève jamais."""
    ports, seen = [], set()
    for h in hits:
        s = str(h)
        m = _MASSCAN_PORT_RX.search(s) or _HOSTPORT_RX.search(s)
        if not m:
            continue
        try:
            p = int(m.group(1))
        except ValueError:
            continue
        if 0 < p < 65536 and p not in seen:
            seen.add(p)
            ports.append(p)
    return ports


def port_inventory_finding(module, action, tool, ports):
    """UN finding INFO d'INVENTAIRE listant les `host:port` OUVERTS découverts (la surface visible en un
    seul finding, au lieu d'être noyée dans le texte de sortie). Ancré sur l'hôte in-scope. Renvoie None
    si aucun port. Pur, ne lève jamais."""
    host = bare_host(action.target)
    seen, hps = set(), []
    for p in ports:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            continue
        if not (0 < pi < 65536) or pi in seen:
            continue
        seen.add(pi)
        hps.append(f"{host}:{pi}")
    if not hps:
        return None
    listing = ", ".join(hps[:_MAX_DISCOVERED_SERVICES + 25])   # borne l'évidence (une seule ligne lisible)
    return module.finding(
        target=action.target, title=f"Inventaire de ports ouverts ({len(hps)}) — {tool}",
        severity="INFO", category="recon", mitre=getattr(module, "mitre", ""), status="tested",
        tool=tool,
        evidence=f"{len(hps)} port(s) ouvert(s) découverts sur {host} via {tool} : {listing}",
        poc=f"# {tool} : inventaire des host:port ouverts")

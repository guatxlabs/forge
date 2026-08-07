# SPDX-License-Identifier: AGPL-3.0-or-later
"""NON-CIBLES d'INFRASTRUCTURE d'edge (CDN/WAF) — reconnaissance PURE (stdlib, JAMAIS de réseau).

Le trou comblé (mesuré sur un run réel derrière Cloudflare) : la découverte backed-browser a capturé
la requête XHR que le navigateur émet VERS LE CDN pour résoudre son propre défi —
`https://<host>/cdn-cgi/challenge-platform/h/b/fo/<token>` — et l'a adoptée comme un endpoint
applicatif ordinaire. Le cerveau en a fait un NŒUD du graphe, puis **85 des 1573 tirs (5,4 %)** ont
visé cette URL. Ce n'est pas une cible : c'est le MUR lui-même. Sur un vrai programme, marteler
l'endpoint de défi d'un CDN ressemble à du hammering et se paie.

CRITÈRE D'INCLUSION (la règle de maintenance — s'y tenir, sinon ça dégénère en deny-list bavarde) :
une famille n'entre ici QUE si le fournisseur d'edge **RÉSERVE** le préfixe de chemin et le
**TERMINE À L'EDGE** — la requête n'atteint JAMAIS l'origine, donc aucun code applicatif n'est
derrière, donc il n'y a rien à tester. C'est un fait d'architecture, pas un goût. Un chemin qui PEUT
être servi par l'origine n'entre PAS (contre-exemple délibérément EXCLU : `/.well-known/acme-challenge/`,
couramment servi par l'application elle-même via le plugin webroot — donc cible légitime).

CE QUI EST RECONNU N'EST PAS SUPPRIMÉ. Le contrat du moteur est coverage-safe : on n'affame jamais une
classe en silence. Un appelant qui écarte une URL sur ce signal DOIT l'ANNONCER (constat nommé, compté)
et la classer `skipped` — « je n'ai pas vérifié » — jamais `tested` — « j'ai vérifié, rien trouvé ».

SUR-FILTRAGE — deux échappatoires EXPLICITES, parce qu'un endpoint d'infra PEUT être une vraie cible :
  1. le périmètre le NOMME : un motif `in_scope` qui mentionne le préfixe (ex. `guatx.com/cdn-cgi/*`)
     désarme la famille correspondante — l'opérateur a dit que c'était une cible, il a raison ;
  2. `FORGE_ALLOW_INFRA_TARGETS=1` désarme TOUTE la reconnaissance (engagement dédié à l'edge).

Pur : ne lève jamais, n'émet aucune requête, ne lit aucun fichier. Seul l'environnement est consulté.
"""
import os
import urllib.parse

# Variable d'environnement d'échappement GLOBAL (échappatoire 2) — désarme toute la reconnaissance.
ALLOW_ENV = "FORGE_ALLOW_INFRA_TARGETS"

# Titre-marqueur PARTAGÉ émetteur/détecteur (zéro duplication de chaîne entre les modules de surface,
# l'engine et les tests) : c'est LE mot par lequel un constat de non-cible se reconnaît dans un rapport.
NON_TARGET_MARKER = "non-cible d'infrastructure (edge CDN/WAF)"

# Familles d'edge à namespace RÉSERVÉ. (nom, préfixes de CHEMIN, pourquoi ce n'est pas une cible).
# Le nom est stable : il apparaît tel quel dans les raisons de SKIP, le ledger et le rapport.
EDGE_NAMESPACES = (
    ("cloudflare/cdn-cgi", ("/cdn-cgi/",),
     "namespace réservé Cloudflare, terminé à l'edge (challenge-platform, rum, trace, bm, zaraz, "
     "l/email-protection…) : la requête n'atteint jamais l'origine"),
    ("cloudflare/__cf", ("/__cf",),
     "chemins de défi/legacy Cloudflare (__cf_chl_*, __cfduid) générés par l'edge pour son propre "
     "cycle de vérification"),
    ("imperva/incapsula", ("/_incapsula_resource",),
     "ressource et défi Imperva/Incapsula servis par l'edge"),
    ("akamai/bot-manager", ("/_sec/cp_challenge/",),
     "défi Akamai Bot Manager (cryptographic challenge) servi par l'edge"),
    ("akamai/edge", ("/akam/",),
     "namespace de diagnostic/sonde Akamai servi par l'edge"),
)


def _path_of(target):
    """CHEMIN d'une cible, casefold, ou '' si elle n'en porte pas. Une cible peut être une URL
    complète, un hôte nu ou un `host:port` — SEULE une URL porte un chemin, donc un hôte nu n'est
    JAMAIS classé (un hôte `cdn-cgi.example.com` reste une cible parfaitement légitime). Pur."""
    s = str(target or "").strip()
    if not s:
        return ""
    try:
        # Sans scheme, `urlsplit` mettrait tout dans `.path` ; on préfixe `//` pour forcer un netloc
        # et n'obtenir un chemin QUE s'il y en a réellement un (`host:port` -> path vide).
        parts = urllib.parse.urlsplit(s if "://" in s else "//" + s)
    except (ValueError, TypeError):                       # netloc/port malformé -> pas de chemin exploitable
        return ""
    return (parts.path or "").casefold()


def _disarmed(prefixes, allow_patterns):
    """True si le périmètre NOMME explicitement ce namespace (échappatoire 1) : un motif in_scope qui
    contient le préfixe réservé signifie « oui, c'est bien ça que je veux tester ». Pur."""
    for pat in (allow_patterns or ()):
        low = str(pat).casefold()
        if any(p in low for p in prefixes):
            return True
    return False


def classify(target, allow_patterns=()):
    """Nom de la famille d'infra d'edge reconnue pour `target`, ou '' si ce n'est PAS une non-cible.

    `allow_patterns` : les motifs `in_scope` du périmètre — un motif qui nomme le préfixe désarme la
    famille (échappatoire 1). `FORGE_ALLOW_INFRA_TARGETS=1` désarme tout (échappatoire 2).

    Ne lève JAMAIS : une entrée hostile (None, objet exotique, URL malformée) rend '' — fail-OPEN,
    parce qu'un défaut de reconnaissance doit coûter un tir inutile, jamais une cible perdue."""
    try:
        if str(os.environ.get(ALLOW_ENV, "")).strip().casefold() in ("1", "true", "yes", "on"):
            return ""
        path = _path_of(target)
        if not path:
            return ""
        for name, prefixes, _why in EDGE_NAMESPACES:
            if not any(path == p.rstrip("/") or path.startswith(p) for p in prefixes):
                continue
            if _disarmed(prefixes, allow_patterns):
                return ""                                 # le périmètre le nomme -> vraie cible
            return name
        return ""
    except Exception:                                     # noqa: BLE001 — entrée hostile : jamais fatal
        return ""


def why(family):
    """Justification COURTE d'une famille (pourquoi ce n'est pas une cible) — '' si inconnue. Pur."""
    for name, _prefixes, reason in EDGE_NAMESPACES:
        if name == family:
            return reason
    return ""


def skip_reason(family):
    """Raison NOMMÉE, prête à porter dans un verdict SKIP / une évidence de finding. Elle DIT ce qui
    est écarté, POURQUOI, et COMMENT le tester quand même (anti-troncature silencieuse). Pur."""
    detail = why(family)
    return (f"{NON_TARGET_MARKER} : {family}"
            + (f" — {detail}" if detail else "")
            + f" ; non testé (aucun code applicatif derrière). Pour le tester quand même : déclarer "
              f"le chemin dans le scope (in_scope) ou {ALLOW_ENV}=1.")

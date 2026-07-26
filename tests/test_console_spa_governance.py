# SPDX-License-Identifier: AGPL-3.0-or-later
"""Invariants de GOUVERNANCE du SPA de la console, vérifiés sur la SOURCE RÉELLEMENT SERVIE.

CE QUE CES TESTS COUVRENT. Les tests Rust appellent les handlers directement : ils ne peuvent pas voir
que le CLIENT n'envoie pas la preuve opérateur. L'invariant à tenir est :

    une requête qui MUTE doit porter la preuve opérateur — en particulier `POST /api/plan`
    (dry-plan INERTE) ne doit JAMAIS être plus restreint que `POST /api/run` (campagne ARMÉE).

POURQUOI CE FICHIER A ÉTÉ RÉÉCRIT (3e fois) — ET CE QUI CHANGE VRAIMENT. Les trois versions
précédentes cherchaient LES ROUTES dans le JavaScript : d'abord sur la même ligne, puis sur des
parenthèses équilibrées. Chaque version a été contournée par l'ÉCRITURE SUIVANTE, mesurée :

    fetch("/api/" + "plan", …)          littéral concaténé            -> non vu
    fetch(`/api/${KIND}`, …)            gabarit interpolé             -> non vu (forme déjà idiomatique ici)
    fetch("/api\\x2Fplan", …)            échappement                   -> non vu
    console/web/app.js                  hors du répertoire scanné     -> non vu
    fetch(…, { body: rewrite(b) })      « write( » fourni par « rewrite( » -> preuve opérateur FAUSSE

Reconnaître une route dans du JavaScript, c'est énumérer des formes d'écriture : la garde est fausse
dès qu'on en ajoute une. La propriété a donc été INVERSÉE, et elle ne lit plus AUCUNE route :

  (1) PÉRIMÈTRE DÉRIVÉ. On ne scanne plus un répertoire écrit en dur. On part de `console/web/index.html`,
      on relève TOUT `<script src=…>` qu'il charge, et on suit les `import` (statiques ET dynamiques)
      jusqu'à fermeture. Un fichier ne peut être exécuté par le SPA que s'il est dans cette fermeture :
      `app.js` en fait partie, et un module ajouté demain aussi, sans que personne ait à le déclarer.

  (2) CARDINALITÉ, PAS RECONNAISSANCE. Dans ce graphe, l'identifiant `fetch` ne doit apparaître QUE
      dans UN SEUL module — celui qui attache la preuve. Aucune concaténation, aucune interpolation,
      aucun échappement ne peut contourner ça : la garde ne regarde pas ce qui est demandé au réseau,
      elle regarde QUI a le droit de parler au réseau. Les autres primitives capables de MUTER
      (`XMLHttpRequest`, `sendBeacon`, `importScripts`, `WebSocket`, et la SOUMISSION DE FORMULAIRE)
      doivent être absentes, et un accès global calculé (`window[…]`, `globalThis[…]`, `self[…]`) aussi.

  (3) LA GOUVERNANCE SE RÉDUIT À UN FICHIER — ET ON L'EXÉCUTE, ON NE LA LIT PLUS. Dans ce module unique,
      la preuve doit être attachée à toute requête mutante. Les versions précédentes le vérifiaient par
      SOUS-CHAÎNE (`"operatorHeaders(" in body`) : mesuré, ce test restait VERT alors que la preuve ne
      partait plus, dans TROIS régressions d'une ligne — helper vidé (`return { ...extra }`), helper
      SOSIE (`xoperatorHeaders`), et même une simple CHAÎNE MORTE (`const dead = "operatorHeaders(";`).
      La propriété est donc désormais COMPORTEMENTALE : `tests/js/spa_door_probe.mjs` importe le module
      d'API RÉEL sous node, remplace toutes les primitives réseau par des enregistreurs, appelle CHAQUE
      export du module (liste prise dans l'espace de noms importé, rien n'est écrit en dur) et rend ce
      qui SERAIT PARTI. Un sosie, un commentaire ou une chaîne morte ne peuvent pas tromper ça : ce qui
      est asserté est l'en-tête effectivement posé sur la requête. Le nom de cet en-tête n'est pas non
      plus écrit ici : il est LU DANS LE SERVEUR (`console/src/auth.rs`), donc renommer d'un seul côté
      fait ÉCHOUER la garde.

CE QUI RESTE ÉNUMÉRÉ, ET POURQUOI C'EST ACCEPTABLE (dit, pas caché) :
  - la liste des primitives réseau du NAVIGATEUR (`fetch`/`XMLHttpRequest`/`sendBeacon`/`importScripts`/
    `WebSocket`) est une énumération — mais elle est bornée par la plateforme, pas par notre code : elle
    ne bouge que si le navigateur ajoute une primitive, alors que l'ancienne énumération (les façons
    d'écrire une route) grandissait à chaque nouveau site d'appel. Cette liste avait un TROU, mesuré et
    fermé ici : la SOUMISSION DE FORMULAIRE (`f.action='/api/'+'plan'; f.submit()`) est une écriture
    réseau qui existe depuis 1995, qu'aucun identifiant de la liste ne nomme. Elle est maintenant fermée
    des DEUX côtés : (a) au RUNTIME par la CSP du dépôt, passée de `form-action 'self'` à
    `form-action 'none'` — le navigateur REFUSE la soumission (les 12 formulaires du SPA sont tous
    pilotés en JS avec `preventDefault()`, aucun ne navigue) ; (b) dans la garde, par la détection des
    appels `.submit(` / `.requestSubmit(` et de `HTMLFormElement`. La CSP elle-même est épinglée par un
    test, aux DEUX endroits qui la portent (meta de `index.html` et `CSP_POLICY` du serveur) ;
  - `EventSource` n'est PAS contraint : il est GET-only par spécification et ne peut porter aucun
    en-tête, donc il ne peut pas être un site d'écriture gouvernée (c'est d'ailleurs pour ça que le SPA
    bascule en polling quand une preuve est nécessaire). Même raisonnement pour les primitives qui ne
    peuvent émettre qu'un GET de ressource (`<img src>`, `<link>`, navigation) : aucune route mutante de
    la console n'est un GET — vérifié sur les DÉCLARATIONS de routes (`console/src/*.rs`), pas seulement
    sur le tableau de `docs/HTTP_API.md` : les seuls handlers `get(...)` dont le nom évoque une mutation
    sont `setup_state` (lecture pure : renvoie `provisioned`/`capabilities`) ;
  - la lecture ignore l'INTÉRIEUR des chaînes. Mesuré, sur une copie hors dépôt, ce que ça laisse
    passer et ce que ça ne laisse PAS passer : `globalThis['fet'+'ch']('/api/plan', …)` est DÉTECTÉ
    (accès global calculé), `(0,eval)('fet'+'ch')('/api/plan', …)` est DÉTECTÉ (la route est rattachée
    à une callee inconnue -> échec bruyant, et la CSP `script-src 'self'` interdit de toute façon
    `eval` au runtime) ; le seul cas NON DÉTECTÉ est l'obfuscation COMPLÈTE — primitive aliasée dans
    une variable ET clé calculée ET route concaténée (`const G = globalThis; G['fet'+'ch']('/api/'+'plan')`).
    Fermer ce cas demanderait d'ÉVALUER le JavaScript, pas de le lire : la garde couvre ce qu'on écrit,
    pas ce qu'on maquille délibérément ;
  - un fichier SERVI mais HORS du graphe du SPA (aujourd'hui le seul `sw.js`, qui vit dans le contexte
    service-worker et ne peut pas importer le module d'API) est ÉPINGLÉ PAR EMPREINTE : le modifier ou
    en ajouter un autre qui touche au réseau fait ÉCHOUER le test, donc oblige à une décision humaine.
    L'épingle ne regardait QUE `fetch` : mesuré, un fichier hors graphe faisant du XHR n'était NI dans
    le graphe NI épinglé. Elle regarde désormais TOUTE primitive mutante (formulaires compris).

DEUX TROUS DE PÉRIMÈTRE, MESURÉS ET FERMÉS ICI (ils étaient dans la version précédente) :
  - `<script src="/track.js?v=2">` — le cache-busting par query-string est idiomatique. `_resolve` ne
    résolvait pas `track.js?v=2` vers un fichier : le fichier n'était donc PAS un point d'entrée, sortait
    du graphe, et (voir ci-dessus) n'était pas épinglé s'il utilisait autre chose que `fetch`. La query
    et le fragment sont maintenant retirés avant résolution, comme le fait le navigateur ;
  - un `<script>` INLINE dans `index.html` n'était JAMAIS lu (la page n'était parcourue que pour ses
    `<script src>`). Les blocs inline font maintenant partie des sources scannées.
    HONNÊTETÉ SUR CE POINT : la CSP `script-src 'self'` (sans `unsafe-inline`) BLOQUE déjà ce script au
    runtime — le trou de garde existait, l'exploitation n'existait pas. C'était la CSP qui tenait, pas
    la garde ; maintenant les deux tiennent, indépendamment.

LIMITE DE LA SONDE COMPORTEMENTALE, DITE PLUTÔT QUE TUE : elle a besoin d'un runtime JavaScript (`node`).
S'il est absent, ces tests-là sont SAUTÉS avec un message explicite — le reste de la garde (périmètre,
cardinalité, primitives, CSP) est pur-stdlib et continue de tourner. Poser `FORGE_REQUIRE_JS_RUNTIME=1`
transforme l'absence en ÉCHEC : c'est ce que fait la CI, pour qu'un saut silencieux ne devienne jamais
une garde éteinte.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WEB_DIR = REPO / "console" / "web"
INDEX_HTML = WEB_DIR / "index.html"
#: source du SERVEUR qui lit la preuve opérateur — la garde y prend le NOM de l'en-tête (cf. docstring).
AUTH_RS = REPO / "console" / "src" / "auth.rs"
#: sonde comportementale (node) : cf. docstring (3).
JS_PROBE = Path(__file__).resolve().parent / "js" / "spa_door_probe.mjs"
#: valeur injectée comme secret opérateur pendant la sonde : elle doit se retrouver TELLE QUELLE sur
#: l'en-tête des requêtes mutantes (une preuve « présente mais vide » n'est pas une preuve).
PROBE_SENTINEL = "S3CRET-PROBE-9f2c"

#: primitives du navigateur capables d'émettre une requête MUTANTE (cf. docstring : énumération bornée
#: par la plateforme). `fetch` est la seule tolérée, et seulement dans le module d'API.
#: `WebSocket` y est PAR PRÉVENTION : aucune route WS n'existe côté serveur aujourd'hui (donc aucune
#: conséquence), mais une trame WS ne porte pas d'en-tête par message — si une route WS apparaît un jour,
#: la question de gouvernance doit être ROUVERTE explicitement, pas héritée en silence.
_MUTATING_PRIMITIVES = ("fetch", "XMLHttpRequest", "sendBeacon", "importScripts", "WebSocket")
#: SOUMISSION DE FORMULAIRE — la primitive mutante que la liste ci-dessus ne nomme pas (aucun identifiant
#: global : c'est une méthode d'élément). Fermée au runtime par `form-action 'none'` (CSP, épinglée plus
#: bas) et détectée ici. `onsubmit`/`addEventListener('submit')` ne matchent pas : ce sont des HANDLERS
#: (le SPA en a 12, tous avec `preventDefault()`), pas des émissions.
_FORM_SUBMISSION = (
    re.compile(r"\.\s*submit\s*\("),
    re.compile(r"\.\s*requestSubmit\s*\("),
    re.compile(r"(?<![A-Za-z0-9_$])HTMLFormElement(?![A-Za-z0-9_$])"),
)
#: directive CSP qui REFUSE la soumission de formulaire, exigée dans les DEUX portées de la politique.
_CSP_FORM_ACTION = "form-action 'none'"
#: conteneurs globaux dont un accès CALCULÉ permettrait d'atteindre une primitive sans l'écrire.
_GLOBAL_CONTAINERS = ("window", "globalThis", "self")

#: fichiers SERVIS hors du graphe du SPA qui touchent au réseau, épinglés par empreinte (cf. docstring).
#: sha256 du contenu exact, relevé sur le fichier du dépôt.
_PINNED_OUT_OF_GRAPH = {
    "sw.js": "218cc8e53833b1737b77b6f53687999d18d21fcdfc300b01ab3f2511fbe35aa3",
}

_IDENT = re.compile(r"[A-Za-z0-9_$]")


# --------------------------------------------------------------------------------------
# lecture du source : commentaires et chaînes neutralisés (longueurs et lignes préservées)
# --------------------------------------------------------------------------------------
def _blank_comments(src):
    """Remplace les commentaires par des espaces. Scanner qui suit l'état de chaîne (`'`, `"`, `` ` ``)
    et les échappements : un `//` dans une URL littérale n'ouvre pas un commentaire."""
    out = list(src)
    i, n = 0, len(src)
    quote = None
    while i < n:
        c = src[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"`":
            quote = c
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            for k in range(i, min(i + 2, n)):
                out[k] = " "
            i += 2
            continue
        i += 1
    return "".join(out)


def _string_literals(src):
    """(début, fin, valeur) de chaque littéral de chaîne. `fin` = index du quote fermant."""
    lits = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"`":
            j = i + 1
            buf = []
            while j < n:
                if src[j] == "\\":
                    buf.append(src[j : j + 2])
                    j += 2
                    continue
                if src[j] == c:
                    break
                buf.append(src[j])
                j += 1
            lits.append((i, j, "".join(buf)))
            i = j + 1
            continue
        i += 1
    return lits


def _blank_strings(code):
    """Vide le CONTENU des chaînes (quotes conservées) : le texte d'une chaîne n'est pas du code."""
    out = list(code)
    for start, end, _v in _string_literals(code):
        for k in range(start + 1, min(end, len(out))):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def _code_only(src):
    """Source sans commentaires ET sans contenu de chaîne : ce qui reste est du code exécutable."""
    return _blank_strings(_blank_comments(src))


def _ident_hits(code, name):
    """Lignes où l'IDENTIFIANT `name` apparaît (jamais une sous-chaîne : `fetchToken` ne compte pas,
    `globalThis.fetch` compte)."""
    pat = re.compile(r"(?<![A-Za-z0-9_$])" + re.escape(name) + r"(?![A-Za-z0-9_$])")
    return [code.count("\n", 0, m.start()) + 1 for m in pat.finditer(code)]


# --------------------------------------------------------------------------------------
# PÉRIMÈTRE DÉRIVÉ : ce que le navigateur charge, pas un répertoire écrit en dur
# --------------------------------------------------------------------------------------
_SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"]", re.I)
#: bloc `<script>` SANS `src` = code INLINE de la page servie (cf. docstring : il était invisible).
_SCRIPT_INLINE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>", re.I | re.S)
_IMPORT_FROM = re.compile(r"""\bfrom\s*['"]([^'"]+)['"]""")
_IMPORT_BARE = re.compile(r"""\bimport\s*(?:\(\s*)?['"]([^'"]+)['"]""")


def _resolve(spec, base):
    """Résout un spécificateur de module vers un fichier de `console/web` (None si hors périmètre)."""
    if spec.startswith(("http://", "https://", "//", "data:")):
        return None
    # Le navigateur charge `/track.js?v=2` DEPUIS `track.js` : la query (cache-busting, idiomatique) et
    # le fragment ne font pas partie du chemin. Ne pas les retirer sortait le fichier du graphe (mesuré).
    spec = spec.split("#", 1)[0].split("?", 1)[0]
    if not spec:
        return None
    p = (WEB_DIR / spec.lstrip("/")) if spec.startswith("/") else (base.parent / spec)
    try:
        p = p.resolve()
    except OSError:
        return None
    if not p.is_file() or WEB_DIR not in p.parents and p.parent != WEB_DIR:
        return None
    return p


def _entry_points():
    """Points d'entrée DÉCLARÉS par la page servie (`<script src=…>`), quel que soit leur `type`."""
    html = INDEX_HTML.read_text(encoding="utf-8")
    entries = []
    for src in _SCRIPT_SRC.findall(html):
        p = _resolve(src, INDEX_HTML)
        if p is not None and p.suffix == ".js":
            entries.append(p)
    return entries


def _module_graph():
    """Fermeture transitive des modules chargés par le SPA (imports statiques ET dynamiques). Un
    fichier hors de cette fermeture n'est jamais exécuté par la page."""
    seen, stack = {}, list(_entry_points())
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        src = p.read_text(encoding="utf-8")
        seen[p] = src
        code = _blank_comments(src)
        for spec in set(_IMPORT_FROM.findall(code)) | set(_IMPORT_BARE.findall(code)):
            t = _resolve(spec, p)
            if t is not None and t not in seen:
                stack.append(t)
    return seen


def _inline_scripts():
    """Code des blocs `<script>` SANS `src` de la page servie. Ils sont exécutables (la CSP
    `script-src 'self'` les bloque aujourd'hui, mais la garde ne doit pas dépendre de la CSP)."""
    html = INDEX_HTML.read_text(encoding="utf-8")
    return [(f"index.html#inline{i + 1}", m.group(1)) for i, m in enumerate(_SCRIPT_INLINE.finditer(html))]


def _served_js():
    return sorted(WEB_DIR.rglob("*.js"))


def _rel(p):
    return str(p.relative_to(WEB_DIR))


def _graph_sources(graph=None):
    """TOUT le code que la page peut exécuter : les modules du graphe + les blocs inline. [(nom, source)]."""
    graph = graph if graph is not None else _module_graph()
    return [(_rel(p), s) for p, s in sorted(graph.items())] + _inline_scripts()


def _network_modules(graph=None):
    """Sources exécutables qui référencent l'identifiant `fetch` (hors commentaires et chaînes)."""
    out = {}
    for name, s in _graph_sources(graph):
        hits = _ident_hits(_code_only(s), "fetch")
        if hits:
            out[name] = hits
    return out


def _form_submission_hits(code):
    """Lignes où une SOUMISSION DE FORMULAIRE est émise (cf. `_FORM_SUBMISSION`)."""
    return [f"{code.count(chr(10), 0, m.start()) + 1} {m.group(0).strip()}" for pat in _FORM_SUBMISSION for m in pat.finditer(code)]


def _network_touches(src):
    """Descriptions des points où `src` touche au réseau, TOUTES primitives (identifiants + formulaire)."""
    code = _code_only(src)
    hits = [f"{prim}:{line}" for prim in _MUTATING_PRIMITIVES for line in _ident_hits(code, prim)]
    return hits + [f"form:{h}" for h in _form_submission_hits(code)]


# --------------------------------------------------------------------------------------
# lecture d'appels (utilisée par le test /api/plan, PLUS par sous-chaîne)
# --------------------------------------------------------------------------------------
def _match_paren(src, open_idx):
    depth, i, n = 0, open_idx, len(src)
    quote = None
    while i < n:
        c = src[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def _enclosing_calls(src, idx):
    """Chaîne des appels ENGLOBANT `src[idx]`, du plus PROCHE au plus LOINTAIN : [(callee, texte)].
    Le callee est un IDENTIFIANT complet (`rewrite` n'est jamais confondu avec `write`)."""
    calls = []
    i, depth = idx, 0
    while i > 0:
        c = src[i]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                j = i - 1
                while j >= 0 and src[j].isspace():
                    j -= 1
                k = j
                while k >= 0 and _IDENT.match(src[k]):
                    k -= 1
                name = src[k + 1 : j + 1]
                if not name:
                    break
                calls.append((name, src[k + 1 : _match_paren(src, i) + 1]))
                i = k
                depth = 0
                continue
            depth -= 1
        i -= 1
    return calls


def _route_refs(code, route):
    """(ligne, index) de chaque LITTÉRAL désignant `route` — égal, ou suivi de `?`/`/`."""
    out = []
    for start, _end, value in _string_literals(code):
        v = value.strip()
        if v == route or v.startswith(route + "?") or v.startswith(route + "/"):
            out.append((code.count("\n", 0, start) + 1, start))
    return out


def _api_module_exports(graph=None):
    """Noms EXPORTÉS par le module réseau unique — c'est-à-dire la liste, DÉRIVÉE du source, des façons
    légitimes d'atteindre le réseau. Un helper ajouté demain dans ce module est reconnu sans que ce
    test soit touché."""
    graph = graph if graph is not None else _module_graph()
    mods = _network_modules(graph)
    if len(mods) != 1:
        return set()
    name = next(iter(mods))
    src = dict(_graph_sources(graph))[name]
    code = _blank_comments(src)
    return set(re.findall(r"\bexport\s+(?:async\s+)?function\s+([A-Za-z0-9_$]+)", code)) | set(
        re.findall(r"\bexport\s+(?:const|let|var)\s+([A-Za-z0-9_$]+)", code)
    )


def _network_call_sites(route, sources=None, callees=None):
    """(fichier, ligne, callee, texte) pour chaque référence à `route` dans le graphe. `callee` est
    `None` si aucune callee réseau connue n'englobe la référence — le cas n'est pas jeté, il est
    REMONTÉ pour que le test échoue au lieu de devenir aveugle."""
    if callees is None:
        callees = _api_module_exports() | {"fetch"}
    if sources is None:
        sources = _graph_sources()
    sites = []
    for name, src in sources:
        code = _blank_comments(src)
        for line, idx in _route_refs(code, route):
            outer = (None, None)
            for callee, text in _enclosing_calls(code, idx):  # du plus proche au plus lointain
                if callee in callees:
                    outer = (callee, text)  # on garde le plus EXTERNE
            sites.append((name, line, outer[0], outer[1]))
    return sites


class TestOnlyOneDoorToTheNetwork(unittest.TestCase):
    """LA garde : personne d'autre que le module d'API ne parle au réseau. Aucune route n'est lue."""

    def test_exactly_one_module_of_the_spa_references_fetch(self):
        graph = _module_graph()
        self.assertTrue(graph, "graphe de modules vide : le périmètre dérivé est cassé (index.html ?)")
        mods = _network_modules(graph)
        self.assertEqual(
            len(mods), 1,
            "une seule source exécutable du SPA a le droit d'appeler le réseau ; trouvé : "
            + ", ".join(f"{k}:{v}" for k, v in sorted(mods.items()))
            + " — passe par le helper partagé (il attache la preuve opérateur), n'ouvre pas une 2e porte",
        )
        # CE QUE CETTE PORTE FAIT n'est PAS vérifié ici par lecture de son texte (un sosie, un
        # commentaire ou une chaîne morte y suffiraient — mesuré) : cf. TestTheDoorAttachesTheProofWhenItRuns.

    def test_no_other_mutating_network_primitive_exists_in_the_spa(self):
        offenders = []
        for name, s in _graph_sources():
            code = _code_only(s)
            for prim in _MUTATING_PRIMITIVES:
                if prim == "fetch":
                    continue
                for line in _ident_hits(code, prim):
                    offenders.append(f"{name}:{line} {prim}")
        self.assertEqual(offenders, [], "primitive réseau mutante hors du module d'API : " + " | ".join(offenders))

    def test_no_form_submission_is_emitted_by_the_spa(self):
        """La SOUMISSION DE FORMULAIRE est une écriture réseau que nul identifiant global ne nomme
        (mesuré : `f.action='/api/'+'plan'; f.submit()` passait la garde). Les 12 formulaires du SPA sont
        pilotés en JS (`preventDefault()`) : aucune émission native n'est légitime ici."""
        offenders = []
        for name, s in _graph_sources():
            for h in _form_submission_hits(_code_only(s)):
                offenders.append(f"{name}:{h}")
        self.assertEqual(
            offenders, [],
            "soumission de formulaire = écriture réseau HORS de la porte gouvernée : " + " | ".join(offenders),
        )

    def test_the_csp_refuses_form_submission_in_both_places_that_carry_it(self):
        """La détection ci-dessus lit le code ; la CSP, elle, tient au RUNTIME (y compris pour du code
        qu'on n'aurait pas lu). Les deux portées de la politique doivent la porter : la `meta` de la page
        servie et la constante du serveur — une seule des deux laisserait la moitié des réponses ouverte."""
        for path, needle in ((INDEX_HTML, "Content-Security-Policy"), (AUTH_RS, "CSP_POLICY")):
            self.assertTrue(path.is_file(), f"{path} introuvable : la garde ne peut pas vérifier la CSP")
            src = path.read_text(encoding="utf-8")
            self.assertIn(needle, src, f"{path.name} ne porte plus de politique CSP")
            self.assertIn(
                _CSP_FORM_ACTION, src,
                f"{path.name} : la CSP doit refuser la soumission de formulaire ({_CSP_FORM_ACTION}) — "
                "c'est la seule primitive d'écriture que la garde ne peut pas nommer par un identifiant",
            )

    def test_no_computed_access_to_a_global_container(self):
        """`globalThis['fet'+'ch']` contournerait une lecture d'identifiants. On interdit donc l'accès
        global CALCULÉ, qui n'est utilisé nulle part dans ce SPA (mesuré)."""
        offenders = []
        for name, s in _graph_sources():
            code = _code_only(s)
            for g in _GLOBAL_CONTAINERS:
                for m in re.finditer(r"(?<![A-Za-z0-9_$])" + g + r"\s*\[", code):
                    offenders.append(f"{name}:{code.count(chr(10), 0, m.start()) + 1} {g}[…]")
        self.assertEqual(offenders, [], "accès global calculé (contournement possible du contrôle) : " + " | ".join(offenders))

    def test_served_files_outside_the_spa_graph_are_pinned_when_they_touch_the_network(self):
        """Le périmètre est DÉRIVÉ de ce qui est servi. Un fichier servi hors du graphe (le service
        worker) ne peut pas importer le module d'API : il est épinglé par empreinte, donc toute
        modification — ou tout nouveau fichier de ce genre — se signale au lieu de passer."""
        graph_names = {_rel(p) for p in _module_graph()}
        for p in _served_js():
            rel = _rel(p)
            if rel in graph_names:
                continue
            src = p.read_text(encoding="utf-8")
            # TOUTE primitive mutante, pas seulement `fetch` : mesuré, un fichier servi hors graphe qui
            # faisait du XHR n'était NI dans le graphe NI épinglé — il n'était vu par personne.
            if not _network_touches(src):
                continue
            digest = hashlib.sha256(src.encode("utf-8")).hexdigest()
            self.assertIn(
                rel, _PINNED_OUT_OF_GRAPH,
                f"{rel} est SERVI, touche au réseau et n'est ni dans le graphe du SPA ni épinglé "
                f"(empreinte mesurée {digest}) : décide explicitement de son sort",
            )
            self.assertEqual(
                digest, _PINNED_OUT_OF_GRAPH[rel],
                f"{rel} a changé (empreinte mesurée {digest}) : relis-le et ré-épingle-le sciemment",
            )


def _server_proof_header():
    """NOM de l'en-tête de preuve, LU DANS LE SERVEUR (`console/src/auth.rs`) et non écrit ici : la garde
    et le serveur ne peuvent pas diverger en silence. Rend la liste des en-têtes `x-forge-*` que le
    serveur LIT (elle doit en contenir exactement un)."""
    src = AUTH_RS.read_text(encoding="utf-8")
    return sorted(set(re.findall(r"""\.get\(\s*"(x-forge-[a-z0-9-]+)"\s*\)""", src)))


def _js_runtime():
    return os.environ.get("FORGE_JS_RUNTIME") or shutil.which("node")


class TestTheDoorHasASingleCallSite(unittest.TestCase):
    """CARDINALITÉ INTERNE de la porte : un 2e `fetch` DANS le module d'API serait invisible à la
    cardinalité inter-modules, et invisible à la sonde s'il n'est atteignable par aucun export."""

    def test_the_door_module_contains_exactly_one_fetch_call_site(self):
        mods = _network_modules()
        self.assertEqual(len(mods), 1, "porte unique introuvable (cf. TestOnlyOneDoorToTheNetwork)")
        name = next(iter(mods))
        code = _blank_comments(dict(_graph_sources())[name])
        calls = [m for m in re.finditer(r"(?<![A-Za-z0-9_$.])fetch\s*\(", code)]
        self.assertEqual(len(calls), 1, f"{name} doit contenir EXACTEMENT un appel fetch (trouvé {len(calls)})")


class TestTheDoorAttachesTheProofWhenItRuns(unittest.TestCase):
    """LA garde de l'invariant, par EXÉCUTION et non par lecture (cf. docstring (3)).

    On importe le module d'API RÉEL sous node, on instrumente TOUTES les primitives réseau, on appelle
    CHAQUE export, et on regarde ce qui serait parti. Ce que ça ferme, mesuré : helper de preuve vidé,
    helper SOSIE, chaîne morte, porte qui retransmet les options de l'appelant, export qui court-circuite
    la porte — cinq régressions d'une ligne qui laissaient la garde textuelle VERTE.
    """

    probe = None
    skip_reason = None

    @classmethod
    def setUpClass(cls):
        runtime = _js_runtime()
        if not runtime:
            cls.skip_reason = (
                "aucun runtime JavaScript (`node`) : la garde COMPORTEMENTALE de la porte réseau n'a PAS "
                "tourné — installe node, ou pose FORGE_JS_RUNTIME=<chemin>. La CI pose "
                "FORGE_REQUIRE_JS_RUNTIME=1 pour que cette absence soit un ÉCHEC."
            )
            return
        mods = _network_modules()
        if len(mods) != 1:
            cls.skip_reason = None
            cls.probe = {"fatal": f"porte unique introuvable : {sorted(mods)}"}
            return
        door = next(iter(mods))
        if not (WEB_DIR / door).is_file():
            cls.probe = {"fatal": f"la porte réseau n'est pas un fichier importable ({door})"}
            return
        out = subprocess.run(
            [runtime, str(JS_PROBE), str(WEB_DIR), door, PROBE_SENTINEL],
            capture_output=True, text=True, timeout=180,
        )
        if out.returncode != 0:
            cls.probe = {"fatal": f"sonde en échec (rc={out.returncode}) : {out.stderr.strip()[:2000]}"}
            return
        try:
            cls.probe = json.loads(out.stdout)
        except ValueError as e:
            cls.probe = {"fatal": f"sortie de sonde illisible ({e}) : {out.stdout[:500]!r}"}

    def _calls(self):
        if self.probe is None:
            if os.environ.get("FORGE_REQUIRE_JS_RUNTIME") == "1":
                self.fail(self.skip_reason)
            self.skipTest(self.skip_reason)
        self.assertNotIn("fatal", self.probe, self.probe.get("fatal"))
        return self.probe["calls"]

    @staticmethod
    def _proof_of(call):
        for k, v in call["headers"].items():
            if k.lower() == "x-forge-operator":
                return v
        return None

    def test_the_server_still_reads_exactly_one_operator_proof_header(self):
        names = _server_proof_header()
        self.assertEqual(
            names, ["x-forge-operator"],
            "le serveur ne lit plus exactement un en-tête de preuve `x-forge-*` : "
            f"{names} — la garde du SPA prend son nom d'en-tête ICI, elle doit être ré-alignée sciemment",
        )

    def test_every_write_that_would_leave_the_spa_carries_the_operator_proof(self):
        calls = self._calls()
        writes = [c for c in calls if c["method"] not in ("GET", "HEAD")]
        # NON-VACUITÉ : la sonde doit avoir réellement fait écrire la porte, sinon « aucune écriture sans
        # preuve » serait vrai par vide. Mesuré sur l'arbre sain : 3 exports écrivent (write/request/adminApi).
        self.assertGreaterEqual(
            len({c["export"] for c in writes}), 2,
            f"la sonde n'a exercé aucune écriture réelle (exports vus : {self.probe['exports']}, "
            f"appels : {calls}) — elle est devenue aveugle, pas la porte",
        )
        for c in writes:
            proof = self._proof_of(c)
            self.assertIsNotNone(
                proof,
                f"{c['export']}() envoie {c['method']} {c['url']} SANS preuve opérateur "
                f"(en-têtes réellement posés : {c['headers']}) — le dry-plan deviendrait plus restreint que le tir",
            )
            self.assertEqual(
                proof, PROBE_SENTINEL,
                f"{c['export']}() pose une preuve qui n'est pas le secret opérateur du module ({proof!r})",
            )

    def test_a_read_does_not_carry_the_operator_proof(self):
        """Symétrie, et c'est un invariant de SÉCURITÉ, pas une coquetterie : attacher l'en-tête à une
        lecture CHANGE l'identité résolue côté serveur en posture bootstrap (mesuré : `GET /api/whoami`
        rend `authenticated:true, role:admin` avec l'en-tête, `false/null` sans)."""
        calls = self._calls()
        reads = [c for c in calls if c["method"] in ("GET", "HEAD")]
        self.assertTrue(reads, "la sonde n'a exercé aucune lecture : elle est devenue aveugle")
        for c in reads:
            self.assertIsNone(
                self._proof_of(c),
                f"{c['export']}() attache la preuve opérateur à une LECTURE {c['method']} {c['url']} "
                f"({c['headers']}) : l'identité résolue par le serveur en serait changée",
            )

    def test_at_runtime_the_door_only_ever_uses_one_primitive(self):
        """La cardinalité statique dit qu'un seul module NOMME `fetch` ; ceci dit qu'à l'exécution, rien
        d'autre ne part (ni XHR, ni beacon, ni WebSocket, ni soumission de formulaire)."""
        calls = self._calls()
        prims = sorted({c["primitive"] for c in calls})
        self.assertEqual(prims, ["fetch"], f"la porte a émis via une autre primitive que fetch : {prims}")


class TestDryPlanIsNotMoreRestrictedThanRun(unittest.TestCase):
    """L'invariant métier, vérifié EN PLUS de la porte unique : le dry-plan emprunte le même chemin
    gouverné que le tir. La preuve n'est plus un test de SOUS-CHAÎNE — c'est le nom EXACT de la callee."""

    def test_plan_goes_through_the_governed_helper(self):
        sites = _network_call_sites("/api/plan")
        self.assertTrue(sites, "aucun appel à /api/plan trouvé dans le SPA (test devenu aveugle)")
        for name, line, callee, text in sites:
            self.assertIsNotNone(callee, f"{name}:{line} référence /api/plan hors d'un appel réseau reconnu -> {text}")
            self.assertNotEqual(callee, "fetch", f"{name}:{line} appelle /api/plan par un fetch brut -> {text}")

    def test_run_call_sites_all_go_through_it_too(self):
        sites = _network_call_sites("/api/run")
        self.assertTrue(sites, "aucun appel à /api/run trouvé dans le SPA (test devenu aveugle)")
        for name, line, callee, text in sites:
            self.assertIsNotNone(callee, f"{name}:{line} référence /api/run hors d'un appel réseau reconnu -> {text}")
            self.assertNotEqual(callee, "fetch", f"{name}:{line} appelle /api/run par un fetch brut -> {text}")

    def test_plan_uses_exactly_the_helper_used_by_the_launch_form(self):
        """Le formulaire de lancement poste /api/run via `write(…, auth: 'operator')`. Le dry-plan doit
        emprunter LE MÊME helper : les deux en-têtes sont alors identiques PAR CONSTRUCTION."""
        plan = [(c, t) for _n, _l, c, t in _network_call_sites("/api/plan")]
        run = [(c, t) for _n, _l, c, t in _network_call_sites("/api/run") if c == "write"]
        self.assertTrue(run, "le lancement n'utilise plus `write()` : invariant à réécrire")
        self.assertTrue(
            any(c == "write" and "operator" in (t or "") for c, t in plan),
            "aucun appel /api/plan via `write(…, auth: 'operator')` : " + " | ".join(map(str, plan)),
        )


class TestTheGuardSeesFormsItWasNotWrittenFor(unittest.TestCase):
    """La garde est mise à l'épreuve sur des ÉCRITURES ABSENTES DU DÉPÔT — dont les quatre qui ont
    contourné la version précédente. Aucune n'est traitée par un cas particulier : elles tombent toutes
    du bon côté parce que la propriété vérifiée ne parle pas de routes."""

    #: écritures d'une régression /api/plan SANS preuve opérateur, telles qu'un contributeur pourrait
    #: les écrire. Toutes doivent être VUES comme une porte réseau supplémentaire.
    REGRESSIONS = [
        ("littéral simple", "export async function p(b){ return fetch('/api/plan', {method:'POST', body:b}); }"),
        ("littéral concaténé", "export async function p(b){ return fetch('/api/' + 'plan', {method:'POST', body:b}); }"),
        ("gabarit interpolé", "const K='plan';\nexport async function p(b){ return fetch(`/api/${K}`, {method:'POST', body:b}); }"),
        ("échappement \\x2F", "export async function p(b){ return fetch('/api\\x2Fplan', {method:'POST', body:b}); }"),
        ("échappement unicode", "export async function p(b){ return fetch('\\u002Fapi\\u002Fplan', {method:'POST', body:b}); }"),
        ("appel qualifié", "export async function p(b){ return globalThis.fetch('/api/plan', {method:'POST', body:b}); }"),
        ("nom et parenthèse séparés", "export async function p(b){ return fetch\n  (\n  '/api/plan', {method:'POST'}\n  ); }"),
        ("URL rangée dans une const", "const U='/api/plan';\nexport async function p(b){ return fetch(U, {method:'POST', body:b}); }"),
        ("route calculée à l'exécution", "export async function p(b,k){ return fetch('/api/'+k, {method:'POST', body:b}); }"),
    ]

    def test_every_written_form_of_a_new_network_door_is_seen(self):
        for label, src in self.REGRESSIONS:
            with self.subTest(label):
                self.assertTrue(
                    _ident_hits(_code_only(src), "fetch"),
                    f"[{label}] une porte réseau supplémentaire n'est PAS vue : la garde est aveugle à cette écriture",
                )

    def test_a_comment_or_a_string_is_not_a_network_door(self):
        """Symétrie : la garde ne doit pas non plus crier au loup sur du texte."""
        for label, src in [
            ("commentaire ligne", "// return fetch('/api/plan');\nconst x = 1;\n"),
            ("commentaire bloc", "/*\n await fetch('/api/plan');\n*/\nconst y = 2;\n"),
            ("texte d'interface", "const ph = { placeholder: 'xhr, fetch, document' };\n"),
            ("nom de fonction voisin", "async function fetchEngagements(){ return api('/engagements'); }\nconst z = refetch;\n"),
        ]:
            with self.subTest(label):
                self.assertEqual(_ident_hits(_code_only(src), "fetch"), [], f"[{label}] faux positif")

    def test_the_operator_proof_is_not_a_substring_test(self):
        """`rewrite(` contient « write( » : la version précédente y voyait une preuve opérateur (mesuré).
        La callee est désormais un IDENTIFIANT complet."""
        src = "export async function p(b){ return fetch(withEngagement('/api/plan'), { method:'POST', body: rewrite(b) }); }"
        code = _blank_comments(src)
        line, idx = _route_refs(code, "/api/plan")[0]
        callees = [c for c, _t in _enclosing_calls(code, idx)]
        self.assertIn("fetch", callees, "l'appel englobant doit être reconnu")
        self.assertNotIn("write", callees, "`rewrite(` ne doit JAMAIS être lu comme le helper `write(`")
        for bad in ("rewrite", "overwrite"):
            self.assertNotEqual(bad, "write")

    def test_the_scan_perimeter_covers_the_entry_point_itself(self):
        """`console/web/app.js` (le point d'entrée) était HORS du répertoire scanné par la version
        précédente : une régression y passait en silence. Il est maintenant dans le graphe par
        construction, comme tout fichier chargé par index.html."""
        names = {_rel(p) for p in _module_graph()}
        self.assertIn("app.js", names, "le point d'entrée du SPA doit faire partie du périmètre dérivé")
        self.assertTrue(any(n.startswith("js/views/") for n in names), "les vues doivent être dans le périmètre")
        self.assertNotIn("sw.js", names, "le service worker n'est pas un module du SPA (contexte séparé)")


if __name__ == "__main__":
    unittest.main()

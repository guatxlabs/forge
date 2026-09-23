"""Module de SURFACE client — lit le JavaScript de la cible et en extrait les couples
source -> puits (XSS DOM) ainsi que les chemins d'API construits (Client-Side Path Traversal).

POURQUOI CE MODULE EXISTE (ajout local 2026-09-09)
--------------------------------------------------
Mesure du jour sur nos 545 findings et sur l'API de hacktivite :

  * 12 couples (cible, classe acceptee CHEZ ELLE) sur 13 sont sous les cinq tentatives
    qu'impose la regle du workspace ; trois sont a ZERO.
  * 173 scripts sur 203 (85 %) ne sont cites dans AUCUN finding. Les deux outils les plus
    employes de toute la base sont `curl` (185) et le navigateur (164) : nous chassons a la
    main, et cinq tentatives a la main coutent une heure la ou l'outil les rend gratuites.
  * « client-side path traversal » rendait ZERO fichier dans tout le toolkit et ZERO module
    dans forge, alors que la technique est acceptee en bug bounty (Facebook, GitLab ;
    whitepaper CSPT2CSRF de Doyensec sur Mattermost et Rocket.Chat).

Un outil range dans `toolkit/` reste OPTIONNEL, donc il dort — c'est le constat ci-dessus.
Ici, la capacite devient MECANIQUE : `planner.coverage_gaps()` ne sait signaler « classe
jamais tentee » que pour une classe DECLAREE. C'est exactement la correction qu'ont recue
`xss` et `lfi` le 2026-09-04, dont les modules n'avaient pas de `cls` et restaient donc
structurellement invisibles au controle de couverture.

CE QU'IL FAIT
-------------
Un GET sur la page in-scope, puis un GET par script de MEME ORIGINE qu'elle reference.
Sur ce corpus :
  1. XSS DOM — apparie 11 familles de SOURCES (location.hash/search/href/pathname,
     document.URL, document.referrer, window.name, URLSearchParams, postMessage,
     localStorage, sessionStorage) a 12 familles de PUITS (innerHTML, outerHTML,
     document.write, insertAdjacentHTML, eval, new Function, jQuery html/append/selecteur,
     srcdoc, setAttribute href/src/formaction, affectation de location) par PROXIMITE.
  2. Motif `innerHTML = …textContent` signale a part : `textContent` DECODE les entites,
     donc un texte affiche comme `<img onerror=…>` echappe en ressort litteral, et le
     reaffecter a `innerHTML` le REPARSE en balise vivante.
  3. CSPT — chemins d'API dont un segment est construit. Le navigateur normalise les `../`
     AVANT d'emettre, si bien que la requete part vers un autre point de service AVEC les
     jetons d'authentification et anti-CSRF que le front ajoute lui-meme : c'est un
     contournement de CSRF, pas une simple traversee. `encodeURIComponent('..') === '..'`,
     l'encodage ne protege pas.

CE QU'IL N'EST PAS
------------------
Ce module est de categorie `recon` : il LIT, il n'injecte rien et ne prouve rien. Sa sortie
est une LISTE DE CANDIDATS A LIRE, jamais un verdict — l'appariement se fait par proximite
textuelle dans du code minifie, sans AST ni suivi inter-procedural, ce qui produit des faux
positifs (internes de bibliotheques) et des faux negatifs (flux traversant plusieurs
fonctions). La PREUVE reste le travail de l'oracle `xss.execution`, qui lit le temoin dans
le DOM vivant. Un oracle CSPT a preuve (forger `../` et constater le detournement de la
requete authentifiee) reste a construire : il exige le navigateur, comme `xss.execution`.
"""
from __future__ import annotations

import re
import urllib.parse

from ._scopeguard import ScopeGuardMixin, web_url_candidates
from .oracle import Oracle
from .registry import register, Module
from .. import techniques

# Bornes DECLAREES — jamais de troncature silencieuse (meme discipline que recon.forms).
MAX_SCRIPTS = 25          # scripts de meme origine telecharges
MAX_BYTES = 3_000_000     # octets de JS analyses au total
MAX_FLOWS = 20            # flux rapportes
WINDOW = 400              # fenetre de proximite source/puits, en caracteres

# ⚠️ Jumeau en ligne de commande : `toolkit/web/dom_sink_finder.py`. Les catalogues sont
# DUPLIQUES a dessein — forge doit rester autonome (stdlib seule, testable hors du dossier
# parent). `tests/test_client_sinks.py` verifie leur alignement quand le jumeau est present,
# pour qu'aucune des deux copies ne derive en silence.
SOURCES = {
    "location.hash":      r'location\s*\.\s*hash',
    "location.search":    r'location\s*\.\s*search',
    "location.href":      r'location\s*\.\s*href',
    "location.pathname":  r'location\s*\.\s*pathname',
    "document.URL":       r'document\s*\.\s*URL',
    "document.referrer":  r'document\s*\.\s*referrer',
    "window.name":        r'window\s*\.\s*name',
    "URLSearchParams":    r'new\s+URLSearchParams',
    "postMessage":        r'addEventListener\(\s*["\']message["\']|onmessage\s*=',
    "localStorage":       r'localStorage\s*\.\s*getItem',
    "sessionStorage":     r'sessionStorage\s*\.\s*getItem',
}
SINKS = {
    "innerHTML":          r'\.\s*innerHTML\s*=',
    "outerHTML":          r'\.\s*outerHTML\s*=',
    "document.write":     r'document\s*\.\s*write(?:ln)?\s*\(',
    "insertAdjacentHTML": r'insertAdjacentHTML\s*\(',
    "eval":               r'(?<![\w.])eval\s*\(',
    "new Function":       r'new\s+Function\s*\(',
    "jQuery.html":        r'\.\s*html\s*\(',
    "jQuery.append":      r'\.\s*(?:append|prepend|after|before|replaceWith)\s*\(',
    "jQuery selector":    r'\$\s*\(\s*[A-Za-z_$][\w$]*\s*\)',
    "srcdoc":             r'\.\s*srcdoc\s*=',
    "setAttribute(href)": r'setAttribute\s*\(\s*["\'](?:href|src|formaction)["\']',
    "location assign":    r'location\s*(?:\.\s*(?:href|assign|replace)\s*(?:=|\())',
}
# Exige que `textContent` soit LU comme valeur affectee — donc pas de `?` ni de `:` entre les
# deux. Sans cette exclusion, le ternaire de Bootstrap est apparie a tort (deux branches
# exclusives, aucun flux) : faux positif rencontre sur une cible reelle.
ENTITY_REPARSE = r'\.\s*innerHTML\s*=\s*[^;?:]{0,120}?\.\s*textContent\s*(?![=\s]*=[^=])'

CSPT_SINKS = {
    "fetch(chemin construit)":   r'fetch\s*\(\s*[`"\'][^`"\']*(?:\$\{|["\']\s*\+)',
    "axios(chemin construit)":   r'axios\s*(?:\.\s*(?:get|post|put|patch|delete)\s*)?\(\s*[`"\'][^`"\']*(?:\$\{|["\']\s*\+)',
    "XHR.open(chemin construit)": r'\.\s*open\s*\(\s*["\'][A-Z]+["\']\s*,\s*[`"\'][^`"\']*(?:\$\{|["\']\s*\+)',
    "$.ajax(url construite)":    r'url\s*:\s*[`"\'][^`"\']*(?:\$\{|["\']\s*\+)',
    "HttpClient(chemin construit)": r'\.\s*(?:get|post|put|patch|delete)\s*(?:<[^>]{0,60}>)?\s*\(\s*[`"\'][^`"\']*(?:\$\{|["\']\s*\+)',
    # Angular passe la methode en ARGUMENT : `httpClient.request("get", `…`, …)`.
    "request(methode, chemin construit)":
        r'\.\s*request\s*\(\s*["\'][a-zA-Z]+["\']\s*,\s*[`"\'][^`"\']*(?:\$\{|["\']\s*\+)',
    # Cas DOMINANT : openapi-generator ne met jamais le chemin parametre en ligne dans
    # l'appel, il le construit dans une variable intermediaire. Sans cette entree, 1,1 Mo
    # de bundles reels rendaient ZERO candidat alors que le code en est truffe.
    "chemin d'API construit en variable":
        r'(?:let|var|const)\s+\w+\s*=\s*`/[^`]*\$\{',
}

VENDOR = re.compile(r'jquery|react|angular|vue|lodash|polyfill|runtime|bootstrap|moment|swiper'
                    r'|core-js|tarteaucitron|eu_cookie_compliance|cookieconsent|owl\.carousel|dsfr',
                    re.I)


def chemin_avant_variable(match_txt):
    """Le texte matche porte-t-il un vrai SEGMENT de chemin avant sa partie variable ?

    Le motif s'arrete au `${` ou au `"+`, donc tout ce qui precede est le prefixe litteral.
    On cherche un `/` APRES le premier delimiteur de chaine :

        `.request("get",`${basePath}`  -> apres le 1er `"` : pas de `/`  -> prefixe d'hote
        `fetch("/api/u/"+`            -> apres le 1er `"` : `/` present  -> candidat
        `let l=`/Reimb/${`            -> apres le backtick : `/` present -> candidat

    Regarder le DERNIER fragment (premiere version) ratait la concatenation par `+`, qui
    ferme le litteral et ne laisse qu'un `+` derriere lui.
    """
    i = min((match_txt.find(c) for c in ('`', '"', "'") if match_txt.find(c) >= 0), default=-1)
    return i >= 0 and "/" in match_txt[i + 1:]


def extraire_scripts(body, page_url):
    """URLs des scripts de MEME ORIGINE que la page + le code inline. Ne sort jamais du site."""
    base = urllib.parse.urlparse(page_url)
    urls, inline = [], []
    for m in re.finditer(r'<script([^>]*)>(.*?)</script>', body, re.I | re.S):
        attrs, corps = m.group(1), m.group(2)
        s = re.search(r'\bsrc\s*=\s*["\']([^"\']+)["\']', attrs, re.I)
        if s:
            u = urllib.parse.urljoin(page_url, s.group(1))
            if urllib.parse.urlparse(u).hostname == base.hostname:
                urls.append(u)
        elif corps.strip():
            inline.append(corps)
    return urls[:MAX_SCRIPTS], inline


def analyser(scripts, window=WINDOW):
    """scripts : {nom: code}. Renvoie la liste des flux candidats, CSPT d'abord."""
    out = []
    for nom, code in scripts.items():
        src_hits = [(k, m.start()) for k, rx in SOURCES.items() for m in re.finditer(rx, code)]
        snk_hits = [(k, m.start()) for k, rx in SINKS.items() for m in re.finditer(rx, code)]

        for sname, spos in src_hits:
            near = sorted((abs(kp - spos), kn, kp) for kn, kp in snk_hits
                          if abs(kp - spos) <= window)
            if not near:
                continue
            dist, kname, kpos = near[0]
            lo, hi = max(0, min(spos, kpos) - 90), min(len(code), max(spos, kpos) + 130)
            out.append({"fichier": nom, "source": sname, "puits": kname, "motif": "XSS_DOM",
                        "distance": dist, "extrait": re.sub(r"\s+", " ", code[lo:hi])[:260]})

        # CSPT : PAS d'appariement par proximite, et c'est delibere. Sur 1,1 Mo de bundles
        # Angular reels, la proximite rend ZERO candidat : dans tout framework moderne la
        # source (parametre de route) et le puits (service d'API genere) vivent dans des
        # FONCTIONS DIFFERENTES. La source d'un CSPT est le segment variable lui-meme.
        for kname, rx in CSPT_SINKS.items():
            for m in re.finditer(rx, code):
                if not chemin_avant_variable(m.group(0)):
                    continue          # `${base}…` : prefixe d'hote, pas un segment de chemin
                lo = max(0, m.start() - 60)
                out.append({"fichier": nom, "source": "segment variable du chemin",
                            "puits": kname, "motif": "CSPT", "distance": 0,
                            "extrait": re.sub(r"\s+", " ", code[lo:m.start() + 200])[:260]})

        for m in re.finditer(ENTITY_REPARSE, code):
            lo = max(0, m.start() - 110)
            out.append({"fichier": nom, "source": "textContent (entites decodees)",
                        "puits": "innerHTML", "motif": "REPARSE_ENTITES", "distance": 0,
                        "extrait": re.sub(r"\s+", " ", code[lo:m.end() + 150])[:260]})

    ordre = {"REPARSE_ENTITES": 0, "CSPT": 1, "XSS_DOM": 2}
    out.sort(key=lambda r: (ordre.get(r["motif"], 3), r["distance"]))
    return out


# --- Enregistrement de la technique (contrat « declare-une-fois -> derive-partout ») ------------
# `register_kind` est le point d'extension prevu : la technique apparait automatiquement au
# catalogue, au pipeline ordonne, aux profils et a `forge modules --json`, sans cablage
# par-technique — et surtout, c'est LUI qui porte `cls`. Mesure du 2026-09-09 : poser `cls`
# en simple attribut de classe du module ne suffit PAS, l'Action ne le recoit pas et
# `coverage_gaps()` (planner.py:370) reste aveugle. Meme piege que celui corrige sur
# `xss.execution` le 2026-09-04.
#
# CWE-22 est retenu faute de mieux : le CSPT n'a pas de CWE propre. Son impact reel est
# souvent un contournement de CSRF (CWE-352), puisque la requete detournee part AVEC les
# jetons que le front ajoute lui-meme — d'ou la mention explicite dans `fix`.
#
# `proof_required=False` est deliberе : ce module LIT, il ne prouve rien. La preuve reste
# l'affaire d'un oracle (a construire pour le CSPT, cf. le docstring).
techniques.register_kind(techniques._k(
    "recon.client_sinks", "CSPT", True, depends_on=("recon.httpx",),
    cls="cspt", cwe="CWE-22", mitre="T1595", exploit=False,
    attck_tactic="Reconnaissance", phase="recon", capability="passive",
    proof_required=False))


@register("recon.client_sinks")
class ClientSinks(ScopeGuardMixin, Module):
    kind = "recon.client_sinks"
    exploit = False              # lecture de code : aucune injection
    destructive = False          # aucune mutation d'etat
    web_allowed = True           # interaction web -> gardee par le ROE
    available = True             # stdlib
    category = "recon"
    cls = "cspt"                 # DECLARE : sans lui, coverage_gaps() ne dirait jamais
                                 # « CSPT jamais tente » — c'est le defaut corrige sur
                                 # xss et lfi le 2026-09-04.
    mitre = techniques.mitre_for("recon.client_sinks") or "T1595"
    tool = "forge/modules/client_sinks.py:recon.client_sinks"
    description = ("Lit le JavaScript de MEME ORIGINE et en extrait les couples source -> puits "
                   "(XSS DOM) et les chemins d'API a segment construit (Client-Side Path "
                   "Traversal). Aucun oracle ne LISAIT le code client : les deux classes qui "
                   "paient le mieux sont precisement celles qui se trouvent en lisant, pas en "
                   "arrosant des parametres devines.")
    fix = ("Ne jamais ecrire une donnee d'origine attaquant dans un puits de rendu (innerHTML, "
           "document.write, eval) : passer par textContent ou un assainisseur a liste blanche. "
           "Pour les chemins d'API, valider le segment cote CLIENT avant de le concatener "
           "(rejeter '..' et '/'), et surtout re-verifier l'autorisation cote SERVEUR sur le "
           "point de service reellement atteint.")

    @staticmethod
    def _get(url, headers=None, timeout=15):
        st, text, _h = Oracle._http(url, headers=headers or {}, timeout=timeout, method="GET")
        return st, text

    def dry(self, action):
        return (f"# GET {action.target} puis GET de ses <script src> de MEME ORIGINE "
                f"(max {MAX_SCRIPTS}) — lecture seule, aucune injection, aucun parametre devine")

    def fire(self, action):
        cands = web_url_candidates(action.target)
        url = cands[0] if cands else str(action.target)
        if not self._in_scope(action, url):
            return [self._f(action, url, "Code client non lu — cible hors perimetre (fail-closed)",
                            "Aucune requete emise.")]
        headers = dict(action.params.get("headers", {}))
        st, body = self._get(url, headers)
        if st is None:
            return [self._f(action, url, "Code client non lu — reseau indisponible",
                            "Aucune reponse du serveur ; degradation gracieuse.")]

        skip_vendor = bool(action.params.get("skip_vendor", True))
        urls, inline = extraire_scripts(body or "", url)
        scripts, total = {}, 0
        for i, code in enumerate(inline):
            scripts[f"(inline #{i + 1})"] = code
            total += len(code)
        for u in urls:
            if skip_vendor and VENDOR.search(u):
                continue
            if total >= MAX_BYTES:
                break
            sst, scode = self._get(u, headers)
            if sst is None or not scode:
                continue
            scripts[u.rsplit("/", 1)[-1] or u] = scode
            total += len(scode)

        if not scripts:
            return [self._f(action, url, "Aucun JavaScript de meme origine sur cette page",
                            f"HTTP {st} ; rien a lire — un negatif de LECTURE, pas un negatif "
                            f"de vulnerabilite.")]

        flux = analyser(scripts)
        entete = self._f(
            action, url,
            f"Surface client — {len(scripts)} script(s) lu(s), {total} octets, {len(flux)} flux",
            (f"HTTP {st} ; bornes declarees MAX_SCRIPTS={MAX_SCRIPTS}, MAX_BYTES={MAX_BYTES}, "
             f"MAX_FLOWS={MAX_FLOWS} — jamais de troncature silencieuse. "
             f"skip_vendor={skip_vendor}. Aucune injection emise."))
        out = [entete]
        for r in flux[:MAX_FLOWS]:
            out.append(self._f(
                action, url,
                f"[{r['motif']}] {r['source']} -> {r['puits']} ({r['fichier']})",
                (f"distance={r['distance']} car. ; extrait : {r['extrait']} "
                 f"— CANDIDAT A LIRE, pas un verdict : appariement par proximite sur du code "
                 f"minifie, sans AST ni suivi inter-procedural.")))
        if len(flux) > MAX_FLOWS:
            out.append(self._f(action, url,
                               f"{len(flux) - MAX_FLOWS} flux supplementaires non detailles",
                               f"Borne MAX_FLOWS={MAX_FLOWS} atteinte — declaree, non silencieuse."))
        return out

    def _f(self, action, target, title, evidence):
        return self.finding(target=target, title=title, evidence=evidence, severity="INFO",
                            status="tested", category=self.category, mitre=self.mitre,
                            tool=self.tool, fix=self.fix, poc=self.dry(action))

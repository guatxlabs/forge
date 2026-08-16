# SPDX-License-Identifier: AGPL-3.0-or-later
"""recon.forms — lire les FORMULAIRES d'une page découverte pour en tirer des paramètres (T1595).

LE MUR MESURÉ. Sur le banc, DVWA piste B rend **0 sur 9 classes opposables** quand la piste AMORCÉE
en trouve 5. Le jugement va bien ; c'est l'ALIMENTATION qui manque, et la cause tient en deux lignes :

    endpoint découvert `/vulnerabilities/sqli/`            ->  3 oracles, AUCUN paramètre
    même endpoint `?id=1&Submit=Submit`                    -> 23 actions, 12 oracles

Un crawler découvre des CHEMINS, pas des paramètres : il ne soumet pas les formulaires. Or les
paramètres de DVWA — et de toute application à formulaires — vivent dans le HTML de la page, dans
`<input name=…>`. Forge ne savait pas les lire, donc tous ses oracles à injection restaient sans
cible sur une surface pourtant banale.

CE MODULE NE FAIT QU'UNE CHOSE : il lit les formulaires d'une page in-scope et émet, par formulaire,
la liste de ses champs. Le cerveau en reconstruit une URL PORTEUSE (`…?id=1&Submit=Submit`) et le
chaînage existant fait le reste — aucun nouveau mécanisme d'injection n'est nécessaire, parce que
`inject_request` PRÉSERVE déjà les co-paramètres (défaut D6, le `Submit` de DVWA).

CE QU'IL NE FAIT PAS : il ne SOUMET rien (`exploit=False`, `destructive=False`), il ne devine aucune
valeur — il recopie celles que le HTML déclare, et laisse vides celles qui le sont.
"""
from __future__ import annotations

import html
import re
import urllib.parse

from ._scopeguard import ScopeGuardMixin, web_url_candidates
from .oracle import Oracle
from .registry import register, Module
from .. import techniques

#: Un `<form>` complet, son ouverture (pour l'`action`/`method`) et son contenu.
_FORM_RX = re.compile(r"<form\b([^>]*)>(.*?)</form\s*>", re.I | re.S)
#: Un champ nommé : input / select / textarea. `name` est ce qui compte — un champ sans nom n'est
#: pas soumis par le navigateur, donc n'existe pas côté serveur.
_FIELD_RX = re.compile(r"<(?:input|select|textarea)\b([^>]*)>", re.I)
_ATTR_RX = re.compile(r"""(\w[\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")

#: Types de champs qui ne portent PAS de valeur soumise utile à une injection.
_SKIP_TYPES = {"submit", "button", "image", "reset", "file"}

#: Bornes DÉCLARÉES du fan-out — un site à formulaires nombreux ne doit pas noyer un plan.
MAX_FORMS = 6
MAX_FIELDS = 8


def _attrs(blob):
    """Attributs d'une balise, en minuscules. Pur, ne lève jamais."""
    out = {}
    for m in _ATTR_RX.finditer(blob or ""):
        out[m.group(1).lower()] = html.unescape(m.group(2) or m.group(3) or m.group(4) or "")
    return out


def parse_forms(body, base_url):
    """[(method, action_url, [(nom, valeur), …])] — les formulaires d'une page. Pur, ne lève jamais.

    `action` vide ou relatif est résolu contre `base_url` : un formulaire qui poste sur lui-même
    (`<form method=GET>` sans action, le cas de DVWA) doit rendre l'URL de SA page, sinon le
    paramètre découvert n'est rattaché à rien."""
    out = []
    for m in _FORM_RX.finditer(body or ""):
        a = _attrs(m.group(1))
        method = (a.get("method") or "GET").upper()
        action = urllib.parse.urljoin(base_url, a.get("action") or "")
        champs = []
        for f in _FIELD_RX.finditer(m.group(2) or ""):
            fa = _attrs(f.group(1))
            nom = fa.get("name")
            if not nom or fa.get("type", "").lower() in _SKIP_TYPES:
                # Un `submit` NOMMÉ est un CO-PARAMÈTRE, pas une cible d'injection : DVWA exige
                # `Submit=Submit` pour entrer dans la branche vulnérable (défaut D6). On le garde
                # donc comme co-paramètre, avec sa valeur, mais on ne l'injectera pas.
                if nom and fa.get("type", "").lower() == "submit":
                    champs.append((nom, fa.get("value", ""), False))
                continue
            champs.append((nom, fa.get("value", ""), True))
            if len(champs) >= MAX_FIELDS:
                break
        if champs:
            out.append((method, action, champs))
        if len(out) >= MAX_FORMS:
            break
    return out


@register("recon.forms")
class FormSurface(ScopeGuardMixin, Module):
    kind = "recon.forms"
    exploit = False              # lecture de page : jamais de soumission
    destructive = False          # aucune mutation d'état
    web_allowed = True           # interaction web -> gardée par le ROE
    available = True             # stdlib
    category = "recon"
    mitre = techniques.mitre_for("recon.forms") or "T1595"
    tool = "forge/modules/form_surface.py:recon.forms"
    # PAS `emit_endpoint_discovery` — et c'est une correction, pas un oubli. Ce module n'émet
    # AUCUN endpoint : il émet des PARAMÈTRES (`DISCOVERY_FORM_MARKER`). Le déclarer producteur
    # d'endpoints le faisait classer « scopé HÔTE » par le garde anti-action-aveugle (D9/D16),
    # qui refusait alors de le chaîner sur un endpoint — exactement là où il doit tourner,
    # puisqu'il lit UNE page. Le garde avait raison ; c'est la déclaration qui mentait.
    description = ("Lit les FORMULAIRES d'une page in-scope et émet leurs champs. Un crawler "
                   "découvre des chemins, pas des paramètres : sans cette lecture, les oracles à "
                   "injection restent sans cible sur toute application à formulaires.")
    fix = ("Valider et typer chaque champ côté serveur (allowlist), ne jamais concaténer une entrée "
           "de formulaire dans une requête SQL, une commande ou un chemin de fichier.")

    @staticmethod
    def _get(url, headers=None, timeout=15):
        """GET -> (status, body). Adossé au câblage partagé `Oracle._http` (qui alimente le témoin
        de cécité : une page de challenge ne doit pas passer pour « aucun formulaire »)."""
        st, text, _h = Oracle._http(url, headers=headers or {}, timeout=timeout, method="GET")
        return st, text

    def dry(self, action):
        return (f"# GET {action.target} : lecture des <form> et de leurs <input name=…> — "
                f"AUCUNE soumission, aucune valeur devinée")

    def fire(self, action):
        cands = web_url_candidates(action.target)
        url = cands[0] if cands else str(action.target)
        if not self._in_scope(action, url):
            return [self._f(action, url, "Formulaires non lus — cible hors périmètre (fail-closed)",
                            "Aucune requête émise.")]
        st, body = self._get(url, dict(action.params.get("headers", {})))
        if st is None:
            return [self._f(action, url, "Formulaires non lus — réseau indisponible (dégradation gracieuse)",
                            "Aucune réponse du serveur ; offline-safe.")]
        forms = parse_forms(body, url)
        if not forms:
            return [self._f(action, url, "Aucun formulaire sur cette page",
                            f"HTTP {st} ; aucun <form> porteur de champ nommé — rien à chaîner.")]
        out = [self._f(action, url, f"Surface de formulaires — {len(forms)} formulaire(s) lu(s)",
                       (f"HTTP {st} ; bornes déclarées MAX_FORMS={MAX_FORMS}, MAX_FIELDS={MAX_FIELDS} "
                        f"— jamais de troncature silencieuse. Aucune soumission émise."))]
        for method, act_url, champs in forms:
            injectables = [(n, v) for n, v, inj in champs if inj]
            co = [(n, v) for n, v, inj in champs if not inj]
            if not injectables:
                continue
            out.append(self._f(
                action, act_url, techniques.form_title(method, champs),
                (f"formulaire {method} sur {act_url} ; champs injectables="
                 f"{[n for n, _ in injectables]} ; co-paramètres={[n for n, _ in co]} "
                 f"(exigés par l'application — c'est le défaut D6 : sans eux la branche vulnérable "
                 f"reste hors d'atteinte). Valeurs recopiées du HTML, jamais devinées.")))
        return out

    def _f(self, action, target, title, evidence):
        return self.finding(target=target, title=title, evidence=evidence, severity="INFO",
                            status="tested", category=self.category, mitre=self.mitre,
                            tool=self.tool, fix=self.fix, poc=self.dry(action))

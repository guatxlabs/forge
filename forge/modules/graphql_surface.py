# SPDX-License-Identifier: AGPL-3.0-or-later
"""recon.graphql — DÉCOUVERTE de la surface injectable d'une API GraphQL (T1595).

POURQUOI CE MODULE EXISTE — le mur mesuré. Deux campagnes de banc, **DVGA à 0 sur 6 classes
opposables**, et la cause n'était ni le jugement ni la découverte au sens habituel : une API GraphQL
n'a NI query-string NI formulaire. Toute sa surface tient derrière UN SEUL `POST /graphql`, et son
point d'injection est un ARGUMENT dans la chaîne `query` d'un corps JSON. La découverte de forge sait
énumérer des URL et lire des paramètres de query ; elle ne sait pas lire un schéma. Les oracles
d'injection restaient donc sans cible sur toute une famille d'applications.

CE QUE CE MODULE FAIT, ET RIEN DE PLUS : il interroge l'introspection, énumère les champs qui portent
un argument SCALAIRE, et émet un finding par argument — dont le titre est encodé par
`techniques.graphql_arg_title`, que le cerveau relit avec `parse_graphql_arg_title`. Émetteur et
détecteur partagent le code, jamais un format recopié : c'est la leçon des listes tenues à la main
de ce dépôt (`_RATE_FLAG_KINDS`, `_SQL_ERROR_SIGNS`), qui ont toutes fini par diverger du terrain.

CE QU'IL NE FAIT PAS, ET C'EST DÉLIBÉRÉ :
  · il n'INJECTE rien — il décrit une surface, les oracles jugent. `exploit=False`, `destructive=False` ;
  · il ne DEVINE pas les co-arguments. `systemDiagnostics(cmd:…)` de DVGA exige `username`/`password`
    corrects : sans eux l'application répond « Password Incorrect » et l'oracle s'abstiendra. Un
    producteur générique ne peut pas inventer ces valeurs ; l'opérateur les fournit par un gabarit
    explicite. La limite est RÉELLE et écrite plutôt que masquée par une heuristique ;
  · il ne juge pas l'introspection elle-même. Un schéma exposé est une information, pas un impact —
    règle du dépôt, et `graphql.access` l'émet déjà en informatif.
"""
from __future__ import annotations

import json

from ._scopeguard import ScopeGuardMixin, web_url_candidates
from .oracle import Oracle
from .registry import register, Module
from .. import techniques

#: Requête d'introspection MINIMALE : juste ce qu'il faut pour nommer les champs et leurs arguments.
#: On ne demande PAS le schéma complet — inutile pour décrire une surface, et volumineux pour rien.
#: On demande AUSSI le type de RETOUR de chaque champ (`type{kind ofType{kind ofType{kind}}}`) : GraphQL
#: exige une sélection de sous-champs sur un champ qui rend un objet et l'INTERDIT sur un scalaire. Sans
#: cette information, le gabarit dérivé serait syntaxiquement faux une fois sur deux, et l'erreur de
#: syntaxe se lirait comme « pas vulnérable » — un faux négatif total, charge pourtant envoyée.
INTROSPECTION = (
    "{__schema"
    "{queryType{name fields{name type{kind ofType{kind ofType{kind ofType{kind}}}}"
    "args{name type{name kind ofType{name kind}}}}}"
    "mutationType{name fields{name type{kind ofType{kind ofType{kind ofType{kind}}}}"
    "args{name type{name kind ofType{name kind}}}}}}}")

#: Chemins d'endpoint GraphQL usuels, sondés SI la cible n'en est pas déjà un.
CANDIDATE_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql")

#: Types d'arguments dans lesquels une charge a un sens. Un `Boolean` ou un type d'entrée composite
#: n'est pas un point d'injection de chaîne : le proposer ne produirait que des erreurs de type.
SCALAR_ARGS = ("String", "ID", "Int")

#: Borne du fan-out. Un schéma large (des centaines de champs) ne doit pas noyer un plan de campagne ;
#: la borne est DÉCLARÉE ici et RAPPELÉE dans le finding de synthèse, jamais silencieuse.
MAX_ARGS = 40


def _arg_type(arg):
    """Nom du type d'un argument, en dépliant un éventuel NON_NULL/LIST. Pur, ne lève jamais."""
    t = arg.get("type") or {}
    return t.get("name") or (t.get("ofType") or {}).get("name") or ""


#: `kind` d'un type GraphQL qui EXIGE une sélection de sous-champs.
_SELECTABLE_KINDS = ("OBJECT", "INTERFACE", "UNION")


def _returns_object(field):
    """Ce champ rend-il un type qui EXIGE une sélection de sous-champs ? Déplie NON_NULL/LIST jusqu'au
    type nu — `[PasteObject!]!` doit compter comme un objet, pas comme une liste opaque.
    Pur, ne lève jamais."""
    t = field.get("type") or {}
    for _ in range(4):                       # profondeur demandée à l'introspection
        if t.get("kind") in _SELECTABLE_KINDS:
            return True
        nxt = t.get("ofType")
        if not nxt:
            break
        t = nxt
    return False


@register("recon.graphql")
class GraphqlSurface(ScopeGuardMixin, Module):
    kind = "recon.graphql"
    exploit = False              # description de surface : jamais d'exploitation
    destructive = False          # lecture seule : aucune mutation d'état
    web_allowed = True           # interaction web (réseau) -> gardée par le ROE
    available = True             # stdlib
    category = "recon"
    mitre = techniques.mitre_for("recon.graphql") or "T1595"
    tool = "forge/modules/graphql_surface.py:recon.graphql"
    emit_endpoint_discovery = True     # producteur de surface -> le planner le classe en découverte
    description = ("Découvre la surface INJECTABLE d'une API GraphQL : introspection, puis un finding "
                   "par argument scalaire de champ (query et mutation). N'injecte rien — la surface "
                   "décrite est chaînée vers les oracles d'injection par le cerveau.")
    fix = ("Désactiver l'introspection en production ; valider et typer chaque argument côté "
           "résolveur ; ne jamais concaténer un argument dans une requête SQL, une commande shell "
           "ou un chemin de fichier.")

    # --- réseau (seam patché par les tests) ---------------------------------------------------
    @staticmethod
    def _post(url, body, headers=None, timeout=15):
        """POST JSON -> (status, body). Adossé au câblage partagé `Oracle._http`."""
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        st, text, _hdrs = Oracle._http(url, headers=h, timeout=timeout, method="POST", data=body)
        return st, text

    def _endpoints(self, action):
        """Endpoints à sonder : la cible si elle EST déjà un endpoint GraphQL, sinon les chemins
        usuels sur son origine. Scope-guardé PAR URL (fail-closed) — aucune requête hors périmètre."""
        cands = web_url_candidates(action.target)
        base = cands[0] if cands else str(action.target)
        if any(base.rstrip("/").endswith(p) for p in CANDIDATE_PATHS):
            urls = [base]
        else:
            root = base.rstrip("/")
            urls = [root + p for p in CANDIDATE_PATHS]
        return [u for u in urls if self._in_scope(action, u)]

    def _schema_args(self, doc):
        """[(operation, field, arg, type)] — les arguments SCALAIRES du schéma. Pur, ne lève jamais."""
        out = []
        schema = ((doc or {}).get("data") or {}).get("__schema") or {}
        for op, key in (("query", "queryType"), ("mutation", "mutationType")):
            for field in ((schema.get(key) or {}).get("fields") or []):
                obj = _returns_object(field)
                for arg in (field.get("args") or []):
                    t = _arg_type(arg)
                    if t in SCALAR_ARGS:
                        out.append((op, field.get("name", ""), arg.get("name", ""), t, obj))
        return out

    def dry(self, action):
        return (f"# POST {action.target} : introspection ({INTROSPECTION[:48]}…) puis un finding par "
                f"argument scalaire de champ — AUCUNE injection émise")

    def fire(self, action):
        headers = dict(action.params.get("headers", {}))
        timeout = int(action.params.get("timeout", 15) or 15)
        endpoints = self._endpoints(action)
        if not endpoints:
            return [self._finding(action, action.target,
                                  "Surface GraphQL non sondée — aucun endpoint candidat in-scope",
                                  "Le scope-guard a refusé tous les chemins candidats ; AUCUNE requête émise.")]
        seen_network = False
        for url in endpoints:
            st, text = self._post(url, json.dumps({"query": INTROSPECTION}), headers, timeout)
            if st is None:
                continue
            seen_network = True
            try:
                doc = json.loads(text or "{}")
            except ValueError:
                continue
            args = self._schema_args(doc)
            if not args:
                continue
            findings = [self._finding(
                action, url, f"Surface GraphQL découverte — {len(args)} argument(s) scalaire(s)",
                (f"introspection ACTIVÉE sur {url} ; arguments scalaires ({'/'.join(SCALAR_ARGS)}) "
                 f"exposés={len(args)}, retenus={min(len(args), MAX_ARGS)} (borne MAX_ARGS={MAX_ARGS}, "
                 f"déclarée — jamais de troncature silencieuse). Ce finding DÉCRIT une surface : "
                 f"aucune charge n'a été envoyée."))]
            for op, field, arg, atype, obj in args[:MAX_ARGS]:
                findings.append(self._finding(
                    action, url, techniques.graphql_arg_title(op, field, arg, returns_object=obj),
                    (f"argument {arg}:{atype} du champ {op} {field} — point d'injection candidat. "
                     f"Le cerveau en dérive un gabarit de corps ; les oracles jugent. "
                     f"CO-ARGUMENTS NON DEVINÉS : un champ qui exige d'autres arguments (auth, id) "
                     f"restera non concluant tant qu'un gabarit explicite ne les porte pas.")))
            return findings
        if not seen_network:
            return [self._finding(action, action.target,
                                  "Surface GraphQL non testée — réseau indisponible (dégradation gracieuse)",
                                  "Aucune réponse d'aucun endpoint candidat ; offline-safe.")]
        return [self._finding(action, endpoints[0],
                              "Surface GraphQL non détectée — pas de schéma introspectable",
                              (f"{len(endpoints)} endpoint(s) candidat(s) sondé(s) ; aucun n'a rendu de "
                               f"schéma exploitable (introspection désactivée, ou pas de GraphQL ici)."))]

    def _finding(self, action, target, title, evidence):
        return self.finding(target=target, title=title, evidence=evidence,
                            severity="INFO", status="tested", category=self.category,
                            mitre=self.mitre, tool=self.tool, fix=self.fix, poc=self.dry(action))

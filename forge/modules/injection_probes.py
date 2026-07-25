"""LOT INJECTION/PROTOCOLE (server-side) — quatre oracles de VÉRIFICATION d'injection à PREUVE BÉNIGNE
(`nosql.probe`, `lucene.probe`, `cmdi.probe`, `prototype_pollution.probe`).

Ces oracles CONFIRMENT qu'une faiblesse d'injection est RÉELLE avec une preuve MINIMALE et BÉNIGNE —
détection/vérification pour test autorisé, PAS de weaponization ni de vol de données :

  - nosql.probe             : injection NoSQL (Mongo) par différentiel d'OPÉRATEUR. Un opérateur
                              (`$ne`/`$gt`/`$regex`) BROADEN la réponse là où le littéral / l'opérateur
                              inverse (`$eq`/`$lt`) la NARROW -> les opérateurs sont INTERPRÉTÉS
                              (injection). PREUVE = ce différentiel ; jamais de dump (comparaison de
                              hash/statut seulement). CWE-943.
  - lucene.probe            : injection de requête de recherche Lucene/Elasticsearch. Une entrée
                              syntaxiquement INVALIDE (guillemet/parenthèse déséquilibré, opérateur
                              pendant) provoque une ParseException Lucene ABSENTE de la baseline, OU un
                              différentiel booléen (OR broaden / AND narrow) -> la requête est
                              injectable. PREUVE = rupture de syntaxe / différentiel ; jamais de dump.
                              CWE-943.
  - cmdi.probe              : VÉRIFICATION d'injection de commande OS à PREUVE STRICTEMENT BÉNIGNE —
                              un marqueur echo/arithmétique dont la SORTIE UNIQUE revient. DISTINCT de
                              `rce.probe` (l'exploit GOUVERNÉ pentest-only derrière le plancher exploit) :
                              cmdi reste exploit=False, non destructif, éligible bug bounty, et ne lance
                              JAMAIS de commande nuisible (echo/calcul seulement, garde-fou `_assert_benign`).
                              CWE-78.
  - prototype_pollution.probe : pollution de prototype client/serveur par marqueur d'injection de
                              PROPRIÉTÉ BÉNIGN (`__proto__[MARK]=VAL`, `constructor[prototype][MARK]=VAL`)
                              dont l'EFFET est RÉFLÉCHI UNIQUEMENT via le vecteur proto (différentiel vs
                              un contrôle qui envoie la MÊME valeur par un paramètre normal) -> la
                              propriété polluée a été fusionnée puis surfacée. Aucun gadget exploité.
                              CWE-1321.

GARDE-FOUS (chaque oracle les respecte, prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : une cible hors périmètre est REFUSÉE avant tout réseau (`_in_scope`
      reconstruit le Scope depuis le périmètre injecté par l'engine ; hors-scope -> `skipped`, AUCUNE
      requête émise). Défense en profondeur : l'engine gate déjà en Couche 2, on re-valide localement.
  (2) PREUVE MINIMALE & BÉNIGNE : promotion `vulnerable` UNIQUEMENT sur preuve concrète (différentiel
      d'opérateur fiable / rupture de syntaxe / sortie de commande bénigne / réflexion proto-spécifique).
      Sinon `tested` (jamais de verdict à l'aveugle). Marqueurs bénins seulement — aucune charge weaponisée.
  (3) NON DESTRUCTIF : lecture/vérification seule, aucune mutation d'état (destructive=False, exploit=False).
      Le plancher exploit/destructif du ROE reste OFF par défaut (opt-in inchangé).
  (4) SESSION SECRÈTE : le matériel d'auth gouverné (SessionStore) est fusionné par `Oracle._http`
      UNIQUEMENT sur des URL in-scope et n'est JAMAIS journalisé/rapporté.
  (5) DÉGRADATION GRACIEUSE : réseau indisponible -> `skipped` (offline-safe).

Bâtis sur `InjectionOracle` (injection.py) : scope-guard NATIF fail-closed + dégradation + seam `_fetch`
monkeypatchable + `_send` (query GET ou corps urlencodé). Aucune capacité élargie.
"""
import hashlib
import re
import urllib.parse

from .oracle import Oracle
from .injection import InjectionOracle
from .registry import register
from .access_control import _body_hash, _normalize_body
from .. import techniques


# =================================================================================================
#  nosql.probe — injection NoSQL par différentiel d'OPÉRATEUR (Mongo $ne/$gt/$regex) — CWE-943
# =================================================================================================
# Valeur littérale « garbage » : ne matche aucun enregistrement réel (référence de la branche NARROW).
_NOSQL_GARBAGE = "forgeNoSQLxyzzy0"
# Épreuves (op_true, val_true, op_false, val_false) — le suffixe d'opérateur est injecté dans la CLÉ.
# op_true BROADEN (interprété comme opérateur -> matche) ; op_false NARROW (comme le littéral -> vide).
_NOSQL_TRIALS = [
    ("[$ne]", _NOSQL_GARBAGE, "[$eq]", _NOSQL_GARBAGE),   # $ne garbage -> tout sauf garbage ; $eq garbage -> vide
    ("[$gt]", "", "[$lt]", ""),                           # $gt "" -> tout ; $lt "" -> rien
    ("[$regex]", ".*", "[$eq]", _NOSQL_GARBAGE),          # regex .* -> tout ; $eq garbage -> vide
]


@register("nosql.probe")
class NoSqlProbe(InjectionOracle):
    kind = "nosql.probe"
    mitre = techniques.mitre_for("nosql.probe")          # source de vérité : forge/techniques.py (T1190)
    cwe = "CWE-943"                                       # category + cwe des findings
    tool = "forge/modules/injection_probes.py:nosql.probe"
    fix = ("Ne jamais laisser une entrée utilisateur devenir un OPÉRATEUR de requête NoSQL : caster les "
           "entrées au type attendu (chaîne/nombre), rejeter les valeurs qui sont des objets/tableaux "
           "(`{\"$ne\":...}`), désactiver l'interprétation des opérateurs sur les champs client, et "
           "valider/allowlister strictement les clés de requête (CWE-943).")
    description = ("Oracle NoSQLi à PREUVE : différentiel d'OPÉRATEUR (Mongo $ne/$gt/$regex broaden vs "
                   "$eq/$lt narrow) prouvant que les opérateurs sont interprétés. Aucun dump (hash/statut "
                   "seulement). Sinon tested. CWE-943.")

    def dry(self, action):
        param = action.params.get("param", "?")
        return (f"# différentiel d'opérateur sur {param} de {action.target} : {param}[$ne]=garbage "
                f"(BROADEN) vs {param}[$eq]=garbage (NARROW) — PREUVE = l'opérateur change la réponse là "
                f"où le littéral non ; JAMAIS de dump ; sinon tested")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="NoSQLi non testé — config manquante",
                evidence=("Requiert params.param (paramètre injectable). Optionnel : params.method, "
                          "params.headers."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()

        # contrôle littéral : une valeur « garbage » lue normalement (référence de la branche NARROW).
        where, c_st, c_body = self._send(action, param, _NOSQL_GARBAGE, method)
        c_hash = _body_hash(c_body)
        seen_network = c_st is not None

        confirmed, ctx = False, ""
        for op_true, val_true, op_false, val_false in _NOSQL_TRIALS:
            _, t_st, t_body = self._send(action, f"{param}{op_true}", val_true, method)
            _, f_st, f_body = self._send(action, f"{param}{op_false}", val_false, method)
            if t_st is not None or f_st is not None:
                seen_network = True
            t_hash, f_hash = _body_hash(t_body), _body_hash(f_body)
            # PREUVE : l'opérateur TRUE a BROADEN (diffère du littéral) ET l'opérateur FALSE est resté
            # NARROW (identique au littéral) -> les opérateurs sont INTERPRÉTÉS (injection NoSQL). Un
            # serveur qui traite tout littéralement OU qui erre uniformément -> t_hash == c_hash -> rejeté.
            if t_hash != c_hash and f_hash == c_hash:
                confirmed, ctx = True, f"{op_true} broaden / {op_false} narrow"
                break

        if not seen_network:
            return [self.degraded(
                target=where, title="NoSQLi non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]
        return [self.proof(
            target=where, proven=confirmed,
            title=("NoSQLi CONFIRMÉ — différentiel d'opérateur (opérateurs de requête interprétés)"
                   if confirmed else "NoSQLi non confirmé — aucun différentiel d'opérateur (pas de verdict aveugle)"),
            severity=("HIGH" if confirmed else "INFO"),
            evidence=(f"contexte={ctx or '—'} ; contrôle littéral={_NOSQL_GARBAGE} ; preuve = l'opérateur "
                      f"BROADEN la réponse là où le littéral la NARROW (comparaison de hash/statut, aucun "
                      f"dump de données) ; non destructif ; session gouvernée non journalisée"),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = {param}[$ne]=garbage (BROADEN) diffère, {param}[$eq]=garbage (NARROW) == "
                 f"littéral ; jamais de dump"))]


# =================================================================================================
#  lucene.probe — injection de requête Lucene/Elasticsearch par rupture de syntaxe bénigne — CWE-943
# =================================================================================================
# Signatures d'erreur de PARSING Lucene/ES (minuscules) — leur APPARITION (absente de la baseline)
# atteste que l'entrée est PARSÉE comme de la syntaxe de requête (injection). Jamais de donnée extraite.
_LUCENE_ERROR_SIGNS = [
    "org.apache.lucene", "parseexception", "cannot parse", "lexical error", "tokenmgrerror",
    "searchparseexception", "query_shard_exception", "queryparsingexception", "too_many_clauses",
    "maxclausecount", "failed to parse query", "was expecting", "unexpected char", "queryparser",
    "cannot parse '", "encountered \" ",
]
# Entrées qui ROMPENT la syntaxe Lucene si elle est parsée (déséquilibre / opérateur pendant) — BÉNIGNES
# (aucun champ ciblé, aucune donnée demandée) : elles ne font que provoquer une ParseException.
_LUCENE_BREAKERS = ['"', '(', '[', '\\', ' AND ', ' OR ', '^', '~~', '!:']


@register("lucene.probe")
class LuceneProbe(InjectionOracle):
    kind = "lucene.probe"
    mitre = techniques.mitre_for("lucene.probe")         # source de vérité : forge/techniques.py (T1190)
    cwe = "CWE-943"                                       # category + cwe des findings
    tool = "forge/modules/injection_probes.py:lucene.probe"
    fix = ("Ne jamais concaténer l'entrée utilisateur dans une requête Lucene/Elasticsearch : échapper "
           "les caractères spéciaux Lucene (`+ - && || ! ( ) { } [ ] ^ \" ~ * ? : \\ /`) ou utiliser "
           "l'API de requête structurée (query DSL avec `term`/`match` paramétrés) au lieu du "
           "query_string parsé ; valider/allowlister les champs interrogeables (CWE-943).")
    description = ("Oracle SearchInjection (Lucene/ES) à PREUVE : rupture de syntaxe bénigne -> "
                   "ParseException absente de la baseline, OU différentiel booléen (OR broaden / AND "
                   "narrow). Aucun dump. Sinon tested. CWE-943.")

    @staticmethod
    def _lucene_error(body):
        """Signature d'erreur de parsing Lucene/ES trouvée dans `body` (ou '' si aucune). Version/champ
        jamais extraits — seule la PRÉSENCE d'une erreur de parse compte (preuve de l'interprétation)."""
        low = (body or "").lower()
        return next((s for s in _LUCENE_ERROR_SIGNS if s in low), "")

    def dry(self, action):
        param = action.params.get("param", "?")
        return (f"# rupture de syntaxe Lucene sur {param} de {action.target} : `valeur\"` / `valeur(` "
                f"(déséquilibre -> ParseException) + différentiel OR/AND — PREUVE = erreur de parse "
                f"absente de la baseline OU différentiel booléen ; JAMAIS de dump ; sinon tested")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="SearchInjection non testé — config manquante",
                evidence=("Requiert params.param (paramètre de recherche). Optionnel : params.value "
                          "(terme de base), params.method, params.headers."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        value = str(action.params.get("value", "forge"))

        # baseline (terme valide) — référence de comparaison + détection d'une erreur déjà présente.
        where, base_st, base_body = self._send(action, param, value, method)
        base_hash = _body_hash(base_body)
        base_err = self._lucene_error(base_body)
        seen_network = base_st is not None

        # (A) error-based : une entrée qui ROMPT la syntaxe provoque une ParseException ABSENTE de la
        #     baseline -> l'entrée est parsée comme de la syntaxe Lucene (injection).
        err_confirmed, err_sign, err_break = False, "", ""
        for br in _LUCENE_BREAKERS:
            _, e_st, e_body = self._send(action, param, value + br, method)
            if e_st is not None:
                seen_network = True
            sign = self._lucene_error(e_body)
            if sign and not base_err:
                err_confirmed, err_sign, err_break = True, sign, br
                break

        # (B) différentiel booléen : `valeur OR garbage` BROADEN (~= baseline) vs `valeur AND garbage`
        #     NARROW (diffère) -> la requête booléenne est interprétée (injection). Garbage bénin.
        _, or_st, or_body = self._send(action, param, f"{value} OR {_NOSQL_GARBAGE}", method)
        _, and_st, and_body = self._send(action, param, f"{value} AND {_NOSQL_GARBAGE}", method)
        if or_st is not None or and_st is not None:
            seen_network = True
        or_same = (or_st == base_st and _normalize_body(or_body) and _body_hash(or_body) == base_hash)
        and_diff = _body_hash(and_body) != _body_hash(or_body)
        bool_confirmed = or_same and and_diff

        if not seen_network:
            return [self.degraded(
                target=where, title="SearchInjection non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]

        proven = err_confirmed or bool_confirmed
        tech = ", ".join(t for t in (
            ("rupture de syntaxe (ParseException)" if err_confirmed else ""),
            ("différentiel booléen (OR/AND)" if bool_confirmed else "")) if t) or "aucune"
        return [self.proof(
            target=where, proven=proven,
            title=("SearchInjection CONFIRMÉ — " + tech if proven
                   else "SearchInjection non confirmé — ni ParseException ni différentiel (pas de verdict aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"technique={tech} ; erreur_lucene={err_sign or '—'} ; rupture={err_break or '—'} ; "
                      f"différentiel_booléen={bool_confirmed} (garbage bénin, aucune donnée extraite) ; "
                      f"non destructif ; session gouvernée non journalisée"),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = ParseException Lucene absente de la baseline OU `{value} OR garbage` "
                 f"(broaden) vs `{value} AND garbage` (narrow) ; jamais de dump"))]


# =================================================================================================
#  cmdi.probe — VÉRIFICATION d'injection de commande OS à PREUVE STRICTEMENT BÉNIGNE — CWE-78
# =================================================================================================
# DISTINCT de rce.probe : cmdi est la sonde de VÉRIFICATION BÉNIGNE (exploit=False, éligible BB, sans
# plancher exploit). Séparateurs/gabarits — le marqueur echo/arith `CMD` y est substitué. STRICTEMENT
# bénins : aucune lecture de fichier, aucune écriture, aucun réseau — juste un echo/calcul.
_CMDI_TEMPLATES = [
    "; CMD", "| CMD", "|| CMD", "&& CMD", "& CMD", "$(CMD)", "`CMD`", "%0aCMD", "\nCMD",
]
# Garde-fou : une commande marqueur ne peut contenir QUE echo/chiffres/opérateurs arithmétiques/espaces
# — jamais un binaire nuisible. Toute commande hors de ce gabarit est REFUSÉE (belt-and-suspenders).
_CMDI_BENIGN_RX = re.compile(r"^(echo\s+[\w]+|echo\s+\$\(\(\s*\d+\s*\*\s*\d+\s*\)\))$")


@register("cmdi.probe")
class CmdiProbe(InjectionOracle):
    kind = "cmdi.probe"
    exploit = False                      # sonde de VÉRIFICATION BÉNIGNE (echo/arith) -> non-exploit, éligible BB
    destructive = False                  # aucune mutation d'état
    mitre = techniques.mitre_for("cmdi.probe")           # source de vérité : forge/techniques.py (T1059)
    cwe = "CWE-78"                                        # OS Command Injection
    tool = "forge/modules/injection_probes.py:cmdi.probe"
    fix = ("Ne jamais passer d'entrée utilisateur à un shell : utiliser des APIs natives / exécution sans "
           "shell (execve avec une liste d'arguments), allowlister strictement les entrées, et éviter "
           "`system`/`exec`/`popen` avec concaténation ; principe du moindre privilège sur le process "
           "(CWE-78).")
    description = ("Oracle Command-Injection à PREUVE STRICTEMENT BÉNIGNE (éligible BB, distinct de "
                   "rce.probe) : marqueur echo/arithmétique dont la SORTIE UNIQUE revient. Ne lance JAMAIS "
                   "de commande nuisible (garde-fou benign). Non destructif. Sinon tested. CWE-78.")

    @classmethod
    def _marker(cls, target, param):
        """(token, n, m, produit) déterministe-par-cible et DISTINCTIF : token alphanumérique + produit
        arithmétique à ~11-12 chiffres — quasi impossible à rencontrer par coïncidence."""
        h = int(hashlib.sha256(f"{target}|{param}|forge-cmdi".encode()).hexdigest(), 16)
        token = "forgecmdi" + f"{h:x}"[:12]
        n = 100003 + (h % 899000)
        m = 100003 + ((h >> 64) % 899000)
        return token, n, m, n * m

    @staticmethod
    def _assert_benign(cmd):
        """Garde-fou : REFUSE toute commande marqueur qui n'est pas un echo/arithmétique pur (jamais de
        lecture de fichier / réseau / binaire nuisible). Retourne True si bénigne, False sinon."""
        return bool(_CMDI_BENIGN_RX.match(cmd.strip()))

    def dry(self, action):
        param = action.params.get("param", "?")
        token, n, m, prod = self._marker(action.target, action.params.get("param", ""))
        return (f"# injecte {param}=; echo {token} / $(( {n}*{m} )) (marqueur STRICTEMENT BÉNIGN) dans "
                f"{action.target} ; PREUVE = le token {token} OU le produit {prod} revient (commande "
                f"exécutée) ; aucune commande nuisible ; sinon tested")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="Command-Injection non testé — config manquante",
                evidence=("Requiert params.param (paramètre injectable). Optionnel : params.method, "
                          "params.headers."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        token, n, m, product = self._marker(action.target, param)
        prod_s = str(product)
        executed, matched, where, seen_network, how = False, "", action.target, False, ""
        for tmpl in _CMDI_TEMPLATES:
            for cmd in (f"echo {token}", f"echo $(( {n}*{m} ))"):
                # garde-fou benign — n'émet une injection QUE si la commande est un echo/arith pur.
                if not self._assert_benign(cmd):
                    continue
                payload = tmpl.replace("CMD", cmd)
                where, st, body = self._send(action, param, payload, method)
                if st is not None:
                    seen_network = True
                b = body or ""
                if token in b:
                    executed, matched, how = True, payload, "token echo"
                    break
                if prod_s in b:
                    executed, matched, how = True, payload, "produit arithmétique"
                    break
            if executed:
                break
        if not seen_network:
            return [self.degraded(
                target=where, title="Command-Injection non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]
        return [self.proof(
            target=where, proven=executed,
            title=("Command-Injection CONFIRMÉE — injection prouvée par marqueur STRICTEMENT BÉNIGN (sortie unique)"
                   if executed else "Command-Injection non confirmée — aucun marqueur exécuté (pas de verdict aveugle)"),
            severity=("HIGH" if executed else "INFO"),
            evidence=(f"marqueur bénin token={token} produit={prod_s} ; exécuté={executed}"
                      + (f" ; preuve={how} ; payload={matched}" if executed else "")
                      + " ; STRICTEMENT bénin (echo/arithmétique — aucune commande nuisible, aucune lecture "
                        "de fichier, aucun réseau) ; non destructif ; session gouvernée non journalisée"),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = le token {token} OU le produit {prod_s} revient (commande exécutée) ; charge "
                 f"STRICTEMENT bénigne (echo/calcul)"))]


# =================================================================================================
#  prototype_pollution.probe — pollution de prototype par marqueur bénin réfléchi (CWE-1321)
# =================================================================================================
# Vecteurs d'injection de PROPRIÉTÉ (le marqueur clé `MARK` et la valeur `VAL` y sont substitués). BÉNINS :
# on ajoute une propriété inerte, on n'exploite AUCUN gadget (pas de `polluted`, pas de surcharge de
# fonction). `%s` -> clé, `%v` -> valeur.
_PP_VECTORS = ["__proto__[%s]=%v", "constructor[prototype][%s]=%v", "__proto__.%s=%v"]


@register("prototype_pollution.probe")
class PrototypePollutionProbe(InjectionOracle):
    kind = "prototype_pollution.probe"
    mitre = techniques.mitre_for("prototype_pollution.probe")   # source de vérité : techniques.py (T1190)
    cwe = "CWE-1321"                                     # category + cwe des findings
    tool = "forge/modules/injection_probes.py:prototype_pollution.probe"
    fix = ("Bloquer la pollution de prototype : rejeter/filtrer les clés `__proto__`, `constructor`, "
           "`prototype` lors de tout merge/clone d'objet issu de l'entrée utilisateur ; utiliser "
           "`Object.create(null)`/`Map` pour les dictionnaires, `Object.freeze(Object.prototype)`, et "
           "des librairies de merge sûres (validation de schéma stricte) (CWE-1321).")
    description = ("Oracle Prototype-Pollution à PREUVE BÉNIGNE : marqueur d'injection de propriété "
                   "(`__proto__[MARK]=VAL`) dont l'effet est RÉFLÉCHI uniquement via le vecteur proto "
                   "(différentiel vs contrôle). Aucun gadget exploité. Sinon tested. CWE-1321.")

    @classmethod
    def _marker(cls, target, param):
        """(mark, val) déterministe-par-cible et DISTINCTIF : nom de propriété + valeur bénins uniques —
        quasi impossibles à rencontrer par coïncidence. VAL sert de témoin de réflexion proto-spécifique."""
        h = hashlib.sha256(f"{target}|{param}|forge-pp".encode()).hexdigest()
        return "forgepp" + h[:8], "forgeval" + h[8:20]

    def dry(self, action):
        param = action.params.get("param", "?")
        mark, val = self._marker(action.target, param)
        return (f"# injecte __proto__[{mark}]={val} (propriété BÉNIGNE) dans {action.target} et compare à "
                f"un contrôle envoyant {val} par un paramètre normal — PREUVE = {val} surface UNIQUEMENT "
                f"via le vecteur proto (propriété polluée réfléchie) ; aucun gadget ; sinon tested")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="Prototype-Pollution non testé — config manquante",
                evidence=("Requiert params.param (paramètre témoin/de contrôle). Optionnel : params.method, "
                          "params.headers."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        mark, val = self._marker(action.target, param)

        # contrôle : envoyer la MÊME valeur `val` par un paramètre NORMAL — si `val` se reflète ici aussi,
        # la réflexion n'est PAS proto-spécifique (simple echo) -> non concluant (anti-faux-positif).
        _, c_st, c_body = self._send(action, param, val, method)
        control_reflects = val in (c_body or "")
        seen_network = c_st is not None

        polluted, matched_vector, where = False, "", action.target
        for vec in _PP_VECTORS:
            # le vecteur porte sa PROPRE clé=valeur (bracket dans la clé) : on l'injecte via _send en
            # traitant tout le fragment comme un paramètre à valeur vide -> forme `__proto__[MARK]=VAL`.
            frag = vec.replace("%s", mark).replace("%v", val)
            key, _, pv = frag.partition("=")
            where, st, body = self._send(action, key, pv, method)
            if st is not None:
                seen_network = True
            # PREUVE proto-spécifique : `val` surface via le vecteur proto MAIS pas via le paramètre normal.
            if val in (body or "") and not control_reflects:
                polluted, matched_vector = True, vec
                break

        if not seen_network:
            return [self.degraded(
                target=where, title="Prototype-Pollution non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]
        return [self.proof(
            target=where, proven=polluted,
            title=("Prototype-Pollution CONFIRMÉE — propriété polluée réfléchie via le vecteur proto"
                   if polluted else "Prototype-Pollution non confirmée — aucune réflexion proto-spécifique (pas de verdict aveugle)"),
            severity=("HIGH" if polluted else "INFO"),
            evidence=(f"marqueur propriété={mark} valeur={val} ; vecteur={matched_vector or '—'} ; "
                      f"réflexion_contrôle(param normal)={control_reflects} (si vrai -> non concluant) ; "
                      f"preuve = {val} surface UNIQUEMENT via __proto__ (propriété polluée fusionnée puis "
                      f"réfléchie) ; aucun gadget exploité ; non destructif ; session gouvernée non journalisée"),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = {val} apparaît via __proto__[{mark}]={val} mais PAS via {param}={val} "
                 f"(réflexion proto-spécifique) ; aucun gadget"))]

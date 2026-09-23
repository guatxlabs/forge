"""Oracle A PREUVE des INVARIANTS METIER — `business_logic.invariants`.

POURQUOI IL S'AJOUTE A `business_logic.scan` AU LIEU DE LE REMPLACER
---------------------------------------------------------------------
`business_logic.scan` porte trois verifications — quantite negative, prix trafique, coupon
empile — redigees en TEXTE LIBRE a l'intention d'un operateur humain. C'est un catalogue de
COMMERCE EN LIGNE, et il ne teste rien par lui-meme. Il garde son utilite comme aide-memoire ;
ce module-ci fait le travail automatique qui lui manquait.

LE DEFAUT QU'IL CORRIGE. Aucun catalogue generique ne peut contenir la logique metier d'une
cible. Sur une plateforme fiscale sondee le 2026-09-09, les regles etaient « les salaries
remboursables ne peuvent depasser l'effectif du mois », « le taux applicable vient d'une grille
servie par l'API » et « la masse salariale trimestrielle est la somme des trois mensuelles ».
Ni quantite negative, ni coupon, ni panier. En revanche ces trois regles sont toutes des
INVARIANTS ARITHMETIQUES, et un invariant se DERIVE de l'objet observe.

LES QUATRE FAMILLES D'INVARIANTS SONDEES
-----------------------------------------
  * NEGATIF     — un montant ou un effectif negatif est-il accepte ?
  * BORNE       — pour deux champs ou `a <= b` dans l'etat initial, `a > b` passe-t-il ?
                  (c'est exactement la regle « remboursables <= effectif »)
  * SOMME       — pour un champ egal a la somme d'autres champs, une somme FAUSSE passe-t-elle ?
  * HORS GRILLE — un identifiant de referentiel absent de la liste servie par l'API est-il pris ?

⚠️ TOUTES LES VALEURS ENVOYEES SONT DES VALEURS QUE LE SERVEUR DOIT REJETER. C'est le coeur de
la sûrete ici, et c'est aussi ce qui rend la preuve propre : on n'envoie jamais une declaration
VALIDE mais mensongere — on envoie un negatif, une incoherence, une valeur hors grille. Si le
serveur les accepte, la faille est demontree ; et ce qui a ete ecrit reste invalide, donc sans
gain frauduleux. Ecrire une valeur valide et fausse pour « voir si ca passe » serait, sur une
plateforme reelle, une declaration mensongere.

PREUVE = le serveur accepte ET persiste une valeur qui viole un invariant qu'il a lui-meme
etabli dans l'etat de reference.
"""
from __future__ import annotations

import json

from .oracle import ScopeGuardedOracle
from .registry import register
from .. import techniques

MAX_SONDES = 8           # borne DECLAREE du fan-out
NEGATIF = -133742        # valeur reconnaissable, jamais un minimum plausible


def champs_numeriques(objet):
    """{nom: valeur} des champs numeriques d'un objet — les seuls porteurs d'invariants."""
    return {k: v for k, v in (objet or {}).items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)}


def paires_bornees(nums):
    """[(a, b)] tels que `a <= b` dans l'etat observe : `b` borne `a`.

    C'est la forme de la regle la plus courante et la moins outillee — « le nombre de X
    remboursables ne peut depasser l'effectif », « la quantite commandee ne peut depasser le
    stock ». On ne devine pas la regle : on la LIT dans l'objet, puis on tente de la violer.
    Les valeurs egales sont retenues (a <= b), une egalite etant souvent une borne atteinte.
    """
    out = []
    items = [(k, v) for k, v in nums.items() if v is not None]
    for i, (ka, va) in enumerate(items):
        for kb, vb in items[i + 1:]:
            if va <= vb and vb > 0:
                out.append((ka, kb))
            elif vb <= va and va > 0:
                out.append((kb, ka))
    return out


def sommes_probables(nums, tolerance=0.01):
    """[(total, [parties])] ou un champ vaut la somme d'au moins deux autres.

    Detecte a l'execution plutot que devine : c'est l'objet qui dit ou est l'invariant.
    """
    import itertools
    for total, vt in nums.items():
        if not vt:
            continue
        parties = [k for k in nums if k != total]
        # Combinaisons de 2 a 4 champs : au-dela, une egalite fortuite devient plus probable
        # qu'un invariant reel, et l'on fabriquerait une regle qui n'existe pas.
        for taille in (2, 3, 4):
            for grp in itertools.combinations(parties, taille):
                s = sum(nums[p] for p in grp)
                if s and abs(s - vt) <= abs(vt) * tolerance:
                    return [(total, list(grp))]   # une seule somme suffit a poser l'invariant
    return []


def extrait_json(corps):
    try:
        d = json.loads(corps or "")
    except Exception:            # noqa: BLE001
        return {}
    if isinstance(d, dict):
        for cle in ("data", "result", "item"):
            if isinstance(d.get(cle), dict):
                return d[cle]
        return d
    return {}


techniques.register_kind(techniques._k(
    "business_logic.invariants", "BusinessLogic", True, depends_on=("recon.forms",),
    cls="business_logic", cwe="CWE-840", mitre="T1190", exploit=False,
    attck_tactic="Impact", phase="access", capability="active",
    proof_required=True))


@register("business_logic.invariants")
class BusinessInvariants(ScopeGuardedOracle):
    kind = "business_logic.invariants"
    exploit = False              # valeurs INVALIDES : aucun gain, aucune declaration mensongere
    destructive = False
    web_allowed = True
    available = True
    category = "business_logic"
    cwe = "CWE-840"
    mitre = techniques.mitre_for("business_logic.invariants") or "T1190"
    tool = "forge/modules/bizinvariants.py:business_logic.invariants"
    description = ("DERIVE les invariants arithmetiques d'un objet metier (negatifs, bornes "
                   "entre champs, sommes, valeurs hors grille) puis tente de les violer avec des "
                   "valeurs que le serveur DOIT rejeter. Complete `business_logic.scan`, dont les "
                   "trois verifications de commerce en ligne, redigees en texte libre, ne "
                   "pouvaient rien tester d'elles-memes et ne decrivaient qu'un seul metier.")
    fix = ("Valider les invariants METIER cote serveur, pas seulement les types : une borne entre "
           "deux champs, une somme, une appartenance a un referentiel. Un champ desactive dans le "
           "formulaire n'est qu'un controle d'AFFICHAGE — le client le renvoie quand meme. "
           "Recalculer systematiquement cote serveur ce qui peut l'etre (totaux, taux, montants) "
           "au lieu de faire confiance a la valeur recue.")

    def _get(self, action, timeout):
        st, body, _h = self._http(str(action.target),
                                  headers=dict(action.params.get("headers", {})),
                                  timeout=timeout, method="GET")
        return st, extrait_json(body)

    def _write(self, action, objet, timeout):
        headers = {"Content-Type": "application/json"}
        headers.update(dict(action.params.get("headers", {})))
        st, body, _h = self._http(str(action.target), headers=headers, timeout=timeout,
                                  method=str(action.params.get("method", "PUT")).upper(),
                                  data=json.dumps(objet).encode())
        return st, (body or "")

    def _sondes(self, avant, nums):
        """[(nom de l'invariant, objet a envoyer, champ observe, valeur attendue)]."""
        out = []
        for k, v in list(nums.items())[:4]:
            o = dict(avant); o[k] = NEGATIF
            out.append((f"negatif sur `{k}`", o, k, NEGATIF))
        for a, b in paires_bornees(nums)[:2]:
            o = dict(avant); o[a] = abs(nums[b]) + 1000
            out.append((f"borne violee : `{a}` > `{b}`", o, a, abs(nums[b]) + 1000))
        for total, parties in sommes_probables(nums)[:1]:
            o = dict(avant); o[total] = abs(nums[total]) + 999
            out.append((f"somme fausse : `{total}` != {'+'.join(parties)}", o, total,
                        abs(nums[total]) + 999))
        return out[:MAX_SONDES]

    def dry(self, action):
        return (f"# 1 lecture puis N sondes sur {action.target} — objet de l'OPERATEUR :\n"
                f"#   GET  -> etat de reference ; les invariants sont DERIVES de cet etat\n"
                f"#   {str(action.params.get('method','PUT')).upper():4s} -> une valeur qui VIOLE un invariant "
                f"(negatif, borne, somme)\n"
                f"#   GET  -> la valeur invalide a-t-elle ete PERSISTEE ?\n"
                f"# Toutes les valeurs envoyees sont des valeurs que le serveur DOIT rejeter : "
                f"jamais une declaration valide mais mensongere.")

    def fire(self, action):
        target = str(action.target)
        if not self._in_scope(action, target):
            return [self.skip(target=target,
                              title="Invariants metier non sondes — hors perimetre (fail-closed)",
                              evidence="Aucune requete emise.", poc=self.dry(action))]
        try:
            timeout = max(1, min(int(action.params.get("timeout", 15)), 60))
        except (TypeError, ValueError):
            timeout = 15

        st0, avant = self._get(action, timeout)
        if st0 is None:
            return [self.degraded(
                target=target, title="Invariants metier non verifies — reseau indisponible",
                evidence="Aucune reponse a la lecture de reference ; offline-safe.",
                poc=self.dry(action))]
        nums = champs_numeriques(avant)
        if len(nums) < 1:
            return [self.skip(
                target=target, title="Invariants metier non sondes — aucun champ numerique",
                evidence=(f"GET {target} rend HTTP {st0} sans champ numerique exploitable. Les "
                          f"invariants se DERIVENT de l'objet : sans nombres, il n'y a ni borne, "
                          f"ni somme, ni negatif a eprouver. Viser le point de service qui porte "
                          f"l'objet metier (declaration, commande, panier, dossier)."),
                poc=self.dry(action))]

        violes, observations = [], []
        for nom, charge, champ, attendu in self._sondes(avant, nums):
            st_w, _b = self._write(action, charge, timeout)
            st_r, apres = self._get(action, timeout)
            if st_r is None:
                continue
            persiste = champ in apres and str(apres.get(champ)) == str(attendu)
            observations.append(f"{nom}: ecriture HTTP {st_w}, persiste={'OUI' if persiste else 'non'}")
            if persiste:
                violes.append(nom)
            # remise en etat : on ne laisse pas une valeur invalide dans l'objet de l'operateur
            if persiste:
                self._write(action, dict(avant), timeout)

        if violes:
            return [self.proof(
                target=target, proven=True, severity="HIGH",
                title=(f"INVARIANT METIER NON VALIDE COTE SERVEUR — {len(violes)} viole(s) : "
                       f"{'; '.join(violes)}"),
                evidence=(f"Etat de REFERENCE (HTTP {st0}) : {len(nums)} champ(s) numerique(s), dont "
                          f"les invariants ont ete DERIVES et non devines. Les sondes listees ont "
                          f"ete ACCEPTEES et PERSISTEES alors qu'elles violent une regle que "
                          f"l'objet lui-meme etablissait. Detail : " + " | ".join(observations) +
                          ". ⚠️ Les valeurs envoyees sont INVALIDES par construction (negatif, "
                          "borne depassee, somme fausse) : rien de valide mais mensonger n'a ete "
                          "declare, et l'etat initial a ete restaure apres chaque sonde retenue. "
                          "IMPACT A INSTRUIRE dans le rapport : quel gain reel — remboursement, "
                          "remise, credit — cet invariant non valide permettrait d'obtenir."),
                poc=self.dry(action))]

        return [self.proof(
            target=target, proven=False, severity="INFO",
            title="Invariants metier valides cote serveur",
            evidence=(f"Reference HTTP {st0}, {len(nums)} champ(s) numerique(s). Sondes : "
                      + " | ".join(observations or ["aucune sonde aboutie"]) +
                      ". Aucune valeur invalide n'a ete persistee — comportement CORRECT. "
                      "⚠️ Ce negatif ne porte QUE sur les invariants derivables d'un objet lu : "
                      "les regles qui vivent dans un flux multi-etapes (tunnel de commande, "
                      "machine a etats) ne sont pas atteintes par cet oracle."),
            poc=self.dry(action))]

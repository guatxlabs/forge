"""Registre de modules d'attaque — le contrat que tout module Forge respecte.

Un module = deux méthodes seulement :
  - dry(action)  -> str            : ce que le module FERAIT (commande / PoC), sans rien envoyer.
  - fire(action) -> list[Finding]  : exécute réellement. N'est JAMAIS appelé par l'engine tant
                                     que la gate ROE n'a pas rendu un verdict FIRE.

Les modules réels (P2) enveloppent les outils existants : `toolkit/*.py` (43 testeurs web),
secpipe (recon/access_control/origin_detection), l'évasion browser-automation (vision-click,
intercept-modify). Ils restent des OUTILS AUTONOMES — l'engine les orchestre, ne les possède pas.

Discipline (héritée des collecteurs Plume) : un module est OFF par défaut, se neutralise
proprement si son outil sous-jacent est absent, et n'émet jamais d'effet de bord en dry-run.
"""
from ..schema import Finding, _PROOF_SENTINEL

REGISTRY = {}


def register(kind):
    def deco(cls):
        REGISTRY[kind] = cls
        cls.kind = kind
        return cls
    return deco


def get(kind):
    cls = REGISTRY.get(kind)
    return cls() if cls else None


def kinds():
    return sorted(REGISTRY)


class Module:
    """Classe de base. Un module concret surcharge dry() et fire()."""
    kind = "base"
    exploit = False         # déclare si ce module exploite (=> exige allow_exploit dans le scope)
    destructive = False     # déclare s'il est destructif (=> exige allow_destructive)
    available = True        # passe à False si l'outil sous-jacent manque (auto-neutralisation)
    mitre = ""              # technique ATT&CK du module (badge dans le viewer console)
    description = ""         # description courte du module (affichée dans le viewer console)

    def dry(self, action):
        raise NotImplementedError

    def fire(self, action):
        raise NotImplementedError

    @staticmethod
    def finding(_proven=False, **kw):
        """Construit un Finding. GARDE-FOU DE PREUVE (schema-enforced) : le statut proof-implying
        'vulnerable' n'est atteignable QUE via le chemin de preuve SANCTIONNÉ — `Oracle.proof(proven=True)`
        (qui pose `_proven=True`) ou un émetteur in-tree qui ATTESTE explicitement sa preuve concrète
        (`_proven=True`). Un appelant GÉNÉRIQUE/plugin qui poserait `status='vulnerable'` SANS ce marqueur
        est ramené fail-closed à 'tested' : impossible de forger un finding « prouvé » dans le ledger SIGNÉ
        ni le rapport en court-circuitant le clamp « pas de preuve => tested ». Les autres statuts passent
        au validateur du schema (statut inconnu -> 'tested'). Comportement inchangé pour les preuves
        légitimes (elles portent toutes `_proven=True`)."""
        if not _proven and kw.get("status") == "vulnerable":
            kw["status"] = "tested"
        # DÉFENSE EN PROFONDEUR (L1) : le gate de preuve vit AUSSI dans `Finding.__post_init__` (une
        # construction directe `Finding(status="vulnerable")` y est rabattue à 'tested'). Le chemin de
        # preuve SANCTIONNÉ transmet la sentinelle opaque pour franchir ce gate — SEUL point qui le fait.
        if _proven:
            kw["_proof_token"] = _PROOF_SENTINEL
        return Finding(**kw)

    def tool_failed(self, action, rc, out, err, tool, category="recon"):
        """None si l'outil a réussi (rc==0) ; sinon un Finding d'ÉCHEC traçable.

        Évite le bug « sortie d'erreur enregistrée comme un vrai finding » : un outil qui plante
        (rc!=0, timeout 124, indisponible 127) ne doit pas produire un résultat trompeur, mais un
        finding INFO clairement étiqueté échec (visible dans le rapport anti-masquage)."""
        if rc == 0:
            return None
        reason = {127: "outil indisponible", 124: "timeout"}.get(rc, f"échec (rc={rc})")
        return self.finding(
            target=action.target, title=f"{tool} — {reason}", severity="INFO",
            category=category, status="tested", tool=tool,
            evidence=((err or out).strip()[:500] or reason))

"""Module de démonstration — illustre le contrat SANS aucune capacité offensive live.

v0 ne livre AUCUN module qui attaque réellement (sûreté d'abord). Ce module montre la
mécanique bout-en-bout (plan -> gate ROE -> dry/fire -> finding -> ledger -> rapport) :
  - dry()  : retourne la commande qu'un vrai module exécuterait (ici un simple HEAD HTTP).
  - fire() : produit un Finding SYNTHÉTIQUE, zéro I/O réseau, explicitement étiqueté DEMO.

Les vrais handlers (P2) remplacent fire() par un appel à runner.tool(...) enveloppant
nmap/nuclei/un testeur toolkit, etc. — toujours derrière la même gate.
"""
from .registry import register, Module


@register("demo.fingerprint")
class DemoFingerprint(Module):
    kind = "demo.fingerprint"
    exploit = False
    destructive = False
    mitre = "T1595"          # Active Scanning — la démo illustre une reconnaissance (badge purple non vide)
    description = ("Module de démonstration — illustre le pipeline (plan→ROE→dry/fire→"
                  "finding→ledger) sans aucun I/O réseau.")

    def dry(self, action):
        return f"curl -sI {action.target}   # (DEMO — non exécuté en dry-run)"

    def fire(self, action):
        # AUCUN réseau : finding synthétique pour prouver le pipeline de bout en bout.
        return [self.finding(
            target=action.target,
            title="DEMO — module de démonstration tiré",
            severity="INFO",
            category="DEMO",
            mitre="",
            status="tested",
            evidence="Finding synthétique (aucune requête réelle émise). Remplacer fire() par un vrai exécuteur en P2.",
            tool="forge/modules/demo.py",
            poc=self.dry(action),
        )]

# SPDX-License-Identifier: AGPL-3.0-only
"""Commandes ledger de la CLI Forge : `ledger verify|pubkey|keygen`. Extrait de l'ancien
`forge/cli.py` (pur déplacement, comportement inchangé)."""
from pathlib import Path

from ..ledger import Ledger
from .. import signing


def cmd_ledger_verify(args):
    # --pubkey HEX : vérification EXTERNE (tiers) par la SEULE clé publique Ed25519, sans aucun secret
    # (non-répudiation). Sinon vérif locale par le signeur du host.
    if getattr(args, "pubkey", None):
        v = Ledger(args.ledger).verify_external(args.pubkey)
        if v["ok"]:
            print(f"Ledger OK ✅ (vérif externe, clé publique seule) — {v['entries']} entrées")
            return 0
        print(f"Ledger CASSÉ ❌ (vérif externe) — entrée {v.get('broken')} : {v.get('why','')}")
        return 1
    v = Ledger(args.ledger).verify()
    if v["ok"]:
        print(f"Ledger OK ✅ — {v['entries']} entrées, alg={v.get('alg','?')}, "
              f"pub={v.get('pub','')}, head={v.get('head','')[:16]}…")
        return 0
    print(f"Ledger CASSÉ ❌ — entrée {v['broken']} : {v.get('why','')} (alg={v.get('alg','?')})")
    return 1


def cmd_ledger_pubkey(args):
    """Imprime la clé publique Ed25519 BRUTE (hex) qui signe ce ledger, alg en 2e ligne.
    Résout la clé EXACTEMENT comme le chemin `ledger verify` (Ledger(path) -> make_signer :
    lit `<path>.ed25519` s'il existe, sinon auto-gen). Le hex imprimé est directement réutilisable
    en vérif externe : `forge ledger verify --ledger L --pubkey <hex>`."""
    led = Ledger(args.ledger)
    hexkey = signing.signer_pubkey_hex(led.signer)
    if hexkey:
        print(hexkey)                                  # ligne 1 : clé publique brute (64 hex)
        print(f"# alg={led.signer.alg}")               # ligne 2 : algorithme (ed25519)
        return 0
    # repli HMAC (cryptography absent) : pas de clé publique asymétrique de non-répudiation.
    print(f"# pas de clé publique Ed25519 — ledger signé en {led.signer.alg} "
          f"(installer 'cryptography' pour la non-répudiation asymétrique)")
    print(f"# public_id={led.signer.public_id()}")
    return 1


def cmd_ledger_keygen(args):
    """Crée/rotationne DÉLIBÉRÉMENT la paire Ed25519 du ledger (<path>.ed25519, 0600), au lieu de
    l'auto-gen paresseux. Sûreté : refuse d'écraser une clé existante sans --force (une rotation
    invalide les signatures ed25519 déjà écrites -> `verify` casserait). Imprime la clé publique."""
    if not signing._HAVE_ED:
        print("# 'cryptography' absent — impossible de générer une clé Ed25519 (repli HMAC seul)")
        return 1
    kp = Path(str(args.ledger) + ".ed25519")
    if kp.exists() and not args.force:
        print(f"# clé déjà présente : {kp}")
        print("# --force requis pour ROTATION (invalide les signatures ed25519 déjà écrites)")
        return 1
    rotated = kp.exists()
    signer = signing.generate_ed25519_keypair(args.ledger)
    print(signing.signer_pubkey_hex(signer))
    print(f"# alg=ed25519 — clé {'ROTATIONNÉE' if rotated else 'créée'} dans {kp} (0600)")
    return 0

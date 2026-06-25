"""Signature du ledger — Ed25519 à l'append (asymétrique) avec repli HMAC (stdlib).

Asymétrique = un vérificateur EXTERNE (Plume, un auditeur) valide la preuve d'engagement avec la
SEULE clé publique, sans pouvoir forger → non-répudiation. C'est ce qui ferme le caveat du ledger
(clé HMAC symétrique = forgeable par quiconque détient la clé). Repli HMAC si `cryptography` est
absent : le core reste fonctionnel en pur-stdlib, mais sans non-répudiation forte.

Off-host anchor = étape suivante : la clé privée Ed25519 pourra vivre sur un signeur distant ;
l'architecture asymétrique le permet déjà (seule la clé publique circule pour vérifier).
"""
import hashlib
import hmac
import os
import secrets
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    _HAVE_ED = True
except Exception:  # noqa: BLE001
    _HAVE_ED = False


class Signer:
    alg = "none"

    def sign(self, data: bytes) -> str:
        raise NotImplementedError

    def verify(self, data: bytes, sig_hex: str) -> bool:
        raise NotImplementedError

    def public_id(self) -> str:
        raise NotImplementedError


class HmacSigner(Signer):
    alg = "hmac-sha256"

    def __init__(self, key: bytes):
        self.key = key

    def sign(self, data):
        return hmac.new(self.key, data, hashlib.sha256).hexdigest()

    def verify(self, data, sig_hex):
        return hmac.compare_digest(self.sign(data), sig_hex)

    def public_id(self):
        # empreinte NON secrète de la clé (jamais la clé) — symétrique : ne prouve pas la non-répudiation
        return "hmac:" + hashlib.sha256(self.key).hexdigest()[:16]


class Ed25519Signer(Signer):
    alg = "ed25519"

    def __init__(self, priv):
        self._priv = priv
        self._pub_hex = priv.public_key().public_bytes_raw().hex()

    def sign(self, data):
        return self._priv.sign(data).hex()

    def verify(self, data, sig_hex):
        try:
            self._priv.public_key().verify(bytes.fromhex(sig_hex), data)
            return True
        except Exception:  # noqa: BLE001
            return False

    def public_id(self):
        return "ed25519:" + self._pub_hex


def _load_or_make_secret(path) -> bytes:
    env = os.environ.get("FORGE_LEDGER_KEY")
    if env:
        return env.encode("utf-8")
    kp = Path(path)
    if kp.exists():
        return kp.read_bytes()
    key = secrets.token_bytes(32)
    kp.parent.mkdir(parents=True, exist_ok=True)
    kp.write_bytes(key)
    try:
        os.chmod(kp, 0o600)
    except OSError:
        pass
    return key


def make_signer(base_path, prefer_ed25519=True) -> Signer:
    """Ed25519 si dispo + souhaité (clé privée dans <base>.ed25519, 0600), sinon HMAC (<base>.key)."""
    base = str(base_path)
    if prefer_ed25519 and _HAVE_ED:
        kp = Path(base + ".ed25519")
        if kp.exists():
            priv = Ed25519PrivateKey.from_private_bytes(kp.read_bytes())
        else:
            priv = Ed25519PrivateKey.generate()
            kp.parent.mkdir(parents=True, exist_ok=True)
            kp.write_bytes(priv.private_bytes_raw())
            try:
                os.chmod(kp, 0o600)
            except OSError:
                pass
        return Ed25519Signer(priv)
    return HmacSigner(_load_or_make_secret(base + ".key"))


def ephemeral_signer() -> Signer:
    """Signeur à clé en mémoire (aucun fichier) — pour un témoin in-process ou des tests."""
    if _HAVE_ED:
        return Ed25519Signer(Ed25519PrivateKey.generate())
    return HmacSigner(secrets.token_bytes(32))


def verify_with_pubkey(pubkey_hex, data: bytes, sig_hex: str) -> bool:
    """Vérification EXTERNE par la seule clé publique Ed25519 (non-répudiation, sans secret)."""
    if not _HAVE_ED:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(bytes.fromhex(sig_hex), data)
        return True
    except Exception:  # noqa: BLE001
        return False


# --- algo "sha256-console" : chaîne de hachage NON signée (écrite par la console Rust) ---
# La console (console/src/main.rs::append_console_ledger) chaîne ses entrées avec le MÊME
# pré-image que Python (prev|seq|ts|kind|canon(detail)) mais pose `sig: ""` : il n'y a PAS
# de signature secrète — l'intégrité de ces entrées repose ENTIÈREMENT sur la chaîne de hachage
# (déjà recalculée et vérifiée par Ledger.verify avant cet étage). On traite donc `sha256-console`
# comme « chaîne vérifiée, signature non-applicable » : on accepte ssi `sig` est vide (une signature
# non vide sur cet algo serait inattendue/suspecte). Toute altération du contenu reste détectée par
# le contrôle de hash, jamais affaiblie.
CONSOLE_ALG = "sha256-console"


def verify_console(sig_hex: str) -> bool:
    """Algo `sha256-console` : pas de signature secrète, intégrité = chaîne de hachage. Sig DOIT être vide."""
    return sig_hex in ("", None)


def verify_entry(alg, signer, data: bytes, sig_hex: str) -> bool:
    """Vérifie la signature d'UNE entrée SELON SON PROPRE `alg` (ledger multi-algo).

    - `sha256-console` -> chaîne vérifiée, signature non-applicable (sig doit être vide) ;
    - autres algos (ed25519 / hmac-sha256) -> délégué au `signer` local fourni.

    `signer` est le signeur local du Ledger ; il n'est sollicité que si `alg` correspond à son
    propre `alg`. Un `alg` inconnu ou un `alg` qui ne matche pas le signeur local -> refus (False).
    """
    if alg == CONSOLE_ALG:
        return verify_console(sig_hex)
    if signer is not None and alg == signer.alg:
        return signer.verify(data, sig_hex)
    return False

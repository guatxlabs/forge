# SPDX-License-Identifier: AGPL-3.0-only
"""ENTERPRISE (SEC-KMS / F4) — PKCS#11 (CKM_EDDSA) OFF-HOST ledger signer. OPTIONAL, opt-in driver.

WHY PKCS#11 (and not AWS-KMS directly): the Forge ledger is **Ed25519**. AWS-KMS signs RSA/ECDSA
only — it cannot produce an Ed25519 signature — so it can't drive this ledger without changing the
ledger algorithm. PKCS#11 (`CKM_EDDSA`) CAN, and it is vendor-neutral: SoftHSM2 for dev/CI, any HSM
(incl. AWS CloudHSM) or a cloud-KMS-via-PKCS#11 bridge for prod. A cloud KMS that natively does
Ed25519 (e.g. GCP-KMS) is reachable through the generic **exec signer** (`gcloud kms asymmetric-sign`),
documented in `docs/KEY_CUSTODY.md` as the escape hatch.

STDLIB-ONLY DEFAULT PRESERVED — the PKCS#11 library (`python-pkcs11`) is a LAZY import INSIDE this
driver (`_import_pkcs11`), never at module top. The community engine imports nothing new: this module
loads with the stdlib alone, and `python-pkcs11` is only touched when an operator actually selects the
PKCS#11 signer (`FORGE_LEDGER_SIGNER=pkcs11`). Absent lib → a clear, actionable install error.

FAIL-CLOSED — `Pkcs11Signer` subclasses `signing.RemoteSigner`, so `sign()` RE-VERIFIES the token's
returned signature against the public key before accepting it (rejecting a bogus/mismatched response),
and NEVER falls back to a local key. The private key stays on the token — this process only ever sees
the signature + the PUBLIC key, so `verify` / `verify_external(pubkey)` are UNCHANGED for auditors.
Off-host key custody is exactly what closes the F4 host-root residual when paired with `WitnessAnchor`.

CONFIG via ENV (never argv — matches the secret-hygiene rule; PIN is a secret):
  FORGE_LEDGER_PKCS11_MODULE       path to the PKCS#11 provider `.so` (e.g. libsofthsm2.so)  [required]
  FORGE_LEDGER_PKCS11_TOKEN_LABEL  token label   (or use ...SLOT)
  FORGE_LEDGER_PKCS11_SLOT         slot index    (alternative to token label)
  FORGE_LEDGER_PKCS11_KEY_LABEL    key label     (CKA_LABEL)   — key_label and/or key_id required
  FORGE_LEDGER_PKCS11_KEY_ID       key id (hex or text, CKA_ID)
  FORGE_LEDGER_PKCS11_PIN          user PIN (SECRET — env only, never argv/logs)
"""
import os

from . import signing

RemoteSignerError = signing.RemoteSignerError

# ENV keys — dedicated to the PKCS#11 signer (kept out of signing.py's HTTP/exec key space).
PKCS11_MODULE_ENV = "FORGE_LEDGER_PKCS11_MODULE"
PKCS11_TOKEN_LABEL_ENV = "FORGE_LEDGER_PKCS11_TOKEN_LABEL"
PKCS11_SLOT_ENV = "FORGE_LEDGER_PKCS11_SLOT"
PKCS11_KEY_LABEL_ENV = "FORGE_LEDGER_PKCS11_KEY_LABEL"
PKCS11_KEY_ID_ENV = "FORGE_LEDGER_PKCS11_KEY_ID"
PKCS11_PIN_ENV = "FORGE_LEDGER_PKCS11_PIN"

# A constant nonce signed once at BUILD time to prove the token's key pair actually verifies (fail fast on
# a wrong token/key pairing) — goes through the same fail-closed re-verify as every real ledger signature.
_SELFTEST = b"forge-pkcs11-selftest"


class Pkcs11Signer(signing.RemoteSigner):
    """OFF-HOST ledger signer whose Ed25519 private key lives on a PKCS#11 token (SoftHSM dev, any HSM /
    AWS CloudHSM / cloud-KMS-via-PKCS#11 prod), signing via `CKM_EDDSA`. Inherits `RemoteSigner`'s
    FAIL-CLOSED contract verbatim: `sign()` re-verifies the token's signature against the public key
    before returning it (reject on mismatch) and never falls back to a local key. Only the signature +
    the PUBLIC key ever reach this process, so `verify_external(pubkey)` is unchanged for third parties."""

    def __init__(self, sign_fn, pubkey_hex, *, backend_label="pkcs11(token redacted)"):
        super().__init__(sign_fn, pubkey_hex, backend_label=backend_label)


def _import_pkcs11():
    """LAZY import of `python-pkcs11` — called ONLY when the PKCS#11 signer is actually built, so the
    default engine stays stdlib-only. Absent lib → an actionable RemoteSignerError (no traceback noise)."""
    try:
        import pkcs11  # noqa: F401  (python-pkcs11)
    except ImportError:
        raise RemoteSignerError(
            "signeur PKCS#11 configuré mais python-pkcs11 n'est pas installé — "
            "installez l'extra optionnel : pip install 'forge[pkcs11]'"
        ) from None
    return pkcs11


def resolve_pkcs11_config(config=None, env=None):
    """Resolve the PKCS#11 signer config: an explicit `config` field wins, else the dedicated ENV var.
    Reads NO secret from argv (PIN via env only). Pure — imports nothing, contacts no token."""
    env = os.environ if env is None else env
    config = config or {}

    def pick(key, envk):
        v = config.get(key)
        if v is None or v == "":
            v = env.get(envk)
        return v

    return {
        "module": pick("module", PKCS11_MODULE_ENV),
        "token_label": pick("token_label", PKCS11_TOKEN_LABEL_ENV),
        "slot": pick("slot", PKCS11_SLOT_ENV),
        "key_label": pick("key_label", PKCS11_KEY_LABEL_ENV),
        "key_id": pick("key_id", PKCS11_KEY_ID_ENV),
        "pin": pick("pin", PKCS11_PIN_ENV),
    }


def _as_id_bytes(key_id):
    """CKA_ID is bytes on the token. Accept bytes, a hex string, or raw text; None/'' → None."""
    if key_id is None or key_id == "":
        return None
    if isinstance(key_id, (bytes, bytearray)):
        return bytes(key_id)
    s = str(key_id)
    if signing._is_hex(s):
        return bytes.fromhex(s)
    return s.encode("utf-8")


def _ed25519_pub_hex_from_ec_point(raw):
    """Decode a PKCS#11 Ed25519 public value (CKA_EC_POINT) to raw 32-byte hex (what `verify_external`
    wants). Handles both the raw 32-byte point and the DER OCTET STRING wrapping `04 20 <32 bytes>`
    that many providers (incl. SoftHSM2) return. Anything else → fail-closed error."""
    if not isinstance(raw, (bytes, bytearray)):
        raise RemoteSignerError("signeur PKCS#11 : CKA_EC_POINT de type inattendu")
    raw = bytes(raw)
    if len(raw) == 32:
        return raw.hex()
    if len(raw) == 34 and raw[0] == 0x04 and raw[1] == 0x20:   # DER OCTET STRING (tag 0x04, len 0x20)
        return raw[2:].hex()
    raise RemoteSignerError(
        "signeur PKCS#11 : clé publique Ed25519 illisible (CKA_EC_POINT attendu : 32 octets bruts "
        "ou DER `04 20 …`)"
    )


def _open_session(p11, cfg):
    """Open a PKCS#11 session on the configured token. Every failure → a SECRET-FREE RemoteSignerError
    (the PIN and module path are never surfaced)."""
    module = cfg.get("module")
    try:
        lib = p11.lib(str(module))
    except Exception as e:  # noqa: BLE001 — provider load can raise provider-specific errors
        raise RemoteSignerError(
            f"signeur PKCS#11 : module provider introuvable/illisible ({type(e).__name__})"
        ) from None
    token_label = cfg.get("token_label")
    slot = cfg.get("slot")
    try:
        if token_label:
            token = lib.get_token(token_label=str(token_label))
        elif slot is not None and str(slot) != "":
            token = lib.get_slots(token_present=True)[int(slot)].get_token()
        else:
            raise RemoteSignerError("signeur PKCS#11 : token_label ou slot requis")
    except RemoteSignerError:
        raise
    except Exception as e:  # noqa: BLE001
        raise RemoteSignerError(f"signeur PKCS#11 : token introuvable ({type(e).__name__})") from None
    try:
        return token.open(user_pin=cfg.get("pin"))
    except Exception as e:  # noqa: BLE001 — bad PIN etc.; never echo the PIN
        raise RemoteSignerError(f"signeur PKCS#11 : ouverture de session refusée ({type(e).__name__})") from None


def _find_keypair(p11, session, cfg):
    """Locate the private + public key objects by label and/or id. Fail-closed on missing/ambiguous."""
    kw = {}
    if cfg.get("key_label"):
        kw["label"] = str(cfg["key_label"])
    kid = _as_id_bytes(cfg.get("key_id"))
    if kid is not None:
        kw["id"] = kid
    if not kw:
        raise RemoteSignerError("signeur PKCS#11 : key_label ou key_id requis pour localiser la clé")
    try:
        priv = session.get_key(object_class=p11.ObjectClass.PRIVATE_KEY, **kw)
        pub = session.get_key(object_class=p11.ObjectClass.PUBLIC_KEY, **kw)
    except Exception as e:  # noqa: BLE001 — NoSuchKey / MultipleObjectsReturned / provider errors
        raise RemoteSignerError(f"signeur PKCS#11 : clé introuvable/ambiguë sur le token ({type(e).__name__})") from None
    return priv, pub


def build_pkcs11_signer(config=None, env=None):
    """Build a `Pkcs11Signer` from config/ENV. Opens the token, reads the PUBLIC key, and binds a
    `CKM_EDDSA` sign closure. A BUILD-TIME self-test signature (re-verified against the public key)
    proves the key pair is correct before the signer is returned — fail fast, fail-closed. Requires
    `python-pkcs11` (lazy import) and the provider module path. Raises RemoteSignerError on any misconfig."""
    p11 = _import_pkcs11()
    cfg = resolve_pkcs11_config(config, env)
    if not cfg.get("module"):
        raise RemoteSignerError(
            "signeur PKCS#11 : chemin du module provider requis (FORGE_LEDGER_PKCS11_MODULE, ex: libsofthsm2.so)"
        )
    session = _open_session(p11, cfg)
    priv, pub = _find_keypair(p11, session, cfg)
    pubkey_hex = _ed25519_pub_hex_from_ec_point(pub[p11.Attribute.EC_POINT])
    mech = p11.Mechanism.EDDSA

    def _sign(data: bytes) -> str:
        try:
            sig = priv.sign(data, mechanism=mech)
        except Exception as e:  # noqa: BLE001 — token op failure → fail-closed, secret-free
            raise RemoteSignerError(f"signeur PKCS#11 : échec de signature sur le token ({type(e).__name__})") from None
        if isinstance(sig, (bytes, bytearray)):
            return bytes(sig).hex()
        if isinstance(sig, str):
            return sig
        raise RemoteSignerError("signeur PKCS#11 : signature de type inattendu (bytes attendus)")

    signer = Pkcs11Signer(_sign, pubkey_hex)
    signer.sign(_SELFTEST)   # build-time proof: raises if the token key pair does not verify (fail-closed)
    return signer

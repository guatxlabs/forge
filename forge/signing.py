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
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

from . import portability

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

    @property
    def pubkey_hex(self):
        """Clé publique Ed25519 BRUTE (hex, 64 chars) — sans le préfixe `ed25519:` de public_id().
        C'est exactement ce qu'attend `verify_external`/`ledger verify --pubkey` (non-répudiation)."""
        return self._pub_hex


class LocalFileSigner(Ed25519Signer):
    """COMMUNITY DEFAULT ledger signer — the local Ed25519 private key ON DISK (`<base>.ed25519`, 0600).

    Behaviour is BYTE-IDENTICAL to today's `Ed25519Signer` over the same key (Ed25519 signatures are
    deterministic): this subclass merely NAMES the "private key lives in a local file" case so the pluggable
    factory (`make_ledger_signer`) can choose between it and a `RemoteSigner`. The private key is read into
    this process, exactly as before — no new exposure. Enterprise deployments that must keep the key off-host
    swap this for `RemoteSigner`; the verify path is identical (public key only)."""

    @classmethod
    def from_base_path(cls, base_path) -> "LocalFileSigner":
        """Load (or lazily create, 0600) the on-disk key `<base>.ed25519` — the DEFAULT community path.
        Identical key material to `make_signer`, so signatures are byte-for-byte the same."""
        if not _HAVE_ED:
            raise RuntimeError("cryptography absent — LocalFileSigner (Ed25519) indisponible (repli HMAC uniquement)")
        return cls(_load_or_make_ed25519_priv(base_path))


# Env var redirecting the ledger signing key OFF the (in HA, SHARED RWX) ledger volume — see `ledger_key_path`.
LEDGER_KEY_PATH_ENV = "FORGE_LEDGER_KEY"


class LedgerKeyProtectionError(RuntimeError):
    """FAIL-CLOSED: the ledger's PRIVATE key / secret file could not be created with owner-only (0600)
    permissions ATOMICALLY (no readable window). A signer that cannot protect its private key MUST NOT
    proceed — rather than leave key material at the process umask (0644/0664 → group/world-readable),
    creation aborts and no key is left behind. Raised only for private-key material on POSIX; see
    `_atomic_write_secret` for the documented non-POSIX (Windows) degradation."""


def ledger_key_path(base_path) -> Path:
    """Resolve the on-disk path of the ledger's Ed25519 PRIVATE key.

    Default (back-compat): the `<base>.ed25519` sibling of the ledger. If `FORGE_LEDGER_KEY` is set
    (non-empty) the key lives at THAT path instead — letting ops mount it on a per-pod / read-only
    k8s-Secret path OFF the shared RWX ledger volume (HA). UNSET ⇒ byte-identical to previous behaviour."""
    env = os.environ.get(LEDGER_KEY_PATH_ENV)
    if env:
        return Path(env)
    return Path(str(base_path) + ".ed25519")


def _atomic_write_secret(path: Path, data: bytes, *, replace: bool = False) -> None:
    """Write PRIVATE-key / secret `data` to `path` so the file NEVER exists at a mode wider than 0600
    (no readable window) — FAIL-CLOSED if that cannot be guaranteed.

    POSIX: the file is born owner-only. First creation uses `os.open(..., O_WRONLY|O_CREAT|O_EXCL, 0o600)`
    (the inode is created already restricted — never observable at the umask 0644/0664); an explicit
    rotation (`replace=True`) writes a fresh 0600 temp in the SAME dir then `os.replace()` (atomic swap,
    still never a wider window). `os.fchmod(fd, 0o600)` then forces exactly 0600 regardless of umask.
    If the secure create / chmod / write fails, `LedgerKeyProtectionError` is raised and no key is left
    behind (any partial file is unlinked) — we NEVER fall back to a umask-perms key. NON-POSIX (Windows):
    POSIX modes are not expressible, so we write then best-effort restrict and accept the DOCUMENTED
    caveat that a hard 0600 guarantee is unavailable on that platform (see docs/KEY_CUSTODY.md)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not portability.is_posix():
        # Non-POSIX: no owner-only mode. Best-effort + documented caveat (never silently claim 0600).
        path.write_bytes(data)
        portability.restrict_file_permissions(path)
        return
    if replace:
        # explicit rotation: atomic overwrite via a 0600 temp in the SAME directory + os.replace
        fd, tmp = tempfile.mkstemp(prefix=".ed25519-", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, str(path))
        except OSError as e:
            try:
                os.close(fd)          # no-op if fdopen already took/closed it
            except OSError:
                pass
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise LedgerKeyProtectionError(
                f"rotation de la clé du ledger impossible en 0600 atomique ({type(e).__name__})"
            ) from e
        return
    # first creation: O_EXCL guarantees WE create it at 0600 (fail-closed if it raced into existence)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as e:
        raise LedgerKeyProtectionError(
            f"création de la clé du ledger impossible en 0600 atomique ({type(e).__name__})"
        ) from e
    try:
        os.fchmod(fd, 0o600)          # force exactly 0600 regardless of umask (belt-and-suspenders)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except OSError as e:
        try:
            os.close(fd)              # no-op if fdopen already took/closed it
        except OSError:
            pass
        try:
            os.unlink(str(path))      # never leave a key at umask perms — fail-closed
        except OSError:
            pass
        raise LedgerKeyProtectionError(
            f"écriture sécurisée de la clé du ledger impossible ({type(e).__name__})"
        ) from e


def _load_or_make_ed25519_priv(base_path):
    """Load the on-disk Ed25519 private key (`<base>.ed25519`, or `FORGE_LEDGER_KEY` if set), creating a
    fresh one on first use. Single source of truth for the COMMUNITY default ledger key — shared by
    `make_signer` and `LocalFileSigner.from_base_path` so both are provably byte-identical.

    A PRE-EXISTING key is READ ONLY — never rewritten or chmod'd — so an operator-provisioned key on a
    READ-ONLY mount (k8s Secret) works and is never clobbered. A fresh key is created ATOMICALLY at 0600
    (no readable window) and FAIL-CLOSED (raises `LedgerKeyProtectionError` rather than leave it readable)."""
    kp = ledger_key_path(base_path)
    if kp.exists():
        return Ed25519PrivateKey.from_private_bytes(kp.read_bytes())   # READ ONLY — never rewrite a provisioned key
    priv = Ed25519PrivateKey.generate()
    _atomic_write_secret(kp, priv.private_bytes_raw())
    return priv


def _load_or_make_secret(path) -> bytes:
    """HMAC fallback secret (pure-stdlib, `cryptography` absent). `FORGE_LEDGER_KEY`, if set, redirects
    the key file to THAT path (same as the Ed25519 case) instead of `path` (`<base>.key`). A pre-existing
    file is READ ONLY; a fresh secret is created ATOMICALLY at 0600, fail-closed."""
    env = os.environ.get(LEDGER_KEY_PATH_ENV)
    kp = Path(env) if env else Path(path)
    if kp.exists():
        return kp.read_bytes()
    key = secrets.token_bytes(32)
    _atomic_write_secret(kp, key)
    return key


def make_signer(base_path, prefer_ed25519=True) -> Signer:
    """Ed25519 si dispo + souhaité (clé privée dans <base>.ed25519, 0600), sinon HMAC (<base>.key).
    Retourne un `LocalFileSigner` (sous-classe d'`Ed25519Signer` — comportement identique) pour le cas
    ed25519. C'est le signeur LOCAL par défaut (communauté) ; pour le seam distant voir `make_ledger_signer`."""
    base = str(base_path)
    if prefer_ed25519 and _HAVE_ED:
        return LocalFileSigner(_load_or_make_ed25519_priv(base))
    return HmacSigner(_load_or_make_secret(base + ".key"))


def generate_ed25519_keypair(base_path) -> "Ed25519Signer":
    """Crée (ou ROTATIONNE si déjà présente) DÉLIBÉRÉMENT une clé privée Ed25519 dans `<base>.ed25519`
    (ou `FORGE_LEDGER_KEY` si défini), écrite ATOMIQUEMENT en 0600 (jamais de fenêtre lisible),
    fail-closed, et retourne le signeur. À l'inverse de `make_signer` (auto-gen paresseux au premier
    usage), c'est une action opérateur EXPLICITE. Lève `RuntimeError` si `cryptography` est absent
    (pas d'asymétrique disponible → seul le repli HMAC existe)."""
    if not _HAVE_ED:
        raise RuntimeError("cryptography absent — Ed25519 indisponible (repli HMAC uniquement)")
    kp = ledger_key_path(base_path)
    priv = Ed25519PrivateKey.generate()
    # explicit operator rotation → atomic 0600 overwrite (never a readable window), fail-closed
    _atomic_write_secret(kp, priv.private_bytes_raw(), replace=True)
    return Ed25519Signer(priv)


def signer_pubkey_hex(signer):
    """Clé publique Ed25519 BRUTE (hex, 64 chars) d'un signeur, ou None si l'algo n'est pas
    asymétrique (repli HMAC = pas de clé publique de non-répudiation). Sert `ledger pubkey`."""
    return getattr(signer, "pubkey_hex", None)


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


# =====================================================================================================
# ENTERPRISE (E3 COMPLIANCE) — PLUGGABLE LEDGER SIGNER: private key OFF-HOST (KMS/HSM/remote/exec).
# -----------------------------------------------------------------------------------------------------
# SEPARABLE + FLAG-GATED: the COMMUNITY default is LOCAL (`make_signer` / LocalFileSigner) and is
# BYTE-IDENTICAL — none of the below runs unless an operator explicitly selects a remote signer via
# config/env AND the enterprise flag `FORGE_ENTERPRISE_COMPLIANCE` is engaged. VERIFY is UNCHANGED:
# a RemoteSigner emits a STANDARD Ed25519 signature over the SAME bytes, so `verify` / `verify_external`
# / `verify_with_pubkey` accept it with the PUBLIC KEY ALONE — no code path in the verifier changes.
# FAIL-CLOSED: an unreachable/misconfigured remote signer RAISES; Forge NEVER falls back to an insecure
# or unsigned entry. SECRETS: the endpoint/credential/argv are redacted — never logged/ledgered/leaked.
# =====================================================================================================

# Enterprise engagement flag — MUST match console/src/compliance.rs::enabled (env source).
ENTERPRISE_COMPLIANCE_FLAG = "FORGE_ENTERPRISE_COMPLIANCE"
# Config/env keys for selecting + configuring the ledger signer.
LEDGER_SIGNER_ENV = "FORGE_LEDGER_SIGNER"                      # local | kms | hsm | http | remote | exec | pkcs11
_SIGNER_ENDPOINT_ENV = "FORGE_LEDGER_SIGNER_ENDPOINT"
_SIGNER_CREDENTIAL_ENV = "FORGE_LEDGER_SIGNER_CREDENTIAL"
_SIGNER_PUBKEY_ENV = "FORGE_LEDGER_SIGNER_PUBKEY"
_SIGNER_ARGV_ENV = "FORGE_LEDGER_SIGNER_ARGV"
_SIGNER_TIMEOUT_ENV = "FORGE_LEDGER_SIGNER_TIMEOUT"

# Config keys treated as SECRET (never surface their value) — endpoint/argv can embed creds too.
_SIGNER_SECRET_KEYS = frozenset({
    "endpoint", "url", "credential", "token", "secret", "password", "api_key", "apikey",
    "authorization", "auth", "argv", "command", "pin",
})
# Config keys safe to surface in a redacted view (all NON-secret; `pubkey` is a PUBLIC key).
_SIGNER_PUBLIC_KEYS = frozenset({"mode", "alg", "pubkey", "pubkey_hex", "public_key", "timeout"})


class RemoteSignerError(RuntimeError):
    """The remote ledger signer (KMS/HSM/remote endpoint or no-shell exec helper) is unreachable, refused,
    or returned an invalid/non-verifying response. Raised FAIL-CLOSED: the caller must abort the append —
    Forge NEVER writes an unsigned or insecure entry, and NEVER silently falls back to a local key.
    Messages are kept SECRET-FREE (no endpoint/credential/argv) so a raised error is safe to log."""


def _is_hex(s) -> bool:
    if not isinstance(s, str) or s == "" or len(s) % 2 != 0:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _env_truthy(env, key) -> bool:
    v = env.get(key)
    return isinstance(v, str) and v.strip().lower() in ("1", "true", "on", "yes")


def enterprise_signer_enabled(env=None) -> bool:
    """Is the enterprise compliance flag engaged (env only)? Mirrors the Rust `env_truthy` check. When
    False, `make_ledger_signer` refuses any remote signer request (community stays local, byte-identical)."""
    return _env_truthy(os.environ if env is None else env, ENTERPRISE_COMPLIANCE_FLAG)


def _parse_argv(raw):
    """Parse a NO-SHELL argv for the exec signer. MUST be a JSON array of strings (or an already-parsed
    list) — a raw shell STRING is rejected so no shell metacharacters are ever interpreted (fixed argv,
    admin-configured). Returns list[str]; raises RemoteSignerError on anything else."""
    if isinstance(raw, (list, tuple)):
        argv = list(raw)
    elif isinstance(raw, str):
        try:
            argv = json.loads(raw)
        except ValueError:
            raise RemoteSignerError(
                "argv du signeur exec doit être un tableau JSON (no-shell) — une chaîne shell est refusée"
            ) from None
    else:
        raise RemoteSignerError("argv du signeur exec manquant")
    if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
        raise RemoteSignerError("argv du signeur exec invalide (liste de chaînes non vide requise)")
    return argv


def redact_signer_config(config) -> dict:
    """Return a LOG/LEDGER-SAFE view of a remote-signer config: every secret (endpoint, credential, argv,
    tokens…) replaced by `***REDACTED***`; only NON-secret fields survive (mode, alg, timeout, and the
    PUBLIC key). Use this ANY time signer config might be logged or ledgered — the raw secret never leaves."""
    if not isinstance(config, dict):
        return {}
    safe = {}
    for k, v in config.items():
        kl = str(k).lower()
        if kl in _SIGNER_PUBLIC_KEYS:
            safe[k] = v                                   # non-secret (pubkey is a PUBLIC key)
        elif v in (None, ""):
            safe[k] = v                                   # nothing to hide
        else:
            safe[k] = "***REDACTED***"                    # secret or unknown → redact (fail-safe)
    return safe


class RemoteSigner(Signer):
    """ENTERPRISE — the ledger's Ed25519 private key lives OFF-HOST (a KMS/HSM, a remote signer endpoint,
    or a no-shell exec helper). `sign(data)` delegates to a configured backend that returns a STANDARD
    Ed25519 signature over the SAME bytes; the private key NEVER lands on disk in this process.

    VERIFY IS UNCHANGED — `verify`/`public_id`/`pubkey_hex` use ONLY the public key, so an existing verifier
    (`Ledger.verify` / `Ledger.verify_external` / `verify_with_pubkey`) accepts these signatures BYTE-IDENTICAL,
    independent of who produced them. FAIL-CLOSED — if the backend is unreachable, or returns anything that
    is not a well-formed Ed25519 signature that VERIFIES against the public key, `sign()` raises
    `RemoteSignerError`; Forge aborts the append and NEVER writes an unsigned/insecure entry. The backend
    label carried for `repr` is NON-secret (never the endpoint/credential/argv)."""

    alg = "ed25519"

    def __init__(self, sign_fn, pubkey_hex, *, backend_label="remote"):
        if not callable(sign_fn):
            raise RemoteSignerError("sign_fn doit être callable (backend KMS/HSM/exec)")
        if not (isinstance(pubkey_hex, str) and len(pubkey_hex) == 64 and _is_hex(pubkey_hex)):
            raise RemoteSignerError("pubkey_hex doit être une clé publique Ed25519 brute (64 hex)")
        self._sign_fn = sign_fn
        self._pub = pubkey_hex.lower()
        self._backend = str(backend_label)               # NON-secret label only

    def sign(self, data: bytes) -> str:
        try:
            sig = self._sign_fn(data)
        except RemoteSignerError:
            raise                                        # already secret-free + typed
        except Exception as e:                           # noqa: BLE001 — any backend failure → fail-closed
            raise RemoteSignerError(f"signeur distant en échec ({type(e).__name__})") from None
        if not isinstance(sig, str):
            raise RemoteSignerError("signeur distant : signature de type invalide")
        sig = sig.strip().lower()
        if len(sig) != 128 or not _is_hex(sig):
            raise RemoteSignerError("signeur distant : signature Ed25519 mal formée (128 hex attendus)")
        # DEFENSE-IN-DEPTH / fail-closed: accept ONLY a signature that verifies against the PUBLIC key.
        # Guarantees the emitted signature is a STANDARD Ed25519 signature an external verifier will accept,
        # and refuses a bogus/empty response rather than writing an unverifiable ledger entry.
        if not verify_with_pubkey(self._pub, data, sig):
            raise RemoteSignerError("signeur distant : signature ne vérifie pas contre la clé publique (rejetée)")
        return sig

    def verify(self, data: bytes, sig_hex: str) -> bool:
        return verify_with_pubkey(self._pub, data, sig_hex)

    def public_id(self):
        return "ed25519:" + self._pub

    @property
    def pubkey_hex(self):
        return self._pub

    def __repr__(self):
        return f"RemoteSigner(alg=ed25519, pub={self._pub[:8]}…, backend={self._backend})"

    __str__ = __repr__


def _http_sign_fn(endpoint, credential, timeout):
    """Build a sign closure for an HTTP(S) KMS/HSM / remote-signer endpoint (stdlib urllib — no external
    dep). Contract: POST JSON `{"alg":"ed25519","data_hex":<hex>}` (Bearer credential if set) → JSON with a
    hex signature under `signature_hex` | `signature` | `sig`. Errors are SECRET-FREE (never the URL/token)."""
    endpoint = str(endpoint)

    def _sign(data: bytes) -> str:
        import urllib.request  # lazy — keeps the community import surface unchanged
        body = json.dumps({"alg": "ed25519", "data_hex": data.hex()}).encode("utf-8")
        req = urllib.request.Request(endpoint, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        if credential:
            req.add_header("Authorization", "Bearer " + str(credential))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — admin-configured endpoint
                raw = resp.read()
        except Exception as e:  # noqa: BLE001 — never leak endpoint/credential (from None drops the cause chain)
            raise RemoteSignerError(f"signeur distant injoignable ({type(e).__name__})") from None
        try:
            obj = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise RemoteSignerError("réponse du signeur distant illisible (JSON attendu)") from None
        sig = obj.get("signature_hex") or obj.get("signature") or obj.get("sig") if isinstance(obj, dict) else None
        if not isinstance(sig, str):
            raise RemoteSignerError("réponse du signeur distant sans signature")
        return sig

    return _sign


def _exec_sign_fn(argv, timeout):
    """Build a sign closure for a NO-SHELL exec helper (fixed, admin-configured argv). The raw bytes to sign
    are piped on STDIN; the helper writes the hex Ed25519 signature to STDOUT. `shell=False` always — no shell
    metacharacters are ever interpreted. Errors are SECRET-FREE (no argv/stderr contents)."""
    argv = list(argv)

    def _sign(data: bytes) -> str:
        try:
            proc = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, shell=False)  # noqa: S603
        except FileNotFoundError:
            raise RemoteSignerError("signeur exec introuvable") from None
        except subprocess.TimeoutExpired:
            raise RemoteSignerError("signeur exec : délai dépassé") from None
        except Exception as e:  # noqa: BLE001
            raise RemoteSignerError(f"signeur exec en échec ({type(e).__name__})") from None
        if proc.returncode != 0:
            raise RemoteSignerError(f"signeur exec : code de sortie {proc.returncode}")
        return proc.stdout.decode("utf-8", "replace").strip()

    return _sign


def build_remote_signer(config) -> "RemoteSigner":
    """Construct a RemoteSigner from a resolved config dict (NOT flag-gated — that is done by
    `make_ledger_signer`). REQUIRES the PUBLIC key (verification uses the public key only). Building is LAZY:
    no network/exec call happens here — the backend is only contacted on `sign()`. Raises RemoteSignerError
    on missing/invalid config. Secrets in `config` are never logged (see `redact_signer_config`)."""
    if not _HAVE_ED:
        raise RemoteSignerError("signeur distant indisponible : 'cryptography' absent (Ed25519 requis)")
    pub = config.get("pubkey") or config.get("pubkey_hex") or config.get("public_key")
    if not (isinstance(pub, str) and len(pub) == 64 and _is_hex(pub)):
        raise RemoteSignerError("clé publique Ed25519 (64 hex) requise pour le signeur distant (verify sans secret)")
    mode = str(config.get("mode", "")).lower()
    try:
        timeout = float(config.get("timeout") or 10)
    except (TypeError, ValueError):
        timeout = 10.0
    if mode in ("exec", "command"):
        sign_fn = _exec_sign_fn(_parse_argv(config.get("argv") or config.get("command")), timeout)
        label = "exec(no-shell)"
    elif mode in ("kms", "hsm", "http", "https", "remote"):
        endpoint = config.get("endpoint") or config.get("url")
        if not (isinstance(endpoint, str) and endpoint.lower().startswith(("http://", "https://"))):
            raise RemoteSignerError("endpoint http(s) requis pour le signeur distant KMS/HSM")
        sign_fn = _http_sign_fn(endpoint, config.get("credential"), timeout)
        label = f"{mode}(endpoint redacted)"
    else:
        raise RemoteSignerError(f"mode de signeur distant inconnu : {mode!r}")
    return RemoteSigner(sign_fn, pub.lower(), backend_label=label)


def _resolve_signer_config(config, env):
    """Resolve the effective signer config: an explicit `config` dict wins; else read it from `env`
    (FORGE_LEDGER_SIGNER + FORGE_LEDGER_SIGNER_*). Default mode = 'local'. No secret is logged."""
    if config is not None:
        cfg = dict(config)
        cfg.setdefault("mode", "local")
        return cfg
    mode = (env.get(LEDGER_SIGNER_ENV) or "local").strip().lower()
    if mode in ("", "local", "file", "localfile"):
        return {"mode": "local"}
    cfg = {"mode": mode}
    pub = env.get(_SIGNER_PUBKEY_ENV)
    if pub:
        cfg["pubkey"] = pub.strip()
    to = env.get(_SIGNER_TIMEOUT_ENV)
    if to:
        try:
            cfg["timeout"] = float(to)
        except ValueError:
            pass
    if mode in ("exec", "command"):
        cfg["argv"] = env.get(_SIGNER_ARGV_ENV)
    elif mode == "pkcs11":
        pass  # PKCS#11 params live in dedicated FORGE_LEDGER_PKCS11_* env, read by signing_pkcs11 (lazy)
    else:
        ep = env.get(_SIGNER_ENDPOINT_ENV)
        if ep:
            cfg["endpoint"] = ep.strip()
        cred = env.get(_SIGNER_CREDENTIAL_ENV)
        if cred:
            cfg["credential"] = cred
    return cfg


def make_ledger_signer(base_path, prefer_ed25519=True, config=None, env=None) -> Signer:
    """PLUGGABLE ledger-signer factory — the seam that lets the Ed25519 private key live in a KMS/HSM/remote
    signer WITHOUT changing verify.

    DEFAULT (community): mode 'local' → `LocalFileSigner` (the on-disk `<base>.ed25519` key), BYTE-IDENTICAL
    to `make_signer`. This is what runs when nothing is configured — the community build is unchanged.

    ENTERPRISE: mode 'kms'/'hsm'/'http'/'remote'/'exec'/'pkcs11' → a `RemoteSigner` (a `Pkcs11Signer` for
    'pkcs11'), selected by `config` (a settings dict) or by env (`FORGE_LEDGER_SIGNER` + `FORGE_LEDGER_SIGNER_*`
    / `FORGE_LEDGER_PKCS11_*`). Gated by the enterprise flag `FORGE_ENTERPRISE_COMPLIANCE`. The 'pkcs11' driver
    (Ed25519/CKM_EDDSA, off-host key custody) is LAZY: `python-pkcs11` is only imported when it is selected.

    FAIL-CLOSED: a remote signer requested WITHOUT the enterprise flag is REFUSED (RemoteSignerError) — Forge
    never silently downgrades a remote-signer intent to the local key. The refusal message carries NO secret."""
    env = os.environ if env is None else env
    cfg = _resolve_signer_config(config, env)
    mode = str(cfg.get("mode", "local")).lower()
    if mode in ("local", "file", "localfile"):
        if prefer_ed25519 and _HAVE_ED:
            return LocalFileSigner(_load_or_make_ed25519_priv(base_path))
        return HmacSigner(_load_or_make_secret(str(base_path) + ".key"))
    # --- enterprise remote signer (flag-gated) ---
    if not enterprise_signer_enabled(env):
        raise RemoteSignerError(
            "signeur distant (KMS/HSM/exec/pkcs11) demandé mais l'entreprise COMPLIANCE n'est pas activée "
            f"({ENTERPRISE_COMPLIANCE_FLAG}=1) — repli LOCAL refusé (fail-closed, open-core)"
        )
    if mode == "pkcs11":
        from . import signing_pkcs11   # LAZY: python-pkcs11 only imported when the operator selects pkcs11
        return signing_pkcs11.build_pkcs11_signer(cfg, env=env)
    return build_remote_signer(cfg)

# SPDX-License-Identifier: AGPL-3.0-or-later
"""ENTERPRISE (E3 COMPLIANCE) — pluggable checkpoint signer + WORM/retention decision (SEPARABLE, INERT).

Open-core discipline: this is an ENTERPRISE seam. It is INERT unless a compliance flow calls it — merely
importing it changes NOTHING in the community engine (no side effects, no global state, no ledger hook).
It sits ON TOP of `forge.signing` (Ed25519, asymmetric → non-repudiation) and adds NOTHING to the ledger
VERIFY path: checkpoint verification delegates verbatim to `signing.verify_with_pubkey`, so verification
stays BYTE-IDENTICAL whether the signature was produced by the local key or a KMS/HSM.

Why it exists — a governed WORM purge (`console.compliance.purge`) archives an expired ledger segment and
must record a SIGNED CHECKPOINT of WHAT was archived+purged (counts, segment hash, time, actor) so the audit
trail of the purge itself is tamper-evident and verifiable with the PUBLIC KEY ONLY (a third party confirms
the purge without any secret). This module produces & verifies that checkpoint signature.

PLUGGABLE (KMS/HSM-ready) — the DEFAULT signer wraps the local Ed25519 key (`forge.signing`), but ANY object
exposing `sign(bytes) -> hex` + a `pubkey_hex` (raw 32-byte Ed25519 public key, hex) can be dropped in
(`CallableComplianceSigner`) — e.g. a KMS/HSM that holds the private key off-host. The verifier only ever
needs the PUBLIC key, so a KMS signature and a local signature verify through the SAME one code path.

FAIL-CLOSED — a compliance checkpoint REQUIRES asymmetric non-repudiation: `default_signer()` refuses (raises)
if Ed25519 is unavailable (HMAC fallback is symmetric → forgeable by the key holder → not admissible here).
`worm_purge_allowed(...)` is the WORM gate: LEGAL-HOLD ALWAYS WINS (a held record is never purgeable, even
past retention); an unset/zero retention never purges (fail-closed). Pure — no I/O.
"""
import hashlib
import json

from . import signing


# --- canonical pre-image: same shape as forge.ledger._canon (sort_keys, compact, ensure_ascii=False) ---
def canonical_payload(payload: dict) -> bytes:
    """Canonical JSON bytes of a checkpoint payload — the exact pre-image that is signed AND verified.
    Deterministic (sorted keys, no whitespace) so an independent verifier reconstructs the identical bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def payload_sha256(payload: dict) -> str:
    """Hex SHA-256 of the canonical payload — recorded in the checkpoint so a verifier can confirm the
    pre-image it re-canonicalises matches the one that was signed (defence-in-depth over the signature)."""
    return hashlib.sha256(canonical_payload(payload)).hexdigest()


class ComplianceSigner:
    """Abstract pluggable signer. Concrete signers implement `sign(bytes) -> hex` and expose `pubkey_hex`
    (raw Ed25519 public key, 64 hex chars). `alg` is always 'ed25519' — the checkpoint is asymmetric so a
    third party verifies with the public key alone (non-repudiation)."""

    alg = "ed25519"

    def sign(self, data: bytes) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    @property
    def pubkey_hex(self) -> str:  # pragma: no cover - abstract
        raise NotImplementedError


class Ed25519ComplianceSigner(ComplianceSigner):
    """Default signer — wraps a `signing.Ed25519Signer` (the local private key in `<ledger>.ed25519`, 0600,
    or an in-memory ephemeral key). The private key never leaves this process."""

    def __init__(self, ed_signer):
        if getattr(ed_signer, "alg", None) != "ed25519":
            raise RuntimeError("Ed25519ComplianceSigner exige un signeur ed25519 (asymétrique)")
        self._signer = ed_signer

    def sign(self, data: bytes) -> str:
        return self._signer.sign(data)

    @property
    def pubkey_hex(self) -> str:
        return self._signer.pubkey_hex


class CallableComplianceSigner(ComplianceSigner):
    """KMS/HSM SEAM — wraps an arbitrary `sign_fn(bytes) -> hex` plus the corresponding `pubkey_hex`. The
    private key lives WHEREVER the callable delegates (KMS, HSM, remote signer); Forge only ever sees the
    signature + the public key. Proves the abstraction is pluggable WITHOUT weakening verify (the signature
    it produces MUST be an Ed25519 signature over the canonical pre-image, verifiable by `pubkey_hex`)."""

    def __init__(self, sign_fn, pubkey_hex: str):
        if not callable(sign_fn):
            raise RuntimeError("sign_fn doit être callable (seam KMS/HSM)")
        if not isinstance(pubkey_hex, str) or len(pubkey_hex) != 64:
            raise RuntimeError("pubkey_hex doit être une clé publique Ed25519 brute (64 hex)")
        self._sign_fn = sign_fn
        self._pub = pubkey_hex

    def sign(self, data: bytes) -> str:
        return self._sign_fn(data)

    @property
    def pubkey_hex(self) -> str:
        return self._pub


def default_signer(base_path=None) -> ComplianceSigner:
    """The DEFAULT local Ed25519 compliance signer. `base_path` (a ledger path) selects the on-disk key
    (`<base>.ed25519`, auto-created 0600 on first use) — matching `signing.make_signer`. When `base_path`
    is None an EPHEMERAL in-memory key is used (tests / stateless signing).

    FAIL-CLOSED: raises RuntimeError if Ed25519 is unavailable (only the symmetric HMAC fallback exists),
    because a compliance checkpoint must be NON-REPUDIABLE — a symmetric signature would be forgeable by
    anyone holding the shared key and is inadmissible as a purge attestation."""
    ed = signing.make_signer(base_path, prefer_ed25519=True) if base_path is not None else signing.ephemeral_signer()
    if getattr(ed, "alg", None) != "ed25519":
        raise RuntimeError(
            "checkpoint de conformité indisponible : Ed25519 absent (repli HMAC symétrique = non recevable, "
            "installez `cryptography` pour la non-répudiation)"
        )
    return Ed25519ComplianceSigner(ed)


def sign_checkpoint(payload: dict, signer: ComplianceSigner) -> dict:
    """Sign a checkpoint payload → an embeddable record `{alg, pub, sig, payload_sha256}`.

    `pub`/`sig` are the Ed25519 public key + signature over `canonical_payload(payload)`; `payload_sha256`
    pins the exact pre-image. The record is safe to store IN the ledger entry `detail` (it carries no secret,
    only the public key + signature) and is verifiable by anyone via `verify_checkpoint`."""
    data = canonical_payload(payload)
    return {
        "alg": signer.alg,
        "pub": signer.pubkey_hex,
        "sig": signer.sign(data),
        "payload_sha256": hashlib.sha256(data).hexdigest(),
    }


def verify_checkpoint(payload: dict, record: dict, pubkey_hex: str = None) -> bool:
    """Verify a checkpoint signature with the PUBLIC KEY ONLY (non-repudiation, no secret). Recomputes the
    canonical pre-image from `payload`, confirms it matches the pinned `payload_sha256`, then delegates the
    signature check verbatim to `signing.verify_with_pubkey` — so verification is BYTE-IDENTICAL to the
    ledger's `verify_external`, independent of how the signature was produced (local key or KMS/HSM).

    `pubkey_hex` overrides the key trusted for verification (pin the auditor's known key); default = the key
    embedded in `record["pub"]`. Any tamper (payload, sig, or pub) → False. Fail-closed on malformed input."""
    if not isinstance(record, dict):
        return False
    if record.get("alg") != "ed25519":
        return False  # only asymmetric checkpoints are externally verifiable (fail-closed)
    data = canonical_payload(payload)
    # defence-in-depth: the recorded pre-image hash must match what we re-canonicalise (catches a swapped payload
    # even before the signature check). Absent/mismatched → reject.
    if record.get("payload_sha256") != hashlib.sha256(data).hexdigest():
        return False
    pub = pubkey_hex if pubkey_hex is not None else record.get("pub")
    sig = record.get("sig")
    if not isinstance(pub, str) or not isinstance(sig, str):
        return False
    return signing.verify_with_pubkey(pub, data, sig)


# --- WORM / retention decision (pure, fail-closed) — HOLD ALWAYS WINS ---
def worm_purge_allowed(retention_secs, record_age_secs: int, legal_hold: bool) -> bool:
    """WORM gate for a single record: may it be purged NOW?

    RULES (fail-closed, HOLD ALWAYS WINS):
      1. `legal_hold` True  → NEVER purgeable (a held record survives regardless of retention).
      2. `retention_secs` unset / <= 0 → NEVER purgeable (no policy configured = keep forever).
      3. else purgeable IFF the record is OLDER than the retention window (`record_age_secs >= retention_secs`).

    Removing rule 1 (the hold check) makes a held-but-expired record purgeable — which the tests assert must
    NOT happen (the mutation flips a test RED). Pure — no I/O, no clock (age is passed in)."""
    if legal_hold:
        return False  # LEGAL-HOLD ALWAYS WINS — do not remove: purge fail-closed depends on this line
    if not isinstance(retention_secs, int) or retention_secs <= 0:
        return False  # no retention policy => never purge (fail-closed)
    return record_age_secs >= retention_secs

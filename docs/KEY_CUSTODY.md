<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Key custody — off-host ledger signing (PKCS#11 / KMS / HSM)

Forge's engagement ledger is signed with **Ed25519** (asymmetric → non-repudiation: a third party
verifies with the **public key alone**). By default the private key lives on the host in
`<ledger>.ed25519` (0600) — the community `LocalFileSigner`. That is byte-identical, zero-dependency,
and stdlib-only, but it leaves one **residual (audit finding F4)**: an attacker who gets **root on the
host** can read the key and rewrite + re-sign history so a local `verify` still passes.

This document explains how to move the private key **off-host** so host-root can no longer forge the
ledger, and — combined with a witness anchor — how that closes F4.

---

## Why PKCS#11 (and not AWS-KMS directly)

The ledger is **Ed25519**. That constrains the backend:

| Backend | Ed25519? | How Forge reaches it |
|---|---|---|
| **AWS KMS** | ❌ RSA / ECDSA only — *cannot* sign Ed25519 | not usable directly for this ledger |
| **PKCS#11 (`CKM_EDDSA`)** | ✅ | `FORGE_LEDGER_SIGNER=pkcs11` (this driver) |
| **GCP KMS** (`ED25519` keys) | ✅ | generic **exec signer** (`gcloud kms asymmetric-sign`) |
| **Any HSM / AWS CloudHSM** | ✅ (expose a PKCS#11 provider) | `FORGE_LEDGER_SIGNER=pkcs11` |
| **SoftHSM2** (dev/CI) | ✅ | `FORGE_LEDGER_SIGNER=pkcs11` |

So **AWS-KMS cannot drive this ledger** without changing the ledger algorithm to RSA/ECDSA (which we
deliberately do not — Ed25519 gives us small, deterministic, fast signatures and clean non-repudiation).
**PKCS#11** is the vendor-neutral path: SoftHSM2 in dev/CI, any HSM (including AWS CloudHSM, which
exposes a PKCS#11 library) or a cloud-KMS→PKCS#11 bridge in prod. It is a thin FFI, so Forge stays
**openssl-free** and the default engine keeps **zero runtime dependencies** — nothing new is imported
unless you explicitly turn the PKCS#11 signer on.

---

## The PKCS#11 signer — how it plugs in

`forge/signing_pkcs11.py` adds `Pkcs11Signer`, a subclass of the existing `RemoteSigner`. It reuses the
**same fail-closed contract**:

- signs via the token with `CKM_EDDSA`;
- **re-verifies** the returned signature against the public key before accepting it — a bogus or
  mismatched response is **rejected**, never written;
- **never falls back** to a local key;
- exposes only the **public key** to this process, so `verify` / `verify_external(pubkey)` are unchanged
  for third-party auditors;
- a **build-time self-test** signature proves the token's key pair actually verifies before the signer is
  returned (fail fast on a wrong token/key pairing).

It is **optional and opt-in**. `python-pkcs11` is a **lazy import inside the driver** — the default
community build imports nothing new and stays stdlib-only. Install the extra only when you use it:

```bash
pip install 'forge[pkcs11]'      # pulls python-pkcs11; the default install does NOT
```

### Configuration — ENV only (PIN never on argv)

| Env var | Meaning |
|---|---|
| `FORGE_ENTERPRISE_COMPLIANCE=1` | **Required** — engages the enterprise off-host signer seam (gate) |
| `FORGE_LEDGER_SIGNER=pkcs11` | selects this driver |
| `FORGE_LEDGER_PKCS11_MODULE` | path to the PKCS#11 provider `.so` (e.g. `libsofthsm2.so`) — **required** |
| `FORGE_LEDGER_PKCS11_TOKEN_LABEL` | token label (or use `…_SLOT`) |
| `FORGE_LEDGER_PKCS11_SLOT` | slot index (alternative to token label) |
| `FORGE_LEDGER_PKCS11_KEY_LABEL` | key label (`CKA_LABEL`) — label and/or id required |
| `FORGE_LEDGER_PKCS11_KEY_ID` | key id, hex or text (`CKA_ID`) |
| `FORGE_LEDGER_PKCS11_PIN` | **user PIN — secret, env only**, never argv/logs |

The PIN and provider/token details are treated as secrets: they never appear in `repr`, logs, ledger
entries, or raised errors (`redact_signer_config` redacts `pin`).

---

## Dev / CI setup with SoftHSM2

SoftHSM2 is a software PKCS#11 token — perfect for development and CI (no hardware). Example:

```bash
# 1. install SoftHSM2 + the Python binding
sudo apt-get install -y softhsm2            # Debian/Ubuntu (provides libsofthsm2.so)
pip install 'forge[pkcs11]'

# 2. isolated token store (so CI leaves no global state)
export SOFTHSM2_CONF="$PWD/softhsm2.conf"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$PWD" > "$SOFTHSM2_CONF"
mkdir -p "$PWD/tokens"

# 3. init a token
softhsm2-util --init-token --free --label forge-test --pin 1234 --so-pin 5678

# 4. generate an Ed25519 key ON the token (pkcs11-tool from opensc, or python-pkcs11)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
    --keypairgen --key-type EC:edwards25519 --label forge-ledger

# 5. point Forge at it
export FORGE_ENTERPRISE_COMPLIANCE=1
export FORGE_LEDGER_SIGNER=pkcs11
export FORGE_LEDGER_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export FORGE_LEDGER_PKCS11_TOKEN_LABEL=forge-test
export FORGE_LEDGER_PKCS11_KEY_LABEL=forge-ledger
export FORGE_LEDGER_PKCS11_PIN=1234
```

Forge now signs every ledger entry on the token; the private key never enters the process.
`tests/test_pkcs11_signer.py::TestLiveSoftHSMRoundTrip` performs exactly this round-trip when SoftHSM2 +
`python-pkcs11` are present (it is auto-skipped otherwise).

---

## Production — HSM / AWS CloudHSM / cloud-KMS via PKCS#11

Any of these exposes a **PKCS#11 provider library**; point `FORGE_LEDGER_PKCS11_MODULE` at it and set the
token/slot, key label/id, and PIN:

- **On-prem / network HSM** (Thales Luna, Entrust nShield, Utimaco, YubiHSM2…): use the vendor's PKCS#11
  `.so`, an Ed25519 key generated non-exportable on the device.
- **AWS CloudHSM**: install the CloudHSM Client SDK, use `libcloudhsm_pkcs11.so`, PIN = `CU_user:password`.
  (Plain **AWS KMS is not usable** here — it does not offer Ed25519; see the table above.)
- **cloud-KMS via a PKCS#11 bridge**: e.g. Google Cloud's `libkmsp11.so`, or a SoftHSM/`p11-kit` proxy in
  front of a KMS that speaks Ed25519.

Store the PIN via your secret manager and inject it as `FORGE_LEDGER_PKCS11_PIN` at runtime (env, not
argv). Rotate the ledger key by generating a new token key and re-anchoring; the public key changes, so
publish the new public key to your auditors/witness.

### Escape hatch — GCP-KMS-Ed25519 / custom signers (exec signer)

If your backend signs Ed25519 but has **no PKCS#11 provider** (e.g. GCP KMS via the CLI), use the generic
**no-shell exec signer** already in `forge/signing.py` — a fixed, admin-configured argv that receives the
bytes on stdin and writes the hex Ed25519 signature to stdout:

```bash
export FORGE_ENTERPRISE_COMPLIANCE=1
export FORGE_LEDGER_SIGNER=exec
export FORGE_LEDGER_SIGNER_PUBKEY=<64-hex Ed25519 public key>
# argv is a JSON array (no shell); the helper must emit the hex signature of stdin:
export FORGE_LEDGER_SIGNER_ARGV='["/opt/forge/gcp-kms-ed25519-sign.sh","projects/…/cryptoKeyVersions/1"]'
```

The helper wraps e.g. `gcloud kms asymmetric-sign --key … --signature-file - --input-file -` (returning
the raw signature as hex). Same fail-closed re-verify applies: a signature that does not verify against
`FORGE_LEDGER_SIGNER_PUBKEY` is rejected.

---

## How this closes the F4 host-root residual

F4 says: with the key on-host and the default `NullAnchor`, a **host-root** attacker can rewrite and
re-sign history. Two opt-in controls together remove that:

1. **Off-host key custody (this driver).** With `FORGE_LEDGER_SIGNER=pkcs11` (or the exec signer to an
   off-host KMS), the private key lives on the token/HSM. Host-root can *request* signatures over new
   content but **cannot extract the key**, so it cannot silently re-sign a rewritten past on its own.
2. **Off-host witness anchor** (`forge/anchor.py` — `WitnessAnchor` + `reconcile`). A separate host holds
   a distinct key and counter-signs `(seq|head|ts)` checkpoints into its own append-only log. `reconcile`
   recomputes the ledger heads from genesis and compares them to what the witness counter-signed —
   detecting a rewritten (even re-signed) past.

**Why both are needed.** Off-host signing alone stops key *exfiltration*, but a host-root that can still
*call* the signer could re-sign a truncated/rewritten ledger going forward. The witness anchor pins the
historical heads somewhere the host cannot alter, so `reconcile` catches the rewrite. Conversely the
witness alone doesn't protect the key. Turn on **both** and forging the audit trail requires compromising
**Forge's host *and* the witness *and* the HSM** — which is what F4 asks for.

This is **opt-in by design** (open-core: the community default stays local + `NullAnchor`, byte-identical
and dependency-free). See `docs/SECURITY_AUDIT.md` §4 (F4) and `forge/anchor.py` for the threat model.

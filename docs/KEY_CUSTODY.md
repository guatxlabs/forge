<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Key custody — off-host ledger signing (PKCS#11 / KMS / HSM)

[English](KEY_CUSTODY.md) | [Français](KEY_CUSTODY.fr.md)

Forge's engagement ledger is signed with **Ed25519** (asymmetric → non-repudiation: a third party
verifies with the **public key alone**). By default, the private key lives on the host in
`<ledger>.ed25519` (0600) — the default `LocalFileSigner`. It is byte-identical, dependency-free,
and stdlib-only, but it has a **known limit**: the signing key sits on the same host as the
writer, so **root on that host** reaches the key.

This document explains how to move the private key **off-host** so that host-root can no longer
sign, and how an off-host witness anchor complements it.

---

## Why PKCS#11 (and not AWS-KMS directly)

The ledger uses **Ed25519**. This constrains the backend:

| Backend | Ed25519? | How Forge reaches it |
|---|---|---|
| **AWS KMS** | ❌ RSA / ECDSA only — *cannot* sign Ed25519 | not usable directly for this ledger |
| **PKCS#11 (`CKM_EDDSA`)** | ✅ | `FORGE_LEDGER_SIGNER=pkcs11` (this driver) |
| **GCP KMS** (`ED25519` keys) | ✅ | generic **exec signer** (`gcloud kms asymmetric-sign`) |
| **Any HSM / AWS CloudHSM** | ✅ (exposes a PKCS#11 provider) | `FORGE_LEDGER_SIGNER=pkcs11` |
| **SoftHSM2** (dev/CI) | ✅ | `FORGE_LEDGER_SIGNER=pkcs11` |

So **AWS-KMS cannot drive this ledger** without changing the ledger algorithm to RSA/ECDSA (which
we deliberately do not do — Ed25519 gives us small, deterministic, fast signatures
and clean non-repudiation). **PKCS#11** is the vendor-neutral path: SoftHSM2 in dev/CI, any
HSM (including AWS CloudHSM, which exposes a PKCS#11 library) or a cloud-KMS→PKCS#11 bridge in
production. It is a thin FFI, so Forge stays **openssl-free** and the default engine keeps **zero
runtime dependencies** — nothing new is imported until you explicitly enable the PKCS#11
signer.

---

## The PKCS#11 signer — how it plugs in

`forge/signing_pkcs11.py` adds `Pkcs11Signer`, a subclass of the existing `RemoteSigner`. It reuses
the **same fail-closed contract**:

- signs via the token with `CKM_EDDSA`;
- **re-verifies** the returned signature against the public key before accepting it — a bogus or
  inconsistent response is **rejected**, never written;
- **never falls back** to a local key;
- exposes only the **public key** to this process, so `verify` / `verify_external(pubkey)` are
  unchanged for third-party auditors;
- a **build-time self-test** signature proves that the token's key pair actually verifies before
  the signer is returned (fail fast on a token/key mismatch).

It is **optional and opt-in**. `python-pkcs11` is a **lazy import inside the driver** — the
default build imports nothing new and stays stdlib-only. Only install the extra
when you use it:

```bash
pip install 'forge[pkcs11]'      # pulls python-pkcs11; the default install does NOT
```

### Configuration — ENV only (the PIN never on argv)

| Env variable | Meaning |
|---|---|
| `FORGE_ENTERPRISE_COMPLIANCE=1` | **Required** — engages the off-host signer seam of the compliance module (gate) |
| `FORGE_LEDGER_SIGNER=pkcs11` | selects this driver |
| `FORGE_LEDGER_PKCS11_MODULE` | path to the PKCS#11 provider `.so` (e.g. `libsofthsm2.so`) — **required** |
| `FORGE_LEDGER_PKCS11_TOKEN_LABEL` | token label (or use `…_SLOT`) |
| `FORGE_LEDGER_PKCS11_SLOT` | slot index (alternative to the token label) |
| `FORGE_LEDGER_PKCS11_KEY_LABEL` | key label (`CKA_LABEL`) — label and/or id required |
| `FORGE_LEDGER_PKCS11_KEY_ID` | key id, hex or text (`CKA_ID`) |
| `FORGE_LEDGER_PKCS11_PIN` | **user PIN — secret, env only**, never argv/logs |

The PIN and the provider/token details are treated as secrets: they never appear in
`repr`, logs, ledger entries, or raised errors (`redact_signer_config` redacts `pin`).

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

Forge now signs every ledger entry on the token; the private key never enters the
process. `tests/test_pkcs11_signer.py::TestLiveSoftHSMRoundTrip` performs exactly this round-trip
when SoftHSM2 + `python-pkcs11` are present (it is auto-skipped otherwise).

---

## Production — HSM / AWS CloudHSM / cloud-KMS via PKCS#11

Each of them exposes a **PKCS#11 provider library**; point `FORGE_LEDGER_PKCS11_MODULE` at it
and fill in the token/slot, the key label/id, and the PIN:

- **On-prem / network HSM** (Thales Luna, Entrust nShield, Utimaco, YubiHSM2…): use the vendor's PKCS#11
  `.so`, with a non-exportable Ed25519 key generated on the device.
- **AWS CloudHSM**: install the CloudHSM Client SDK, use `libcloudhsm_pkcs11.so`, PIN = `CU_user:password`.
  (Bare **AWS KMS** **is not usable** here — it does not offer Ed25519; see the table above.)
- **cloud-KMS via a PKCS#11 bridge**: e.g. Google Cloud's `libkmsp11.so`, or a SoftHSM/`p11-kit` proxy
  in front of a KMS that speaks Ed25519.

Store the PIN in your secrets manager and inject it as `FORGE_LEDGER_PKCS11_PIN` at runtime
(env, not argv). Rotate the ledger key by generating a new token key and re-anchoring;
the public key changes, so publish the new public key to your auditors/witness.

### Escape hatch — GCP-KMS-Ed25519 via the generic exec signer (recommended cloud-KMS path)

If your backend signs Ed25519 but has **no PKCS#11 provider** — the canonical case is **GCP KMS
driven by the `gcloud` CLI** — use the generic **no-shell exec signer** already present in
`forge/signing.py`. It runs a **fixed, admin-configured argv** (a JSON array — never a
shell string, so no metacharacter is ever interpreted), sends the bytes-to-sign on **stdin**,
and reads back the **Ed25519 signature in hex (128 hex characters)** from **stdout**. Same fail-closed guarantee
as any off-host signer: `RemoteSigner.sign` **re-verifies** the returned signature against
`FORGE_LEDGER_SIGNER_PUBKEY` before the entry is written — a malformed or non-verifying response
is **rejected** and the append aborts (never an unsigned entry).

> **No bespoke GCP driver — by design.** Forge ships **no** GCP-KMS-specific code:
> the generic exec signer already covers GCP-KMS end to end (below). **AWS-KMS remains unsupported
> for this ledger** — it offers no Ed25519 key type (RSA/ECDSA only; see the table above).
> For AWS, put a **PKCS#11** HSM/CloudHSM in front of the ledger instead, or use GCP KMS.

**1 — create an Ed25519 signing key in GCP KMS** (algorithm `EC_SIGN_ED25519`):

```bash
gcloud kms keyrings create forge --location=global
gcloud kms keys create ledger \
  --location=global --keyring=forge \
  --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-ed25519      # EC_SIGN_ED25519 — Ed25519, matches the ledger algorithm
```

**2 — export the PUBLIC key as 64-hex** (exactly what `verify_external` / `ledger verify --pubkey` expects):

```bash
gcloud kms keys versions get-public-key 1 \
  --location=global --keyring=forge --key=ledger --output-file=ledger.pub.pem
# PEM (SubjectPublicKeyInfo) → raw 32-byte Ed25519 pubkey → hex:
python3 -c 'from cryptography.hazmat.primitives.serialization import load_pem_public_key; \
  print(load_pem_public_key(open("ledger.pub.pem","rb").read()).public_bytes_raw().hex())'
# → 64 hex chars. This is FORGE_LEDGER_SIGNER_PUBKEY — publish it to your auditors/witness.
```

**3 — the signing helper** `/opt/forge/gcp-kms-ed25519-sign.sh` — reads the bytes on stdin, calls
`gcloud kms asymmetric-sign` (which, for Ed25519, signs the **raw input**, without pre-digest), and hex-encodes
the **raw 64-byte** signature that GCP returns on stdout:

```bash
#!/usr/bin/env bash
set -euo pipefail
loc="$1"; kr="$2"; key="$3"; ver="$4"                    # passed as fixed argv elements (no shell parsing)
gcloud kms asymmetric-sign \
  --location="$loc" --keyring="$kr" --key="$key" --version="$ver" \
  --input-file=- --signature-file=- \
  | python3 -c 'import sys; sys.stdout.write(sys.stdin.buffer.read().hex())'
```

**4 — wire the exec signer** (the argv is a JSON array — the helper path plus its fixed arguments):

```bash
export FORGE_ENTERPRISE_COMPLIANCE=1
export FORGE_LEDGER_SIGNER=exec
export FORGE_LEDGER_SIGNER_PUBKEY=<64-hex from step 2>
export FORGE_LEDGER_SIGNER_ARGV='["/opt/forge/gcp-kms-ed25519-sign.sh","global","forge","ledger","1"]'
```

The private key **never leaves GCP KMS** (only `gcloud … asymmetric-sign` is invoked; no key material
on a pod volume). Rotate by creating a new key version and re-exporting
the public key (step 2) — then publish the new public key to your auditors/witness.

---

## Key custody in HA (Kubernetes) — keep the private key OFF the shared ledger volume

> **Why this matters in HA.** In HA, the tamper-evident ledger is a **file** on a **shared
> ReadWriteMany PVC** (`forge-ledger`, mounted at `/data/ledger` by every replica — see
> `k8s/40-console.yaml`). The default `LocalFileSigner` writes its **private** key next to the ledger
> as `<ledger>.ed25519` (0600). On this RWX volume, a `0600` permission bit is **not** an isolation
> boundary: **any pod or sidecar** that mounts the same PVC, and **any PVC
> snapshot/backup**, hands over the raw Ed25519 signing key — with which an attacker can
> forge arbitrary forge ledger entries. The permissions-only local key is fine for a
> single-tenant host; it is **not** fine on a shared multi-writer volume. Move the key **off**
> that volume. Two supported patterns, safest first:

### Pattern 1 (PREFERRED for HA / multi-tenant) — off-host signer, key on no pod volume

Use the **PKCS#11 signer** (`FORGE_LEDGER_SIGNER=pkcs11`, documented above) or the generic **exec signer**
towards an off-host KMS. The private key lives on an HSM/token and **never touches any pod
volume** — so neither the RWX PVC, nor a snapshot, nor a co-mounted sidecar ever sees it. This is the recommended HA
posture and also the control that removes the host-root limit described below.

k8s wiring (opt-in block in `k8s/40-console.yaml`; PIN/module via the `forge-ledger-pkcs11` Secret —
placeholder in `k8s/10-secrets.example.yaml`, EVAL-ONLY, applied explicitly):

```yaml
env:
  - name: FORGE_ENTERPRISE_COMPLIANCE
    value: "1"
  - name: FORGE_LEDGER_SIGNER
    value: pkcs11
  - name: FORGE_LEDGER_PKCS11_MODULE
    valueFrom: { secretKeyRef: { name: forge-ledger-pkcs11, key: FORGE_LEDGER_PKCS11_MODULE } }
  - name: FORGE_LEDGER_PKCS11_TOKEN_LABEL
    valueFrom: { secretKeyRef: { name: forge-ledger-pkcs11, key: FORGE_LEDGER_PKCS11_TOKEN_LABEL } }
  - name: FORGE_LEDGER_PKCS11_KEY_LABEL
    valueFrom: { secretKeyRef: { name: forge-ledger-pkcs11, key: FORGE_LEDGER_PKCS11_KEY_LABEL } }
  - name: FORGE_LEDGER_PKCS11_PIN
    valueFrom: { secretKeyRef: { name: forge-ledger-pkcs11, key: FORGE_LEDGER_PKCS11_PIN } }
```

Requires a `store-postgres` image built with the `pkcs11` extra and a PKCS#11 provider `.so`
present in the container (baked in or via a sidecar). No key Secret is created; the RWX PVC then
carries **only** the JSONL projection of the ledger.

### Pattern 2 (FALLBACK) — local signer, key in a read-only Secret NOT on the RWX PVC

If you must keep the **local** signer in HA (e.g. no HSM available), decouple the key **path** from
the ledger path with **`FORGE_LEDGER_KEY`** and provide the key as a **dedicated read-only
Secret** rather than letting it be written to `/data/ledger`:

1. **Pre-generate** the Ed25519 key out of band (do not let the pod create it automatically on the shared volume):

   ```bash
   python3 -c 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K; \
               import base64; print(base64.b64encode(K.generate().private_bytes_raw()).decode())'
   # → base64 of the raw 32-byte private key; put it in Secret forge-ledger-key, data.forge.ed25519
   ```

2. Provide it as the **`forge-ledger-key`** Secret (placeholder in `k8s/10-secrets.example.yaml`),
   mounted **read-only** at a path, and point **`FORGE_LEDGER_KEY`** at that mount (opt-in block in
   `k8s/40-console.yaml`):

   ```yaml
   env:
     - name: FORGE_LEDGER_KEY
       value: /etc/forge/ledger-key/forge.ed25519      # read-only Secret mount, NOT /data/ledger
   volumeMounts:
     - name: ledger-key
       mountPath: /etc/forge/ledger-key
       readOnly: true                                   # signer READS the key; never rewrites it
   volumes:
     - name: ledger-key
       secret:
         secretName: forge-ledger-key
         defaultMode: 0440   # owner+group read; fsGroup gives the process the GROUP, not ownership
         items: [ { key: forge.ed25519, path: forge.ed25519 } ]
   ```

`FORGE_LEDGER_KEY` makes the signer read the key **from the read-only mount** instead of writing/reading
`<ledger>.ed25519` on the RWX PVC. Since the mount is read-only and the key pre-exists, it is
**read, not rewritten** — the private key is **never** placed on the shared `forge-ledger` volume, which then
carries only `engagement.jsonl` + the high-water-mark. Rotate by replacing the Secret and
re-anchoring (publish the new public key to your auditors/witness).

**Residual for Pattern 2.** The key still lands in a k8s **Secret** (etcd) and is present
in the pod's tmpfs mount — so cluster-admin / etcd access still reaches it. Pattern 2 removes
the *shared-volume / snapshot* exposure, not the trust in the k8s secret store; for the
stronger property (key on no pod volume at all, host-root cannot exfiltrate) use
**Pattern 1**. Both keep `runAsNonRoot`, `readOnlyRootFilesystem`, and the deny-by-default
NetworkPolicies intact; the key Secret and the PKCS#11 Secret are **opt-in** (outside the default
`kubectl apply -k k8s/` path).

See `docs/DEPLOYMENT.md` §3bis.6 (HA on Kubernetes) for the surrounding topology.

## What the two modes protect against

With the on-host key and the default `NullAnchor`, ledger integrity depends on the host itself:
anyone with root on it reaches the signing key. Two opt-in controls together remove this
dependency:

1. **Off-host key custody (this driver).** With `FORGE_LEDGER_SIGNER=pkcs11` (or the exec signer towards an
   off-host KMS), the private key lives on the token/HSM. Host-root can *request* signatures on
   new content but **cannot extract the key**, so it cannot silently re-sign a
   rewritten past on its own.
2. **Off-host witness anchor** (`forge/anchor.py` — `WitnessAnchor` + `reconcile`). A separate host holds
   a distinct key and countersigns `(seq|head|ts)` checkpoints in its own append-only log.
   `reconcile` recomputes the ledger heads from genesis and compares them with what the witness
   countersigned — detecting a rewritten past (even re-signed).

**Why both are needed.** Off-host signing alone stops key *exfiltration*, but
a host-root that can still *call* the signer could re-sign a truncated/rewritten ledger going
forward. The witness anchor pins the historical heads somewhere the host cannot alter, so
`reconcile` catches the rewrite. Conversely, the witness alone does not protect the key. Enable **both**
and forging the audit trail requires compromising **the Forge host *and* the witness *and* the HSM**.

Both controls are **opt-in**: the default remains local + `NullAnchor` (byte-identical and
dependency-free). See `forge/anchor.py` for the threat model behind the witness anchor.

---

## Data-at-rest secrets — what you must keep, and what breaks otherwise

The custody discussion above is about the **ledger signing key** (integrity). Two
*other* secrets govern **confidentiality at rest**. They are independent of each other and of
the signing key, and a restore is only fully successful when you still hold the ones
you used:

| Secret | Protects | If you lose it |
|---|---|---|
| `FORGE_FIELD_KEY` (+ `_FILE`) | The engagements' **authentication material** — bearers, cookies and header values of the operator's test accounts (`scope_json.auth`). Field encryption, **default build**, pure-Rust AEAD. | The database stays fully intact and readable; only this material stays **sealed**. Runs on these engagements **refuse to start** (never a silently empty auth context). Recovery = **re-enter** the material in the engagement editor. |
| `FORGE_DB_KEY` | The **entire SQLite file** (SQLCipher, `encryption` image only). | The database is **unreadable**. No partial recovery. |
| Backup passphrase | The **archive** (`forge backup`), which carries the DB snapshot + the ledger + the signing key. | The archive is **unrecoverable** — there is no plaintext way out. |

**They compose, and they are checked independently.** Restoring an archive with the right passphrase
on a host that does not have `FORGE_FIELD_KEY` yields a complete, working installation whose
auth material stays sealed — which is the intended fail-closed behaviour, not corruption. Store
the field key where you store the backup passphrase: they are needed together to bring back an
**armed** engagement.

> **Rotation.** Sealing is per-write and idempotent: material already sealed under an old
> key is left as is. To move an engagement to a new key, set the new
> `FORGE_FIELD_KEY` and **re-enter** its material in the editor — the console then seals it under the
> new key. There is no in-place bulk re-key, deliberately: it would require holding both
> keys at once in the process.

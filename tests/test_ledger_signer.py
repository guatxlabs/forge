"""ENTERPRISE (E3 COMPLIANCE) — PLUGGABLE LEDGER SIGNER. `python -m unittest -v`.

Proves the ledger's Ed25519 signer is PLUGGABLE without weakening verify:
  (a) LocalFileSigner is BYTE-IDENTICAL to today's Ed25519Signer over the same on-disk key, and the DEFAULT
      ledger (`make_ledger_signer`, no config/env) is exactly today's local signer — community unchanged;
  (b) a mocked RemoteSigner (private key held "off-host") produces a STANDARD Ed25519 signature the EXISTING
      external verifier (`Ledger.verify_external` / `verify_with_pubkey`) accepts UNCHANGED;
  (c) an UNREACHABLE remote signer => clean RemoteSignerError, and NO unsigned/insecure entry is written
      (fail-closed) — and the error carries NO secret;
  (d) the remote-signer CONFIG SECRET (endpoint/credential/argv) is REDACTED — never in repr/logs/errors;
  (e) the exec signer is NO-SHELL (fixed argv, JSON-only) and its signature also verifies externally;
  (f) a remote signer requested WITHOUT the enterprise flag is REFUSED (no silent local fallback).

The module is SEPARABLE + FLAG-GATED: with nothing configured the default build behaves as before.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import signing  # noqa: E402
from forge.ledger import Ledger  # noqa: E402

_HAVE_ED = signing._HAVE_ED
if _HAVE_ED:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _remote_keypair():
    """An off-host Ed25519 keypair standing in for a KMS/HSM-held private key: returns (sign_fn, pubkey_hex).
    `sign_fn` emits a STANDARD Ed25519 signature (hex) — exactly what a real remote signer would return."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    return (lambda data: priv.sign(data).hex()), pub


# A NO-SHELL exec signer helper: reads the private key path from a FIXED argv element, the bytes to sign from
# stdin, and writes the hex Ed25519 signature to stdout. Invoked as [python, -c, SCRIPT, keyfile] — no shell.
_EXEC_SIGN_SCRIPT = (
    "import sys;"
    "from pathlib import Path;"
    "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;"
    "priv=Ed25519PrivateKey.from_private_bytes(Path(sys.argv[1]).read_bytes());"
    "sys.stdout.write(priv.sign(sys.stdin.buffer.read()).hex())"
)


@unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
class TestLocalFileSignerByteIdentical(unittest.TestCase):
    def setUp(self):
        self.base = str(Path(tempfile.mkdtemp(prefix="forge-lfs-")) / "l")

    def test_localfilesigner_is_byte_identical_to_ed25519signer(self):
        # Create the on-disk key, then load it three ways: the raw Ed25519Signer (today), LocalFileSigner, and
        # make_signer. All MUST produce the identical signature (Ed25519 is deterministic) and public id.
        priv_bytes = signing._load_or_make_ed25519_priv(self.base).private_bytes_raw()
        today = signing.Ed25519Signer(Ed25519PrivateKey.from_private_bytes(priv_bytes))
        lfs = signing.LocalFileSigner.from_base_path(self.base)
        via_make = signing.make_signer(self.base)
        data = b"engagement-ledger-entry-hash"
        self.assertEqual(today.sign(data), lfs.sign(data))
        self.assertEqual(today.sign(data), via_make.sign(data))
        self.assertEqual(today.public_id(), lfs.public_id())
        self.assertEqual(lfs.alg, "ed25519")
        self.assertIsInstance(via_make, signing.LocalFileSigner)

    def test_default_ledger_signer_is_localfile_and_verifies(self):
        led = Ledger(self.base + ".jsonl")
        self.assertIsInstance(led.signer, signing.LocalFileSigner)
        led.append("roe.arm", {"reason": "x"})
        led.append("finding", {"title": "y"})
        v = led.verify()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["alg"], "ed25519")
        pub = led.public_id().split(":", 1)[1]
        self.assertTrue(led.verify_external(pub)["ok"])

    def test_make_ledger_signer_default_local_with_empty_env(self):
        s = signing.make_ledger_signer(self.base, env={})
        self.assertIsInstance(s, signing.LocalFileSigner)


@unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
class TestRemoteSignerVerifiesExternally(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp(prefix="forge-remote-")) / "l.jsonl"

    def test_remote_signature_accepted_by_standard_external_verifier(self):
        sign_fn, pub = _remote_keypair()
        signer = signing.RemoteSigner(sign_fn, pub, backend_label="kms(endpoint redacted)")
        led = Ledger(self.path, signer=signer)
        led.append("roe.decision", {"verdict": "FIRE", "target": "app.test"})
        led.append("finding", {"title": "x", "severity": "HIGH"})
        # local verify (uses signer.verify → public key) AND external verify (public key only) both accept.
        self.assertTrue(led.verify()["ok"])
        self.assertTrue(led.verify_external(pub)["ok"], "remote-produced Ed25519 sig must verify externally")
        # wrong public key rejected; tamper detected — verify path is byte-identical to the local signer.
        self.assertFalse(led.verify_external("00" * 32)["ok"])

    def test_remote_signed_ledger_detects_tamper(self):
        sign_fn, pub = _remote_keypair()
        led = Ledger(self.path, signer=signing.RemoteSigner(sign_fn, pub))
        led.append("finding", {"t": "a"})
        led.append("finding", {"t": "b"})
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[0]); rec["detail"] = {"t": "FORGED"}
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.path.write_text("\n".join(lines) + "\n")
        self.assertFalse(led.verify_external(pub)["ok"])

    def test_remote_signer_rejects_nonverifying_signature(self):
        # A bogus (well-formed hex but wrong) signature MUST be refused by sign() — fail-closed, never written.
        _, pub = _remote_keypair()
        signer = signing.RemoteSigner(lambda data: "00" * 64, pub)
        with self.assertRaises(signing.RemoteSignerError):
            signer.sign(b"whatever")

    def test_remote_signer_rejects_malformed_signature(self):
        _, pub = _remote_keypair()
        signer = signing.RemoteSigner(lambda data: "not-hex", pub)
        with self.assertRaises(signing.RemoteSignerError):
            signer.sign(b"x")


class TestRemoteSignerFailClosed(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp(prefix="forge-fc-")) / "l.jsonl"

    def test_unreachable_remote_signer_writes_no_entry(self):
        # The backend raises (e.g. KMS down). append() MUST raise a clean RemoteSignerError and write NOTHING —
        # no unsigned entry, no partial file. And the error must not leak the secret embedded in the cause.
        def boom(data):
            raise ConnectionError("connect to https://kms.secret.internal/sign token=SUPERSECRET failed")

        signer = signing.RemoteSigner(boom, "ab" * 32)
        led = Ledger(self.path, signer=signer)
        with self.assertRaises(signing.RemoteSignerError) as ctx:
            led.append("roe.arm", {"reason": "must-not-persist"})
        self.assertFalse(self.path.exists(), "no ledger file may be created when signing fails (fail-closed)")
        msg = str(ctx.exception)
        self.assertNotIn("SUPERSECRET", msg)
        self.assertNotIn("kms.secret.internal", msg)

    def test_http_signer_unreachable_clean_error_no_secret_leak(self):
        # A real connection attempt to a closed port → RemoteSignerError with NO endpoint/credential in it.
        sign_fn = signing._http_sign_fn("http://127.0.0.1:1/sign", "SUPERSECRETTOKEN", timeout=2)
        with self.assertRaises(signing.RemoteSignerError) as ctx:
            sign_fn(b"data")
        msg = str(ctx.exception)
        self.assertNotIn("SUPERSECRETTOKEN", msg)
        self.assertNotIn("127.0.0.1", msg)


class TestSignerConfigRedaction(unittest.TestCase):
    def test_redact_signer_config_hides_secrets_keeps_public(self):
        cfg = {
            "mode": "kms",
            "endpoint": "https://kms.example.internal/sign",
            "credential": "TOPSECRET-TOKEN",
            "pubkey": "ab" * 32,
            "timeout": 10,
        }
        safe = signing.redact_signer_config(cfg)
        blob = json.dumps(safe)
        self.assertNotIn("TOPSECRET-TOKEN", blob)
        self.assertNotIn("kms.example.internal", blob)
        self.assertEqual(safe["endpoint"], "***REDACTED***")
        self.assertEqual(safe["credential"], "***REDACTED***")
        # non-secret fields survive: mode, timeout, and the PUBLIC key.
        self.assertEqual(safe["mode"], "kms")
        self.assertEqual(safe["timeout"], 10)
        self.assertEqual(safe["pubkey"], "ab" * 32)

    def test_redact_signer_config_redacts_argv(self):
        safe = signing.redact_signer_config({"mode": "exec", "argv": ["/opt/signer", "--key", "SECRETPATH"]})
        self.assertEqual(safe["argv"], "***REDACTED***")
        self.assertNotIn("SECRETPATH", json.dumps(safe))

    @unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
    def test_remote_signer_repr_leaks_no_secret(self):
        cfg = {
            "mode": "kms",
            "endpoint": "https://kms.example.internal/sign",
            "credential": "TOPSECRET-TOKEN",
            "pubkey": "cd" * 32,
        }
        signer = signing.build_remote_signer(cfg)  # lazy — no network call
        r = repr(signer)
        self.assertNotIn("TOPSECRET-TOKEN", r)
        self.assertNotIn("kms.example.internal", r)
        self.assertIn("kms", r)  # non-secret backend label kept


class TestExecSignerNoShell(unittest.TestCase):
    def test_parse_argv_rejects_shell_string(self):
        with self.assertRaises(signing.RemoteSignerError):
            signing._parse_argv("echo hi; rm -rf /")           # a shell string is refused (no-shell)
        self.assertEqual(signing._parse_argv('["a", "b"]'), ["a", "b"])
        self.assertEqual(signing._parse_argv(["a", "b"]), ["a", "b"])

    def test_build_exec_signer_missing_argv_raises(self):
        with self.assertRaises(signing.RemoteSignerError):
            signing.build_remote_signer({"mode": "exec", "pubkey": "ab" * 32})

    @unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
    def test_exec_signer_end_to_end_no_shell_verifies_externally(self):
        d = Path(tempfile.mkdtemp(prefix="forge-exec-"))
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        keyfile = d / "k.ed25519"
        keyfile.write_bytes(priv.private_bytes_raw())
        cfg = {
            "mode": "exec",
            "argv": [sys.executable, "-c", _EXEC_SIGN_SCRIPT, str(keyfile)],  # FIXED argv, no shell
            "pubkey": pub,
            "timeout": 30,
        }
        # goes through make_ledger_signer (flag on) → build_remote_signer → _exec_sign_fn.
        signer = signing.make_ledger_signer(
            str(d / "l"), config=cfg, env={signing.ENTERPRISE_COMPLIANCE_FLAG: "1"})
        self.assertIsInstance(signer, signing.RemoteSigner)
        data = b"hash-bytes-to-sign"
        sig = signer.sign(data)
        self.assertTrue(signing.verify_with_pubkey(pub, data, sig))
        # and end-to-end through the ledger: the exec-produced signatures verify externally.
        led = Ledger(d / "l.jsonl", signer=signer)
        led.append("roe.arm", {"reason": "exec-signed"})
        led.append("finding", {"title": "x"})
        self.assertTrue(led.verify_external(pub)["ok"])


class TestFlagGating(unittest.TestCase):
    def test_remote_requested_without_enterprise_flag_is_refused(self):
        env = {
            signing.LEDGER_SIGNER_ENV: "kms",
            "FORGE_LEDGER_SIGNER_ENDPOINT": "https://kms.example.internal/sign",
            "FORGE_LEDGER_SIGNER_CREDENTIAL": "SECRET",
            "FORGE_LEDGER_SIGNER_PUBKEY": "ab" * 32,
        }  # note: no FORGE_ENTERPRISE_COMPLIANCE
        with self.assertRaises(signing.RemoteSignerError) as ctx:
            signing.make_ledger_signer("unused-base", env=env)
        self.assertNotIn("SECRET", str(ctx.exception))          # refusal message carries no secret

    @unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
    def test_remote_built_lazily_when_flag_on(self):
        env = {
            signing.ENTERPRISE_COMPLIANCE_FLAG: "1",
            signing.LEDGER_SIGNER_ENV: "kms",
            "FORGE_LEDGER_SIGNER_ENDPOINT": "https://kms.example.internal/sign",
            "FORGE_LEDGER_SIGNER_CREDENTIAL": "SECRET",
            "FORGE_LEDGER_SIGNER_PUBKEY": "ab" * 32,
        }
        signer = signing.make_ledger_signer("unused-base", env=env)  # lazy: no network here
        self.assertIsInstance(signer, signing.RemoteSigner)
        self.assertEqual(signer.pubkey_hex, "ab" * 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)

# SPDX-License-Identifier: AGPL-3.0-only
"""PKCS#11 (CKM_EDDSA) OFF-HOST ledger signer — driver + wiring tests. `python -m pytest tests/test_pkcs11_signer.py`.

Proves:
  (a) DEFAULT/community path is UNCHANGED: `make_ledger_signer` with empty env → `LocalFileSigner`, and
      importing `forge.signing` (and building the default signer) imports NO PKCS#11 lib — the default
      engine stays STDLIB-ONLY (a documented Forge strength);
  (b) LIVE round-trip (skipped unless SoftHSM2 + python-pkcs11 are installed): init a temp SoftHSM token,
      generate an Ed25519 key, sign a ledger entry via `Pkcs11Signer`, verify + `verify_external(pubkey)`
      accept, and a tampered signature is rejected;
  (c) MOCKED driver (always runs): a fake PKCS#11 module drives the real driver code path
      (sign → re-verify → reject-on-mismatch), the EC_POINT DER/raw decode, the flag gate, the
      wiring `FORGE_LEDGER_SIGNER=pkcs11` → `Pkcs11Signer`, and the actionable "lib not installed" error.
"""
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import signing  # noqa: E402
from forge import signing_pkcs11  # noqa: E402  (module load must NOT import python-pkcs11)
from forge.ledger import Ledger  # noqa: E402

_HAVE_ED = signing._HAVE_ED
if _HAVE_ED:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


# ============================ (a) DEFAULT PATH — STDLIB-ONLY, UNCHANGED ============================

class TestDefaultPathStaysStdlibOnly(unittest.TestCase):
    def setUp(self):
        self.base = str(Path(tempfile.mkdtemp(prefix="forge-p11-default-")) / "l")

    @unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
    def test_default_signer_is_localfile_and_imports_no_pkcs11(self):
        # Building the default ledger signer must NOT drag in any PKCS#11 lib.
        for m in ("pkcs11", "PyKCS11"):
            self.assertNotIn(m, sys.modules, f"{m} must not be imported before the default signer is built")
        s = signing.make_ledger_signer(self.base, env={})
        self.assertIsInstance(s, signing.LocalFileSigner)
        for m in ("pkcs11", "PyKCS11"):
            self.assertNotIn(m, sys.modules, f"default LocalFileSigner path must not import {m}")

    def test_importing_forge_signing_does_not_import_pkcs11_at_module_load(self):
        # Fresh interpreter: importing forge.signing (and forge.signing_pkcs11) must leave the PKCS#11 lib
        # unimported — the lazy `_import_pkcs11` is the ONLY place it is touched.
        code = (
            "import sys; import forge.signing, forge.signing_pkcs11; "
            "assert 'pkcs11' not in sys.modules, 'python-pkcs11 imported at module load'; "
            "assert 'PyKCS11' not in sys.modules, 'PyKCS11 imported at module load'; "
            "print('OK')"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1]) + os.pathsep + env.get("PYTHONPATH", "")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("OK", out.stdout)


# ============================ Fake PKCS#11 module (mocked driver exercise) ============================

class _FakeAttribute:
    EC_POINT = "CKA_EC_POINT"


class _FakeObjectClass:
    PRIVATE_KEY = "PRIVATE_KEY"
    PUBLIC_KEY = "PUBLIC_KEY"


class _FakeMechanism:
    EDDSA = "EDDSA"


class _FakePrivKey:
    def __init__(self, priv, tamper=False):
        self._priv = priv
        self._tamper = tamper

    def sign(self, data, mechanism=None):
        assert mechanism == _FakeMechanism.EDDSA, "driver must sign with CKM_EDDSA"
        if self._tamper:
            return b"\x00" * 64          # well-formed length, WRONG signature → must be rejected on re-verify
        return self._priv.sign(data)     # a genuine Ed25519 signature (bytes), like a real token


class _FakePubKey:
    def __init__(self, raw32, der=True):
        self._raw = raw32
        self._der = der

    def __getitem__(self, attr):
        assert attr == _FakeAttribute.EC_POINT
        return (b"\x04\x20" + self._raw) if self._der else self._raw


class _FakeSession:
    def __init__(self, priv, pub):
        self._priv, self._pub = priv, pub

    def get_key(self, object_class=None, label=None, id=None):
        return self._priv if object_class == _FakeObjectClass.PRIVATE_KEY else self._pub


class _FakeToken:
    def __init__(self, session):
        self._s = session
        self.opened_pin = None

    def open(self, user_pin=None, rw=False):
        self.opened_pin = user_pin
        return self._s


class _FakeSlot:
    def __init__(self, token):
        self._t = token

    def get_token(self):
        return self._t


class _FakeLib:
    def __init__(self, token):
        self._t = token

    def get_token(self, token_label=None):
        return self._t

    def get_slots(self, token_present=True):
        return [_FakeSlot(self._t)]


class _FakeModule:
    Attribute = _FakeAttribute
    ObjectClass = _FakeObjectClass
    Mechanism = _FakeMechanism

    def __init__(self, priv_obj, pub_obj):
        self._token = _FakeToken(_FakeSession(priv_obj, pub_obj))
        self.loaded_path = None

    def lib(self, path):
        self.loaded_path = path
        return _FakeLib(self._token)


def _fake_module(tamper=False, der=True):
    priv = Ed25519PrivateKey.generate()
    raw32 = priv.public_key().public_bytes_raw()
    return _FakeModule(_FakePrivKey(priv, tamper=tamper), _FakePubKey(raw32, der=der)), raw32.hex()


@unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
class TestMockedPkcs11Driver(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="forge-p11-mock-"))
        self._orig_import = signing_pkcs11._import_pkcs11
        self.cfg = {"module": "/fake/libsofthsm2.so", "token_label": "forge", "key_label": "forge-ledger", "pin": "1234"}

    def tearDown(self):
        signing_pkcs11._import_pkcs11 = self._orig_import
        shutil.rmtree(self.dir, ignore_errors=True)

    def _patch(self, module):
        signing_pkcs11._import_pkcs11 = lambda: module

    def test_roundtrip_sign_verify_external_der_point(self):
        module, pub = _fake_module(der=True)
        self._patch(module)
        signer = signing_pkcs11.build_pkcs11_signer(self.cfg)
        self.assertIsInstance(signer, signing_pkcs11.Pkcs11Signer)
        self.assertIsInstance(signer, signing.RemoteSigner)   # same seam
        self.assertEqual(signer.pubkey_hex, pub)
        self.assertEqual(module._token.opened_pin, "1234")    # PIN passed to token.open, not argv
        data = b"engagement-ledger-entry-hash"
        sig = signer.sign(data)
        self.assertTrue(signing.verify_with_pubkey(pub, data, sig))
        # end-to-end through the ledger: external verifier accepts with the PUBLIC key alone.
        led = Ledger(self.dir / "l.jsonl", signer=signer)
        led.append("roe.arm", {"reason": "pkcs11-signed"})
        led.append("finding", {"title": "x", "severity": "HIGH"})
        self.assertTrue(led.verify()["ok"])
        self.assertTrue(led.verify_external(pub)["ok"], "pkcs11-produced Ed25519 sig must verify externally")
        self.assertFalse(led.verify_external("00" * 32)["ok"])  # wrong pubkey rejected

    def test_roundtrip_raw_ec_point(self):
        module, pub = _fake_module(der=False)   # provider returns raw 32-byte point, no DER wrapping
        self._patch(module)
        signer = signing_pkcs11.build_pkcs11_signer(self.cfg)
        self.assertEqual(signer.pubkey_hex, pub)
        self.assertTrue(signing.verify_with_pubkey(pub, b"z", signer.sign(b"z")))

    def test_tampered_token_signature_rejected_at_build_selftest(self):
        # A token returning a bogus signature must be caught by the build-time self-test (fail-closed) —
        # the signer never comes into existence, no local fallback.
        module, _ = _fake_module(tamper=True)
        self._patch(module)
        with self.assertRaises(signing.RemoteSignerError):
            signing_pkcs11.build_pkcs11_signer(self.cfg)

    def test_sign_reverify_rejects_mismatch_after_build(self):
        # Directly exercise the sign → re-verify → reject path: a good signer whose token later returns a
        # wrong signature must raise on sign() (inherited RemoteSigner fail-closed), never emit it.
        module, pub = _fake_module(der=True)
        self._patch(module)
        signer = signing_pkcs11.build_pkcs11_signer(self.cfg)
        signer._sign_fn = lambda data: "11" * 64   # simulate a token going rogue → wrong Ed25519 sig
        with self.assertRaises(signing.RemoteSignerError):
            signer.sign(b"post-build")

    def test_missing_module_path_raises(self):
        self._patch(_fake_module()[0])
        with self.assertRaises(signing.RemoteSignerError):
            signing_pkcs11.build_pkcs11_signer({"token_label": "forge", "key_label": "k"})  # no module

    def test_missing_key_selector_raises(self):
        self._patch(_fake_module()[0])
        with self.assertRaises(signing.RemoteSignerError):
            signing_pkcs11.build_pkcs11_signer({"module": "/fake.so", "token_label": "forge"})  # no label/id

    def test_bad_ec_point_raises(self):
        priv = Ed25519PrivateKey.generate()
        bad = _FakeModule(_FakePrivKey(priv), _FakePubKey(b"\x00" * 10, der=False))  # 10 bytes → invalid
        self._patch(bad)
        with self.assertRaises(signing.RemoteSignerError):
            signing_pkcs11.build_pkcs11_signer(self.cfg)


class TestPkcs11LibAbsentError(unittest.TestCase):
    def test_actionable_error_when_lib_not_installed(self):
        # If python-pkcs11 is genuinely not importable, the driver must raise a clear, actionable error
        # naming the extra. (When the lib IS installed, this assertion is vacuously skipped.)
        try:
            import pkcs11  # noqa: F401
            self.skipTest("python-pkcs11 installed on this host — absent-lib path not exercisable")
        except ImportError:
            pass
        with self.assertRaises(signing.RemoteSignerError) as ctx:
            signing_pkcs11._import_pkcs11()
        self.assertIn("forge[pkcs11]", str(ctx.exception))


# ============================ Wiring: FORGE_LEDGER_SIGNER=pkcs11 → Pkcs11Signer ============================

@unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
class TestPkcs11Wiring(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="forge-p11-wire-"))
        self._orig_import = signing_pkcs11._import_pkcs11

    def tearDown(self):
        signing_pkcs11._import_pkcs11 = self._orig_import
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_env_selects_pkcs11_when_flag_on(self):
        module, pub = _fake_module()
        signing_pkcs11._import_pkcs11 = lambda: module
        env = {
            signing.ENTERPRISE_COMPLIANCE_FLAG: "1",
            signing.LEDGER_SIGNER_ENV: "pkcs11",
            signing_pkcs11.PKCS11_MODULE_ENV: "/fake/libsofthsm2.so",
            signing_pkcs11.PKCS11_TOKEN_LABEL_ENV: "forge",
            signing_pkcs11.PKCS11_KEY_LABEL_ENV: "forge-ledger",
            signing_pkcs11.PKCS11_PIN_ENV: "9999",
        }
        signer = signing.make_ledger_signer(str(self.dir / "l"), env=env)
        self.assertIsInstance(signer, signing_pkcs11.Pkcs11Signer)
        self.assertEqual(signer.pubkey_hex, pub)
        self.assertEqual(module._token.opened_pin, "9999")

    def test_pkcs11_requested_without_flag_is_refused(self):
        # No FORGE_ENTERPRISE_COMPLIANCE → refused, and python-pkcs11 is NEVER imported (fail before build).
        called = {"import": False}

        def _should_not_run():
            called["import"] = True
            raise AssertionError("must not import pkcs11 when flag off")

        signing_pkcs11._import_pkcs11 = _should_not_run
        env = {signing.LEDGER_SIGNER_ENV: "pkcs11", signing_pkcs11.PKCS11_MODULE_ENV: "/fake.so"}
        with self.assertRaises(signing.RemoteSignerError):
            signing.make_ledger_signer(str(self.dir / "l"), env=env)
        self.assertFalse(called["import"], "flag gate must reject before importing python-pkcs11")

    def test_pin_redacted_in_signer_config_view(self):
        safe = signing.redact_signer_config({"mode": "pkcs11", "pin": "SUPERSECRETPIN", "pubkey": "ab" * 32})
        self.assertEqual(safe["pin"], "***REDACTED***")
        self.assertNotIn("SUPERSECRETPIN", json.dumps(safe))
        self.assertEqual(safe["mode"], "pkcs11")


# ============================ (b) LIVE SoftHSM2 round-trip (skipped unless installed) ============================

def _softhsm_available():
    if shutil.which("softhsm2-util") is None:
        return False
    try:
        import pkcs11  # noqa: F401
    except ImportError:
        return False
    return _HAVE_ED


def _find_softhsm_module():
    for p in (
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    ):
        if Path(p).exists():
            return p
    return os.environ.get("FORGE_TEST_SOFTHSM_MODULE")


@unittest.skipUnless(_softhsm_available(), "SoftHSM2 + python-pkcs11 non installés — round-trip live sauté")
class TestLiveSoftHSMRoundTrip(unittest.TestCase):
    def setUp(self):
        self.module = _find_softhsm_module()
        if not self.module:
            self.skipTest("libsofthsm2.so introuvable (poser FORGE_TEST_SOFTHSM_MODULE)")
        self.tokendir = Path(tempfile.mkdtemp(prefix="forge-softhsm-"))
        self.conf = self.tokendir / "softhsm2.conf"
        self.conf.write_text(f"directories.tokendir = {self.tokendir}\nobjectstore.backend = file\n")
        os.environ["SOFTHSM2_CONF"] = str(self.conf)
        self.token_label = "forge-test"
        self.pin = "1234"
        self.so_pin = "5678"
        self.key_label = "forge-ledger"
        subprocess.run(
            ["softhsm2-util", "--init-token", "--free", "--label", self.token_label,
             "--pin", self.pin, "--so-pin", self.so_pin],
            check=True, capture_output=True,
        )
        # Generate an Ed25519 key ON the token via python-pkcs11.
        import pkcs11
        lib = pkcs11.lib(self.module)
        token = lib.get_token(token_label=self.token_label)
        with token.open(user_pin=self.pin, rw=True) as session:
            session.generate_keypair(
                pkcs11.KeyType.EC_EDWARDS, 255, label=self.key_label, store=True,
                mechanism=pkcs11.Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                private_template={pkcs11.Attribute.TOKEN: True, pkcs11.Attribute.SIGN: True},
                public_template={pkcs11.Attribute.TOKEN: True, pkcs11.Attribute.VERIFY: True,
                                 pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("edwards25519")},
            )

    def tearDown(self):
        os.environ.pop("SOFTHSM2_CONF", None)
        shutil.rmtree(self.tokendir, ignore_errors=True)

    def test_live_softhsm_sign_verify_and_tamper_reject(self):
        cfg = {"module": self.module, "token_label": self.token_label, "key_label": self.key_label, "pin": self.pin}
        signer = signing_pkcs11.build_pkcs11_signer(cfg)
        pub = signer.pubkey_hex
        self.assertEqual(len(pub), 64)
        led = Ledger(self.tokendir / "l.jsonl", signer=signer)
        led.append("roe.arm", {"reason": "live-softhsm"})
        led.append("finding", {"title": "real-hsm", "severity": "HIGH"})
        self.assertTrue(led.verify()["ok"])
        self.assertTrue(led.verify_external(pub)["ok"])
        # tamper a signed entry → external verify must reject.
        lines = (self.tokendir / "l.jsonl").read_text().splitlines()
        rec = json.loads(lines[0]); rec["detail"] = {"reason": "FORGED"}
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        (self.tokendir / "l.jsonl").write_text("\n".join(lines) + "\n")
        self.assertFalse(led.verify_external(pub)["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Ledger PRIVATE-key protection — audit F2 (no readable window) + F1 (configurable path). `pytest`.

Proves the ledger signing key is created SAFELY:
  (a) a freshly created key file is 0600 AND is BORN restricted — `os.open` is called with O_CREAT|O_EXCL
      and mode 0600, so the inode never exists at a wider (umask 0644/0664) mode (no readable window);
  (b) a PRE-EXISTING (operator-provisioned, read-only mount) key is READ, never rewritten/chmod'd/clobbered;
  (c) `FORGE_LEDGER_KEY` redirects the key to the configured path (off the shared ledger volume) — and the
      default (unset) is byte-identical to `<base>.ed25519`;
  (d) a secure-create / chmod failure FAILS CLOSED (raises `LedgerKeyProtectionError`) and leaves NO
      world-readable key behind — the signer never silently proceeds with an unprotected key.
"""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import signing  # noqa: E402
from forge import portability  # noqa: E402

_HAVE_ED = signing._HAVE_ED
_POSIX = portability.is_posix()


def _mode(p):
    return stat.S_IMODE(os.stat(str(p)).st_mode)


class _EnvGuard:
    """Save/restore FORGE_LEDGER_KEY around a test so cases are isolated."""

    def __enter__(self):
        self._saved = os.environ.get("FORGE_LEDGER_KEY")
        os.environ.pop("FORGE_LEDGER_KEY", None)
        return self

    def set(self, value):
        os.environ["FORGE_LEDGER_KEY"] = str(value)

    def __exit__(self, *exc):
        if self._saved is None:
            os.environ.pop("FORGE_LEDGER_KEY", None)
        else:
            os.environ["FORGE_LEDGER_KEY"] = self._saved
        return False


@unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
class TestFreshKeyIsBornRestricted(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="forge-keyprot-"))
        self.base = str(self.d / "ledger")

    @unittest.skipUnless(_POSIX, "perms POSIX requises")
    def test_fresh_key_is_0600_and_created_atomically(self):
        # Spy on os.open to prove the key inode is BORN at O_CREAT|O_EXCL, mode 0600 — never a wider window.
        seen = {}
        real_open = os.open

        def spy_open(path, flags, mode=0o777):
            if str(path).endswith(".ed25519"):
                seen["flags"] = flags
                seen["mode"] = mode
            return real_open(path, flags, mode)

        with _EnvGuard():
            os.open = spy_open
            try:
                priv = signing._load_or_make_ed25519_priv(self.base)
            finally:
                os.open = real_open

        kp = Path(self.base + ".ed25519")
        self.assertTrue(kp.exists())
        self.assertEqual(_mode(kp), 0o600, "clé fraîche doit être 0600")
        # atomic-restrictive create: O_CREAT + O_EXCL, mode 0600 (inode never observable at a wider mode)
        self.assertTrue(seen.get("flags", 0) & os.O_CREAT)
        self.assertTrue(seen.get("flags", 0) & os.O_EXCL, "doit utiliser O_EXCL (pas de fenêtre lisible)")
        self.assertEqual(seen.get("mode"), 0o600)
        # sanity: the loaded key is usable
        self.assertEqual(len(priv.private_bytes_raw()), 32)

    @unittest.skipUnless(_POSIX, "perms POSIX requises")
    def test_umask_cannot_widen_the_key(self):
        # Even under a permissive umask (0), the key must land at exactly 0600 (fchmod enforces it).
        old_umask = os.umask(0)
        try:
            with _EnvGuard():
                signing._load_or_make_ed25519_priv(self.base)
        finally:
            os.umask(old_umask)
        self.assertEqual(_mode(Path(self.base + ".ed25519")), 0o600)

    @unittest.skipUnless(_POSIX, "perms POSIX requises")
    def test_hmac_secret_also_born_0600(self):
        with _EnvGuard():
            key = signing._load_or_make_secret(self.base + ".key")
        self.assertEqual(len(key), 32)
        self.assertEqual(_mode(Path(self.base + ".key")), 0o600)

    @unittest.skipUnless(_POSIX, "perms POSIX requises")
    def test_rotation_is_atomic_0600(self):
        with _EnvGuard():
            signing.generate_ed25519_keypair(self.base)   # first
            s2 = signing.generate_ed25519_keypair(self.base)   # rotate (replace=True overwrite)
        kp = Path(self.base + ".ed25519")
        self.assertEqual(_mode(kp), 0o600)
        self.assertEqual(kp.read_bytes(), s2._priv.private_bytes_raw())


@unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
class TestPreexistingKeyReadNeverRewritten(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="forge-keyro-"))
        self.base = str(self.d / "ledger")
        self._restore_dir_mode = None

    def tearDown(self):
        if self._restore_dir_mode is not None:
            os.chmod(str(self.d), self._restore_dir_mode)

    def test_preexisting_key_is_read_not_rewritten(self):
        # Provision a key, then guarantee any write attempt would fail the test.
        with _EnvGuard():
            first = signing._load_or_make_ed25519_priv(self.base)
            provisioned = Path(self.base + ".ed25519").read_bytes()

            boom = {"called": False}
            real = signing._atomic_write_secret

            def no_write(*a, **k):
                boom["called"] = True
                raise AssertionError("clé pré-existante ne doit JAMAIS être réécrite")

            signing._atomic_write_secret = no_write
            try:
                again = signing._load_or_make_ed25519_priv(self.base)
            finally:
                signing._atomic_write_secret = real

        self.assertFalse(boom["called"])
        self.assertEqual(again.private_bytes_raw(), first.private_bytes_raw())
        self.assertEqual(Path(self.base + ".ed25519").read_bytes(), provisioned)

    @unittest.skipUnless(_POSIX, "perms POSIX requises")
    def test_read_from_readonly_mount_succeeds(self):
        # Simulate a read-only Secret mount: provision the key, then strip write from the parent dir.
        with _EnvGuard():
            first = signing._load_or_make_ed25519_priv(self.base)
            self._restore_dir_mode = _mode(self.d)
            os.chmod(str(self.d), 0o500)   # read+exec only — no create/rename possible
            again = signing._load_or_make_ed25519_priv(self.base)   # must READ, not write
        self.assertEqual(again.private_bytes_raw(), first.private_bytes_raw())


@unittest.skipUnless(_HAVE_ED, "cryptography/Ed25519 indisponible")
class TestConfigurablePath(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="forge-keypath-"))
        self.base = str(self.d / "ledger")

    def test_default_path_is_sibling(self):
        with _EnvGuard():
            self.assertEqual(signing.ledger_key_path(self.base), Path(self.base + ".ed25519"))

    def test_env_redirects_key_off_shared_volume(self):
        custom = self.d / "secret-mount" / "signing.key"
        with _EnvGuard() as g:
            g.set(custom)
            self.assertEqual(signing.ledger_key_path(self.base), Path(custom))
            signer = signing.make_signer(self.base)
        self.assertTrue(custom.exists(), "clé créée au chemin FORGE_LEDGER_KEY")
        self.assertFalse(Path(self.base + ".ed25519").exists(), "PAS créée au chemin sibling par défaut")
        if _POSIX:
            self.assertEqual(_mode(custom), 0o600)
        # the signer uses the redirected key
        self.assertEqual(signer._priv.private_bytes_raw(), custom.read_bytes())


@unittest.skipUnless(_HAVE_ED and _POSIX, "perms POSIX + Ed25519 requis")
class TestFailClosedOnPermsFailure(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="forge-keyfail-"))
        self.base = str(self.d / "ledger")

    def test_chmod_failure_raises_and_leaves_no_key(self):
        # Force the 0600 enforcement to fail → must fail-closed (raise) and leave NO key on disk.
        real_fchmod = os.fchmod

        def boom_fchmod(fd, mode):
            raise OSError("simulated chmod failure")

        with _EnvGuard():
            os.fchmod = boom_fchmod
            try:
                with self.assertRaises(signing.LedgerKeyProtectionError):
                    signing._load_or_make_ed25519_priv(self.base)
            finally:
                os.fchmod = real_fchmod

        # fail-closed: no key material left readable at umask perms
        self.assertFalse(Path(self.base + ".ed25519").exists(),
                         "aucune clé ne doit rester après un échec de perms (fail-closed)")

    def test_secure_create_failure_raises(self):
        # Force os.open to fail → fail-closed raise, no key written.
        real_open = os.open

        def boom_open(path, flags, mode=0o777):
            if str(path).endswith(".ed25519"):
                raise OSError("simulated secure-create failure")
            return real_open(path, flags, mode)

        with _EnvGuard():
            os.open = boom_open
            try:
                with self.assertRaises(signing.LedgerKeyProtectionError):
                    signing._load_or_make_ed25519_priv(self.base)
            finally:
                os.open = real_open
        self.assertFalse(Path(self.base + ".ed25519").exists())

    def test_rotation_failure_is_fail_closed(self):
        # generate_ed25519_keypair uses replace=True; a temp-chmod failure must raise, not leave a key.
        real_fchmod = os.fchmod

        def boom_fchmod(fd, mode):
            raise OSError("simulated chmod failure")

        with _EnvGuard():
            os.fchmod = boom_fchmod
            try:
                with self.assertRaises(signing.LedgerKeyProtectionError):
                    signing.generate_ed25519_keypair(self.base)
            finally:
                os.fchmod = real_fchmod
        self.assertFalse(Path(self.base + ".ed25519").exists())


if __name__ == "__main__":
    unittest.main()

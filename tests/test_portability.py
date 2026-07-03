# SPDX-License-Identifier: AGPL-3.0-only
"""Portability seams (cross-platform) — comportement inchangé sous Linux, dégradation gracieuse
ailleurs. Couvre : config_dir/data_dir résolus PAR plateforme (override FORGE_* prioritaire),
restrict_file_permissions (0600 POSIX / no-op Windows sans crash), résolution de binaire via
shutil.which dans le tool-wrapper runner, et non-crash sur un os.name non-POSIX monkeypatché.
"""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import portability                                # noqa: E402
from forge import runner, signing                            # noqa: E402


class TestPredicates(unittest.TestCase):
    def test_predicates_are_mutually_consistent(self):
        # Exactement une famille d'OS active ; sous Linux CI -> POSIX vrai, Windows faux.
        self.assertTrue(portability.is_posix())
        self.assertFalse(portability.is_windows())
        self.assertIsInstance(portability.is_macos(), bool)

    def test_windows_predicate_under_monkeypatched_name(self):
        # Prédicats purs (aucune construction de Path) : on peut simuler os.name sans risque.
        with mock.patch.object(os, "name", "nt"):
            self.assertTrue(portability.is_windows())
            self.assertFalse(portability.is_posix())


class TestConfigDir(unittest.TestCase):
    def test_posix_default_uses_xdg_config_home(self):
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/xdg/cfg"}, clear=False):
            os.environ.pop("FORGE_CONFIG_DIR", None)
            self.assertEqual(portability.config_dir("forge"), Path("/xdg/cfg") / "forge")

    def test_posix_default_without_xdg_is_dot_config(self):
        env = {k: v for k, v in os.environ.items()}
        env.pop("XDG_CONFIG_HOME", None)
        env.pop("FORGE_CONFIG_DIR", None)
        with mock.patch.dict(os.environ, env, clear=True):
            expected = Path(os.path.expanduser("~")) / ".config" / "forge"
            self.assertEqual(portability.config_dir("forge"), expected)

    def test_env_override_wins_on_posix(self):
        with mock.patch.dict(os.environ, {"FORGE_CONFIG_DIR": "/custom/forge/cfg"}, clear=False):
            self.assertEqual(portability.config_dir("forge"), Path("/custom/forge/cfg"))

    def test_windows_default_uses_appdata(self):
        # On simule Windows via le prédicat portability.is_windows (PAS via os.name global, qui
        # ferait planter pathlib.Path -> WindowsPath sur un hôte POSIX en 3.14).
        with mock.patch.object(portability, "is_windows", lambda: True), \
             mock.patch.dict(os.environ, {"APPDATA": r"C:\Users\bob\AppData\Roaming"}, clear=False):
            os.environ.pop("FORGE_CONFIG_DIR", None)
            self.assertEqual(portability.config_dir("forge"),
                             Path(r"C:\Users\bob\AppData\Roaming") / "forge")

    def test_env_override_wins_even_on_windows(self):
        with mock.patch.object(portability, "is_windows", lambda: True), \
             mock.patch.dict(os.environ, {"FORGE_CONFIG_DIR": r"D:\forge"}, clear=False):
            self.assertEqual(portability.config_dir("forge"), Path(r"D:\forge"))

    def test_create_makes_the_directory(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"FORGE_CONFIG_DIR": os.path.join(td, "sub", "forge")},
                                 clear=False):
                p = portability.config_dir("forge", create=True)
                self.assertTrue(p.is_dir())


class TestDataDir(unittest.TestCase):
    def test_posix_default_without_xdg_is_local_share(self):
        env = {k: v for k, v in os.environ.items()}
        env.pop("XDG_DATA_HOME", None)
        env.pop("FORGE_DATA_DIR", None)
        with mock.patch.dict(os.environ, env, clear=True):
            expected = Path(os.path.expanduser("~")) / ".local" / "share" / "forge"
            self.assertEqual(portability.data_dir("forge"), expected)

    def test_windows_default_uses_localappdata(self):
        with mock.patch.object(portability, "is_windows", lambda: True), \
             mock.patch.dict(os.environ, {"LOCALAPPDATA": r"C:\Users\bob\AppData\Local"}, clear=False):
            os.environ.pop("FORGE_DATA_DIR", None)
            self.assertEqual(portability.data_dir("forge"),
                             Path(r"C:\Users\bob\AppData\Local") / "forge")

    def test_env_override_wins(self):
        with mock.patch.dict(os.environ, {"FORGE_DATA_DIR": "/srv/forge/data"}, clear=False):
            self.assertEqual(portability.data_dir("forge"), Path("/srv/forge/data"))


class TestRestrictPermissions(unittest.TestCase):
    def test_posix_applies_0600(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            self.assertTrue(portability.restrict_file_permissions(path))
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)
        finally:
            os.unlink(path)

    def test_non_posix_is_noop_and_never_crashes(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            with mock.patch.object(portability, "is_posix", lambda: False):
                # Sur non-POSIX : no-op best-effort, retourne False, ne lève pas, fichier intact.
                self.assertFalse(portability.restrict_file_permissions(path))
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)

    def test_oserror_is_swallowed(self):
        # Chemin inexistant -> os.chmod lève OSError -> avalé, retourne False (jamais de crash).
        self.assertFalse(portability.restrict_file_permissions("/no/such/forge/path/zzz.key"))


class TestRunnerResolvesBinary(unittest.TestCase):
    """Le tool-wrapper runner.tool construit l'argv avec le binaire RÉSOLU par shutil.which
    (gère .exe/.bat via PATHEXT sous Windows), pas le nom nu."""

    def test_local_argv_uses_shutil_which_resolved_path(self):
        orig_which = runner.shutil.which
        orig_run = runner.subprocess.run
        sentinel = "/opt/forge/bin/mytool"          # chemin résolu simulé (ex. wrapper .bat sous Windows)
        runner.shutil.which = lambda name: sentinel if name == "mytool" else None
        captured = {}

        class _P:
            returncode, stdout, stderr = 0, "ok", ""

        def fake_run(cmd, **k):
            captured["cmd"] = cmd
            self.assertFalse(k.get("shell", False))   # NO-SHELL préservé
            return _P()

        runner.subprocess.run = fake_run
        try:
            runner.tool("mytool", docker_image=None, args=["--flag", "x"])
        finally:
            runner.shutil.which = orig_which
            runner.subprocess.run = orig_run
        self.assertEqual(captured["cmd"][0], sentinel)          # argv[0] = binaire résolu, pas "mytool"
        self.assertEqual(captured["cmd"][1:], ["--flag", "x"])


class TestSigningNonPosixDoesNotCrash(unittest.TestCase):
    """Génération de clé sous un os.name non-POSIX monkeypatché : la clé atterrit quand même
    (perms POSIX simplement non appliquées) — jamais de crash à l'exécution."""

    def test_hmac_key_lands_under_non_posix(self):
        # Non-POSIX simulé via le prédicat portability.is_posix (le chmod 0600 est alors sauté) —
        # on ne touche pas os.name global (pathlib.Path/WindowsPath planterait sur cet hôte 3.14).
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "ledger")
            with mock.patch.object(portability, "is_posix", lambda: False):
                signer = signing.make_signer(base, prefer_ed25519=False)
            self.assertEqual(signer.alg, "hmac-sha256")
            self.assertTrue(os.path.exists(base + ".key"))

    @unittest.skipUnless(signing._HAVE_ED, "Ed25519 requis (cryptography absent -> repli HMAC)")
    def test_ed25519_key_lands_under_non_posix(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "ledger")
            with mock.patch.object(portability, "is_posix", lambda: False):
                signer = signing.generate_ed25519_keypair(base)
            self.assertEqual(signer.alg, "ed25519")
            self.assertTrue(os.path.exists(base + ".ed25519"))


if __name__ == "__main__":
    unittest.main()

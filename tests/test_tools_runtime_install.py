# SPDX-License-Identifier: AGPL-3.0-or-later
"""Surcouche RUNTIME des outils (`forge tools install|update|remove`) — la GOUVERNANCE, prouvee.

Installer un binaire au runtime dans un outil offensif est la capacite qui annule une gouvernance si
elle est mal posee. Ce fichier verifie, une par une, les contraintes posees dans
`forge/toolsinstall.py` — et surtout leur cote FAIL-CLOSED (ce qui doit REFUSER refuse bien, et ne
laisse RIEN derriere) :

  * INTEGRITE      — digest non concordant, digest absent pour l'architecture : refus, zero octet pose
                     sur le PATH, refus JOURNALISE.
  * ALLOWLIST      — un nom hors manifeste n'est pas installable, et RIEN n'est telecharge ; l'URL
                     provient exclusivement du manifeste (il n'existe pas de parametre d'URL) ; une
                     redirection quittant HTTPS est refusee.
  * PAS DE SHELL   — aucun sous-processus n'est lance (ni curl, ni unzip, ni tar) : c'est de l'urllib,
                     du zipfile et du tarfile. Verifie en instrumentant `subprocess`.
  * LEDGER         — install / update / remove / refus produisent une entree chainee et signee, et le
                     ledger reste VERIFIABLE ; sans ledger resoluble, l'action est refusee.
  * PAS D'EVASION  — une archive hostile (membre nomme `../../evil`) n'ecrit QUE dans le repertoire
                     outils : la destination est calculee par nous, jamais lue dans l'archive.
  * PAS D'ELEVATION— un outil installe au runtime reste soumis au scope-guard fail-closed : cible hors
                     perimetre -> `skipped`, aucun processus lance.
  * NO-OP PAR DEFAUT — importer le module ne cree rien, ne sonde rien ; la CLI existante est intacte.
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import unittest
import urllib.error
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import toolsinstall, toolsmanifest                          # noqa: E402
from forge.ledger import Ledger                                        # noqa: E402
from forge.modules.toolspec import ToolSpec, make_module               # noqa: E402
from forge.roe import Action                                           # noqa: E402
from tests._tmp import temp_dir                                        # noqa: E402

BIN_PAYLOAD = b"#!/bin/sh\necho outil-factice\n"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _targz_bytes(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeOpener:
    """Reseau simule : mappe URL -> octets. Enregistre CE QUI A ETE DEMANDE, ce qui permet d'affirmer
    « rien n'a ete telecharge » sur les chemins de refus."""

    def __init__(self, mapping=None):
        self.mapping = dict(mapping or {})
        self.calls = []

    def open(self, url, timeout=None):
        self.calls.append(url)
        if url not in self.mapping:
            raise urllib.error.URLError(f"cible inconnue: {url}")
        return io.BytesIO(self.mapping[url])


class ToolsInstallCase(unittest.TestCase):
    """Socle : un repertoire outils isole, un ledger isole, un manifeste synthetique."""

    def setUp(self):
        self.root = temp_dir(self, "forge-toolsrt-")
        self.ledger_path = self.root / "engagement.jsonl"
        self._env = {}
        self._set_env(toolsinstall.TOOLS_DIR_ENV, str(self.root / "tools"))
        self._set_env(toolsinstall.LEDGER_ENV, None)          # jamais d'heritage depuis l'hote
        self.zip_bytes = _zip_bytes({"toolx": BIN_PAYLOAD})
        self.tar_bytes = _targz_bytes({"toolx-1.0-linux/toolx": BIN_PAYLOAD})

    def _set_env(self, key, value):
        if key not in self._env:
            self._env[key] = os.environ.get(key)
            self.addCleanup(self._restore, key)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

    def _restore(self, key):
        old = self._env.get(key)
        if old is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old

    def manifest(self, *, digest=None, archive="zip", member="toolx", version="1.0",
                 arches=("amd64",), name="toolx"):
        payload = self.zip_bytes if archive == "zip" else self.tar_bytes
        d = digest or _sha(payload)
        raw = {"schema": 1, "tools": [{
            "name": name, "group": "core", "version": version, "archive": archive,
            "url": "https://tools.invalid/{version}/" + name + ".bin",
            "member": member, "bin": name, "sha256": {a: d for a in arches}}]}
        return toolsmanifest.Manifest(raw, path="<test>")

    def opener(self, *, version="1.0", archive="zip", name="toolx", payload=None):
        url = f"https://tools.invalid/{version}/{name}.bin"
        body = payload if payload is not None else (self.zip_bytes if archive == "zip" else self.tar_bytes)
        return FakeOpener({url: body})

    def install(self, **kw):
        kw.setdefault("manifest", self.manifest())
        kw.setdefault("arch", "amd64")
        kw.setdefault("ledger_path", str(self.ledger_path))
        kw.setdefault("opener", self.opener())
        kw.setdefault("sleep", lambda *_: None)
        return toolsinstall.install(kw.pop("name", "toolx"), **kw)

    def ledger_kinds(self):
        if not self.ledger_path.exists():
            return []
        return [json.loads(l)["kind"]
                for l in self.ledger_path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def ledger_entries(self, kind):
        if not self.ledger_path.exists():
            return []
        out = []
        for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec["kind"] == kind:
                out.append(rec["detail"])
        return out


# =================================================================================================
#  Chemin nominal — ce qui doit marcher, et ce qui doit etre trace
# =================================================================================================
class TestInstallHappyPath(ToolsInstallCase):
    def test_binary_lands_executable_in_the_tools_dir(self):
        res = self.install()
        dest = toolsinstall.bin_dir() / "toolx"
        self.assertEqual(res["action"], "installed")
        self.assertTrue(dest.exists())
        self.assertEqual(dest.read_bytes(), BIN_PAYLOAD)
        self.assertTrue(toolsinstall.is_executable(dest))
        self.assertEqual(os.stat(dest).st_mode & 0o777, 0o755)

    def test_url_comes_from_the_manifest_and_nothing_else_is_fetched(self):
        op = self.opener()
        self.install(opener=op)
        self.assertEqual(op.calls, ["https://tools.invalid/1.0/toolx.bin"])

    def test_the_api_exposes_no_url_or_digest_parameter(self):
        """La garantie « source allowlistee » tient a l'ABSENCE de ces parametres : on la verrouille
        ici pour qu'un ajout futur (par commodite) ne passe pas inapercu."""
        for forbidden in ("url", "sha256", "digest"):
            with self.assertRaises(TypeError):
                toolsinstall.install("toolx", **{forbidden: "x"})

    def test_receipt_records_the_verified_digest(self):
        res = self.install()
        receipt = json.loads(toolsinstall.receipt_path("toolx").read_text(encoding="utf-8"))
        self.assertEqual(receipt["version"], "1.0")
        self.assertEqual(receipt["sha256"], _sha(self.zip_bytes))
        self.assertEqual(receipt["sha256"], res["sha256"])

    def test_ledger_entry_carries_name_version_digest_and_actor_and_still_verifies(self):
        self.install(actor="alice")
        self.assertIn("tools.install", self.ledger_kinds())
        detail = self.ledger_entries("tools.install")[0]
        self.assertEqual(detail["name"], "toolx")
        self.assertEqual(detail["version"], "1.0")
        self.assertEqual(detail["arch"], "amd64")
        self.assertEqual(detail["sha256"], _sha(self.zip_bytes))
        self.assertEqual(detail["actor"], "alice")
        self.assertEqual(detail["url"], "https://tools.invalid/1.0/toolx.bin")
        self.assertTrue(Ledger(self.ledger_path).verify()["ok"])

    def test_targz_member_with_a_directory_prefix_is_extracted(self):
        man = self.manifest(archive="tar.gz", member="toolx-1.0-linux/toolx",
                            digest=_sha(self.tar_bytes))
        self.install(manifest=man, opener=self.opener(archive="tar.gz"))
        self.assertEqual((toolsinstall.bin_dir() / "toolx").read_bytes(), BIN_PAYLOAD)

    def test_glob_member_is_resolved(self):
        man = self.manifest(archive="tar.gz", member="*/toolx", digest=_sha(self.tar_bytes))
        self.install(manifest=man, opener=self.opener(archive="tar.gz"))
        self.assertEqual((toolsinstall.bin_dir() / "toolx").read_bytes(), BIN_PAYLOAD)

    def test_second_install_of_the_same_version_is_a_no_op(self):
        self.install()
        op = self.opener()
        res = self.install(opener=op)
        self.assertEqual(res["action"], "unchanged")
        self.assertEqual(op.calls, [], "une version deja installee ne doit pas etre re-telechargee")

    def test_update_reinstalls_and_is_logged_as_an_update(self):
        self.install()
        newer = _zip_bytes({"toolx": b"#!/bin/sh\necho v2\n"})
        man = self.manifest(version="2.0", digest=_sha(newer))
        res = toolsinstall.update("toolx", manifest=man, arch="amd64",
                                  ledger_path=str(self.ledger_path),
                                  opener=self.opener(version="2.0", payload=newer),
                                  sleep=lambda *_: None)
        self.assertEqual(res["action"], "updated")
        self.assertEqual(res["previous_version"], "1.0")
        self.assertIn("tools.update", self.ledger_kinds())
        self.assertEqual((toolsinstall.bin_dir() / "toolx").read_bytes(), b"#!/bin/sh\necho v2\n")
        self.assertTrue(Ledger(self.ledger_path).verify()["ok"])

    def test_remove_deletes_binary_and_receipt_and_is_logged(self):
        self.install()
        res = toolsinstall.remove("toolx", manifest=self.manifest(),
                                  ledger_path=str(self.ledger_path), actor="bob")
        self.assertEqual(res["action"], "removed")
        self.assertFalse((toolsinstall.bin_dir() / "toolx").exists())
        self.assertFalse(toolsinstall.receipt_path("toolx").exists())
        self.assertEqual(self.ledger_entries("tools.remove")[0]["actor"], "bob")
        self.assertTrue(Ledger(self.ledger_path).verify()["ok"])

    def test_remove_of_an_absent_tool_is_logged_and_harmless(self):
        res = toolsinstall.remove("toolx", manifest=self.manifest(),
                                  ledger_path=str(self.ledger_path))
        self.assertEqual(res["action"], "absent")
        self.assertIn("tools.remove", self.ledger_kinds())

    def test_status_reports_target_and_installed_versions_without_executing_anything(self):
        man = self.manifest()
        before = toolsinstall.status(manifest=man, arch="amd64")[0]
        self.assertEqual(before["source"], "absent")
        self.assertEqual(before["version"], "1.0")
        self.install(manifest=man)
        os.environ["PATH"] = f"{toolsinstall.bin_dir()}{os.pathsep}{os.environ['PATH']}"
        self.addCleanup(os.environ.__setitem__, "PATH", os.environ["PATH"].split(os.pathsep, 1)[1])
        after = toolsinstall.status(manifest=man, arch="amd64")[0]
        self.assertEqual(after["source"], "runtime")
        self.assertEqual(after["installed_version"], "1.0")
        self.assertTrue(after["up_to_date"])


# =================================================================================================
#  Integrite — le coeur de la gouvernance
# =================================================================================================
class TestIntegrityFailsClosed(ToolsInstallCase):
    def test_digest_mismatch_refuses_and_installs_nothing(self):
        man = self.manifest(digest="b" * 64)
        with self.assertRaises(toolsinstall.ToolInstallError) as ctx:
            self.install(manifest=man)
        self.assertIn("INTEGRITE", str(ctx.exception))
        self.assertFalse((toolsinstall.bin_dir() / "toolx").exists())
        self.assertFalse(toolsinstall.receipt_path("toolx").exists())

    def test_digest_mismatch_is_journalled_as_a_refusal(self):
        with self.assertRaises(toolsinstall.ToolInstallError):
            self.install(manifest=self.manifest(digest="b" * 64))
        refused = self.ledger_entries("tools.refused")
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["expected_sha256"], "b" * 64)
        self.assertEqual(refused[0]["actual_sha256"], _sha(self.zip_bytes))
        self.assertNotIn("tools.install", self.ledger_kinds())
        self.assertTrue(Ledger(self.ledger_path).verify()["ok"])

    def test_no_staging_residue_is_left_after_a_refusal(self):
        with self.assertRaises(toolsinstall.ToolInstallError):
            self.install(manifest=self.manifest(digest="b" * 64))
        staging = toolsinstall.tools_dir() / ".staging"
        self.assertEqual(list(staging.iterdir()) if staging.exists() else [], [])

    def test_missing_pin_for_the_target_arch_refuses_before_any_network(self):
        op = self.opener()
        with self.assertRaises(toolsinstall.ToolInstallError) as ctx:
            self.install(manifest=self.manifest(arches=("amd64",)), arch="arm64", opener=op)
        self.assertIn("aucun pin", str(ctx.exception).lower())
        self.assertEqual(op.calls, [], "aucun octet ne doit partir sans pin")

    def test_unknown_architecture_refuses_before_any_network(self):
        op = self.opener()
        with self.assertRaises(toolsinstall.ToolInstallError):
            self.install(arch="riscv64", opener=op)
        self.assertEqual(op.calls, [])

    def test_a_truncated_download_is_caught_by_the_digest(self):
        op = FakeOpener({"https://tools.invalid/1.0/toolx.bin": self.zip_bytes[:-5]})
        with self.assertRaises(toolsinstall.ToolInstallError):
            self.install(opener=op)
        self.assertFalse((toolsinstall.bin_dir() / "toolx").exists())


# =================================================================================================
#  Allowlist de source
# =================================================================================================
class TestSourceAllowlist(ToolsInstallCase):
    def test_a_tool_absent_from_the_manifest_is_not_installable(self):
        op = self.opener()
        with self.assertRaises(toolsinstall.ToolInstallError) as ctx:
            self.install(name="evilcorp-implant", opener=op)
        self.assertIn("absent du manifeste", str(ctx.exception))
        self.assertEqual(op.calls, [])

    def test_a_manifest_with_a_plain_http_url_cannot_even_be_loaded(self):
        raw = {"schema": 1, "tools": [{
            "name": "toolx", "version": "1.0", "archive": "zip",
            "url": "http://tools.invalid/toolx.bin", "member": "toolx",
            "sha256": {"amd64": "a" * 64}}]}
        with self.assertRaises(toolsmanifest.ManifestError):
            toolsmanifest.Manifest(raw, path="<test>")

    def test_a_redirect_leaving_https_is_refused(self):
        handler = toolsinstall._HttpsOnlyRedirect()
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(object(), None, 302, "Found", {},
                                     "http://downgrade.invalid/payload")

    def test_the_default_opener_carries_the_redirect_guard(self):
        opener = toolsinstall._default_opener()
        self.assertTrue(any(isinstance(h, toolsinstall._HttpsOnlyRedirect) for h in opener.handlers))


# =================================================================================================
#  Pas de shell, pas d'evasion de chemin
# =================================================================================================
class TestNoShellNoEscape(ToolsInstallCase):
    def test_no_subprocess_is_spawned_at_any_point(self):
        """Ni curl, ni unzip, ni tar : urllib + zipfile. On instrumente `subprocess.Popen` : le moindre
        lancement de processus ferait echouer ce test (et signalerait une porte ouverte au shell)."""
        spawned = []
        real = subprocess.Popen

        def spy(*a, **kw):
            spawned.append(a[0] if a else kw.get("args"))
            return real(*a, **kw)

        subprocess.Popen = spy
        self.addCleanup(setattr, subprocess, "Popen", real)
        self.install()
        self.assertEqual(spawned, [])

    def test_a_hostile_archive_member_cannot_write_outside_the_tools_dir(self):
        """Le nom du membre n'est JAMAIS utilise comme chemin d'ecriture : meme un membre nomme
        `../../evil` atterrit sous le nom `bin` que NOUS avons fixe, dans le repertoire outils."""
        hostile = _zip_bytes({"../../evil": BIN_PAYLOAD})
        man = self.manifest(member="*evil*", digest=_sha(hostile))
        self.install(manifest=man, opener=self.opener(payload=hostile))
        self.assertTrue((toolsinstall.bin_dir() / "toolx").exists())
        self.assertFalse((self.root / "evil").exists())
        self.assertFalse((toolsinstall.tools_dir().parent / "evil").exists())

    def test_an_ambiguous_or_missing_member_is_refused(self):
        two = _zip_bytes({"a/toolx": BIN_PAYLOAD, "b/toolx": BIN_PAYLOAD})
        man = self.manifest(member="*/toolx", digest=_sha(two))
        with self.assertRaises(toolsinstall.ToolInstallError):
            self.install(manifest=man, opener=self.opener(payload=two))
        empty = _zip_bytes({"autre": BIN_PAYLOAD})
        man2 = self.manifest(member="toolx", digest=_sha(empty))
        with self.assertRaises(toolsinstall.ToolInstallError):
            self.install(manifest=man2, opener=self.opener(payload=empty))
        self.assertFalse((toolsinstall.bin_dir() / "toolx").exists())


# =================================================================================================
#  Ledger obligatoire
# =================================================================================================
class TestLedgerIsMandatory(ToolsInstallCase):
    def test_install_without_a_resolvable_ledger_is_refused_before_any_network(self):
        op = self.opener()
        with self.assertRaises(toolsinstall.ToolInstallError) as ctx:
            toolsinstall.install("toolx", manifest=self.manifest(), arch="amd64",
                                 ledger_path=None, opener=op)
        self.assertIn("ledger", str(ctx.exception).lower())
        self.assertEqual(op.calls, [])
        self.assertFalse(toolsinstall.bin_dir().exists())

    def test_remove_without_a_resolvable_ledger_is_refused(self):
        with self.assertRaises(toolsinstall.ToolInstallError):
            toolsinstall.remove("toolx", manifest=self.manifest(), ledger_path=None)

    def test_the_environment_ledger_is_honoured(self):
        self._set_env(toolsinstall.LEDGER_ENV, str(self.ledger_path))
        toolsinstall.install("toolx", manifest=self.manifest(), arch="amd64",
                             opener=self.opener(), sleep=lambda *_: None)
        self.assertIn("tools.install", self.ledger_kinds())

    def test_every_capability_change_ends_up_in_a_verifiable_chain(self):
        self.install()
        with self.assertRaises(toolsinstall.ToolInstallError):
            self.install(manifest=self.manifest(digest="c" * 64), force=True)
        toolsinstall.remove("toolx", manifest=self.manifest(), ledger_path=str(self.ledger_path))
        self.assertEqual(self.ledger_kinds(), ["tools.install", "tools.refused", "tools.remove"])
        self.assertTrue(Ledger(self.ledger_path).verify()["ok"])


# =================================================================================================
#  Aucune elevation — l'outil installe reste sous les memes gates
# =================================================================================================
class TestNoPrivilegeEscalation(ToolsInstallCase):
    def test_a_runtime_installed_tool_is_still_scope_guarded(self):
        """L'outil devient RESOLVABLE sur le PATH, donc `available` passe a True — et c'est tout : la
        cible hors perimetre reste refusee AVANT tout lancement de processus."""
        self.install()
        old_path = os.environ["PATH"]
        os.environ["PATH"] = f"{toolsinstall.bin_dir()}{os.pathsep}{old_path}"
        self.addCleanup(os.environ.__setitem__, "PATH", old_path)

        spec = ToolSpec("recon.toolx", "Recon", "toolx", ("{target}",))
        mod = make_module(spec)()
        self.assertTrue(mod.available, "le binaire installe doit etre resolu par shutil.which")

        spawned = []
        real = subprocess.Popen
        subprocess.Popen = lambda *a, **kw: spawned.append(a) or real(*a, **kw)
        self.addCleanup(setattr, subprocess, "Popen", real)

        act = Action("recon.toolx", "hors-perimetre.invalid",
                     params={"in_scope": ["autorise.invalid"], "out_scope": []})
        findings = mod.fire(act)
        self.assertTrue(all(f.status == "skipped" for f in findings))
        self.assertTrue(any("hors périmètre" in f.title for f in findings))
        self.assertEqual(spawned, [], "scope-guard fail-closed : aucun processus lance")

    def test_installing_a_tool_does_not_touch_the_exploit_floor(self):
        """Le contrat `Module` est inchange : `exploit`/`destructive` restent declares par le spec."""
        self.install()
        spec = ToolSpec("sqli.toolx", "SQLi", "toolx", ("{target}",), exploit=True)
        mod = make_module(spec)()
        self.assertTrue(mod.exploit)


# =================================================================================================
#  No-op par defaut + surface CLI
# =================================================================================================
class TestDefaultIsNoOp(unittest.TestCase):
    def test_importing_the_installer_creates_nothing_and_probes_nothing(self):
        import importlib
        root = temp_dir(self, "forge-noop-")
        old = os.environ.get(toolsinstall.TOOLS_DIR_ENV)
        os.environ[toolsinstall.TOOLS_DIR_ENV] = str(root / "tools")
        self.addCleanup(lambda: os.environ.__setitem__(toolsinstall.TOOLS_DIR_ENV, old)
                        if old is not None else os.environ.pop(toolsinstall.TOOLS_DIR_ENV, None))
        importlib.reload(toolsinstall)
        self.assertFalse(toolsinstall.tools_dir().exists())
        self.assertFalse(toolsinstall.bin_dir().exists())
        self.assertFalse(toolsinstall.state_dir().exists())

    def test_status_does_not_create_the_tools_directory(self):
        root = temp_dir(self, "forge-noop-")
        old = os.environ.get(toolsinstall.TOOLS_DIR_ENV)
        os.environ[toolsinstall.TOOLS_DIR_ENV] = str(root / "tools")
        self.addCleanup(lambda: os.environ.__setitem__(toolsinstall.TOOLS_DIR_ENV, old)
                        if old is not None else os.environ.pop(toolsinstall.TOOLS_DIR_ENV, None))
        rows = toolsinstall.status()
        self.assertTrue(rows)
        self.assertFalse(toolsinstall.tools_dir().exists())

    def test_no_engine_module_imports_the_installer(self):
        """La surcouche est un OUTIL OPERATEUR, pas un chemin d'execution : aucun module du moteur ne
        doit en dependre (sinon un run pourrait, un jour, installer quelque chose tout seul)."""
        import ast
        root = Path(__file__).resolve().parents[1] / "forge"
        offenders = []
        for py in sorted(root.rglob("*.py")):
            if py.name == "toolsinstall.py" or py.parent.name == "cli":
                continue
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
            for node in ast.walk(tree):                 # IMPORTS reels, pas une mention en docstring
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""] + [a.name for a in node.names]
                if any("toolsinstall" in n for n in names):
                    offenders.append(str(py.relative_to(root.parent)))
                    break
        self.assertEqual(offenders, [])

    def test_the_existing_cli_surface_is_unchanged_and_tools_is_purely_additive(self):
        from forge.cli import build_parser
        sub = next(a for a in build_parser()._actions if hasattr(a, "choices") and a.choices
                   and "run" in a.choices)
        for previous in ("scope-check", "plan", "run", "campaign", "ledger", "modules",
                         "techniques", "workflows", "doctor", "import", "demo", "detections"):
            self.assertIn(previous, sub.choices)
        self.assertIn("tools", sub.choices)


class TestToolsCli(ToolsInstallCase):
    def _cli(self, *argv):
        from forge.cli import main
        return main(list(argv))

    def test_list_json_describes_every_manifest_tool(self):
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._cli("tools", "list", "--json")
        self.assertEqual(rc, 0)
        rows = json.loads(buf.getvalue())
        self.assertEqual({r["name"] for r in rows}, set(toolsmanifest.load().names()))

    def test_install_without_a_ledger_exits_nonzero_and_says_why(self):
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._cli("tools", "install", "httpx")
        self.assertEqual(rc, 1)
        self.assertIn("REFUS", buf.getvalue())
        self.assertIn("ledger", buf.getvalue().lower())

    def test_install_of_an_unknown_tool_exits_nonzero(self):
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self._cli("tools", "install", "pas-un-outil", "--ledger", str(self.ledger_path))
        self.assertEqual(rc, 1)
        self.assertIn("absent du manifeste", buf.getvalue())

    def test_the_cli_offers_no_url_or_sha_option(self):
        import contextlib
        from forge.cli import build_parser
        for option in ("--url", "--sha256"):
            with contextlib.redirect_stderr(io.StringIO()):   # argparse ecrit son usage sur stderr
                with self.assertRaises(SystemExit):
                    build_parser().parse_args(
                        ["tools", "install", "httpx", option, "https://evil.invalid/x"])


if __name__ == "__main__":
    unittest.main()

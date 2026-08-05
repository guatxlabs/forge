# SPDX-License-Identifier: AGPL-3.0-or-later
"""Manifeste d'outils — source UNIQUE, fin de la duplication Dockerfile↔compose, et PREUVE que la
boucle d'installation du build le consomme correctement.

Trois familles de tests :

  1. **Schema & pins** — le manifeste charge, chaque digest est 64 hexa minuscules, chaque URL est un
     gabarit HTTPS, le groupe socle `core` est pinne pour amd64 ET arm64, et l'emetteur refuse
     fail-closed tout ce qui est malforme (digest tronque, URL http://, `bin` avec un `/`, doublon).

  2. **Non-duplication (la raison d'etre du lot)** — AUCUNE version ni AUCUN digest d'outil ne doit
     reapparaitre dans `Dockerfile` ou `docker-compose.yml`. C'est la garde qui empeche la classe de
     bug d'origine (deux copies d'un pin qui divergent en silence) de revenir en douce.

  3. **La boucle du build est EXECUTEE** — le bloc `RUN` du Dockerfile est extrait et joue REELLEMENT
     sous `sh`, avec `curl`/`sha256sum`/`unzip`/`tar`/`install` remplaces par des doublures qui
     JOURNALISENT leurs arguments. On verifie que, pour chaque outil du manifeste : la bonne URL est
     telechargee, le bon digest est presente a `sha256sum -c`, le bon membre est extrait avec le bon
     `--strip-components`, et le binaire est pose sous le bon nom. Un `sha256sum` qui ECHOUE doit faire
     ECHOUER tout le bloc sans rien installer — le fail-closed du build, prouve et pas seulement ecrit.
     (Un `docker build` reel n'est pas jouable en CI : c'est ce test qui tient lieu de preuve.)
"""
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import toolsmanifest                                        # noqa: E402
from tests._tmp import temp_dir                                        # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE = ROOT / "docker-compose.yml"
MANIFEST = ROOT / "forge" / "tools.json"
EMITTER = ROOT / "forge" / "toolsmanifest.py"

# Les 12 outils telecharges, avec leur URL amd64 EXACTE. Golden explicite : si un pin/gabarit change,
# ce test le dit, avec le nom de l'outil. (C'etait, mot pour mot, ce que le Dockerfile codait en dur.)
GOLDEN_AMD64 = {
    "httpx": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip",
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip",
    "subfinder": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip",
    "dnsx": "https://github.com/projectdiscovery/dnsx/releases/download/v1.3.0/dnsx_1.3.0_linux_amd64.zip",
    "naabu": "https://github.com/projectdiscovery/naabu/releases/download/v2.6.1/naabu_2.6.1_linux_amd64.zip",
    "katana": "https://github.com/projectdiscovery/katana/releases/download/v1.6.1/katana_1.6.1_linux_amd64.zip",
    "amass": "https://github.com/owasp-amass/amass/releases/download/v5.1.1/amass_linux_amd64.tar.gz",
    "gau": "https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_amd64.tar.gz",
    "gospider": "https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_linux_x86_64.zip",
    "dalfox": "https://github.com/hahwul/dalfox/releases/download/v3.1.2/dalfox-v3.1.2-linux-x86_64.tar.gz",
    "feroxbuster": "https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.tar.gz",
    "ffuf": "https://github.com/ffuf/ffuf/releases/download/v2.2.1/ffuf_2.2.1_linux_amd64.tar.gz",
}
# Membre d'archive + profondeur de strip attendus (l'ancien Dockerfile les codait un par un).
GOLDEN_MEMBER_AMD64 = {
    "amass": ("amass_linux_amd64/amass", 1),
    "gospider": ("*/gospider", 1),
    "dalfox": ("dalfox-v3.1.2-linux-x86_64/dalfox", 1),
    "ffuf": ("ffuf", 0),
    "httpx": ("httpx", 0),
}

_SHA_RX = re.compile(r"\b[0-9a-f]{64}\b")


def _load():
    return toolsmanifest.load(MANIFEST)


# =================================================================================================
#  1. Schema & pins
# =================================================================================================
class TestManifestSchema(unittest.TestCase):
    def setUp(self):
        self.man = _load()

    def test_loads_and_covers_the_twelve_downloaded_tools(self):
        self.assertEqual(sorted(self.man.names()), sorted(GOLDEN_AMD64))

    def test_every_url_is_an_https_template_and_every_digest_is_64_lowercase_hex(self):
        for t in self.man:
            self.assertTrue(t.url_template.startswith("https://"), t.name)
            self.assertTrue(t.sha256, f"{t.name}: aucun pin — un outil sans digest serait non installable")
            for arch, digest in t.sha256.items():
                self.assertIn(arch, toolsmanifest.ARCH_ALIASES, t.name)
                self.assertRegex(digest, r"^[0-9a-f]{64}$", t.name)

    def test_core_group_is_pinned_for_both_architectures(self):
        """Le socle est promis par l'image `full` sur amd64 ET arm64 : un pin manquant doit casser le
        build (`--require-complete core`), jamais produire une image amputee."""
        for arch in ("amd64", "arm64"):
            toolsmanifest.require_complete(self.man, arch, "core", profile="full")
        self.assertEqual(sorted(t.name for t in self.man.select(group="core")),
                         ["httpx", "nuclei", "subfinder"])

    def test_extended_group_is_amd64_only_and_degrades_instead_of_failing(self):
        """Comportement historique conserve : hors amd64, la suite etendue est ECARTEE du plan (jamais
        telechargee non verifiee) et les modules degradent en available:false."""
        self.assertEqual(self.man.select(group="extended", arch="arm64"), [])
        self.assertEqual(sorted(toolsmanifest.omitted(self.man, "arm64", group="extended")),
                         sorted(n for n in GOLDEN_AMD64 if n not in ("httpx", "nuclei", "subfinder")))
        with self.assertRaises(toolsmanifest.ManifestError):
            toolsmanifest.require_complete(self.man, "arm64", "extended")

    def test_urls_members_and_strip_depth_match_the_previously_hardcoded_values(self):
        for name, url in GOLDEN_AMD64.items():
            self.assertEqual(self.man.get(name).url("amd64"), url, name)
        for name, (member, strip) in GOLDEN_MEMBER_AMD64.items():
            entry = self.man.get(name)
            self.assertEqual(entry.member("amd64"), member, name)
            self.assertEqual(entry.strip_components("amd64"), strip, name)

    def test_arm64_core_pins_differ_from_amd64(self):
        """Garde-fou contre le copier-coller : un digest arm64 identique a l'amd64 serait un pin faux."""
        for name in ("httpx", "nuclei", "subfinder"):
            e = self.man.get(name)
            self.assertNotEqual(e.digest("amd64"), e.digest("arm64"), name)

    def test_emitted_fields_never_contain_whitespace(self):
        """La boucle du Dockerfile lit avec l'IFS par defaut : un champ a espace la casserait."""
        for arch in ("amd64", "arm64"):
            for row in toolsmanifest.emit_rows(self.man, arch):
                self.assertEqual(len(row.split(" ")), 8, row)


class TestManifestFailsClosed(unittest.TestCase):
    """Un manifeste malforme doit etre REFUSE au chargement — jamais tolere puis telecharge."""

    BASE = {"name": "x", "group": "core", "version": "1.0", "archive": "zip",
            "url": "https://example.invalid/x-{version}.zip", "member": "x",
            "sha256": {"amd64": "a" * 64}}

    def _load(self, **over):
        raw = {"schema": 1, "tools": [dict(self.BASE, **over)]}
        return toolsmanifest.Manifest(raw, path="<test>")

    def test_baseline_entry_is_accepted(self):
        self.assertEqual(len(self._load()), 1)

    def test_non_https_url_is_refused(self):
        with self.assertRaises(toolsmanifest.ManifestError):
            self._load(url="http://example.invalid/x.zip")

    def test_truncated_or_uppercase_digest_is_refused(self):
        for bad in ("a" * 63, "A" * 64, "zz" + "a" * 62, ""):
            with self.assertRaises(toolsmanifest.ManifestError):
                self._load(sha256={"amd64": bad})

    def test_missing_sha256_block_is_refused(self):
        with self.assertRaises(toolsmanifest.ManifestError):
            self._load(sha256={})

    def test_unknown_architecture_is_refused(self):
        with self.assertRaises(toolsmanifest.ManifestError):
            self._load(sha256={"riscv64": "a" * 64})

    def test_bin_with_a_path_separator_is_refused(self):
        for bad in ("../evil", "sub/dir", "/absolute"):
            with self.assertRaises(toolsmanifest.ManifestError):
                self._load(bin=bad)

    def test_member_escaping_the_archive_is_refused(self):
        for bad in ("../outside", "/etc/shadow"):
            with self.assertRaises(toolsmanifest.ManifestError):
                self._load(member=bad)

    def test_unknown_archive_kind_is_refused(self):
        with self.assertRaises(toolsmanifest.ManifestError):
            self._load(archive="rar")

    def test_duplicate_tool_names_are_refused(self):
        raw = {"schema": 1, "tools": [dict(self.BASE), dict(self.BASE)]}
        with self.assertRaises(toolsmanifest.ManifestError):
            toolsmanifest.Manifest(raw, path="<test>")

    def test_unsupported_schema_version_is_refused(self):
        with self.assertRaises(toolsmanifest.ManifestError):
            toolsmanifest.Manifest({"schema": 999, "tools": [dict(self.BASE)]}, path="<test>")

    def test_entry_without_pin_for_target_arch_is_never_emitted(self):
        man = self._load(sha256={"amd64": "a" * 64})
        self.assertEqual(toolsmanifest.emit_rows(man, "arm64"), [])
        self.assertEqual(toolsmanifest.omitted(man, "arm64"), ["x"])


# =================================================================================================
#  2. Non-duplication — plus AUCUN pin recopie dans le Dockerfile ni dans le compose
# =================================================================================================
class TestNoDuplicatedPins(unittest.TestCase):
    def setUp(self):
        self.man = _load()
        self.docker = DOCKERFILE.read_text(encoding="utf-8")
        self.compose = COMPOSE.read_text(encoding="utf-8")

    def test_no_tool_version_is_repeated_in_dockerfile_or_compose(self):
        for t in self.man:
            for where, text in (("Dockerfile", self.docker), ("docker-compose.yml", self.compose)):
                self.assertNotIn(
                    t.version, text,
                    f"{where} contient encore la version {t.version} de {t.name} — le manifeste "
                    f"forge/tools.json est la source UNIQUE (c'est cette duplication qu'on ferme)")

    def test_no_tool_digest_is_repeated_in_dockerfile_or_compose(self):
        # On cible les digests D'OUTILS. Un digest d'IMAGE docker (`postgres:16@sha256:…`) est un pin
        # legitime d'une autre nature, qui n'a jamais ete duplique — il n'est pas concerne.
        pinned = {d for t in self.man for d in t.sha256.values()}
        for where, text in (("Dockerfile", self.docker), ("docker-compose.yml", self.compose)):
            leaked = sorted(pinned.intersection(_SHA_RX.findall(text)))
            self.assertEqual([], leaked,
                             f"{where} contient encore un digest d'outil en dur ({leaked}) — ils "
                             f"vivent dans forge/tools.json, source unique")

    def test_the_build_no_longer_declares_tool_pins_as_build_args(self):
        """Forme historique de la duplication : `ARG <OUTIL>_VERSION=` / `ARG <OUTIL>_SHA256_<arch>=`
        dans le Dockerfile, repropages en `args:` par le compose. Aucun ne doit subsister."""
        for where, text in (("Dockerfile", self.docker), ("docker-compose.yml", self.compose)):
            for t in self.man:
                upper = t.name.upper()
                self.assertNotIn(f"{upper}_VERSION", text, f"{where}: ARG de version residuel {t.name}")
                self.assertNotIn(f"{upper}_SHA256", text, f"{where}: ARG de digest residuel {t.name}")

    def test_no_tool_url_is_repeated_in_dockerfile_or_compose(self):
        for t in self.man:
            for arch in t.sha256:
                url = t.url(arch)
                self.assertNotIn(url, self.docker, f"{t.name}: URL encore en dur dans le Dockerfile")
                self.assertNotIn(url, self.compose, f"{t.name}: URL encore en dur dans le compose")

    def test_dockerfile_reads_the_manifest(self):
        """La contrepartie du test precedent : sans cette assertion, supprimer purement et simplement
        l'installation des outils passerait pour une « fin de duplication »."""
        self.assertIn("COPY forge/tools.json forge/toolsmanifest.py", self.docker)
        self.assertIn("--require-complete core", self.docker)

    def test_compose_still_drives_the_build_profile_only(self):
        self.assertIn("FORGE_TOOLS_PROFILE", self.compose)

    def test_persistent_tools_volume_is_declared_end_to_end(self):
        self.assertIn('"/data/tools"', self.docker)                   # VOLUME
        self.assertIn("/data/tools/bin", self.docker)                 # PATH + mkdir
        self.assertIn("FORGE_TOOLS_DIR=/data/tools", self.docker)
        self.assertIn("forge-tools:/data/tools", self.compose)
        self.assertIn("\n  forge-tools:\n", self.compose)             # declaration du volume nomme

    def test_operator_mount_keeps_priority_over_the_runtime_layer_on_path(self):
        """L'ordre du PATH est un choix : le bind-mount operateur (/opt/tools) garde la priorite qu'il
        a toujours eue ; la couche runtime s'insere derriere lui mais DEVANT le /usr/local/bin bake."""
        self.assertIn('ENV PATH="/opt/tools:/data/tools/bin:${PATH}"', self.docker)


# =================================================================================================
#  3. La boucle d'installation du Dockerfile, REELLEMENT EXECUTEE (doublures instrumentees)
# =================================================================================================
STUBS = {
    # Journalise l'URL demandee et fabrique une archive factice a l'emplacement `-o`.
    "curl": """#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf 'CURL %s -> %s\\n' "$url" "$out" >> "$FORGE_TEST_LOG"
printf 'archive-factice' > "$out"
""",
    # Journalise la ligne "<digest>  <fichier>" recue sur stdin. FORGE_TEST_SHA_FAIL simule un
    # digest non concordant : le build DOIT alors echouer (set -e) sans rien installer.
    "sha256sum": """#!/bin/sh
IFS= read -r line
printf 'SHA %s\\n' "$line" >> "$FORGE_TEST_LOG"
if [ -n "${FORGE_TEST_SHA_FAIL:-}" ]; then
  printf 'sha256sum: WARNING: 1 computed checksum did NOT match\\n' >&2
  exit 1
fi
exit 0
""",
    "unzip": """#!/bin/sh
archive=""; member=""; dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-j) shift ;;
    -d) dir="$2"; shift 2 ;;
    *) if [ -z "$archive" ]; then archive="$1"; else member="$1"; fi; shift ;;
  esac
done
printf 'UNZIP member=%s dir=%s\\n' "$member" "$dir" >> "$FORGE_TEST_LOG"
mkdir -p "$dir"
printf 'binaire' > "$dir/$(basename "$member")"
""",
    "tar": """#!/bin/sh
archive=""; strip=""; dir=""; member=""
while [ $# -gt 0 ]; do
  case "$1" in
    -xzf) archive="$2"; shift 2 ;;
    --strip-components=*) strip="${1#--strip-components=}"; shift ;;
    -C) dir="$2"; shift 2 ;;
    *) member="$1"; shift ;;
  esac
done
printf 'TAR member=%s strip=%s dir=%s\\n' "$member" "$strip" "$dir" >> "$FORGE_TEST_LOG"
mkdir -p "$dir"
printf 'binaire' > "$dir/$(basename "$member")"
""",
    "install": """#!/bin/sh
mode=""; src=""; dest=""
while [ $# -gt 0 ]; do
  case "$1" in
    -m) mode="$2"; shift 2 ;;
    *) if [ -z "$src" ]; then src="$1"; else dest="$1"; fi; shift ;;
  esac
done
printf 'INSTALL mode=%s dest=%s\\n' "$mode" "$dest" >> "$FORGE_TEST_LOG"
mkdir -p "$(dirname "$dest")"
cp "$src" "$dest"
""",
}


def dockerfile_tools_block():
    """Extrait le corps shell du `RUN` d'installation des outils (celui qui lit le manifeste).

    On l'identifie par la seam `FORGE_BUILD_MANIFEST_PY` — presente UNIQUEMENT dans ce bloc — puis on
    remonte au `RUN ` et on descend jusqu'a la derniere ligne de continuation. On rend le texte tel
    quel : `sh` gere lui-meme les `\\`-retours a la ligne."""
    lines = DOCKERFILE.read_text(encoding="utf-8").splitlines()
    anchor = next(i for i, l in enumerate(lines) if "FORGE_BUILD_MANIFEST_PY" in l)
    start = anchor
    while not lines[start].startswith("RUN "):
        start -= 1
    end = start
    while lines[end].rstrip().endswith("\\"):
        end += 1
    return "\n".join(lines[start:end + 1])[len("RUN "):]


class TestDockerfileInstallLoopExecutes(unittest.TestCase):
    """Joue REELLEMENT la boucle du Dockerfile hors Docker. Un `docker build` n'etant pas jouable en
    CI (reseau + daemon), c'est ici que se prouve que le bloc consomme le manifeste correctement."""

    def setUp(self):
        self.work = temp_dir(self, "forge-toolsbuild-")
        self.stubs = self.work / "stubs"
        self.stubs.mkdir()
        for name, body in STUBS.items():
            p = self.stubs / name
            p.write_text(body, encoding="utf-8")
            p.chmod(0o755)
        self.log = self.work / "calls.log"
        self.bindir = self.work / "bin"
        self.script = dockerfile_tools_block()

    def _run(self, arch="amd64", profile="full", extra_env=None):
        env = dict(os.environ)
        env.update({
            "PATH": f"{self.stubs}{os.pathsep}{os.environ.get('PATH', '')}",
            "FORGE_TEST_LOG": str(self.log),
            "FORGE_TOOLS_PROFILE": profile,
            "TARGETARCH": arch,
            "FORGE_BUILD_MANIFEST_PY": str(EMITTER),
            "FORGE_BUILD_BINDIR": str(self.bindir),
            "FORGE_BUILD_STAGE": str(self.work / "stage"),
        })
        env.pop("FORGE_TEST_SHA_FAIL", None)
        env.update(extra_env or {})
        return subprocess.run(["sh", "-c", self.script], env=env, capture_output=True, text=True)

    def _calls(self, prefix):
        if not self.log.exists():
            return []
        return [l[len(prefix) + 1:] for l in self.log.read_text(encoding="utf-8").splitlines()
                if l.startswith(prefix + " ")]

    # --- chemin nominal -------------------------------------------------------------------------
    def test_amd64_installs_every_manifest_tool_from_the_manifest_url(self):
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        fetched = {line.split(" -> ")[0] for line in self._calls("CURL")}
        self.assertEqual(fetched, set(GOLDEN_AMD64.values()))

    def test_each_archive_is_checked_against_its_manifest_digest(self):
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        presented = {line.split()[0] for line in self._calls("SHA")}
        man = _load()
        self.assertEqual(presented, {t.digest("amd64") for t in man.select(arch="amd64")})

    def test_every_binary_lands_under_its_probed_name(self):
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        installed = sorted(p.name for p in self.bindir.iterdir())
        self.assertEqual(installed, sorted(GOLDEN_AMD64))
        for line in self._calls("INSTALL"):
            self.assertTrue(line.startswith("mode=0755 "), line)

    def test_tar_members_are_extracted_with_the_right_strip_depth(self):
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        seen = {}
        for line in self._calls("TAR"):                      # "member=<m> strip=<n> dir=<d>"
            parts = dict(tok.split("=", 1) for tok in line.split(" "))
            seen[parts["member"]] = parts["strip"]
        self.assertEqual(seen["amass_linux_amd64/amass"], "1")
        self.assertEqual(seen["dalfox-v3.1.2-linux-x86_64/dalfox"], "1")
        self.assertEqual(seen["ffuf"], "0")
        self.assertEqual(seen["gau"], "0")
        self.assertEqual(seen["feroxbuster"], "0")

    def test_zip_member_glob_is_passed_through_unexpanded(self):
        """`*/gospider` doit arriver TEL QUEL a unzip (c'est lui qui fait la correspondance) — un
        glob expanse par le shell viserait un fichier du repertoire courant."""
        self._run()
        self.assertIn("member=*/gospider dir=" + str(self.work / "stage" / "x"),
                      self._calls("UNZIP"))

    # --- fail-closed ----------------------------------------------------------------------------
    def test_a_digest_mismatch_fails_the_build_and_installs_nothing(self):
        r = self._run(extra_env={"FORGE_TEST_SHA_FAIL": "1"})
        self.assertNotEqual(r.returncode, 0, "un digest non concordant DOIT faire echouer le build")
        self.assertFalse(self.bindir.exists() and any(self.bindir.iterdir()),
                         "aucun binaire ne doit etre pose quand la verification echoue")

    def test_mini_profile_installs_nothing_and_never_reads_the_manifest(self):
        r = self._run(profile="mini")
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertFalse(self.log.exists(), "le profil mini ne doit lancer AUCUN telechargement")
        self.assertFalse(self.bindir.exists())
        self.assertIn("mini", r.stdout + r.stderr)

    def test_unsupported_architecture_is_a_hard_failure(self):
        r = self._run(arch="riscv64")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FATAL", r.stderr)

    def test_arm64_installs_only_the_pinned_core_and_reports_the_rest_as_omitted(self):
        r = self._run(arch="arm64")
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        self.assertEqual(sorted(p.name for p in self.bindir.iterdir()),
                         ["httpx", "nuclei", "subfinder"])
        self.assertIn("OMIS", r.stderr)
        presented = {line.split()[0] for line in self._calls("SHA")}
        man = _load()
        self.assertEqual(presented, {t.digest("arm64") for t in man.select(arch="arm64")})


class TestEmitterCli(unittest.TestCase):
    """L'emetteur est l'interface consommee par le Dockerfile : son contrat CLI est teste en propre."""

    def _emit(self, *argv):
        return subprocess.run([sys.executable, str(EMITTER), *argv],
                              capture_output=True, text=True)

    def test_plan_is_one_line_per_tool_with_eight_fields(self):
        r = self._emit("--arch", "amd64", "--profile", "full")
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = r.stdout.strip().splitlines()
        self.assertEqual(len(rows), len(GOLDEN_AMD64))
        for row in rows:
            self.assertEqual(len(row.split(" ")), 8, row)

    def test_require_complete_fails_when_a_pin_is_missing(self):
        broken = temp_dir(self, "forge-manifest-") / "tools.json"
        raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
        for tool in raw["tools"]:
            if tool["name"] == "httpx":
                tool["sha256"].pop("arm64")
        broken.write_text(json.dumps(raw), encoding="utf-8")
        r = self._emit("--arch", "arm64", "--profile", "full", "--require-complete", "core",
                       "--manifest", str(broken))
        self.assertEqual(r.returncode, 1)
        self.assertIn("FATAL", r.stderr)
        self.assertIn("httpx", r.stderr)
        self.assertEqual(r.stdout, "", "aucun plan ne doit sortir quand le socle est incomplet")

    def test_a_malformed_manifest_yields_a_fatal_and_no_plan(self):
        bad = temp_dir(self, "forge-manifest-") / "tools.json"
        bad.write_text('{"schema": 1, "tools": [{"name": "x"}]}', encoding="utf-8")
        r = self._emit("--arch", "amd64", "--manifest", str(bad))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, "")

    def test_omitted_tools_are_reported_on_stderr_not_stdout(self):
        r = self._emit("--arch", "arm64", "--profile", "full")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OMIS", r.stderr)
        self.assertEqual(len(r.stdout.strip().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()

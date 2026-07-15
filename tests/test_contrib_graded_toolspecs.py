# SPDX-License-Identifier: AGPL-3.0-only
"""Les 3 exemples gradués de ToolSpec (`forge/modules/contrib/{simple,medium,hard}.toolspec.json`)
DOIVENT être des exemples COPIER-COLLER-FONCTIONNELS : chacun charge via le loader déclaratif,
s'ENREGISTRE (le kind apparaît dans `kinds()`), et construit l'argv attendu avec les params par défaut.

On prouve AUSSI que la sûreté tient : une variante volontairement dangereuse (drapeau d'exfil `-o` dans
la flag_allowlist) est REFUSÉE fail-closed par le MÊME loader (parité avec l'endpoint Rust /api/tools).
"""
import json
import os
import tempfile

import pytest

import forge.modules  # noqa: F401 — déclenche l'autoload (registre peuplé)
from forge import techniques
from forge.modules import registry
from forge.modules.loader import load_toolspec_file, SpecError
from forge.modules.registry import get, kinds
from forge.modules.toolspec import build_argv

CONTRIB = os.path.join(os.path.dirname(forge.modules.__file__), "contrib")


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Les specs contrib ne sont PAS auto-chargées (contrib est exclu de l'autoload) ; ce test les
    charge à la main -> il DOIT restaurer les tables globales (REGISTRY / TECHNIQUES / CATALOG) pour
    ne PAS polluer les autres tests (ex le pin `test_kind_set_matches_literal_pin`)."""
    snap = (dict(registry.REGISTRY), dict(techniques.TECHNIQUES), dict(techniques.CATALOG))
    try:
        yield
    finally:
        for live, saved in zip(
            (registry.REGISTRY, techniques.TECHNIQUES, techniques.CATALOG), snap):
            live.clear()
            live.update(saved)


def _load(name):
    return load_toolspec_file(os.path.join(CONTRIB, f"{name}.toolspec.json"))


# ---------------------------------------------------------------------------------------------------
#  Chaque exemple : charge + s'enregistre + argv attendu (défauts) ------------------------------------
# ---------------------------------------------------------------------------------------------------
def test_simple_loads_registers_and_builds_argv():
    kind = _load("simple")
    assert kind == "custom.whatweb"
    assert kind in kinds()                       # ENREGISTRÉ (apparaît au catalogue)
    spec = get(kind).spec
    # Strict minimum : juste la cible, aucun param. target_url force le schéma http://.
    assert build_argv(spec, "example.com", {}) == ["http://example.com"]
    assert spec.exploit is False
    assert spec.params_schema == ()
    assert spec.flag_allowlist == ()


def test_medium_loads_registers_and_builds_argv():
    kind = _load("medium")
    assert kind == "custom.dirfuzz"
    assert kind in kinds()
    spec = get(kind).spec
    # Params typés : threads/rate/match_codes tirent leurs défauts du gabarit ; wordlist est fournie.
    argv = build_argv(spec, "https://x.com", {"wordlist": "/wl.txt"})
    assert argv == [
        "-u", "https://x.com/FUZZ",
        "-w", "/wl.txt",
        "-t", "40",
        "-rate", "0",
        "-mc", "200,204,301,302,401,403",
    ]
    assert spec.exploit is False
    assert "-e" in spec.flag_allowlist         # extension flag ffuf : NON dangereux, conservé
    assert "--timeout" in spec.flag_allowlist


def test_medium_extra_args_governed_by_allowlist():
    spec = get(_load("medium")).spec
    from forge.modules.toolspec import unsafe_extra_args
    # Un flag allowlisté passe...
    assert unsafe_extra_args(spec, {"extra_args": ["-fc", "404"]}) is None
    # ...un flag HORS allowlist est refusé fail-closed.
    assert unsafe_extra_args(spec, {"extra_args": ["-o", "/tmp/x"]}) is not None


def test_hard_loads_registers_and_is_exploit_class():
    kind = _load("hard")
    assert kind == "custom.nuclei_scan"
    assert kind in kinds()
    spec = get(kind).spec
    argv = build_argv(spec, "https://x.com", {"tags": "cve", "templates": "/t"})
    assert argv == [
        "-u", "https://x.com",
        "-severity", "low,medium,high,critical",
        "-tags", "cve",
        "-t", "/t",
        "-rl", "0",
        "-jsonl", "-silent",
    ]
    # (c) exploit-class honoré + parser JSONL avec extraction de champs.
    assert spec.exploit is True
    assert spec.parser == "jsonl"
    assert spec.parser_json_path == ("info.name", "info.severity", "matched-at")
    # hit_status ne peut pas s'auto-promouvoir en `vulnerable` (clampé à {tested, reported_by_tool}).
    assert spec.hit_status == "reported_by_tool"


def test_hard_module_class_declares_exploit_true():
    """Le plancher exploit s'appuie sur l'attribut de classe `exploit` (posé par make_module)."""
    cls = type(get(_load("hard")))
    assert cls.exploit is True


# ---------------------------------------------------------------------------------------------------
#  Namespace + la sûreté TIENT : une variante dangereuse est REJETÉE ---------------------------------
# ---------------------------------------------------------------------------------------------------
def test_all_three_use_custom_namespace():
    for name in ("simple", "medium", "hard"):
        data = json.load(open(os.path.join(CONTRIB, f"{name}.toolspec.json")))
        assert data["kind"].startswith("custom."), name


def test_bad_variant_dangerous_flag_is_rejected():
    """Prend le medium, ajoute `-o` (exfil output-file) à la flag_allowlist -> DOIT être refusé."""
    base = json.load(open(os.path.join(CONTRIB, "medium.toolspec.json")))
    bad = dict(base)
    bad["kind"] = "custom.__bad_o_flag__"
    bad["flag_allowlist"] = list(base["flag_allowlist"]) + ["-o"]
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps(bad).encode())
    os.close(fd)
    try:
        with pytest.raises(SpecError):
            load_toolspec_file(path)
        # Le kind dangereux n'a JAMAIS été enregistré (aucun enregistrement partiel).
        assert "custom.__bad_o_flag__" not in kinds()
    finally:
        os.unlink(path)


def test_bad_variant_output_in_argv_is_rejected():
    """Un `--output` glissé dans argv_template -> refusé (exfil écriture-fichier)."""
    base = json.load(open(os.path.join(CONTRIB, "simple.toolspec.json")))
    bad = dict(base)
    bad["kind"] = "custom.__bad_argv_output__"
    bad["argv_template"] = list(base["argv_template"]) + ["--output", "{param:dst}"]
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, json.dumps(bad).encode())
    os.close(fd)
    try:
        with pytest.raises(SpecError):
            load_toolspec_file(path)
    finally:
        os.unlink(path)

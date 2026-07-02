#!/usr/bin/env python3
"""Garde-fou de dérive de version (source de vérité unique = fichier `VERSION` à la racine).

Échoue (exit 1) si `VERSION`, `pyproject.toml` (`[project].version`) et
`console/Cargo.toml` (`[package].version`) ne coïncident pas. Utilisé par `make check-version`
et la CI. Zéro dépendance : extraction par regex CIBLÉE PAR TABLE (tolère l'absence de `tomllib`
sur Python 3.9/3.10, et ne confond jamais la version du paquet avec celle d'une dépendance).
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_HEADER = re.compile(r"^\s*\[([^\[\]]+)\]\s*$")          # en-tête de table `[section]` (pas `[[array]]`)
_VERSION = re.compile(r'^\s*version\s*=\s*"([^"]+)"')    # `version = "X.Y.Z"`


def table_version(path, table):
    """Retourne la 1re `version = "…"` DANS la table `[table]`, ou None. S'arrête au prochain
    en-tête pour ne jamais capter la version d'une dépendance (ex: `axum = "0.7"` sous [dependencies])."""
    in_table = False
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        h = _HEADER.match(line)
        if h:
            in_table = (h.group(1).strip() == table)
            continue
        if in_table:
            m = _VERSION.match(line)
            if m:
                return m.group(1)
    return None


def main():
    vfile = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    py = table_version(ROOT / "pyproject.toml", "project")
    rust = table_version(ROOT / "console" / "Cargo.toml", "package")
    print(f"VERSION              = {vfile!r}")
    print(f"pyproject [project]  = {py!r}")
    print(f"Cargo    [package]   = {rust!r}")
    if not vfile:
        print("ERREUR : fichier VERSION vide/absent.", file=sys.stderr)
        return 1
    if not (vfile == py == rust):
        print("ERREUR : dérive de version — VERSION, pyproject.toml et Cargo.toml doivent "
              "TOUS trois coïncider (source de vérité = fichier VERSION).", file=sys.stderr)
        return 1
    print(f"OK : version unique cohérente ({vfile}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

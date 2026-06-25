#!/usr/bin/env bash
# Forge — CI locale (équivalent runnable de .github/workflows/ci.yml).
# =============================================================================
#
# À utiliser tant qu'aucun repo GitHub n'existe (le workflow ci.yml prendra le relais
# quand le repo sera créé). Mêmes étapes, mêmes garanties : tests python (stdlib),
# cargo test + cargo build --release de la console. Usage AUTORISÉ uniquement,
# AUCUN I/O réseau offensif.
#
# Exécution (depuis n'importe où) :
#     forge/ci.sh
# Codes de sortie : 0 = tout vert ; !=0 = première étape en échec.

set -euo pipefail

# Racine du package forge = dossier de ce script (indépendant du cwd).
FORGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLE_DIR="${FORGE_DIR}/console"
CORE_DIR="$(cd "${FORGE_DIR}/.." && pwd)/core"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m[ci] ÉCHEC: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1) Python — tests du cœur (stdlib, zéro dépendance).
# ---------------------------------------------------------------------------
step "python — unittest discover (cœur stdlib)"
command -v python3 >/dev/null 2>&1 || fail "python3 introuvable"
( cd "${FORGE_DIR}" && python3 -m unittest discover -s tests -p 'test_*.py' ) \
    || fail "tests python"

# ---------------------------------------------------------------------------
# 2) Console — cargo test + build release (nécessite le sibling core/).
# ---------------------------------------------------------------------------
if command -v cargo >/dev/null 2>&1; then
    [ -f "${CORE_DIR}/Cargo.toml" ] \
        || fail "crate guatx-core introuvable (${CORE_DIR}/Cargo.toml) — requis par console (path = ../../core)"

    step "console — cargo test --locked"
    ( cd "${CONSOLE_DIR}" && cargo test --locked ) || fail "cargo test (console)"

    step "console — cargo build --release --locked"
    ( cd "${CONSOLE_DIR}" && cargo build --release --locked ) || fail "cargo build --release (console)"
else
    printf '\033[1;33m[ci] cargo absent — étapes console SAUTÉES (installer Rust 1.96.0 pour la console).\033[0m\n' >&2
fi

step "CI OK — toutes les étapes disponibles sont vertes."

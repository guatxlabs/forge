# SPDX-License-Identifier: AGPL-3.0-or-later
"""Garde de PORTABILITÉ (filet anti-régression, statique) — comportement runtime INCHANGÉ.

Ce test ne modifie RIEN au moteur : il lit l'arbre source et ÉCHOUE si un chemin OS codé en dur
(`/tmp`, `/usr/bin`, `/home/`) réapparaît dans le code *porteur* — le moteur Python (`forge/`) ou la
source de la console Rust (`console/src/*.rs`). But : empêcher l'anti-pattern « suppose un seul OS via
un chemin absolu » de revenir en douce après que les seams portables (forge/portability.py :
config_dir/data_dir/restrict_file_permissions, résolution de binaire via shutil.which) ont été posés.

Précision (pas de faux positif) :
  - COMMENTAIRES exclus       — `#…` (Python) et `//…` / `/* … */` (Rust) sont retirés avant scan ;
                                un commentaire qui MENTIONNE « jamais /tmp » ne déclenche pas la garde.
  - TESTS/FIXTURES exclus      — les tests Python (`tests/`) ne sont pas scannés ; côté Rust, tout le
                                module `#[cfg(test)]` (fixtures : `/tmp/eng1.jsonl`, `/usr/bin/rclone`)
                                est retiré par appariement d'accolades.
  - ALLOWLIST minime           — l'IP de métadonnées cloud `169.254.169.254` et les exemples de doc
                                sont tolérés ; une ligne peut être blanchie explicitement via le
                                marqueur `portability-ok` (échappatoire pour un exemple légitime).

Se lance dans la suite (`python3 -m unittest discover -s tests -t .`) ET en script autonome
(`python3 tests/test_portability_guard.py` → sortie 1 si violation, 0 sinon).
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Racines de code PORTEUR à surveiller (le reste — docs/, examples/, tests/ — n'est pas scanné).
PYTHON_ENGINE = ROOT / "forge"
RUST_CONSOLE = ROOT / "console" / "src"

# Motifs interdits — précis : bornés à droite pour ne pas capturer un identifiant (`/tmpfs`, `/usr/binary`).
FORBIDDEN = [
    ("/tmp", re.compile(r"/tmp(?![\w])")),
    ("/usr/bin", re.compile(r"/usr/bin(?![\w])")),
    ("/home/", re.compile(r"/home/")),
]

# Exceptions légitimes : sous-chaînes tolérées sur une ligne (IP métadonnées cloud, exemples de doc).
# `169.254.169.254` ne matche de toute façon aucun motif interdit — présent ici par policy/robustesse.
ALLOW_SUBSTRINGS = ("169.254.169.254",)
# Marqueur d'exemption explicite ligne-à-ligne (à poser en commentaire sur un exemple légitime).
ALLOW_PRAGMA = "portability-ok"


def _blank_rust_block_comments(text):
    """Blanchit les commentaires bloc `/* … */` (Rust) en conservant le nombre de lignes."""
    def repl(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    return re.sub(r"/\*.*?\*/", repl, text, flags=re.DOTALL)


def _code_before_comment(line, lang):
    """Retourne la portion CODE de la ligne, commentaire de fin retiré, contenu des STRINGS conservé
    (c'est là que vivent les vraies violations). Conscient des strings pour ne pas couper sur un `#`
    ou `//` situé à l'intérieur d'un littéral."""
    out = []
    i, n = 0, len(line)
    in_str = False
    str_ch = ""
    while i < n:
        c = line[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(line[i + 1])
                i += 2
                continue
            if c == str_ch:
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            str_ch = c
            out.append(c)
            i += 1
            continue
        if lang == "rust" and c == "'":
            # Littéral de caractère ('x' / '\n') → conservé ; sinon lifetime (`'a`) → char ordinaire.
            m = re.match(r"'(?:\\.|[^'\\])'", line[i:])
            if m:
                out.append(m.group(0))
                i += len(m.group(0))
                continue
            out.append(c)
            i += 1
            continue
        if lang == "py" and c == "'":
            in_str = True
            str_ch = c
            out.append(c)
            i += 1
            continue
        if lang == "py" and c == "#":
            break
        if lang == "rust" and c == "/" and i + 1 < n and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _rust_structural(line):
    """Version « structurelle » d'une ligne Rust (strings + chars + commentaire de fin retirés) —
    sert UNIQUEMENT à compter les accolades pour délimiter le module `#[cfg(test)]`."""
    s = _code_before_comment(line, "rust")
    s = re.sub(r'"(?:\\.|[^"\\])*"', "", s)      # strings mono-ligne
    s = re.sub(r"'(?:\\.|[^'\\])'", "", s)       # char literals
    return s


def _rust_test_region(lines):
    """Ensemble des indices de lignes appartenant à un item `#[cfg(test)]` (module ou fn de test),
    délimité par appariement d'accolades. Convention du dépôt : un unique `mod tests` en pied de
    fichier — mais l'algo gère un item quelconque, et englobe jusqu'à EOF si les accolades ne se
    referment pas (fail-safe : on préfère sur-exclure du test que sous-exclure)."""
    region = set()
    i, n = 0, len(lines)
    while i < n:
        if "#[cfg(test)]" in _rust_structural(lines[i]):
            start = i
            depth = 0
            started = False
            j = i
            while j < n:
                for ch in _rust_structural(lines[j]):
                    if ch == "{":
                        depth += 1
                        started = True
                    elif ch == "}":
                        depth -= 1
                if started and depth <= 0:
                    break
                j += 1
            for k in range(start, min(j, n - 1) + 1):
                region.add(k)
            i = j + 1
        else:
            i += 1
    return region


def _iter_source_files():
    for p in sorted(PYTHON_ENGINE.rglob("*.py")):
        yield p, "py"
    for p in sorted(RUST_CONSOLE.rglob("*.rs")):
        # Modules de test EXTRAITS EN FICHIER (convention dépôt : `#[cfg(test)] mod tests;` en
        # pied de main.rs -> tests.rs / tests_*.rs ; cf. docs/ARCHITECTURE_REFACTOR_PLAN.md).
        # Leurs `/tmp/...` sont des FIXTURES de test — exclus au même titre qu'un module
        # `#[cfg(test)]` inline (que `_rust_test_region` saute déjà quand le marqueur est présent).
        if p.name == "tests.rs" or p.name.startswith("tests_"):
            continue
        yield p, "rust"


def _line_is_allowed(line):
    if ALLOW_PRAGMA in line:
        return True
    return any(sub in line for sub in ALLOW_SUBSTRINGS)


def scan_source_tree():
    """Scanne le code porteur. Retourne une liste de violations (dict path/line/pattern/text)."""
    violations = []
    for path, lang in _iter_source_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        if lang == "rust":
            text = _blank_rust_block_comments(text)
        lines = text.splitlines()
        skip = _rust_test_region(lines) if lang == "rust" else set()
        for idx, raw in enumerate(lines):
            if idx in skip:
                continue
            if _line_is_allowed(raw):
                continue
            code = _code_before_comment(raw, lang)
            for label, rx in FORBIDDEN:
                if rx.search(code):
                    violations.append({
                        "path": str(path.relative_to(ROOT)),
                        "line": idx + 1,
                        "pattern": label,
                        "text": raw.strip(),
                    })
                    break
    return violations


class TestPortabilityGuard(unittest.TestCase):
    def test_no_hardcoded_os_path_in_load_bearing_code(self):
        """Aucun `/tmp`, `/usr/bin`, `/home/` codé en dur dans forge/ ou console/src/ (hors
        commentaires/tests/allowlist). Une régression fait ÉCHOUER ce test avec l'emplacement exact."""
        violations = scan_source_tree()
        if violations:
            report = "\n".join(
                f"  {v['path']}:{v['line']}  [{v['pattern']}]  {v['text']}" for v in violations
            )
            self.fail(
                "Chemin(s) OS codé(s) en dur dans le code porteur — résoudre via "
                "forge/portability.py (config_dir/data_dir) ou shutil.which, "
                f"ou exempter avec « {ALLOW_PRAGMA} » si légitime :\n" + report
            )

    def test_guard_detects_a_synthetic_violation(self):
        """Méta-test : la garde DÉTECTE bien un chemin codé en dur (prouve que le filet mord)."""
        self.assertTrue(FORBIDDEN[0][1].search('open("/tmp/forge.sock")'))
        self.assertTrue(FORBIDDEN[1][1].search('cmd = "/usr/bin/nmap"'))
        self.assertTrue(FORBIDDEN[2][1].search('base = "/home/op/.forge"'))
        # …mais PAS sur un identifiant proche, ni sur du texte commenté, ni sur l'IP métadonnées.
        self.assertFalse(FORBIDDEN[0][1].search("tmpdir = mkdtemp()"))
        self.assertIsNone(FORBIDDEN[1][1].search("/usr/binary/x"))
        self.assertEqual(_code_before_comment("x = 1  # never /tmp here", "py"), "x = 1  ")
        self.assertTrue(_line_is_allowed("url = 'http://169.254.169.254/latest/'"))
        self.assertTrue(_line_is_allowed('let p = "/tmp/x";  // portability-ok: doc example'))


if __name__ == "__main__":
    found = scan_source_tree()
    if found:
        print("PORTABILITY GUARD: FAIL — hardcoded OS path(s) in load-bearing code:")
        for v in found:
            print(f"  {v['path']}:{v['line']}  [{v['pattern']}]  {v['text']}")
        sys.exit(1)
    print("PORTABILITY GUARD: OK — no hardcoded /tmp, /usr/bin, /home/ in forge/ or console/src/.")
    sys.exit(0)

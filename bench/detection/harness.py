# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exécution de forge et récolte des findings, en MACHINE-LISIBLE.

Le banc pilote la CLI publique (`forge run` / `forge campaign`) — pas l'API interne — pour mesurer
le chemin que prend réellement un opérateur. Les findings sont récoltés dans le store `--memory`
(JSONL de `Finding.to_dict()`), qui est la seule sortie structurée du moteur.

BUDGET. Chaque run est borné par `--run-timeout`. Le drapeau `partial` remonté par `run_forge()`
dit si la borne a coupé : un banc interrompu qui se présenterait comme complet serait exactement le
défaut qu'on vient de corriger côté moteur.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

FORGE_ROOT = Path(__file__).resolve().parents[2]
ANSI = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class RunResult:
    track: str
    app: str
    cmd: list
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    findings: list
    partial: bool
    report: Path
    ledger: Path


def _read_memory(path: Path) -> list:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def loopback_safe_modules(exclude) -> list:
    """Kinds enregistrés MOINS ceux qui interrogent un tiers. Calculé depuis le registre du moteur
    (pas une liste recopiée) pour ne pas dériver quand le registre bouge."""
    r = subprocess.run(["python3", "-m", "forge.cli", "modules", "--json"],
                       cwd=FORGE_ROOT, capture_output=True, text=True)
    try:
        rows = json.loads(ANSI.sub("", r.stdout))
    except json.JSONDecodeError:
        return []
    kinds = [row["kind"] for row in rows] if isinstance(rows, list) else list(rows)
    return sorted(k for k in kinds if k not in set(exclude))


def run_forge(track, app, workdir: Path, scope: Path, *, actions=None, targets=None,
              modules=None, auto_pentest=False, timeout_s=900) -> RunResult:
    workdir.mkdir(parents=True, exist_ok=True)
    mem = workdir / f"{track}.findings.jsonl"
    report = workdir / f"{track}.report.md"
    ledger = workdir / f"{track}.ledger.jsonl"
    for p in (mem, report, ledger):
        if p.exists():
            p.unlink()

    cmd = ["python3", "-m", "forge.cli", "run" if actions else "campaign",
           "--scope", str(scope), "--arm", "--mode", "auto",
           "--memory", str(mem), "--report", str(report), "--ledger", str(ledger)]
    if actions:
        cmd += ["--actions", str(actions)]
    else:
        cmd += ["--targets", str(targets), "--run-timeout", str(timeout_s)]
        if auto_pentest:
            cmd.append("--auto-pentest")
        if modules:
            cmd += ["--modules", ",".join(modules)]

    env = dict(os.environ)
    env.setdefault("TMPDIR", str(workdir / "tmp"))
    (workdir / "tmp").mkdir(exist_ok=True)
    t0 = time.time()
    try:
        # marge dure au-dessus du budget interne : si le moteur ne rend pas la main, on le sait.
        p = subprocess.run(cmd, cwd=FORGE_ROOT, capture_output=True, text=True,
                           timeout=timeout_s + 300, env=env)
        rc, so, se = p.returncode, ANSI.sub("", p.stdout), ANSI.sub("", p.stderr)
        hard_kill = False
    except subprocess.TimeoutExpired as e:
        rc, hard_kill = -9, True
        so = ANSI.sub("", (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes)
                      else (e.stdout or ""))
        se = "TIMEOUT DUR — le processus n'a pas rendu la main dans budget+300 s"
    dt = time.time() - t0

    text = (so + "\n" + (report.read_text(encoding="utf-8") if report.exists() else ""))
    partial = hard_kill or ("PARTIEL" in text.upper()) or ("interrompu" in text.lower())
    return RunResult(track, app, cmd, rc, so, se, dt, _read_memory(mem), partial, report, ledger)

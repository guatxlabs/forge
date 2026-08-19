# SPDX-License-Identifier: AGPL-3.0-or-later
"""Banc — D'OÙ VIENT LE TEMPS D'`origin.find`, ET QUELLE BORNE LE PORTE VRAIMENT.

CE QUE L'ARTEFACT DIT DÉJÀ, SANS MODÈLE
----------------------------------------
Campagne réelle du 2026-08-10 (programme H1 public `kong`, budget 3 600 s de mur). Sidecar
`ledger.jsonl.durations` : `origin.find` = **32,43 / 32,86 / 1 799,08 s**. Le tir long est celui sur
`konghq.com`, et son rapport porte **429 findings `origin-exposure`, dont 429 « IP résolue
HORS-SCOPE — connexion refusée »** (`grep -c 'hors du périmètre autorisé'`). Or cette branche
`continue` AVANT tout httpx, et la baseline de corrélation est PARESSEUSE (résolue au 1er candidat
in-scope — il n'y en a eu aucun). Donc :

    httpx émis pendant ce tir = 0        (fait, pas hypothèse)
    subfinder                 ≤ 120 s    (borne du sous-processus)
    => ≥ 1 679 s dans la SEULE boucle restante : `socket.gethostbyname`, séquentielle et bloquante.

CE QUE CE BANC AJOUTE : LE CONTRE-FACTUEL QU'AUCUN ARTEFACT NE PORTE
--------------------------------------------------------------------
La question n'est pas « où est passé le temps CE JOUR-LÀ » (l'artefact répond) mais « quelle borne
tient sur les DEUX formes de travail que ce module peut prendre ». On rejoue donc deux FORMES, à
matériel identique, sous trois configurations :

  formes    · `hors-scope` — celle de kong : N hôtes résolus, toutes les IP HORS périmètre -> 0 httpx ;
            · `in-scope`   — la même énumération, mais les IP sont DANS le périmètre -> N vérifications
                             httpx à 30 s. Rien d'exotique : c'est le cas NOMINAL du module (celui où
                             il trouve quelque chose), et c'est le plus cher.
  configs   · `aucune`   — l'état d'AVANT ce lot (échéance neutralisée) ;
            · `cap`      — plafond sur le NOMBRE de candidats, échéance neutralisée ;
            · `échéance` — l'état LIVRÉ (`origin.MAX_RUNTIME`, consultée dans les deux boucles).

LE TEMPS EST INJECTÉ, JAMAIS ATTENDU : `origin.time` est une horloge virtuelle que les seams
(`socket.gethostbyname`, `runner.tool`) font AVANCER. Zéro réseau, zéro sommeil, reproductible.

CALIBRATION — CE QUI EST MESURÉ ET CE QUI EST CHOISI. L'artefact donne la DURÉE (1 799,08 s) et le
NOMBRE DE CANDIDATES (429) ; il ne donne NI le nombre d'hôtes rendus par subfinder, NI la latence par
résolution. On prend le couple qui REPRODUIT la durée mesurée (1 679 hôtes x 1,0 s), et le banc
affiche l'écart au réel pour qu'on puisse en juger. Les deux sont réglables (`--hosts`,
`--dns-latency`) : la conclusion (quelle borne porte) ne dépend d'aucun des deux.

Usage :
    python3 tests/bench_origin_bound.py
    python3 tests/bench_origin_bound.py --hosts 3000 --dns-latency 0.5 --cap 300
"""
from __future__ import annotations

import argparse
import sys
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import runner                                       # noqa: E402
from forge.modules import origin as origin_mod                 # noqa: E402
from forge.modules.origin import OriginFind                    # noqa: E402
from forge.roe import Action                                   # noqa: E402

DOMAIN = "konghq.com"
MEASURED_SECS = 1799.0833          # verbatim `ledger.jsonl.durations`
MEASURED_CANDIDATES = 429          # verbatim : findings « hors du périmètre autorisé » du rapport
DEFAULT_HOSTS = 1644               # calibration : 1644 + 35 candidats passifs = 1679 résolutions
#                                    x 1,0 s + 120 s de subfinder == 1 799 s == la durée MESURÉE
DEFAULT_LATENCY = 1.0
DEFAULT_CAP = 300


class _Clock:
    """Horloge monotone VIRTUELLE — `advance` est la seule façon dont le temps passe ici."""

    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += max(0.0, float(seconds))


class _Harness:
    """Les deux seams du module, instrumentés et branchés sur l'horloge virtuelle."""

    def __init__(self, *, hosts: int, latency: float, candidates: int, subfinder_secs: float = 120.0):
        self.clock = _Clock()
        self.hosts = [f"h{i}.{DOMAIN}" for i in range(hosts)]
        self.latency = latency
        self.candidates = candidates
        self.subfinder_secs = subfinder_secs
        self.dns_calls = 0
        self.httpx_calls = 0

    # -- seam 1 : sous-processus --------------------------------------------------------------
    def tool(self, binary, image, argv, timeout=None, prefer_docker=False):
        if binary == OriginFind.SUB:                            # subfinder : rend la liste d'hôtes
            self.clock.advance(min(self.subfinder_secs, float(timeout or self.subfinder_secs)))
            return 0, "\n".join(self.hosts) + "\n", ""
        self.httpx_calls += 1                                   # httpx : pire cas = il tient son mur
        self.clock.advance(float(timeout or origin_mod.HTTPX_TIMEOUT))
        return 0, f"http://x [200] [{DOMAIN}]", ""

    # -- seam 2 : résolution DNS --------------------------------------------------------------
    def gethostbyname(self, name):
        self.dns_calls += 1
        self.clock.advance(self.latency)
        idx = self.dns_calls - 1
        if idx >= self.candidates:                              # au-delà : NXDOMAIN (temps payé quand même)
            raise OSError("NXDOMAIN (banc)")
        return f"9.{(idx // 65536) % 256}.{(idx // 256) % 256}.{idx % 256}"

    def patches(self):
        return [mock.patch.object(origin_mod, "time", self.clock),
                mock.patch.object(runner, "tool", self.tool),
                mock.patch.object(origin_mod.socket, "gethostbyname", self.gethostbyname)]


def run_case(shape: str, config: str, *, hosts: int, latency: float, candidates: int,
             cap: int, max_runtime: float) -> dict:
    """UNE campagne d'un tir. `shape` décide du périmètre, `config` de la borne en vigueur."""
    # `cap` est modélisé par la SORTIE de subfinder : plafonner les candidats revient exactement à
    # n'en résoudre que `cap` (et donc à n'en vérifier que `cap`). Aucune autre différence.
    n_hosts = min(hosts, cap) if config == "cap" else hosts
    n_cands = min(candidates, n_hosts)
    h = _Harness(hosts=n_hosts, latency=latency, candidates=n_cands)
    # `in-scope` : le périmètre couvre les IP rendues (9.0.0.0/8) -> chaque candidate part en httpx.
    in_scope = ["9.0.0.0/8", DOMAIN] if shape == "in-scope" else [DOMAIN]
    action = Action("origin.find", DOMAIN)
    action.params.update({"in_scope": in_scope, "out_scope": []})
    bound = max_runtime if config == "échéance" else 10 ** 9    # « aucune »/« cap » : échéance neutralisée
    stack = []
    try:
        for p in h.patches() + [mock.patch.object(origin_mod, "MAX_RUNTIME", bound)]:
            p.__enter__()
            stack.append(p)
        findings = OriginFind().fire(action)
    finally:
        for p in reversed(stack):
            p.__exit__(None, None, None)
    titles = [f.title for f in findings]
    return {
        "shape": shape, "config": config, "elapsed": h.clock.t,
        "dns": h.dns_calls, "httpx": h.httpx_calls, "findings": len(findings),
        "cut": sum(1 for t in titles if "borne de durée atteinte" in t),
        "absence": sum(1 for t in titles if "Aucune origine hors-CDN trouvée" in t),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hosts", type=int, default=DEFAULT_HOSTS, help="hôtes rendus par subfinder")
    ap.add_argument("--dns-latency", type=float, default=DEFAULT_LATENCY, help="secondes par résolution")
    ap.add_argument("--candidates", type=int, default=MEASURED_CANDIDATES, help="hôtes qui RÉSOLVENT")
    ap.add_argument("--cap", type=int, default=DEFAULT_CAP, help="plafond de candidats (config `cap`)")
    ap.add_argument("--max-runtime", type=float, default=float(origin_mod.MAX_RUNTIME),
                    help="échéance de tir (config `échéance`)")
    args = ap.parse_args()

    print(f"# Banc BORNE origin.find — {args.hosts} hôtes x {args.dns_latency}s de résolution, "
          f"{args.candidates} résolvent, httpx {origin_mod.HTTPX_TIMEOUT}s, cap={args.cap}, "
          f"échéance={args.max_runtime:.0f}s (horloge VIRTUELLE)")
    print(f"{'forme':10s} {'config':10s} {'écoulé (s)':>12s} {'DNS':>7s} {'httpx':>7s} "
          f"{'findings':>9s} {'skips borne':>12s} {'constat absence':>16s}")
    rows = []
    for shape in ("hors-scope", "in-scope"):
        for config in ("aucune", "cap", "échéance"):
            r = run_case(shape, config, hosts=args.hosts, latency=args.dns_latency,
                         candidates=args.candidates, cap=args.cap, max_runtime=args.max_runtime)
            rows.append(r)
            print(f"{r['shape']:10s} {r['config']:10s} {r['elapsed']:12.1f} {r['dns']:7d} "
                  f"{r['httpx']:7d} {r['findings']:9d} {r['cut']:12d} {r['absence']:16d}")
    base = next(r for r in rows if r["shape"] == "hors-scope" and r["config"] == "aucune")
    print(f"\n# reproduction de la mesure réelle : modèle {base['elapsed']:.1f}s "
          f"vs ledger {MEASURED_SECS:.1f}s (écart {base['elapsed'] - MEASURED_SECS:+.1f}s), "
          f"httpx modèle {base['httpx']} vs artefact 0")
    for shape in ("hors-scope", "in-scope"):
        cap = next(r for r in rows if r["shape"] == shape and r["config"] == "cap")
        dl = next(r for r in rows if r["shape"] == shape and r["config"] == "échéance")
        verdict = "PORTE" if cap["elapsed"] <= args.max_runtime else "NE PORTE PAS"
        print(f"# {shape:10s} : cap -> {cap['elapsed']:8.1f}s ({verdict}) | "
              f"échéance -> {dl['elapsed']:8.1f}s (PORTE)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

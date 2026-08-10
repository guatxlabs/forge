# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rend le tableau du banc — par application, par classe de vulnérabilité, pour les deux pistes.

    python3 -m bench.detection.report --workdir <workdir> [--verdicts verdicts.json] > rapport.md

`--verdicts` porte la VÉRIFICATION MANUELLE de chaque finding ≥ MEDIUM (mandat : « vérifie CHAQUE
finding ≥ MEDIUM à la main contre la vérité terrain »). Deux formes de clé, la seconde STABLE :

    {"<app>/<piste>/<index>":            {"verdict": "TP|FP", "why": "…"},
     "<app>/<piste>/<module>@<cible>":   {"verdict": "TP|FP", "why": "…"}}

Un ≥ MEDIUM sans entrée est rendu **NON VÉRIFIÉ** — jamais silencieusement compté comme correct.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import groundtruth as gt
from . import score


def load_findings(work: Path, app: str, track: str):
    p = work / app / f"{track}.findings.jsonl"
    if not p.exists():
        return None
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--verdicts", default="")
    args = ap.parse_args(argv)
    work = Path(args.workdir)
    manifest = {}
    mp = work / "manifest.json"
    if mp.exists():
        manifest = json.loads(mp.read_text(encoding="utf-8"))
    verdicts = {}
    if args.verdicts and Path(args.verdicts).exists():
        verdicts = json.loads(Path(args.verdicts).read_text(encoding="utf-8"))

    print("# Banc de détection multi-applications — résultats\n")
    print("Vérité terrain fournie par CHAQUE application (registre de challenges, liste de modules, "
          "README, pages de solutions). Aucune métrique ne vient de forge.\n")

    print("## Synthèse\n")
    print("| app | stack | piste | opposables | vrais positifs | faux négatifs | classes sans oracle | "
          "findings émis | ≥MEDIUM revendiqués | partiel |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    summaries = {}
    for app in ("juiceshop", "dvwa", "vampi", "dvga"):
        for track in ("A", "B"):
            f = load_findings(work, app, track)
            if f is None:
                continue
            partial = bool(manifest.get("apps", {}).get(app, {})
                           .get("tracks", {}).get(track, {}).get("partial"))
            s = score.score_app(app, f, partial=partial)
            summaries[(app, track)] = s
            d = score.summary(s)
            print(f"| {app} | {gt.APPS[app].stack} | {track} | {d['opposables']} | "
                  f"{d['vrais_positifs']} | {d['faux_negatifs']} | {d['sans_oracle']} | "
                  f"{d['findings_total']} | {d['candidats_fp']} | {'OUI' if d['partiel'] else 'non'} |")

    print("\n## Détail par classe\n")
    for (app, track), s in summaries.items():
        print(f"\n#### {app} — piste {track}\n")
        primed = manifest.get("apps", {}).get(app, {}).get("primed", "—")
        print(f"*Amorcé* : {primed}\n")
        print(f"*Vérité terrain* : {gt.APPS[app].truth_source}\n")
        print(score.markdown_table(s))

    print("\n## Findings ≥ MEDIUM — vérification manuelle\n")
    print("Chaque ligne a été rejouée à la main contre l'application. "
          "Un finding sans verdict est marqué NON VÉRIFIÉ.\n")
    print("| app | piste | module | sév. | titre | cible | verdict manuel | pourquoi |")
    print("|---|---|---|---|---|---|---|---|")
    tally = {"TP": 0, "FP": 0, "NON VÉRIFIÉ": 0}
    for (app, track), s in summaries.items():
        for i, f in enumerate(s.fp_candidates):
            kind = score.module_kind(f)
            v = (verdicts.get(f"{app}/{track}/{kind}@{f.get('target')}")
                 or verdicts.get(f"{app}/{track}/{i}") or {})
            verdict = v.get("verdict", "**NON VÉRIFIÉ**")
            tally[verdict if verdict in tally else "NON VÉRIFIÉ"] += 1
            print(f"| {app} | {track} | {kind} | {f.get('severity')} | "
                  f"{str(f.get('title'))[:70]} | {str(f.get('target'))[:55]} | {verdict} | "
                  f"{v.get('why', '')} |")
    total = sum(tally.values())
    print(f"\n**Bilan ≥ MEDIUM** : {total} revendication(s) — "
          f"**{tally['TP']} vrai(s) positif(s)**, **{tally['FP']} FAUX POSITIF(S)**, "
          f"{tally['NON VÉRIFIÉ']} non vérifié(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

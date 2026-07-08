# SPDX-License-Identifier: AGPL-3.0-only
"""Commandes moteur de la CLI Forge : `plan`, `run`, `campaign` (chargement d'actions/cibles,
armement, ledger, planner, workflows, ingest console). Extrait de l'ancien `forge/cli.py` (pur
déplacement, comportement inchangé)."""
import json
import os
from pathlib import Path

from ..roe import Scope, Roe, Action
from ..ledger import Ledger
from ..engine import Engine
from ..report import build_report
from ..schema import Target
from ..brain import HeuristicBrain, AutoPentestBrain
from ..planner import Planner
from ..memory import Memory
from .. import purple
from .. import console_client
from .. import workflows


def _load_actions(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for i, a in enumerate(data):
        try:
            out.append(Action(kind=a["kind"], target=a["target"],
                              exploit=a.get("exploit", False), destructive=a.get("destructive", False),
                              desc=a.get("desc", ""), params=a.get("params", {})))
        except KeyError as e:                          # champ requis manquant -> message clair (pas un KeyError brut)
            raise SystemExit(f"actions[{i}] : champ requis manquant {e} dans {path} "
                             f"(chaque action exige 'kind' et 'target')")
    return out


def _demo_actions(scope):
    # une action par cible littérale du scope (les globs/CIDR sont ignorés ici)
    tgts = [t for t in scope.in_scope if "*" not in t and "/" not in t] or ["demo.local"]
    return [Action(kind="demo.fingerprint", target=t, desc="demo") for t in tgts]


def cmd_plan(args):
    scope = Scope.load(args.scope)
    roe = Roe(scope)                       # pas armé : tout sera VETO ou DRY_RUN
    actions = _load_actions(args.actions) if args.actions else _demo_actions(scope)
    print(f"# Plan ({len(actions)} actions) — non armé, aucune action ne sera tirée\n")
    for a in actions:
        d = roe.decide(a)
        print(f"  [{d.verdict:7}] {a.kind} → {a.target}   ({' ; '.join(d.reasons)})")
    return 0


def cmd_run(args):
    scope = Scope.load(args.scope)
    ledger = Ledger(args.ledger) if args.ledger else None
    memory = Memory(args.memory) if args.memory else None
    engine = Engine(scope, ledger=ledger, mode=args.mode, memory=memory)
    if args.arm:
        engine.arm(f"forge run --arm ({args.reason or 'cli'})")
    for ap in (args.approve or []):
        engine.approve(ap)
    actions = _load_actions(args.actions) if args.actions else _demo_actions(scope)
    engine.run(actions)
    if ledger is not None:                 # scelle la fin de run : checkpoint (ancré si anchor configuré)
        ledger.checkpoint(note="forge run end")
    cov = engine.coverage()
    print(f"Tirées={len(cov['fired'])}  Simulées={len(cov['dry_run'])}  "
          f"Refusées={len(cov['vetoed'])}  Erreurs={len(cov['errors'])}  Findings={len(engine.findings)}")
    rep = build_report(engine)
    if args.report:
        Path(args.report).write_text(rep, encoding="utf-8")
        print(f"Rapport -> {args.report}")
    else:
        print("\n" + rep)
    return 0


def _load_targets(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for i, t in enumerate(data):
        try:
            out.append(Target(host=t["host"], kind=t.get("kind", "host"), attrs=t.get("attrs", {})))
        except KeyError as e:                          # 'host' manquant -> message clair (pas un KeyError brut)
            raise SystemExit(f"targets[{i}] : champ requis manquant {e} dans {path} "
                             f"(chaque cible exige 'host')")
    return out


def _workflows_path(args):
    """Chemin du fichier de workflows UTILISATEUR : `--workflows PATH` sinon env `FORGE_WORKFLOWS_FILE`
    sinon "" (builtins seuls — WorkflowStore.load tolère un chemin absent). Les workflows INTÉGRÉS sont
    toujours disponibles sans fichier (dérivés du registre)."""
    return getattr(args, "workflows", None) or os.environ.get("FORGE_WORKFLOWS_FILE", "")


def cmd_campaign(args):
    scope = Scope.load(args.scope)
    ledger = Ledger(args.ledger) if args.ledger else None
    memory = Memory(args.memory) if args.memory else None
    # ÉMISSION PROGRESSIVE : la console pompe le stdout du moteur ligne à ligne vers le flux SSE du run.
    # On branche un callback qui imprime CHAQUE ligne d'avancement immédiatement (flush) pour que les
    # verdicts/SKIP par action et les bannières de vague STREAMENT en direct (au lieu du seul récap final).
    # `flush=True` complète PYTHONUNBUFFERED posé par la console au spawn (sortie non bufferisée).
    def _progress(line):
        print(line, flush=True)
    engine = Engine(scope, ledger=ledger, mode=args.mode, memory=memory, progress=_progress)
    if args.arm:
        engine.arm(f"forge campaign --arm ({args.reason or 'cli'})")
    for ap in (args.approve or []):
        engine.approve(ap)
    targets = _load_targets(args.targets)
    planner = Planner(budget=args.budget, exhaustive=args.exhaustive)
    # --modules kind1,kind2 : RESTREINT le plan aux kinds demandés (sélection UI/console).
    # Absent/vide -> plan complet du cerveau (comportement inchangé).
    modules = [m.strip() for m in (args.modules or "").split(",") if m.strip()] or None
    # params par-module globaux : exposés par Scope (plus de double-lecture du scope.json) ;
    # les params par-cible vivent dans targets.json[].attrs.module_params (chargés via _load_targets).
    module_params = dict(scope.module_params or {})
    auto_pentest = getattr(args, "auto_pentest", False)
    # --workflow NAME : lance EXACTEMENT les étapes d'un workflow SAUVEGARDÉ (pipeline composé sans code).
    # Un workflow est une PROPOSITION : ses kinds RESTREIGNENT le plan (--modules) et ses params par-étape
    # enrichissent module_params, MAIS le scope-guard + la sélection par-scope restent seuls JUGES —
    # `resolve()` FILTRE les étapes par l'ensemble EFFECTIF activé du scope (une étape hors-scope/
    # désactivée est LARGUÉE, fail-closed), et l'engine ré-enforce `enabled_kinds` + ROE au tir (défense
    # en profondeur). On force le balayage auto-pentest pour que CHAQUE étape activée soit bien proposée.
    if getattr(args, "workflow", None):
        store = workflows.WorkflowStore.load(_workflows_path(args))
        wf = store.get(args.workflow)
        if wf is None:
            raise SystemExit(f"forge campaign : workflow inconnu '{args.workflow}' "
                             f"(disponibles : {', '.join(sorted(store.list()))})")
        enabled = scope.effective_technique_kinds()
        kept, dropped = workflows.resolve(wf, enabled)
        modules = workflows.step_kinds(wf) or None     # la PROPOSITION (l'engine larguera les désactivées)
        for kind, p in workflows.workflow_module_params(wf).items():
            merged = dict(module_params.get(kind, {})); merged.update(p or {}); module_params[kind] = merged
        auto_pentest = True
        print(f"# Workflow '{wf['name']}' — {len(kept)} étape(s) activée(s) pour ce scope, "
              f"{len(dropped)} larguée(s) (hors-scope/désactivée, fail-closed).")
        if kept:
            print("  Activées : " + ", ".join(s["kind"] for s in kept))
        if dropped:
            print("  Larguées : " + ", ".join(s["kind"] for s in dropped))
    # --auto-pentest : MODE PENTEST AUTOMATISÉ — balaie TOUTES les techniques ACTIVÉES du scope à
    # travers la surface découverte (recon -> chaînage -> oracles), gouverné à l'identique (scope-guard,
    # plancher exploit, ledger). Sinon cerveau heuristique standard. L'ensemble balayé = l'effective set
    # du scope (profil + toggles) -> respecte la sélection par-scope sans câblage par-technique.
    brain = (AutoPentestBrain(scope.effective_technique_kinds())
             if auto_pentest else HeuristicBrain())
    engine.campaign(targets, brain, planner,
                    modules=modules, module_params=module_params)
    if ledger is not None:                 # scelle la fin de campagne : checkpoint (ancré si anchor configuré)
        ledger.checkpoint(note="forge campaign end")
    cov = engine.coverage()
    print(f"Tirées={len(cov['fired'])}  Simulées={len(cov['dry_run'])}  Refusées={len(cov['vetoed'])}  "
          f"Erreurs={len(cov['errors'])}  Déférées(budget)={len(engine.skipped_budget)}  "
          f"Findings={len(engine.findings)}  Dups={engine.dups}  Run-records={len(engine.run_records)}")
    if engine.coverage_gaps:
        print("Lacunes de couverture (classes jamais tentées) :")
        for tgt, miss in engine.coverage_gaps.items():
            print(f"  {tgt}: {', '.join(miss)}")
    if args.purple and engine.run_records:
        n = purple.emit(args.purple, engine.run_records)
        print(f"Run-records ATT&CK -> {args.purple} ({n})")
    if args.console:
        try:
            st, resp = console_client.ingest(
                args.campaign, engine.findings, engine.run_records,
                url=args.console, token=args.console_token,
                run_id=args.run_id, roe_decisions=engine.roe_decisions(),
                coverage=cov, coverage_gaps=engine.coverage_gaps,
                skipped_budget=engine.skipped_budget)
            print(f"Console <- ingest (HTTP {st}): {resp}")
        except Exception as e:  # noqa: BLE001
            print(f"Console: échec ingest ({e!r})")
    rep = build_report(engine)
    if args.report:
        Path(args.report).write_text(rep, encoding="utf-8")
        print(f"Rapport -> {args.report}")
    else:
        print("\n" + rep)
    return 0

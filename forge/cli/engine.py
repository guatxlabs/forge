# SPDX-License-Identifier: AGPL-3.0-only
"""Commandes moteur de la CLI Forge : `plan`, `run`, `campaign` (chargement d'actions/cibles,
armement, ledger, planner, workflows, ingest console). Extrait de l'ancien `forge/cli.py` (pur
déplacement, comportement inchangé)."""
import json
import os
import signal
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


class _Terminate(BaseException):
    """Arrêt GRACIEUX d'un run sur watchdog SIGTERM (console). Dérive de `BaseException` (PAS de
    `Exception`) EXPRÈS : le `except Exception` du moteur (M6, robustesse du tir) ne doit PAS l'avaler
    — il doit dérouler la campagne jusqu'au flush final (finally) pour ne perdre aucun travail."""


def _parse_cli_params(param_args):
    """Parse `--param KIND.KEY=VALUE` (répétable) en dict imbriqué {kind: {key: value}}. FAIL-CLOSED :
    un `--param` malformé (sans '=' séparant la valeur, ou sans '.' séparant kind.key) -> SystemExit
    avec un message clair (jamais un drop silencieux). Les valeurs restent des CHAÎNES (le tool/schéma
    coerce les types comme aujourd'hui). N'INJECTE QUE de la donnée dans module_params : l'allowlist de
    drapeaux, le no-shell et le scope-guard restent appliqués en aval (même chemin que les params UI)."""
    out = {}
    for raw in (param_args or []):
        if "=" not in raw:
            raise SystemExit(f"forge campaign : --param invalide '{raw}' — format attendu KIND.KEY=VALUE "
                             f"(ex : recon.nmap.ports=1-65535)")
        left, value = raw.split("=", 1)
        if "." not in left:
            raise SystemExit(f"forge campaign : --param invalide '{raw}' — 'KIND.KEY' doit contenir un '.' "
                             f"séparant le kind du paramètre (ex : recon.nmap.ports=1-65535)")
        kind, key = left.rsplit(".", 1)
        if not kind or not key:
            raise SystemExit(f"forge campaign : --param invalide '{raw}' — kind et clé requis "
                             f"(ex : recon.nmap.ports=1-65535)")
        out.setdefault(kind, {})[key] = value
    return out


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


def _register_toolspecs(args):
    """Enregistre les ToolSpecs déclaratifs de `--toolspec FILE` (répétable) AVANT le plan. FAIL-CLOSED :
    une spec invalide -> SystemExit avec un message NOMMANT le fichier (aucun enregistrement partiel).
    L'enregistrement passe par `register_spec` -> le kind est gouverné à l'identique d'un module natif."""
    from ..modules import loader as _loader
    for f in (getattr(args, "toolspec", None) or []):
        try:
            kind = _loader.load_toolspec_file(f)
            print(f"ToolSpec enregistré : {kind}  (<- {f})")
        except _loader.SpecError as e:
            raise SystemExit(f"forge : --toolspec invalide -> {e}")


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
    _register_toolspecs(args)              # --toolspec : outils déclaratifs gouvernés, AVANT le plan
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
    _register_toolspecs(args)              # --toolspec : outils déclaratifs gouvernés, AVANT le plan
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
    # --param KIND.KEY=VALUE (répétable) : params par-module ergonomiques pour CE run, SANS éditer
    # scope.json. Intention EXPLICITE de l'opérateur -> PRIORITAIRE : fusionnés PAR-DESSUS scope.module_params
    # ET les params de workflow (le --param gagne). N'injecte QUE de la donnée dans module_params : le
    # scope-guard + l'allowlist de drapeaux + le no-shell restent seuls juges au tir (un extra_arg hors
    # allowlist passé via --param est refusé en aval, exactement comme un param posé via l'UI).
    for kind, p in _parse_cli_params(getattr(args, "param", None)).items():
        merged = dict(module_params.get(kind, {})); merged.update(p or {}); module_params[kind] = merged
    # --auto-pentest : MODE PENTEST AUTOMATISÉ — balaie TOUTES les techniques ACTIVÉES du scope à
    # travers la surface découverte (recon -> chaînage -> oracles), gouverné à l'identique (scope-guard,
    # plancher exploit, ledger). Sinon cerveau heuristique standard. L'ensemble balayé = l'effective set
    # du scope (profil + toggles) -> respecte la sélection par-scope sans câblage par-technique.
    brain = (AutoPentestBrain(scope.effective_technique_kinds())
             if auto_pentest else HeuristicBrain())
    # ── DURABILITÉ INCRÉMENTALE + ARRÊT GRACIEUX AU WATCHDOG ─────────────────────────────────────
    # Sous pilotage console (--console), on FLUSHE findings/run-records/décisions AU FIL DE L'EAU
    # (batch intra-vague via checkpoint_every + frontière de vague) au lieu d'un unique POST « tout ou
    # rien » en fin de run. Un run tué par le watchdog (kill group SIGTERM) ne perd plus le travail des
    # vagues/actions déjà accomplies. Le sink suit des offsets -> chaque item n'est posté qu'UNE fois.
    sink = None
    if args.console:
        sink = console_client.IncrementalIngest(
            args.campaign, args.run_id, url=args.console, token=args.console_token)
    term = {"sig": False}

    def _flush(partial):
        """Flush best-effort du delta vers la console. Erreurs réseau AVALÉES (le run continue) ; les
        offsets du sink n'avancent que sur succès (le delta repart au flush suivant sinon)."""
        if sink is None:
            return
        try:
            r = sink.flush(engine, partial=partial, coverage=engine.coverage(),
                           coverage_gaps=engine.coverage_gaps,
                           skipped_budget=engine.skipped_budget, not_planned=engine.not_planned)
            if r is not None:
                st, resp = r
                print(f"Console <- ingest {'partiel' if partial else 'final'} (HTTP {st}): {resp}",
                      flush=True)
        except Exception as e:  # noqa: BLE001 — l'ingest ne doit JAMAIS casser le run
            print(f"Console: échec ingest {'partiel' if partial else 'final'} ({e!r})", flush=True)

    def _checkpoint():
        """Appelé par le moteur (intra-vague + par vague) : flush PARTIEL, puis — si un SIGTERM de
        watchdog est arrivé — DÉCLENCHE l'arrêt gracieux via `_Terminate`. Le raise est posé À UNE
        FRONTIÈRE d'action (jamais pendant un flush ni un fire) -> pas de réentrance ni de double-envoi."""
        _flush(partial=True)
        if term["sig"]:
            raise _Terminate()

    def _on_sigterm(_signum, _frame):
        # Watchdog console : kill_group envoie SIGTERM PUIS attend le process (pas de SIGKILL immédiat) ->
        # on a le temps de flusher. On ne meurt PAS ici : on POSE un drapeau ; le prochain checkpoint
        # flushe le travail en cours et lève `_Terminate` pour une sortie propre + flush final.
        term["sig"] = True

    # intervalle de checkpoint intra-vague (actions). Réglable via FORGE_INGEST_EVERY (défaut 25).
    every = 0
    old_sigterm = None
    if args.console:
        try:
            every = max(0, int(os.environ.get("FORGE_INGEST_EVERY", "25")))
        except ValueError:
            every = 25
        try:                                    # SIGTERM indisponible hors thread principal / plateforme
            old_sigterm = signal.signal(signal.SIGTERM, _on_sigterm)
        except (ValueError, OSError):
            old_sigterm = None

    terminated = False
    try:
        if args.console:
            engine.campaign(targets, brain, planner,
                            modules=modules, module_params=module_params,
                            checkpoint=_checkpoint, checkpoint_every=every)
        else:
            # chemin SANS console : appel HISTORIQUE (aucun kwarg de durabilité) -> byte-identique.
            engine.campaign(targets, brain, planner,
                            modules=modules, module_params=module_params)
    except _Terminate:
        terminated = True
        print("watchdog: SIGTERM reçu — arrêt gracieux, flush du travail accompli", flush=True)
    finally:
        if old_sigterm is not None:
            try:
                signal.signal(signal.SIGTERM, old_sigterm)
            except (ValueError, OSError):
                pass

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
    if engine.not_planned:
        # bucket anti-lacune : modules sélectionnés/disponibles jamais ordonnancés par le plan.
        print(f"Modules disponibles non planifiés ({len(engine.not_planned)}) :")
        for kind, reason in engine.not_planned.items():
            print(f"  {kind}: {reason}")
    if args.purple and engine.run_records:
        n = purple.emit(args.purple, engine.run_records)
        print(f"Run-records ATT&CK -> {args.purple} ({n})")
    # FLUSH FINAL : envoie le delta RESTANT (dernière vague partielle) + gaps/skipped/not_planned
    # complets. `partial=terminated` : sur une fin NORMALE (partial=False) le run_job est marqué 'done' ;
    # sur un arrêt watchdog (partial=True) le statut reste 'running' pour que le superviseur console le
    # marque honnêtement 'timeout' (compteurs non nuls déjà persistés par les flushes incrémentaux).
    _flush(partial=terminated)
    rep = build_report(engine)
    if args.report:
        Path(args.report).write_text(rep, encoding="utf-8")
        print(f"Rapport -> {args.report}")
    else:
        print("\n" + rep)
    return 0

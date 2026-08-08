# SPDX-License-Identifier: AGPL-3.0-or-later
"""Commandes moteur de la CLI Forge : `plan`, `run`, `campaign` (chargement d'actions/cibles,
armement, ledger, planner, workflows, ingest console). Extrait de l'ancien `forge/cli.py` (pur
déplacement, comportement inchangé).

LIVRABLE GARANTI (lot BUDGET/INTERRUPTION). Ce fichier est l'endroit exact où deux campagnes réelles
ont perdu leur rendu : `build_report` et `_save_durations` vivaient APRÈS la boucle, et le handler de
signal qui aurait permis de les atteindre n'était installé QUE sous `--console`. Un `timeout(1)`
externe tombait donc sur le handler par défaut de Python et tuait le process à l'instruction courante
— ledger complet sur le disque, zéro rapport, zéro sidecar de durées.

Trois causes d'arrêt, un seul chemin de sortie : le rendu (rapport + durées + checkpoint de ledger)
est désormais dans un `finally` et s'exécute pour **l'échéance du budget**, pour un **SIGTERM/SIGINT
externe** et pour une **exception non rattrapée** (qui continue de remonter APRÈS le rendu, pour que
le code de sortie reste honnête)."""
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
from ..memory import make_memory
from ..durations import DurationStore
from ..interrupt import (Budget, GracefulStop, Terminate, CAUSE_ERROR,
                         interruption_record, resolve_run_timeout)
from .. import purple
from .. import console_client
from .. import workflows
from .. import runner

#: Arrêt gracieux — nom HISTORIQUE conservé pour les appelants existants (tests de durabilité,
#: `_checkpoint` du watchdog console). La classe vit maintenant dans `forge.interrupt` : le moteur
#: doit pouvoir la lever lui-même (frontière d'action), et il ne peut pas importer la CLI.
_Terminate = Terminate


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


def _report_view(args):
    """Vue de rendu du rapport demandée en ligne de commande (`--view pentest|bounty`), ou None.

    `getattr` TOLÉRANT à dessein : tant que le parseur (`forge/cli/__init__.py`, hors de ce module)
    n'expose pas `--view`, on renvoie None et `report.build_report` retombe sur `$FORGE_REPORT_VIEW`
    puis `scope.triage.view` / `scope.triage.auto_hide` puis le défaut `pentest`. Aucune vue n'est
    donc imposée en silence, et l'ajout du drapeau au parseur suffira à l'activer."""
    return getattr(args, "view", None)


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


def _make_memory(args):
    """Store mémoire du run, ou None si `--memory` absent (comportement inchangé). Le BACKEND de dedup
    vient de `--memory-mode` (défaut `exact` == comportement historique) ; `--memory-allow-download`
    est l'opt-in d'egress du backend `embeddings`. `make_memory` dégrade seul vers le repli stdlib si
    le backend demandé est indisponible — la CLI n'a donc aucun cas d'erreur à traiter ici."""
    if not getattr(args, "memory", None):
        return None
    return make_memory(args.memory,
                       mode=getattr(args, "memory_mode", "exact") or "exact",
                       allow_download=bool(getattr(args, "memory_allow_download", False)))


def _make_durations(args):
    """Magasin de DURÉES OBSERVÉES par kind, sidecar `<ledger>.durations` — donc PAR ENGAGEMENT (la
    console donne à chaque engagement son ledger dédié), donc supprimé avec lui. Rend None sans
    `--ledger` : aucun fichier créé, préchauffage sur `action.cost` comme avant. `FORGE_DURATIONS=0`
    l'éteint. Alimente UNIQUEMENT l'ordre de SOUMISSION du préchauffage — jamais une décision de tir."""
    return DurationStore.for_ledger(getattr(args, "ledger", None))


def _save_durations(store):
    """Persiste les durées mesurées par ce run (best-effort, jamais une cause d'échec)."""
    if store is not None:
        store.save()


def _make_budget(args):
    """BUDGET DE TEMPS de ce run (`interrupt.Budget`), ou None si l'opérateur n'en a pas posé.

    SURFACE, ET POURQUOI CELLE-LÀ. On ne crée PAS un nouveau levier : `run_timeout_secs` existe déjà
    dans `resource_profile` (valeurs par profil 1800/3600/7200), avec son override d'env DÉJÀ
    tabulé (`FORGE_RUN_TIMEOUT`) et DÉJÀ validé côté console (`runs_validate.rs` : clé `run_timeout`,
    bornes 1..604800) — c'est même la variable que la console pose au spawn du moteur et que son
    watchdog Rust lit. Le levier n'avait qu'un défaut : il n'était appliqué que DE L'EXTÉRIEUR, à
    coups de SIGKILL. On lui donne son exécution IN-PROCESS, sur la même variable et les mêmes
    bornes, plus le drapeau `--run-timeout` qui manquait à l'échelon « override explicite » de la
    précédence documentée. Aucun réglage nouveau à tenir en cohérence avec l'existant.

    ABSENT PAR DÉFAUT : sans drapeau ni variable, aucun budget (cf. `interrupt.resolve_run_timeout`)."""
    secs = resolve_run_timeout(getattr(args, "run_timeout", None))
    if not secs:
        return None
    return Budget(secs)


def _make_stop(args, emit):
    """Prédicat d'arrêt gracieux du run : budget + signaux externes (SIGTERM/SIGINT).

    Le handler ne meurt PAS sur place : il pose un drapeau ET coupe les groupes d'outils EN VOL
    (`runner.terminate_live_tool_groups`) — les outils tournent dans des sessions séparées
    (start_new_session, E3), donc un SIGTERM whole-run ne les atteint pas et le moteur resterait
    bloqué dans `communicate()` au lieu d'atteindre sa prochaine frontière d'action."""
    def _cut_tools():
        try:
            runner.terminate_live_tool_groups(force=True)
        except Exception:  # noqa: BLE001 — un handler de signal ne doit JAMAIS lever
            pass
    stop = GracefulStop(budget=_make_budget(args), on_signal=_cut_tools, emit=emit)
    if stop.budget is not None:
        emit(f"# Budget de temps : {stop.budget.seconds}s — à l'échéance le run S'ARRÊTE proprement "
             f"(frontière d'action) et rend un rapport annoncé PARTIEL.")
    return stop


def _render(args, engine, interruption, durations, ledger, sink_flush=None,
            ledger_note="forge run end"):
    """RENDU FINAL — l'unique chemin de sortie, appelé depuis un `finally` : fin normale, échéance de
    budget, signal externe, ou exception non rattrapée. C'est CE bloc que les deux campagnes tuées
    n'ont jamais atteint.

    ORDRE VOULU : (1) durées observées (le sidecar `.durations`, perdu pour la même raison que le
    rapport — un run coupé a MESURÉ des durées qui doivent profiter au suivant) ; (2) checkpoint du
    ledger ; (3) flush console ; (4) rapport. Chaque étape est isolée : l'échec de l'une n'empêche
    pas les suivantes, et AUCUNE ne peut masquer l'exception qui nous a menés ici."""
    def _step(label, fn):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — un rendu best-effort ne masque JAMAIS la cause d'arrêt
            print(f"[!] rendu : échec {label} ({e!r})", flush=True)

    _step("sidecar de durées", lambda: _save_durations(durations))
    if ledger is not None:
        _step("checkpoint ledger", lambda: ledger.checkpoint(note=ledger_note))
    if sink_flush is not None:
        _step("flush console", sink_flush)
    if interruption:
        print(f"[STOP] run INTERROMPU ({interruption.get('label')}) — "
              f"{interruption.get('ran')} action(s) exécutée(s)"
              + (f" sur {interruption['planned']} planifiée(s)" if interruption.get("planned") else "")
              + " ; le rapport est marqué PARTIEL.", flush=True)

    def _report():
        rep = build_report(engine, view=_report_view(args), interruption=interruption)
        if args.report:
            Path(args.report).write_text(rep, encoding="utf-8")
            print(f"Rapport{' PARTIEL' if interruption else ''} -> {args.report}", flush=True)
        else:
            print("\n" + rep)
    _step("écriture du rapport", _report)


def cmd_run(args):
    _register_toolspecs(args)              # --toolspec : outils déclaratifs gouvernés, AVANT le plan
    scope = Scope.load(args.scope)
    ledger = Ledger(args.ledger) if args.ledger else None
    memory = _make_memory(args)
    durations = _make_durations(args)
    stop = _make_stop(args, lambda line: print(line, flush=True))
    engine = Engine(scope, ledger=ledger, mode=args.mode, memory=memory, durations=durations,
                    stop=stop.reason)
    if args.arm:
        engine.arm(f"forge run --arm ({args.reason or 'cli'})")
    for ap in (args.approve or []):
        engine.approve(ap)
    actions = _load_actions(args.actions) if args.actions else _demo_actions(scope)
    # `run()` n'a PAS de campagne : le dénominateur « planifiées » est la liste d'actions elle-même.
    actions = list(actions)
    engine.planned_total = len(actions)
    interruption = None
    with stop:
        try:
            engine.run(actions)
        except Terminate as t:
            interruption = interruption_record(t, budget=stop.budget, engine=engine)
        except BaseException as exc:       # noqa: BLE001 — on RÉÉMET après avoir rendu (voir finally)
            interruption = interruption_record(Terminate(CAUSE_ERROR, f"{type(exc).__name__}: {exc}"),
                                               budget=stop.budget, engine=engine)
            raise
        finally:
            if interruption is not None:   # actions ordonnées jamais atteintes (aucun verdict émis)
                done = {r["action"] for r in engine.results}
                engine.not_attempted = [a for a in actions if a.id not in done]
                interruption["not_attempted"] = len(engine.not_attempted)
            cov = engine.coverage()
            print(f"Tirées={len(cov['fired'])}  Simulées={len(cov['dry_run'])}  "
                  f"Refusées={len(cov['vetoed'])}  Erreurs={len(cov['errors'])}  "
                  f"Findings={len(engine.findings)}")
            _render(args, engine, interruption, durations, ledger)
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
    memory = _make_memory(args)
    durations = _make_durations(args)
    # ÉMISSION PROGRESSIVE : la console pompe le stdout du moteur ligne à ligne vers le flux SSE du run.
    # On branche un callback qui imprime CHAQUE ligne d'avancement immédiatement (flush) pour que les
    # verdicts/SKIP par action et les bannières de vague STREAMENT en direct (au lieu du seul récap final).
    # `flush=True` complète PYTHONUNBUFFERED posé par la console au spawn (sortie non bufferisée).
    def _progress(line):
        print(line, flush=True)
    # ARRÊT GRACIEUX — INSTALLÉ INCONDITIONNELLEMENT (le correctif central de ce lot). Il l'était
    # UNIQUEMENT sous `--console` : les deux campagnes réelles, lancées en CLI directe, n'avaient donc
    # AUCUN handler et mouraient sur le SIGTERM par défaut de Python, sans rendre ni rapport ni durées.
    stop = _make_stop(args, _progress)
    engine = Engine(scope, ledger=ledger, mode=args.mode, memory=memory, progress=_progress,
                    durations=durations, stop=stop.reason)
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
        FRONTIÈRE d'action (jamais pendant un flush ni un fire) -> pas de réentrance ni de double-envoi.

        Le déclenchement est aujourd'hui DOUBLÉ (défense en profondeur) : le moteur consulte le même
        `stop` à CHAQUE action, donc sans attendre le prochain checkpoint (25 actions par défaut).
        On garde le raise ici parce que la cadence du flush console et celle de l'arrêt restent des
        décisions distinctes, et parce que ce chemin est celui que couvrent les tests de durabilité."""
        _flush(partial=True)
        term = stop.reason()
        if term is not None:
            raise term

    # intervalle de checkpoint intra-vague (actions). Réglable via FORGE_INGEST_EVERY (défaut 25).
    every = 0
    if args.console:
        try:
            every = max(0, int(os.environ.get("FORGE_INGEST_EVERY", "25")))
        except ValueError:
            every = 25

    interruption = None
    # `with stop` : handlers SIGTERM/SIGINT posés pour TOUT le run (plus seulement sous --console) et
    # restaurés à la sortie, y compris sur exception.
    with stop:
        try:
            if args.console:
                engine.campaign(targets, brain, planner,
                                modules=modules, module_params=module_params,
                                checkpoint=_checkpoint, checkpoint_every=every)
            else:
                # chemin SANS console : appel HISTORIQUE (aucun kwarg de durabilité) -> byte-identique.
                engine.campaign(targets, brain, planner,
                                modules=modules, module_params=module_params)
        except Terminate as t:
            interruption = interruption_record(t, budget=stop.budget, engine=engine)
        except BaseException as exc:       # noqa: BLE001 — RÉÉMISE après le rendu (voir `finally`)
            # 3e cause : exception non rattrapée. Le rendu doit AVOIR LIEU (le travail est fait et le
            # ledger est intact) ; l'exception continue ensuite sa route pour que le code de sortie
            # reste honnête — un plantage ne doit pas se déguiser en run réussi.
            interruption = interruption_record(Terminate(CAUSE_ERROR, f"{type(exc).__name__}: {exc}"),
                                               budget=stop.budget, engine=engine)
            raise
        finally:
            cov = engine.coverage()
            print(f"Tirées={len(cov['fired'])}  Simulées={len(cov['dry_run'])}  "
                  f"Refusées={len(cov['vetoed'])}  Erreurs={len(cov['errors'])}  "
                  f"Déférées(budget)={len(engine.skipped_budget)}  Findings={len(engine.findings)}  "
                  f"Dups={engine.dups}  Run-records={len(engine.run_records)}")
            if engine.coverage_gaps:
                print("Lacunes de couverture (classes jamais tentées) :")
                for tgt, miss in engine.coverage_gaps.items():
                    print(f"  {tgt}: {', '.join(miss)}")
            if engine.not_planned:
                # bucket anti-lacune : modules sélectionnés/disponibles jamais ordonnancés par le plan.
                print(f"Modules disponibles non planifiés ({len(engine.not_planned)}) :")
                for kind, reason in engine.not_planned.items():
                    print(f"  {kind}: {reason}")
            if engine.not_attempted:
                print(f"Actions planifiées JAMAIS TENTÉES ({len(engine.not_attempted)} sur "
                      f"{engine.planned_total} ordonnée(s)) — aucun verdict émis pour elles.")
            if args.purple and engine.run_records:
                try:
                    n = purple.emit(args.purple, engine.run_records)
                    print(f"Run-records ATT&CK -> {args.purple} ({n})")
                except Exception as e:  # noqa: BLE001 — jamais au prix du rapport
                    print(f"[!] rendu : échec run-records ATT&CK ({e!r})", flush=True)
            # FLUSH FINAL : delta RESTANT + gaps/skipped/not_planned complets. `partial` : sur une fin
            # NORMALE (False) le run_job est marqué 'done' ; sur un arrêt anticipé (True) le statut
            # reste 'running' pour que le superviseur console le marque honnêtement 'timeout'.
            _render(args, engine, interruption, durations, ledger,
                    sink_flush=lambda: _flush(partial=bool(interruption)),
                    ledger_note="forge campaign end")
    return 0

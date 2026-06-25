"""Engine Forge — la boucle de contrôle : plan -> gate ROE -> dry|fire -> ledger -> findings.

Tout passe par la gate `Roe`. Un module n'est JAMAIS appelé en fire() sans verdict FIRE.
Chaque action est tracée (results) avec son verdict pour le rapport anti-masquage.

Bridge secpipe (optionnel) : si secpipe est importable, on pourra brancher son planner
coverage-safe + graph (P2). v0 fonctionne sans, en mode liste-d'actions explicite.
"""
from .roe import Roe, Action, VETO, DRY_RUN, FIRE
from .graph import EngagementGraph
from . import modules as mods
from . import purple


class Engine:
    def __init__(self, scope, ledger=None, mode="propose", memory=None, graph=None):
        self.scope = scope
        self.ledger = ledger
        self.memory = memory       # memory.Memory | None — dedup + persistance des findings
        self.graph = graph if graph is not None else EngagementGraph()
        self.roe = Roe(scope, ledger=ledger, mode=mode)
        self.findings = []
        self.results = []          # [{action, verdict, reasons, output}]
        self.run_records = []      # boucle purple : un record ATT&CK par action tirée
        self.skipped_budget = []   # actions déférées par le planner (defer != delete)
        self.coverage_gaps = {}    # classes jamais tentées, par cible
        self.dups = 0              # findings ignorés car déjà en mémoire

    # --- armement délégué (gestes journalisés) ---
    def arm(self, reason="armed by operator"):
        self.roe.arm(reason)

    def approve(self, action_id, reason="approved by operator"):
        self.roe.approve(action_id, reason)

    # --- exécution d'une action via son module ---
    def execute(self, action):
        module = mods.get(action.kind)
        if module is None:
            res = {"action": action.id, "target": action.target, "kind": action.kind,
                   "verdict": "ERROR", "reasons": [f"aucun module enregistré pour '{action.kind}'"],
                   "output": None}
            self.results.append(res)
            if self.ledger:
                self.ledger.append("engine.error", res)
            return res

        if getattr(module, "available", True) is False:
            res = {"action": action.id, "target": action.target, "kind": action.kind,
                   "verdict": "SKIP", "reasons": ["module indisponible (outil sous-jacent absent)"],
                   "output": None}
            self.results.append(res)
            return res

        # le module peut imposer exploit/destructif au-delà de ce que l'action déclare
        action.exploit = action.exploit or bool(getattr(module, "exploit", False))
        action.destructive = action.destructive or bool(getattr(module, "destructive", False))

        decision = self.roe.decide(action)

        if decision.verdict == VETO:
            output = None
        elif decision.verdict == DRY_RUN:
            output = module.dry(action)              # AUCUN effet de bord
        else:                                        # FIRE
            raw = module.fire(action) or []
            new = []
            for f in raw:
                if self.memory is not None and not self.memory.store(f):
                    self.dups += 1                   # déjà vu -> dedup
                    continue
                new.append(f)
                self.findings.append(f)
                self.graph.add_finding(f)            # enrichit le world-model
                if self.ledger:
                    self.ledger.append("finding", f.to_dict())
            # run-record purple : la technique a été exécutée (mitre du finding, sinon du module,
            # sinon des params). Fallback module pour qu'une action tirée SANS finding ait quand même
            # son ATT&CK dans le record (sinon trou de couverture purple sur les tirs « rien trouvé »).
            mitre = action.params.get("mitre") or (new[0].mitre if new else "") or getattr(module, "mitre", "") or ""
            rr = purple.run_record(action.target, action.kind, mitre, fired=True,
                                   detail=f"{len(new)} finding(s)")
            self.run_records.append(rr)
            if self.ledger:
                self.ledger.append("purple.runrecord", rr)
            output = [f.to_dict() for f in new]

        res = {"action": action.id, "target": action.target, "kind": action.kind,
               "verdict": decision.verdict, "reasons": decision.reasons, "output": output}
        self.results.append(res)
        return res

    def run(self, actions):
        return [self.execute(a) for a in actions]

    def campaign(self, targets, brain, planner, modules=None, module_params=None):
        """recon-state -> cerveau propose -> planner ordonne (coverage-safe) -> run gaté.

        `targets` = list[Target]. `modules` (list[str] | None) RESTREINT le plan aux kinds
        demandés (sélection UI/console) : si fourni non vide, seules les actions dont le `kind`
        figure dans `modules` sont planifiées. None/vide => comportement inchangé (plan complet
        du cerveau). Le filtre RESTREINT seulement : il n'ajoute jamais de capacité (la gate ROE
        reste seule juge ; un kind demandé mais exploit/destructif sera quand même vétoé).

        `module_params` ({kind: {param: val}} | None) = params globaux (issus du scope) mappés
        dans `action.params`. Les params PAR-CIBLE de `target.attrs.module_params[kind]` sont
        aussi mappés (et l'emportent sur les globaux). Les modules les lisent via params.get(...).

        Trace skipped_budget + coverage_gaps pour le rapport (anti-masquage). Rien ne tire
        sans verdict FIRE de la gate.
        """
        for t in targets:                            # amorce le world-model avec les cibles
            self.graph.add_host(t.host, kind=t.kind, **(t.attrs or {}))
        actions = brain.propose(targets)

        # (1) RESTRICTION par sélection de modules (UI/console) : ne garder que les kinds demandés.
        wanted = {m for m in (modules or []) if m}
        if wanted:
            actions = [a for a in actions if a.kind in wanted]

        # (2) params par-module -> action.params (la console les écrit dans scope ET target.attrs).
        #     Priorité : params spécifiques à la cible (target.attrs) > params globaux (scope).
        #     setdefault : on n'écrase jamais un param déjà posé par le cerveau.
        global_params = module_params or {}
        attrs_by_host = {t.host: (t.attrs or {}).get("module_params", {}) or {} for t in targets}
        for a in actions:
            for src in (global_params, attrs_by_host.get(a.target, {})):
                for k, v in (src.get(a.kind, {}) or {}).items():
                    a.params.setdefault(k, v)

        # injecte les creds/URLs du scope dans les actions IDOR (grey/white box)
        for a in actions:
            if a.cls in ("access_control", "idor", "bola") and not a.params.get("urls"):
                a.params.setdefault("accounts", self.scope.known_creds)
                a.params.setdefault("urls", self.scope.idor_targets)
                a.params.setdefault("mitre", "T1190")

        # injecte le périmètre dans les actions origin.find : la cible (domaine) est gatée par le ROE,
        # mais origin.find résout des sous-domaines vers des IP à runtime -> chaque IP DOIT être
        # re-validée fail-closed contre le scope avant connexion (miroir de l'injection IDOR ci-dessus).
        for a in actions:
            if a.kind == "origin.find":
                a.params.setdefault("in_scope", self.scope.in_scope)
                a.params.setdefault("out_scope", self.scope.out_scope)
        hosts = [t.host for t in targets]
        ordered, self.skipped_budget = planner.order(actions)
        self.coverage_gaps = planner.coverage_gaps(actions, hosts)
        self.run(ordered)
        return self.coverage()

    # --- transparence (anti-masquage, repris de secpipe) ---
    def coverage(self):
        fired = [r for r in self.results if r["verdict"] == FIRE]
        dry = [r for r in self.results if r["verdict"] == DRY_RUN]
        vetoed = [r for r in self.results if r["verdict"] == VETO]
        errors = [r for r in self.results if r["verdict"] in ("ERROR", "SKIP")]
        return {"fired": fired, "dry_run": dry, "vetoed": vetoed, "errors": errors}

    def roe_decisions(self):
        """Trace ROE sérialisable : un verdict par action évaluée (anti-masquage).

        Dérivé de `self.results` (le journal des décisions) — chaque entrée porte le
        verdict ROE et ses raisons, sans la sortie (output) du module. Consommé par la
        console pour exposer la couverture par action. Pur, sans réseau."""
        return [
            {"action_id": r["action"], "target": r["target"], "kind": r["kind"],
             "verdict": r["verdict"], "reasons": list(r.get("reasons") or [])}
            for r in self.results
        ]

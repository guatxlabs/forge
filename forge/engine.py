"""Engine Forge — la boucle de contrôle : plan -> gate ROE -> dry|fire -> ledger -> findings.

Tout passe par la gate `Roe`. Un module n'est JAMAIS appelé en fire() sans verdict FIRE.
Chaque action est tracée (results) avec son verdict pour le rapport anti-masquage.

Bridge secpipe (optionnel) : si secpipe est importable, on pourra brancher son planner
coverage-safe + graph (P2). v0 fonctionne sans, en mode liste-d'actions explicite.
"""
from .roe import Roe, VETO, DRY_RUN, FIRE
from .graph import EngagementGraph
from . import modules as mods
from . import purple
from . import session

# Kinds dont le module DÉCOUVRE/RÉSOUT des hôtes à runtime (au-delà de la cible gatée par le ROE) :
# l'engine leur injecte le périmètre (in_scope/out_scope) dans action.params pour que chaque hôte
# dérivé soit re-validé fail-closed AVANT émission/connexion (cf. _prepare + modules recon_surface/origin).
_SCOPE_INJECT_KINDS = frozenset({
    "origin.find", "recon.subdomains", "recon.dns", "recon.js_endpoints", "recon.urls", "recon.tech",
    # modules ACTIFS de reachability/discovery (recon_active.py) : ils requêtent/dérivent des assets
    # à runtime -> re-validation fail-closed contre le périmètre injecté (cf. recon_active).
    "recon.content", "recon.secrets", "recon.waf",
    # DÉCOUVERTE backed-browser (evasion.discover) : navigue derrière le WAF et EXTRAIT des endpoints
    # à runtime -> mêmes garanties que recon.js_endpoints : le périmètre injecté sert à RE-VALIDER
    # fail-closed chaque endpoint découvert avant émission (le scope-guard du module en dépend).
    "evasion.discover",
})

# Kinds ACTIFS rate-limités : l'engine injecte le débit ROE du scope (`rate`) dans action.params pour
# que le module borne son trafic (ex: ffuf -rate). Additif (setdefault) : n'écrase jamais un param posé.
_RATE_LIMITED_KINDS = frozenset({"recon.content", "recon.secrets", "recon.waf"})


class Engine:
    def __init__(self, scope, ledger=None, mode="propose", memory=None, graph=None,
                 campaign=None, run_id=None):
        self.scope = scope
        self.ledger = ledger
        self.memory = memory       # memory.Memory | None — dedup + persistance des findings
        self.graph = graph if graph is not None else EngagementGraph()
        self.roe = Roe(scope, ledger=ledger, mode=mode)
        # SESSION GOUVERNÉE (SECRET) : store d'authentification dérivé du scope (`session` défaut global
        # + `sessions` par-hôte). Lié autour de chaque fire() (execute) ; les modules recon/oracle y
        # puisent le matériel à attacher AUX SEULES requêtes in-scope. Store inerte si rien de configuré.
        self.sessions = session.SessionStore.from_scope(scope)
        self.campaign_id = campaign  # boucle purple : corrèle les run-records à la campagne…
        self.run_id = run_id         # …et au run (console). None tant que non fournis (additif).
        self.findings = []
        self.results = []          # [{action, verdict, reasons, output}]
        self.run_records = []      # boucle purple : un record ATT&CK par action tirée
        self.skipped_budget = []   # actions déférées par le planner (defer != delete)
        self.coverage_gaps = {}    # classes jamais tentées, par cible
        self.dups = 0              # findings ignorés car déjà en mémoire
        self.waves = 0             # nb de vagues plan->observe->replan exécutées (campagne itérative)

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

        # GOUVERNANCE CONNECTEUR (console) : un kind DÉSACTIVÉ par l'opérateur (scope.disabled_modules)
        # est SKIP comme un outil absent — même si son binaire/service EST présent. C'est l'enforcement
        # au tir de la gouvernance UI : disabling un connecteur empêche RÉELLEMENT le module de tirer,
        # y compris quand c'est le planner (et non `--modules`) qui l'a choisi. Vérifié avant la sonde
        # `available` pour porter la raison la plus spécifique dans le rapport anti-masquage.
        disabled = getattr(self.scope, "disabled_modules", None) or set()
        if action.kind in disabled:
            res = {"action": action.id, "target": action.target, "kind": action.kind,
                   "verdict": "SKIP",
                   "reasons": ["module désactivé par la console (gouvernance connecteur)"],
                   "output": None}
            self.results.append(res)
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
            # SESSION GOUVERNÉE : lie le store (scope-guardé) le temps du fire — les modules recon/oracle
            # attachent le matériel d'auth SECRET aux requêtes IN-SCOPE via les chokepoints HTTP partagés.
            # Rien de secret ne transite par les findings ni le ledger (le matériel n'est que dans la
            # requête sortante). Le contexte est restauré en sortie même en cas d'exception.
            with session.using(self.sessions):
                raw = module.fire(action) or []
            new = []
            for f in raw:
                if self.memory is not None and not self.memory.store(f):
                    self.dups += 1                   # déjà vu -> dedup
                    continue
                new.append(f)
                self.findings.append(f)
                self.graph.add_finding(f)            # enrichit le world-model
                # SESSION À TRAVERS LA CHAÎNE : un module de découverte a dérivé un NOUVEL hôte/endpoint
                # in-scope (origine IP, sous-domaine, endpoint) depuis action.target. On fait HÉRITER à
                # cette cible dérivée la session gouvernée de la source (SCOPE-GUARDÉE : no-op si la
                # dérivée est hors-scope) pour que les oracles chaînés soient authentifiés. Le matériel
                # reste SECRET : `inherit` ne journalise/retourne rien et n'entre ni dans le finding, ni
                # dans le ledger, ni dans action.params, ni dans le graphe.
                dst = getattr(f, "target", None)
                if dst and dst != action.target:
                    self.sessions.inherit(action.target, dst)
                if self.ledger:
                    self.ledger.append("finding", f.to_dict())
            # run-record purple : la technique a été exécutée. Priorité du mitre (le VRAI prime) :
            #   1. params.mitre (posé par le scope/console)   2. mitre du 1er finding émis
            #   3. mitre déclaré par le module                4. fallback par-kind (DEFAULT_MITRE_BY_KIND)
            # Le repli par-kind garantit un record NON VIDE même pour un tir SANS finding sur un module
            # à mitre='' (sinon trou de couverture purple sur les tirs « rien trouvé »).
            mitre = (action.params.get("mitre") or (new[0].mitre if new else "")
                     or getattr(module, "mitre", "") or purple.mitre_for_kind(action.kind) or "")
            rr = purple.run_record(action.target, action.kind, mitre, fired=True,
                                   detail=f"{len(new)} finding(s)",
                                   run_id=self.run_id, campaign=self.campaign_id)
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

    def _prepare(self, actions, modules, global_params, attrs_by_host):
        """Filtre (sélection modules) + injection de params/scope sur une VAGUE d'actions.

        Extrait de la boucle pour être appliqué identiquement à chaque vague (1re proposition ET
        re-propositions chaînées). N'AJOUTE aucune capacité : restreint + pré-remplit (setdefault).
        Retourne la liste filtrée+enrichie (les Actions sont mutées en place via leurs params)."""
        # (1) RESTRICTION par sélection de modules (UI/console) : ne garder que les kinds demandés.
        wanted = {m for m in (modules or []) if m}
        if wanted:
            actions = [a for a in actions if a.kind in wanted]

        # (2) params par-module -> action.params (la console les écrit dans scope ET target.attrs).
        #     Priorité : params spécifiques à la cible (target.attrs) > params globaux (scope).
        #     setdefault : on n'écrase jamais un param déjà posé par le cerveau.
        for a in actions:
            for src in (global_params, attrs_by_host.get(a.target, {})):
                for k, v in (src.get(a.kind, {}) or {}).items():
                    a.params.setdefault(k, v)

        # injecte les creds/URLs du scope dans les actions IDOR (grey/white box). setdefault PUR : une
        # action IDOR CHAÎNÉE sur un endpoint découvert porte déjà `urls=[endpoint]` (edge C) -> on ne
        # l'écrase pas, mais on lui injecte quand même les comptes/mitre du scope (sinon l'oracle
        # skiperait faute de creds). Une action IDOR de base (sans urls) reçoit urls=idor_targets.
        for a in actions:
            if a.cls in ("access_control", "idor", "bola"):
                a.params.setdefault("accounts", self.scope.known_creds)
                a.params.setdefault("urls", self.scope.idor_targets)
                a.params.setdefault("mitre", "T1190")

        # injecte le périmètre dans les actions qui DÉCOUVRENT/RÉSOLVENT des hôtes à runtime : la
        # cible (domaine) est gatée par le ROE, mais ces modules produisent de NOUVEAUX hôtes (IP
        # d'origine, sous-domaines, URLs historiques, endpoints JS) qui DOIVENT être re-validés
        # fail-closed contre le scope avant d'être émis/connectés (miroir de l'injection IDOR ci-dessus).
        for a in actions:
            if a.kind in _SCOPE_INJECT_KINDS:
                a.params.setdefault("in_scope", self.scope.in_scope)
                a.params.setdefault("out_scope", self.scope.out_scope)
            if a.kind in _RATE_LIMITED_KINDS:                # débit ROE -> borne le trafic actif du module
                a.params.setdefault("rate", self.scope.rate)
        return actions

    def campaign(self, targets, brain, planner, modules=None, module_params=None, max_waves=4):
        """ITÉRATIF : plan -> observe -> replan, jusqu'à un critère d'arrêt.

        Boucle (chaque vague) : `brain.propose(self.graph)` lit le world-model -> planner ordonne
        (coverage-safe) -> run gaté -> les findings enrichissent le graphe (fait dans execute()) ->
        re-propose à partir du graphe enrichi (chaînage : CDN->origin->nuclei/idor, fingerprint->oracles).

        Critères d'ARRÊT (le premier atteint) :
          1. plus de NOUVELLE action (toutes les actions proposées ont déjà été exécutées) -> point fixe ;
          2. `max_waves` vagues atteint (garde-fou anti-boucle) ;
          3. planner sans budget restant pour de nouvelles actions non-qualifiantes (implicite via order()).
        Le ROE/gouvernance reste appliqué À CHAQUE VAGUE (rien ne tire sans verdict FIRE).

        `targets` = list[Target]. `modules` / `module_params` : voir _prepare() (restriction +
        injection, inchangés, appliqués à chaque vague). `max_waves` borne le nombre d'itérations.

        Idempotence/dedup : on suit les ids d'actions DÉJÀ PLANIFIÉES (executed_ids) ; une action
        re-proposée à l'identique (id stable kind:target) n'est jamais rejouée -> point fixe garanti.
        skipped_budget et coverage_gaps sont ACCUMULÉS sur l'ensemble des vagues (anti-masquage).
        """
        for t in targets:                            # amorce le world-model avec les cibles
            # SESSION par-cible (SECRET) : matériel d'auth déclaré dans targets.json[].attrs.session.
            # RETIRÉ des attrs poussés au graphe (le secret ne doit JAMAIS entrer dans le world-model,
            # que le brain/rapport peuvent surfacer) et versé dans le store scope-guardé pour ce host.
            attrs = dict(t.attrs or {})
            tsess = attrs.pop("session", None)
            self.graph.add_host(t.host, kind=t.kind, **attrs)
            if tsess:
                self.sessions.add_host_session(t.host, tsess)

        global_params = module_params or {}
        attrs_by_host = {t.host: (t.attrs or {}).get("module_params", {}) or {} for t in targets}
        hosts = [t.host for t in targets]

        executed_ids = set()                         # ids d'actions déjà planifiées (dedup inter-vagues)
        skipped_by_id = {}                           # accumule les déférées (par id, pas de doublon)
        waves = 0
        while waves < max_waves:
            # le cerveau lit l'ÉTAT (graphe enrichi par la vague précédente), pas juste les cibles.
            proposed = brain.propose(self.graph)
            proposed = self._prepare(proposed, modules, global_params, attrs_by_host)
            # NOUVELLES actions seulement (idempotence : on ne rejoue pas une action déjà planifiée).
            fresh = [a for a in proposed if a.id not in executed_ids]
            if not fresh:                            # critère d'arrêt 1 : point fixe (rien de neuf)
                break
            for a in fresh:
                executed_ids.add(a.id)

            ordered, skipped = planner.order(fresh)
            for a in skipped:                        # defer != delete : accumulé, jamais jeté
                skipped_by_id[a.id] = a
            self.run(ordered)
            waves += 1

        self.skipped_budget = list(skipped_by_id.values())
        # une classe n'est une lacune QUE si elle n'a JAMAIS été tentée sur AUCUNE vague :
        # recalcul final à partir de tous les kinds réellement exécutés (results), par host.
        self.coverage_gaps = self._final_gaps(planner, hosts)
        self.waves = waves
        return self.coverage()

    def _final_gaps(self, planner, hosts):
        """Lacunes APRÈS toutes les vagues : classe de la checklist jamais tentée sur le host.

        Dérive des `results` (kinds réellement planifiés, toutes vagues confondues) -> reflète le
        chaînage (une classe tentée en vague 2 n'est plus une lacune). cls = suffixe du kind, comme
        la dataclass Action (`access_control.idor` -> `idor`... mais on garde la classe d'action si
        connue). On reconstruit la classe par la même règle que Action.__post_init__."""
        attempted = {h: set() for h in hosts}
        for r in self.results:
            cls = r["kind"].split(".")[-1]
            # repli sur le préfixe pour les kinds composés (access_control.idor -> access_control)
            prefix = r["kind"].split(".")[0]
            tgt = str(r["target"])
            for h in hosts:
                # rattacher une action au host si la cible EST le host, ou en dérive par un
                # délimiteur franc (host:port, host/path). Un simple startswith rattacherait à tort
                # `app.test` à `app.testing`/`app.test.evil` -> faux « tenté » masquant une lacune.
                hs = str(h)
                if tgt == hs or tgt.startswith(hs + ":") or tgt.startswith(hs + "/"):
                    attempted[h].add(cls)
                    attempted[h].add(prefix)
        out = {}
        for h in hosts:
            missing = [c for c in planner.checklist if c not in attempted[h]]
            if missing:
                out[h] = missing
        return out

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

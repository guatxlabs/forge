# SPDX-License-Identifier: AGPL-3.0-or-later
"""Planner coverage-safe — le joyau du moteur.

Ordonne les actions par espérance de valeur EV = value*confidence/cost, MAIS applique un
plancher (FLOOR) aux classes QUALIFIANTES (idor/access_control/auth/ato/rce/sqli/ssrf/biz/
privesc) pour qu'une voie payable ne soit JAMAIS affamée même si le cerveau la sous-note.

Garanties anti-masquage :
  - `defer != delete` : les actions hors-budget vont dans `skipped_budget` (VISIBLE), pas jetées.
  - `coverage_gaps()` : par cible, les classes de la checklist jamais tentées.
  - `exhaustive=True` : désactive l'ordonnancement -> couverture maximale.

Self-test en __main__ : une action qualifiante sous-notée reste planifiée. Zéro dépendance.

SOURCE DE VÉRITÉ : QUALIFYING et DEFAULT_CHECKLIST sont DÉRIVÉS de forge/techniques.py (la table
unique) — plus de recopie de la taxonomie entre planner, brain, schema et les modules.

DEUXIÈME CLÉ DE TRI, STRUCTURELLE : L'ÉTAGE (`stage`) — LA DÉCOUVERTE D'ABORD
-----------------------------------------------------------------------------
L'EV seule ne suffit pas, et deux campagnes réelles à budget ÉGAL (60 min, `rate=2`, mêmes assets)
l'ont montré à la mesure. Entre les deux, une seule variable : les 11 outils externes sont passés
d'INDISPONIBLES à disponibles.

                            outils absents      outils disponibles
    actions exécutées       3 184               223
    URLs distinctes         49                  0 au-delà des 3 graines
    vagues                  plusieurs           1, jamais terminée

RENDRE LES OUTILS DISPONIBLES A RÉDUIT LA PORTÉE. Le ledger du 2e run donne l'ordre exact des 202
décisions : `recon.subdomains` / `recon.js_endpoints` / `recon.urls` sont les décisions **189 à 197**,
appliquées à **t=2827 s d'un budget de 3600 s** ; `recon.nmap` à 2850 s ; `origin.find` à 4646 s. Les
producteurs de surface ont donc tourné EN DERNIER, et la vague 1 n'a jamais fini : leurs 263 endpoints
découverts (mesuré au ledger) n'ont jamais été replanifiés. On ne teste pas ce qu'on n'a pas trouvé.

POURQUOI L'INTENTION D'ORDRE EXISTANTE NE PORTAIT PAS. Le cerveau DÉCLARE bien une intention
(`brain._CONTENT_SCANNER_EV`, « AVANT les ÉNUMÉRATEURS LENTS »). Elle ne pouvait pas porter, pour
deux raisons INDÉPENDANTES, toutes deux vérifiées sur le ledger :
  1. **la table n'est appliquée qu'à deux endroits** (`_base_actions` et l'edge « service découvert »),
     via `_content_scanner_action`. Le BALAYAGE `AutoPentestBrain.propose` — celui qui propose
     `web.testssl`, `web.nikto`, `xss.dalfox`, `recon.katana`, `recon.gau`… sur chaque cible — appelle
     `_action(kind, tgt)` NU : ces kinds partent aux DÉFAUTS de `Action` (0.5·0.5/1.0 = **EV 0.25**),
     jamais aux 0.04/0.07/0.08 de la table. L'intention n'a donc jamais été appliquée aux actions qu'elle
     visait ;
  2. **elle ne parle pas des producteurs**. Les graines de découverte valent EV 0.15
     (`recon.subdomains/js_endpoints/urls`), `recon.nmap` 0.105, `origin.find` 0.10 — c'est-à-dire
     MOINS que le balayage (0.25) et infiniment moins que le plancher qualifiant (0.5). Elles sont, par
     construction, les actions les moins bien notées du plan.
Une troisième cause a été SUSPECTÉE et MESURÉE FAUSSE : le préchauffage (`engine._preheat_order`) ne
peut pas annuler cet ordre — il est plafonné à `pool - 1` slots de SOUMISSION et ne touche JAMAIS
l'ordre d'APPLICATION (drainage par indice croissant). Sur le run réel il a mis au four `auth.takeover`
(cost 3.0, le palier le plus cher), qui est VETO-é en 0 s.

CE QU'ON FAIT, ET POURQUOI PAS AUTREMENT. On ajoute une clé de tri PRIMAIRE, structurelle :
`(stage, -EV)`. `stage` vaut STAGE_SURFACE pour les kinds qui **produisent** la surface que tous les
autres consomment, STAGE_VERIFY pour les autres. Ce n'est PAS un re-réglage de nombres — c'est
précisément ce qui a échoué : trois tables d'EV successives n'ont pas tenu parce qu'une quatrième voie
de proposition (le balayage) les contournait. Un étage ne se contourne pas : il s'applique à TOUTE
action, quelle que soit la voie qui l'a proposée.

  · Écartée — « remonter l'EV des graines » : ne survit pas à la prochaine voie de proposition, exactement
    comme les trois précédentes ; et une EV élevée sur `origin.find` (mesuré 1799 s sur une cible) le
    ferait passer devant `recon.httpx` (14 s), ce qui n'a aucun sens.
  · Écartée — « une phase = une vague » (ne planifier QUE la découverte à la vague 1) : la découverte
    ET la vérification tomberaient dans des vagues distinctes, `max_waves` (4) deviendrait 2 vagues
    utiles, et les tests qui espionnent `run(actions)` par vague changeraient de forme. Le gain est le
    même : ce qui compte est que le producteur soit APPLIQUÉ avant le consommateur, pas qu'il soit dans
    une vague à lui.
  · Écartée — « repousser les scanners lents en queue » : `nikto` a produit les 16 SEULS signaux
    qualifiables du run 2. L'étage ne les repousse pas *après tout* — il les met après les PRODUCTEURS,
    donc ils tournent sur une surface DÉJÀ découverte, ce qui est exactement leur intérêt.

L'étage NE RETIRE RIEN et NE DIFFÈRE RIEN : c'est un ré-ordonnancement pur. `skipped_budget`,
`coverage_gaps` et le PLANCHER qualifiant sont inchangés — la ligne rouge coverage-safe tient.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

try:                                            # import package normal
    from . import techniques
except ImportError:                             # exécution directe (python3 forge/planner.py — self-test)
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from forge import techniques

if TYPE_CHECKING:                                         # imports paresseux (type-checking uniquement)
    from .roe import Action

FLOOR = 0.5
# classes qualifiantes (plancher anti-starvation) = jetons `qualifying=True` de la table unique.
QUALIFYING = techniques.qualifying_classes()
# checklist par défaut = ce qu'on veut couvrir sur une cible web (ordre = priorité hacktivity)
DEFAULT_CHECKLIST = list(techniques.DEFAULT_CHECKLIST)


def _floored(action: Action) -> bool:
    """True si l'action doit recevoir le PLANCHER anti-starvation. Trois voies COMPLÉMENTAIRES :

      1. `action.cls ∈ QUALIFYING` : les 12 jetons de classe historiques (idor/access_control/auth/
         ato/rce/sqli/ssrf/biz/privesc…) — inchangé.
      2. le KIND est `bug_bounty_eligible` dans le catalogue : couvre les 22 classes payables dont le
         `cls` par défaut (`kind.split('.')[-1]`) n'est PAS un jeton qualifiant (`graphql.access` ->
         "access", `xss.stored` -> "stored", `ssti.eval` -> "eval", `xxe.probe`, `cmdi.probe`,
         `oauth.flow`, `race.condition`, `csrf.state_change`…). Sans cette voie, ces voies payables
         gardaient une EV ~0.003 vs le plancher 0.5 et étaient affamées par un budget fini / un SIGTERM.
      3. le `cls` DÉCLARÉ du KIND dans le catalogue est qualifiant (`CATALOG[kind].cls ∈ QUALIFYING`).
         Ferme le trou de `rce.probe` (`vuln_class='RCE'`, `phase='exploit'`, cls déclaré "rce" MAIS
         `bug_bounty_eligible=False` — c'est un EXPLOIT pentest-only, PAS une classe BB payable). Le
         `cls` de l'Action DÉRIVE par défaut du suffixe du kind ("probe") quand le cerveau ne pose pas
         l'override -> voies 1 & 2 le manquaient et la classe la PLUS forte (RCE) tombait entièrement
         (EV ~0.003 vs plancher 0.5, affamable). On ne TOUCHE PAS `bug_bounty_eligible` (qui rangerait
         cet exploit dans le profil bug_bounty et casserait `pentest_only`) : on planche par la classe
         planner déclarée, qui EST qualifiante par construction (`_t("rce", qualifying=True)`).

    Ainsi TOUTE classe payable/qualifiante reçoit le MÊME plancher que l'IDOR REST — et une action de
    scan non-qualifiante (`web.nuclei`, `recon.subfinder`, cls déclaré "" ) n'est JAMAIS planchée
    (`"" ∉ QUALIFYING`, pas over-flooring). Pur, ne lève jamais."""
    if action.cls in QUALIFYING:
        return True
    t = techniques.CATALOG.get(action.kind)
    if t is None:
        return False
    return bool(t.bug_bounty_eligible) or t.cls in QUALIFYING


def is_floored(action: Action) -> bool:
    """Vue PUBLIQUE de `_floored` — « cette action appartient-elle à une classe QUALIFIANTE ? ».

    Existe pour que le MOTEUR n'ait pas à recopier la règle : la part-de-budget par kind
    (`engine._kind_share_gate`) exempte les classes qualifiantes EXACTEMENT comme `order()` les
    exempte du budget de plan. Une seule définition de « qualifiant » dans le dépôt, deux
    consommateurs. Pur, ne lève jamais."""
    return _floored(action)


# --- ÉTAGE STRUCTUREL : les PRODUCTEURS de surface passent avant leurs CONSOMMATEURS ---------------
STAGE_SURFACE = 0          # produit des ASSETS (hôtes/endpoints/services) que le reste consomme
STAGE_VERIFY = 1           # consomme la surface connue (oracles, scanners, exploitation)

#: Kinds NATIFS (sans `ToolSpec`) qui émettent un marqueur de DÉCOUVERTE `techniques.DISCOVERY_*` —
#: c'est-à-dire qui posent un NŒUD CHAÎNABLE au graphe, que le cerveau reprend aux edges (d)/(e)/(g).
#: Cette liste n'est PAS une taxonomie recopiée : elle est VÉRIFIÉE par
#: `tests/test_planner_discovery_first.py::TestNativeProducerList`, qui lit le SOURCE de chaque module
#: natif enregistré et exige l'ÉQUIVALENCE EXACTE « émet un marqueur/finding de découverte » <=>
#: « figure ici ». Aucune exception, aucun écart toléré : un nouveau module de découverte natif qui
#: oublierait de s'y inscrire fait ÉCHOUER la suite — pas de dérive silencieuse.
#:
#: `origin.find` N'Y FIGURE PAS, ET C'EST UNE DÉCISION MESURÉE — pas un oubli. Il publie bien une
#: cible NOUVELLE (l'IP d'origine hors-CDN, edge (a) de `_chained_actions`), mais ce qu'il produit est
#: une ROUTE ALTERNATIVE vers la surface DÉJÀ connue — le cerveau y rejoue le MÊME panel d'oracles —
#: et non de la surface nouvelle à découvrir. Aucun consommateur de la vague n'attend son résultat au
#: sens où un scanner attend les URLs d'un crawler. Le faire attendre coûtait très cher : il pèse
#: **1 864 s sur le run de référence, soit 24 % de tout le travail mesuré et 51 % d'un budget de
#: 3 600 s** (dont un tir unique de 1 799 s — le module ne déclarait alors AUCUNE borne, donc la gate
#: absolue de `Engine._budget_gate` fail-open ; il en déclare une depuis, `origin.MAX_RUNTIME` = 600 s,
#: ce qui borne le débordement mais ne change RIEN à son classement d'étage). Le classer
#: producteur bloquait la frontière de replanification derrière lui. Mesuré au banc
#: `tests/bench_wave_reach.py`, à identique par ailleurs :
#:      budget 2400 s : 45 actions / 0 URL / 15 kinds  ->  1 234 / 32 / 49
#:      budget 3600 s : 45 actions / 0 URL / 15 kinds  ->  1 285 / 32 / 53
#:      budget 5918 s : 1 288 / 32 / 55 kinds          ->  1 292 / 32 / 58
#: Strictement meilleur à TOUS les budgets. Il reste évidemment PLANIFIÉ (consommateur ordinaire,
#: ordonné par son EV) : rien n'est retiré, seul son rang change.
#:
#: `recon.content` Y FIGURE DEPUIS QU'IL ÉMET — et le classement N'A PAS BASCULÉ TOUT SEUL : `stage()`
#: dérive de `surface_producers()`, qui n'ajoute automatiquement que les modules à `ToolSpec`
#: (`asset_hits`). Un module NATIF doit être inscrit ICI, et c'est le test d'équivalence ci-dessus qui
#: l'a EXIGÉ dès que le marqueur est apparu dans son source (vérifié : suite rouge avant l'ajout).
#: Il rejoint ainsi son jumeau spec-driven `recon.feroxbuster` (même technique, même T1595.003), qui
#: était déjà producteur.
NATIVE_SURFACE_PRODUCERS = frozenset({
    "evasion.discover",     # franchit le challenge et émet des endpoints (DISCOVERY_ENDPOINT_MARKER)
    "recon.content",        # routes ffuf in-scope -> DISCOVERY_ENDPOINT_MARKER (chaînables)
    "recon.httpx",          # ports HTTP confirmés -> DISCOVERY_SERVICE_MARKER (host:port chaînable)
    "recon.js_endpoints",   # endpoints référencés dans le JS -> DISCOVERY_ENDPOINT_MARKER
    "recon.nmap",           # services -> DISCOVERY_SERVICE_MARKER
    "recon.subdomains",     # sous-domaines in-scope -> DISCOVERY_SUBDOMAIN_MARKER
    "recon.urls",           # URLs historiques -> DISCOVERY_HISTORICAL_URL_MARKER
})

_PRODUCERS: "frozenset[str] | None" = None


def surface_producers() -> "frozenset[str]":
    """Les kinds qui PRODUISENT de la surface — l'ensemble qui définit STAGE_SURFACE.

    DEUX SOURCES, aucune recopie de taxonomie :
      1. **DÉCLARÉE PAR L'OUTIL** — tout module `ToolSpec` (catalogue, `--toolspec`, plugin tiers) dont
         le spec dit que ses hits sont des ASSETS (`spec.asset_hits`, dérivé de `hit_is_asset` /
         `phase == "recon"`) ou qui émet des découvertes (`emit_endpoint_discovery` /
         `emit_service_discovery`). C'est CE champ qui sépare proprement, sans liste à tenir,
         `recon.katana`/`gau`/`subfinder`/`amass`/`feroxbuster`/`dnsx`/`naabu`/`gobuster_dns`
         (producteurs) de `web.nikto`/`web.testssl`/`xss.dalfox`/`web.wpscan`/`web.zap_baseline`
         (consommateurs, tous `hit_is_asset=False`) — c'est-à-dire EXACTEMENT les 11 outils dont
         l'arrivée a provoqué la régression de portée.
      2. **NATIFS** — `NATIVE_SURFACE_PRODUCERS` (ci-dessus), test-gardée contre la dérive.

    Un module qui n'est ni l'un ni l'autre est un CONSOMMATEUR (STAGE_VERIFY) — défaut sûr : au pire un
    producteur inconnu garde l'ordre d'AVANT ce lot, jamais moins.

    Le registre est lu PARESSEUSEMENT et mis en cache : le planner n'importe rien de `forge.modules`
    au chargement (il est importé par la CLI avant les modules), et un registre absent/en défaut rend
    simplement l'ensemble natif — jamais une exception."""
    global _PRODUCERS
    if _PRODUCERS is not None:
        return _PRODUCERS
    out = set(NATIVE_SURFACE_PRODUCERS)
    try:
        try:
            from .modules import registry as _registry
        except ImportError:                         # exécution directe (python3 forge/planner.py)
            from forge.modules import registry as _registry  # type: ignore[no-redef]
        for kind, module in dict(_registry.REGISTRY).items():
            spec = getattr(module, "spec", None)
            src = spec if spec is not None else module
            if (getattr(src, "asset_hits", False)
                    or getattr(src, "emit_endpoint_discovery", False)
                    or getattr(src, "emit_service_discovery", False)):
                out.add(kind)
    except Exception:                               # noqa: BLE001 — registre absent -> natifs seuls
        pass
    _PRODUCERS = frozenset(out)
    return _PRODUCERS


def reset_surface_producers_cache() -> None:
    """Invalide le cache de `surface_producers()`. Utile aux TESTS qui substituent des modules dans le
    registre (et à `register_spec` d'un tool-spec chargé après le premier appel)."""
    global _PRODUCERS
    _PRODUCERS = None


def is_endpoint_target(target: Any) -> bool:
    """True si `target` désigne un ENDPOINT (chemin/query), pas un hôte nu. Robuste : hôte nu /
    host:port / IP -> False ; URL à chemin ou à query -> True.

    VIT ICI, et `brain.HeuristicBrain._is_endpoint` y DÉLÈGUE : le cerveau s'en sert pour ne pas semer
    de recon sur une URL, le planner pour ne pas classer une action d'endpoint en PRODUCTEUR. Deux
    consommateurs, une seule définition — la recopier serait exactement la dérive que ce dépôt corrige
    partout ailleurs. Pur, ne lève jamais."""
    s = str(target)
    if "://" in s:
        s = s.split("://", 1)[1]
    if "?" in s or "#" in s:
        return True
    _, _, path = s.partition("/")
    return bool(path.strip("/"))


def is_bare_host_target(target: Any) -> bool:
    """True si `target` est un HÔTE NU — un nom ou une IP qu'un outil qui CONSOMME un hôte peut
    résoudre TEL QUEL. FAUX dès qu'il y a un scheme, un chemin/query/fragment, un userinfo ou un
    `:port`.

    POURQUOI CE PRÉDICAT EN PLUS de `is_endpoint_target` (défaut D16 du banc). `is_endpoint_target`
    répond à « y a-t-il un CHEMIN ? » — et une URL de RACINE n'en a pas : `http://127.0.0.1:8081`
    comme `http://127.0.0.1:8081/` lui rendent `False`, donc « c'est un hôte ». Un `host:port` aussi.
    MESURÉ, en passant les trois formes au vrai binaire :

        nmap -sV -Pn --top-ports 20 http://127.0.0.1:8081   -> Unable to split netmask from target
                                                               expression -> 0 IP addresses (0 hosts up)
        nmap … http://127.0.0.1:8081/                       -> idem
        nmap … 127.0.0.1:8081                               -> Failed to resolve "127.0.0.1:8081"
                                                               -> 0 IP addresses (0 hosts up)
        nmap … 127.0.0.1                                    -> 1 IP address (1 host up) — le SEUL vrai

    Les trois sortent **rc=0** : la borne `rc != 0` de `blindness.tool_did_not_run` ne peut PAS les
    voir. Il fallait donc un prédicat sur la FORME de la cible, et il vit ici pour la même raison que
    son voisin : deux consommateurs (le cerveau qui ne sème pas, le module qui s'abstient), une seule
    définition.

    IPv6 : un littéral non crocheté (`::1`, `fe80::1`) est un HÔTE NU (deux `:` ou plus, jamais de
    port) ; la forme crochetée `[::1]:8081` porte un port et ne l'est pas. Pur, ne lève jamais."""
    s = str(target).strip()
    if not s or "://" in s or "@" in s:
        return False
    if any(c in s for c in "/?# "):
        return False
    if s.startswith("["):                          # `[::1]` / `[::1]:8081` — forme à port explicite
        return False
    if s.count(":") >= 2:                          # littéral IPv6 nu (jamais de port sans crochets)
        return True
    return ":" not in s


def stage(action: Action) -> int:
    """STAGE_SURFACE si l'action PRODUIT de la surface, STAGE_VERIFY sinon. Pur.

    UN PRODUCTEUR NE L'EST QUE SUR UN HÔTE, jamais sur un ENDPOINT déjà dérivé — et c'est une MESURE,
    pas une intuition. Le balayage auto-pentest propose CHAQUE kind activé sur CHAQUE cible qu'il
    touche, endpoints DÉRIVÉS compris : sur le banc `bench_wave_reach`, 263 endpoints découverts ont
    ainsi produit **224 actions de « découverte » supplémentaires** (`recon.httpx`/`katana`/`gau`… sur
    une URL à chemin), qui, classées STAGE_SURFACE, passaient devant TOUS les oracles de vérification
    et consommaient le budget restant sans rien découvrir — la portée retombait de 2 000+ actions à 32.

    C'est aussi la règle que le cerveau applique DÉJÀ à sa propre discipline de profondeur (« racine ->
    sous-domaines, mais un sous-domaine ne relance pas l'énumération », `seed_discovery=False` sur une
    cible dérivée) : le balayage la contournait, l'étage la rétablit pour tout le monde. L'action n'est
    PAS retirée — elle redevient un consommateur ordinaire, ordonné par son EV."""
    if action.kind not in surface_producers():
        return STAGE_VERIFY
    return STAGE_VERIFY if is_endpoint_target(action.target) else STAGE_SURFACE


class Planner:
    def __init__(self, budget: float | None = None, exhaustive: bool = False,
                 checklist: Iterable[str] | None = None) -> None:
        self.budget = budget                       # None = illimité
        self.exhaustive = exhaustive
        self.checklist = list(checklist or DEFAULT_CHECKLIST)

    @staticmethod
    def ev(action: Action) -> float:
        base = action.value * action.confidence / max(action.cost, 0.01)
        if _floored(action):                       # plancher : jamais affamer une voie payable
            return max(base, FLOOR)
        return base

    def rank_key(self, action: Action) -> tuple[int, float]:
        """Clé de tri d'une action : `(étage, -EV)` — l'étage PRIME, l'EV départage À L'INTÉRIEUR.

        Pourquoi l'étage prime : cf. l'en-tête du module. Un producteur de surface passe avant un
        consommateur MÊME s'il est moins bien noté — c'est le seul ordre qui a un sens quand le second
        travaille sur ce que le premier trouve.

        Le tri reste STABLE : à étage ET EV égaux, l'ordre de proposition est préservé, exactement
        comme l'ancien `sorted(key=ev, reverse=True)` (Python ne renverse pas les ex æquo). Une vague
        entièrement PRODUCTRICE ou entièrement CONSOMMATRICE sort donc dans l'ordre d'AVANT ce lot,
        à l'action près."""
        return (stage(action), -self.ev(action))

    def order(self, actions: list[Action]) -> tuple[list[Action], list[Action]]:
        """Retourne (ordered, skipped_budget). Préserve toutes les actions (defer != delete).

        Le budget ne borne QUE le travail NON-QUALIFIANT : une action dont `cls` est dans
        QUALIFYING est toujours conservée dans `ordered`, même si le budget est dépassé (elle
        ne tombe jamais dans `skipped_budget`). Seules les classes non-qualifiantes hors-budget
        sont reportées (defer != delete : visibles dans `skipped_budget`, jamais jetées).

        L'ordre est `(étage, -EV)` (cf. `rank_key`) : les PRODUCTEURS de surface d'abord. Le budget de
        plan, lui, est consommé DANS cet ordre — un producteur non-qualifiant sert donc avant un
        scanner lent, ce qui est le point : le scanner qui reste travaillera sur une surface découverte."""
        if self.exhaustive:
            return list(actions), []
        ranked = sorted(actions, key=self.rank_key)
        if self.budget is None:
            return ranked, []
        ordered: list[Action] = []
        skipped: list[Action] = []
        spent = 0.0
        for a in ranked:
            qualifying = _floored(a)
            if spent + a.cost <= self.budget or qualifying:  # qualifiant = toujours gardé
                ordered.append(a)
                if not qualifying:
                    # le budget ne BORNE que le travail non-qualifiant : une action qualifiante est
                    # gardée sans consommer le budget, donc elle n'affame jamais les non-qualifiantes.
                    spent += a.cost
            else:
                skipped.append(a)
        return ordered, skipped

    def coverage_gaps(self, actions: list[Action], targets: Iterable[str]) -> dict[str, list[str]]:
        """Par cible : classes de la checklist jamais présentes dans les actions proposées."""
        gaps: dict[str, list[str]] = {}
        for t in targets:
            attempted = {a.cls for a in actions if a.target == t}
            missing = [c for c in self.checklist if c not in attempted]
            if missing:
                gaps[t] = missing
        return gaps


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from forge.roe import Action
    # IDOR délibérément sous-noté vs un scan bien noté
    idor = Action("access_control.idor", "app.test", cls="access_control", value=0.1, confidence=0.1, cost=3)
    scan = Action("web.nuclei", "app.test", value=0.9, confidence=0.9, cost=1)
    ordered, skipped = Planner(budget=1.0).order([scan, idor])
    assert idor in ordered, "REGRESSION : l'IDOR sous-noté a été affamé !"
    assert not skipped or idor not in skipped
    print("OK — planner coverage-safe : l'IDOR sous-noté reste planifié malgré le budget.")
    # La DÉCOUVERTE passe avant son CONSOMMATEUR, même quand le consommateur est mieux noté.
    katana = Action("recon.katana", "app.test", value=0.4, confidence=0.4, cost=2)   # EV 0.08
    testssl = Action("web.testssl", "app.test", value=0.5, confidence=0.5, cost=1)   # EV 0.25 (défauts)
    ordered2, _ = Planner().order([testssl, katana])
    assert ordered2[0] is katana, "REGRESSION : un scanner lent passe devant la découverte !"
    print("OK — planner discovery-first : le producteur de surface passe devant son consommateur.")

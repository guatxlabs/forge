# SPDX-License-Identifier: AGPL-3.0-only
"""Registre unique de techniques / taxonomie — LA SOURCE DE VÉRITÉ (stdlib only, zéro dépendance).

Avant ce module, la même donnée « technique » (ATT&CK, CWE, classe de vuln, caractère qualifiant,
remédiation) était recopiée et DÉRIVAIT dans quatre endroits :
  - chaque module (ses chaînes `kind` / `mitre` / `cwe`),
  - `planner.py`  (l'ensemble QUALIFYING + DEFAULT_CHECKLIST),
  - `brain.py`    (les affectations par kind `Action(cls=..., exploit=...)`),
  - `schema.py`   (le dict de remédiation DEFAULT_FIXES),
  - `purple.py`   (le repli ATT&CK par kind DEFAULT_MITRE_BY_KIND).

Ici, une table `TECHNIQUES` mappe une CLÉ (kind de module OU jeton de classe OU clé CWE) vers un
enregistrement `Technique`. Les autres fichiers DÉRIVENT leurs vues de cette table :
  - schema.DEFAULT_FIXES         = {clé: remediation}    pour toute clé avec remédiation ;
  - planner.QUALIFYING           = {clé}                 pour toute clé qualifiante ;
  - brain (cls/exploit par kind) = action_class(kind) / action_exploit(kind) ;
  - purple.DEFAULT_MITRE_BY_KIND = mitre_by_kind()       (repli par kind, sous-ensemble curé) ;
  - modules (mitre/cwe)          = TECHNIQUES[kind].mitre / .cwe.

Trois espaces de clés cohabitent SANS collision dans la même table :
  - les *kinds* de module contiennent un point (`ssrf.callback`, `access_control.idor`, `web.nuclei`) ;
  - les *jetons de classe* planner sont des mots simples (`ssrf`, `access_control`, `auth`, `biz`…) ;
  - les *clés CWE* de remédiation sont préfixées (`cwe-918`, `cwe-639`…).

CATALOGUE ATT&CK STRUCTURÉ (LOT SURFACE) — chaque enregistrement porte désormais des champs
structurés additifs : `attck_tactic` (tactique ATT&CK lisible), `phase` (recon | access | exploit),
`capability` (passive | active | exploit) et `proof_required` (une promotion au-delà de
`status=tested` EXIGE une preuve concrète). Ces champs sont OPTIONNELS : un alias de classe/CWE les
laisse vides (ce ne sont pas des « techniques de module »), un kind de module les porte.

DEUX TABLES, UN CATALOGUE — pour garantir l'invariance BYTE-À-BYTE des vues dérivées historiques :
  - `TECHNIQUES` = le noyau HÉRITÉ (classes de vuln, clés CWE, kinds de modules LIVRÉS). Son ensemble
    de clés est FIGÉ : les vues `remediation_map()` / `qualifying_classes()` / `mitre_by_kind()`
    l'itèrent et restent donc identiques au pré-refactor (aucune clé surface ne peut les polluer).
  - `SURFACE` = les entrées de cartographie de surface d'attaque (métadonnées seules ; le code des
    modules arrive dans des slices ultérieures). Chaque entrée a `phase="recon"`, une `capability`
    passive/active, un `mitre` ATT&CK, et une remédiation propre — SANS jamais entrer dans le map de
    remédiation des vulns (elle vit hors de `TECHNIQUES`).
  - `CATALOG = {**TECHNIQUES, **SURFACE}` = le catalogue consolidé et ÉLARGI : le squelette dans
    lequel les nouveaux modules s'enregistrent et que les vues `by_phase()`/`by_capability()`/
    `by_tactic()` exposent. Les résolveurs `mitre_for()`/`cwe_for()`/`action_*()` l'interrogent
    (superset de `TECHNIQUES` : identique pour toute clé héritée, résout en plus les kinds surface).
"""
from .techniques_data import (  # noqa: F401  (ré-export : chemins d'import publics stables)
    Technique, _t, _k,
    TECHNIQUES, SURFACE, CATALOG, SURFACE_KEYS,
    DEFAULT_CHECKLIST, PURPLE_FALLBACK_KINDS,
    DISCOVERY_SUBDOMAIN_MARKER, DISCOVERY_ENDPOINT_MARKER,
    DISCOVERY_HISTORICAL_URL_MARKER, DISCOVERY_CHALLENGE_MARKER,
    PROFILES, _PHASE_RANK, PROFILE_NAMES,
)
from .challenge import (  # noqa: F401  (ré-export : `techniques.looks_like_challenge` stable)
    CHALLENGE_STATUS_CODES, CHALLENGE_BODY_SIGNATURES, looks_like_challenge,
)


# --- Vues dérivées HISTORIQUES (byte-à-byte identiques — itèrent le noyau hérité TECHNIQUES) -------
def remediation_map():
    """Dict clé -> remédiation (== l'ancien schema.DEFAULT_FIXES). Toute clé HÉRITÉE avec `remediation`.

    Itère `TECHNIQUES` (le noyau figé) : les entrées `SURFACE` portent leur propre remédiation mais
    n'entrent PAS dans le map de remédiation des vulns (elles vivent hors de `TECHNIQUES`)."""
    return {k: t.remediation for k, t in TECHNIQUES.items() if t.remediation}


def qualifying_classes():
    """Ensemble des jetons de classe qualifiants (== l'ancien planner.QUALIFYING). Noyau hérité."""
    return {k for k, t in TECHNIQUES.items() if t.qualifying}


def mitre_by_kind():
    """Repli ATT&CK par kind (== l'ancien purple.DEFAULT_MITRE_BY_KIND). Sous-ensemble curé."""
    return {k: TECHNIQUES[k].mitre for k in PURPLE_FALLBACK_KINDS}


# --- Vues du CATALOGUE ÉLARGI (héritage + surface) -------------------------------------------------
def by_phase(phase):
    """Sous-catalogue {clé -> Technique} des entrées d'une `phase` (recon | access | exploit)."""
    return {k: t for k, t in CATALOG.items() if t.phase == phase}


def by_capability(capability):
    """Sous-catalogue {clé -> Technique} des entrées d'une `capability` (passive | active | exploit)."""
    return {k: t for k, t in CATALOG.items() if t.capability == capability}


def by_tactic(tactic):
    """Sous-catalogue {clé -> Technique} des entrées d'une tactique ATT&CK (`attck_tactic`)."""
    return {k: t for k, t in CATALOG.items() if t.attck_tactic == tactic}


def technique_for(key):
    """L'enregistrement `Technique` du catalogue consolidé pour `key` (None si inconnu). Pur."""
    return CATALOG.get(key)


# --- EXTENSION POINT — enregistrement DYNAMIQUE d'un KIND de module (tool-specs externes) -----------
def register_kind(technique):
    """Enregistre une technique de KIND de module dans la table unique (`TECHNIQUES`) ET le catalogue
    consolidé (`CATALOG`), pour qu'un tool-spec EXTERNE (wrapper générique d'un outil CLI, cf.
    `forge/modules/toolspec.py`) apparaisse AUTOMATIQUEMENT dans TOUTES les vues dérivées
    (technique_kinds / by_vuln_class / pipeline_ordered / profile_set / resolve_enabled_kinds) et les
    résolveurs (mitre_for / cwe_for / action_class / action_exploit / technique_for), EXACTEMENT comme
    une entrée `_k(...)` LIVRÉE — c'est le contrat « déclare-une-fois -> dérive-partout » ouvert aux
    outils tiers (absorbe la propriété wrap-any-tool de Trickest/Faraday/Osmedeus, SOUS la gouvernance).

    Mutation ADDITIVE des DEUX dicts (l'invariant `CATALOG == TECHNIQUES ∪ SURFACE` est préservé, cf.
    test_catalog ; c'est le MÊME geste que le test « new_module_auto_appears_everywhere »). Un KIND de
    module doit être une clé POINTÉE portant une `vuln_class` et ne doit PORTER NI `remediation` NI
    `qualifying` (réservés au noyau hérité) — ainsi les vues HISTORIQUES remediation_map() /
    qualifying_classes() / mitre_by_kind() restent byte-à-byte identiques (elles itèrent `TECHNIQUES`
    mais ne sélectionnent QUE les entrées portant remediation/qualifying). Idempotent (ré-enregistrer la
    même clé écrase proprement). Retourne la technique enregistrée."""
    TECHNIQUES[technique.key] = technique
    CATALOG[technique.key] = technique
    return technique


# --- Résolveurs par kind (interrogent le catalogue consolidé : héritage identique + kinds surface) -
def action_class(kind):
    """Classe planner à passer au brain pour ce kind ("" si aucune override -> Action dérive le suffixe)."""
    t = CATALOG.get(kind)
    return t.cls if t else ""


def action_exploit(kind):
    """Flag exploit à passer au brain pour ce kind (False si inconnu)."""
    t = CATALOG.get(kind)
    return bool(t.exploit) if t else False


def mitre_for(kind):
    """ATT&CK id d'un kind ("" si inconnu)."""
    t = CATALOG.get(kind)
    return t.mitre if t else ""


def cwe_for(kind):
    """CWE canonique d'un kind ("" si inconnu)."""
    t = CATALOG.get(kind)
    return t.cwe if t else ""


def mitre_for_cwe(cwe):
    """ATT&CK id de la PREMIÈRE technique du catalogue dont le CWE canonique == `cwe` ("" si aucune).

    Résolveur INVERSE (CWE -> ATT&CK) : un outil tiers (Burp/nuclei) signale une classe de vuln par
    son CWE (ex "CWE-89") sans porter d'ATT&CK. On rattache ce CWE à la tactique/technique ATT&CK de
    la table (source de vérité) pour que le finding rejoigne la boucle purple. Pur, ne lève jamais ;
    ignore les entrées sans mitre ; casse-insensible sur l'identifiant CWE."""
    if not cwe:
        return ""
    target = str(cwe).strip().upper()
    for t in CATALOG.values():
        if t.cwe and t.mitre and t.cwe.upper() == target:
            return t.mitre
    return ""


# --- CONSOLIDATION taxonomie : vues DÉRIVÉES « scale » (LOT REGISTRY) ------------------------------
# Le contrat « derive-everywhere » : un module qui s'enregistre avec UNE entrée technique apparaît
# AUTOMATIQUEMENT dans le catalogue groupé par catégorie (`by_vuln_class`), le pipeline pentest
# ordonné (`pipeline_ordered`/`techniques_for`), la sélection par-scope et les bons profils
# (`profile_set`) — sans câblage par-technique ailleurs. Ces vues DÉRIVENT toutes de la table unique.


def technique_kinds():
    """Liste des KINDS de module-technique du catalogue (clé pointée portant une `vuln_class`). C'est
    l'ensemble des techniques RÉELLES (un module enregistré) — à l'exclusion des ALIAS de classe/CWE
    (non-phasés, sans vuln_class) et des placeholders de SURFACE (métadonnées sans module livré)."""
    return [k for k, t in CATALOG.items() if "." in k and t.vuln_class]


def by_vuln_class():
    """Dict CATÉGORIE -> [kinds triés] : LE catalogue groupé par classe de vuln (SQLi/XSS/IDOR/SSRF/…).
    C'est la vue « catalogue » : un nouveau module apparaît sous sa catégorie sans autre câblage."""
    out = {}
    for k in technique_kinds():
        out.setdefault(CATALOG[k].vuln_class, []).append(k)
    for v in out.values():
        v.sort()
    return out


def profile_set(profile, custom=None):
    """Ensemble de kinds appartenant à un PROFIL :
      - "pentest"     -> TOUTES les techniques (le pentest peut tout lancer) ;
      - "bug_bounty"  -> les techniques `bug_bounty_eligible` (les classes payables) ;
      - "custom"      -> l'ensemble fourni par l'appelant (`custom=...`) ;
      - un ensemble/liste/tuple de kinds passé DIRECTEMENT -> pris tel quel (custom implicite) ;
      - tout autre nom de profil -> les techniques dont `default_profiles` contient ce nom.
    Pur ; ne lève jamais. Cohérent par construction : `bug_bounty` via le flag == via default_profiles."""
    kinds = technique_kinds()
    if isinstance(profile, (set, frozenset, list, tuple)):
        return set(profile)
    if profile == "pentest":
        return set(kinds)
    if profile == "bug_bounty":
        return {k for k in kinds if CATALOG[k].bug_bounty_eligible}
    if profile == "custom":
        return set(custom or ())
    return {k for k in kinds if profile in CATALOG[k].default_profiles}


def pipeline_ordered():
    """Les kinds-techniques ordonnés TOPOLOGIQUEMENT par phase (recon < access < exploit) puis par
    dépendances (`depends_on`) — l'ordonnancement du pipeline pentest automatisé. Déterministe
    (tie-break stable : rang de phase puis clé). Robuste : un `depends_on` hors de l'ensemble est
    ignoré ; un cycle (ne devrait jamais arriver — les deps pointent vers des phases antérieures) est
    brisé en repli sur l'ordre de priorité (jamais de boucle infinie)."""
    kinds = technique_kinds()
    nodeset = set(kinds)
    deps = {k: [d for d in CATALOG[k].depends_on if d in nodeset] for k in kinds}

    def prio(k):
        return (_PHASE_RANK.get(CATALOG[k].phase, 3), k)

    ordered, placed, remaining = [], set(), set(kinds)
    while remaining:
        ready = [k for k in remaining if all(d in placed for d in deps[k])]
        if not ready:                                    # cycle défensif : ne jamais boucler
            ready = list(remaining)
        nxt = min(ready, key=prio)
        ordered.append(nxt)
        placed.add(nxt)
        remaining.discard(nxt)
    return ordered


def techniques_for(selection):
    """Le pipeline FILTRÉ + ORDONNÉ pour une sélection : un nom de profil ("bug_bounty"/"pentest"/
    "custom") OU un ensemble explicite de kinds activés (sélection par-scope). Retourne les kinds
    ACTIVÉS dans l'ordre de `pipeline_ordered`. Les dépendances non activées sont simplement absentes
    (filtrage, pas d'auto-ajout) : c'est « le pipeline filtré » demandé par la sélection."""
    if isinstance(selection, str):
        enabled = profile_set(selection)
    else:
        enabled = set(selection or ())
    return [k for k in pipeline_ordered() if k in enabled]


# --- SÉLECTION PAR-SCOPE : profil + toggles catégorie/technique (DÉRIVÉE de la table unique) --------
# Contrat : un scope (ou la console) porte un `profile` + des toggles explicites, et l'ENSEMBLE EFFECTIF
# de techniques activées en est RÉSOLU — sans câblage par-technique. C'est LA fonction que l'enforcement
# (engine/planner/brain, cf. Scope.effective_technique_kinds) et l'API `GET /api/techniques` partagent.
# La résolution ci-dessous est la SPEC PARTAGÉE (mirroir Rust côté console) : garder les deux en phase.


def recon_infra_kinds():
    """Kinds de PHASE recon = infrastructure de DÉCOUVERTE de surface (subdomains/httpx/js_endpoints/…,
    scanners, origin). TOUJOURS inclus dans la base du profil bug_bounty : un profil choisit les CLASSES
    de vuln à VÉRIFIER, pas s'il faut découvrir la surface — un profil sans recon affamerait tout le
    pipeline (recon -> chaînage -> oracles). Restent DÉSACTIVABLES explicitement (toggle -> fail-closed)."""
    return {k for k in technique_kinds() if CATALOG[k].phase == "recon"}


def _profile_base(profile, custom=None):
    """Ensemble de BASE d'un profil pour la sélection PAR-SCOPE :
      - "pentest"    -> TOUTES les techniques (le pentest peut tout balayer) ;
      - "bug_bounty" -> les techniques bug_bounty_eligible + l'infrastructure de recon (surface) ;
      - "custom"     -> vide (l'opérateur construit tout via les toggles explicites) ;
      - un ensemble/liste/tuple passé DIRECTEMENT -> pris tel quel.
    Distinct de `profile_set` (INCHANGÉ — contrat historique où bug_bounty == strictement bb-eligible) :
    ce base AJOUTE le recon au bug_bounty pour que la sélection reste un PIPELINE FONCTIONNEL. Pur."""
    if isinstance(profile, (set, frozenset, list, tuple)):
        return set(profile)
    if profile == "pentest":
        return set(technique_kinds())
    if profile == "bug_bounty":
        return profile_set("bug_bounty") | recon_infra_kinds()
    if profile == "custom":
        return set(custom or ())
    return profile_set(profile)                     # nom inconnu -> via default_profiles (cohérent)


def _split_toggles(spec):
    """Sépare une spec de toggles en (activés, désactivés). Accepte :
      - None                -> (set(), set()) ;
      - un ITÉRABLE de clés -> toutes ACTIVÉES (forme « ensemble d'ajouts ») ;
      - une MAP {clé: bool}  -> True = activée, False = désactivée (forme « panneau de toggles »).
    Pur ; ne lève jamais (une valeur non-bool d'une map est traitée par sa véracité)."""
    enabled, disabled = set(), set()
    if spec is None:
        return enabled, disabled
    if isinstance(spec, dict):
        for k, v in spec.items():
            (enabled if v else disabled).add(k)
    else:
        try:
            for k in spec:
                enabled.add(k)
        except TypeError:                           # spec non itérable -> ignorée (fail-safe)
            pass
    return enabled, disabled


def resolve_enabled_kinds(profile="bug_bounty", techniques_enabled=None,
                          categories_enabled=None, custom=None):
    """L'ENSEMBLE EFFECTIF de kinds-techniques ACTIVÉS pour un scope. Sémantique CLAIRE (SPEC PARTAGÉE) :
      1. BASE   = le profil (bug_bounty = classes payables + recon ; pentest = tout ; custom = vide) ;
      2. + ADD  = activations explicites (catégories entières PUIS techniques) ;
      3. − DROP = désactivations explicites (catégories PUIS techniques) — qui PRIMENT (fail-closed) ;
      4. ∩ technique_kinds() (seuls des kinds RÉELS survivent).
    `techniques_enabled` / `categories_enabled` acceptent chacun soit un ITÉRABLE (tout activé), soit une
    MAP {clé: bool} (toggle on/off) — exactement ce qu'un panneau de sélection produit. Les DÉSACTIVATIONS
    l'emportent sur les activations (ordre-indépendant, fail-closed) : « au scope retirer une technique/
    catégorie des tests automatiques » supprime DÉFINITIVEMENT ces kinds de l'ensemble effectif. Pur."""
    all_kinds = set(technique_kinds())
    base = _profile_base(profile if profile else "bug_bounty", custom=custom)
    cat_en, cat_dis = _split_toggles(categories_enabled)
    tech_en, tech_dis = _split_toggles(techniques_enabled)
    bvc = by_vuln_class()
    enabled = set(base)
    for cat in cat_en:                              # (2) ADD catégories entières
        enabled |= set(bvc.get(cat, ()))
    enabled |= {k for k in tech_en if k in all_kinds}   # (2) ADD techniques
    for cat in cat_dis:                             # (3) DROP catégories (PRIMENT)
        enabled -= set(bvc.get(cat, ()))
    enabled -= set(tech_dis)                        # (3) DROP techniques (PRIMENT)
    return enabled & all_kinds                      # (4) seuls des kinds réels

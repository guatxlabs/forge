# SPDX-License-Identifier: AGPL-3.0-only
"""Workflows éditables & sauvegardés — pipelines COMPOSÉS par l'opérateur, SANS code (stdlib only).

Un WORKFLOW est un pipeline NOMMÉ, SAUVEGARDÉ et ÉDITABLE : une SÉLECTION ORDONNÉE de techniques /
outils (+ params par-étape) puisée dans le registre `forge/techniques.py`. C'est l'absorption des
« scan-engines » de reNgine, des « workflows » d'Osmedeus et des pipelines visuels de Trickest —
mais SOUS la gouvernance de Forge : un workflow n'est qu'une PROPOSITION, le scope-guard ROE et la
sélection par-scope restent seuls JUGES de ce qui tire réellement.

Contrat de sûreté (fail-closed) — le point CENTRAL de ce module :
  - un workflow ne peut JAMAIS activer une technique/outil HORS scope ou DÉSACTIVÉE pour le scope ;
  - `resolve(workflow, enabled_kinds)` FILTRE les étapes par l'ensemble EFFECTIF activé du scope
    (`Scope.effective_technique_kinds()`) : une étape hors de cet ensemble est LARGUÉE (dropped),
    jamais élargie — le workflow ne peut que NARROWER, jamais WIDENER ;
  - les étapes exploit restent derrière le plancher opt-in (le ROE les VETO tant que l'engagement
    n'est pas armé + autorisé — géré par l'engine/ROE, inchangé ici) ;
  - l'exécution passe par la MÊME pipeline que le planner (l'engine ré-enforce `enabled_kinds` + ROE
    au tir : défense en profondeur). Ce module ne TIRE rien — il DÉCRIT et RÉSOUT le pipeline.

Tout DÉRIVE du registre unique : `technique_kinds()` (kinds réels), `by_vuln_class()` (catalogue
groupé), `pipeline_ordered()` (ordre topologique recon<access<exploit), `resolve_enabled_kinds()`
(profils). Les WORKFLOWS INTÉGRÉS (`builtin_workflows()`) sont donc TOUJOURS à jour : un nouveau
module `@register` apparaît automatiquement dans les workflows intégrés pertinents, SANS câblage.

Zéro dépendance (stdlib). Aucune I/O réseau. `WorkflowStore` est une persistance fichier OPTIONNELLE
pour l'usage CLI standalone ; la console persiste les workflows dans sa table `settings` (côté Rust) —
les deux côtés partagent EXACTEMENT cette forme + cette sémantique de résolution (zéro dérive).
"""
import json
import re
from pathlib import Path

from . import techniques

# Grammaire d'un NOM de workflow / d'un KIND d'étape : [A-Za-z0-9._-], 1..64, pas de '-' en tête
# (parité avec validate_campaign/validate_login/le validateur de sélection côté console — anti
# confusion avec un flag CLI et entrées hostiles).
_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
MAX_STEPS = 128                 # borne anti-runaway sur le nombre d'étapes d'un workflow
MAX_DESC = 500                  # borne sur la description (tronquée, jamais rejetée)


class WorkflowError(ValueError):
    """Workflow mal formé (nom/étapes invalides). Sous-classe de ValueError pour un `except` simple."""


def _valid_token(s):
    """True si `s` est un identifiant bien formé (nom de workflow ou kind d'étape) : grammaire
    [A-Za-z0-9._-]{1,64}, non vide, ne débute pas par '-' (anti-flag). Pur, ne lève jamais."""
    return bool(isinstance(s, str) and s and not s.startswith("-") and _NAME_RE.fullmatch(s))


def validate_workflow(data, name=None):
    """Valide/NORMALISE un workflow POSTé/chargé -> dict canonique, ou lève `WorkflowError`.

    Forme canonique : {name, description, builtin(False), steps:[{kind, params}]}. Règles :
      - `name` : bien formé (grammaire ci-dessus) ; l'argument `name` (ex: segment d'URL) l'override ;
      - `description` : chaîne (tronquée à MAX_DESC) ; absente -> "" ;
      - `steps` : liste (<= MAX_STEPS) de {kind: str bien formé, params: dict}. L'ORDRE est PRÉSERVÉ ;
        les kinds INCONNUS du registre sont TOLÉRÉS (comme le validateur de sélection) — ils seront
        simplement LARGUÉS par `resolve()` (∩ enabled_kinds) : jamais une capacité fabriquée.
    `builtin` est FORCÉ à False pour un workflow utilisateur (seul `builtin_workflows()` en pose True).
    Fonction PURE (aucune I/O)."""
    if not isinstance(data, dict):
        raise WorkflowError("workflow attendu : objet {name, description?, steps:[...]}")
    nm = name if name is not None else data.get("name")
    if not _valid_token(nm):
        raise WorkflowError("nom de workflow invalide (grammaire [A-Za-z0-9._-], 1..64, pas de '-' en tête)")
    desc = data.get("description", "")
    if desc is None:
        desc = ""
    if not isinstance(desc, str):
        raise WorkflowError("description doit être une chaîne")
    desc = desc[:MAX_DESC]
    raw_steps = data.get("steps", [])
    if not isinstance(raw_steps, list):
        raise WorkflowError("steps doit être une liste [{kind, params}]")
    if len(raw_steps) > MAX_STEPS:
        raise WorkflowError(f"trop d'étapes (> {MAX_STEPS})")
    steps = []
    for i, st in enumerate(raw_steps):
        if not isinstance(st, dict):
            raise WorkflowError(f"steps[{i}] : objet {{kind, params}} attendu")
        kind = st.get("kind")
        if not _valid_token(kind):
            raise WorkflowError(f"steps[{i}] : kind '{kind}' mal formé ([A-Za-z0-9._-], 1..64)")
        params = st.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise WorkflowError(f"steps[{i}] : params doit être un objet {{clé: valeur}}")
        steps.append({"kind": kind, "params": params})
    return {"name": nm, "description": desc, "builtin": False, "steps": steps}


def step_kinds(workflow):
    """Liste ORDONNÉE + DÉDUPLIQUÉE des kinds d'un workflow (1re occurrence conservée). Pur."""
    out, seen = [], set()
    for st in (workflow.get("steps") or []):
        k = st.get("kind")
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def workflow_module_params(workflow):
    """Params par-module MERGÉS d'un workflow : {kind: {param: valeur}}. Les étapes de MÊME kind sont
    fusionnées (les dernières priment). C'est ce qu'on injecte dans `module_params` de la campagne
    (chaque module lit ses params par son kind). Pur ; ne lève jamais."""
    out = {}
    for st in (workflow.get("steps") or []):
        k = st.get("kind")
        p = st.get("params") or {}
        if not k or not isinstance(p, dict):
            continue
        out.setdefault(k, {})
        out[k].update(p)
    return out


def resolve(workflow, enabled_kinds):
    """LE cœur fail-closed : FILTRE les étapes d'un workflow par l'ensemble EFFECTIF activé du scope.

    Retourne (kept, dropped) — deux listes ORDONNÉES + DÉDUPLIQUÉES d'étapes {kind, params} :
      - `kept`    : les étapes dont le kind ∈ `enabled_kinds` (in-scope ET activé pour le scope) ;
      - `dropped` : les étapes LARGUÉES (kind hors de l'ensemble : hors scope, technique désactivée,
                    profil qui l'exclut, ou kind inconnu du registre).
    Un workflow est une PROPOSITION : `resolve` ne peut que RESTREINDRE (intersection), jamais élargir.
    C'est la garantie « le scope-guard reste juge » au niveau de la proposition ; l'engine ré-applique
    la MÊME règle au tir (`Engine.enabled_kinds` + ROE) — défense en profondeur. Pur ; ne lève jamais.

    `enabled_kinds` = un ensemble/itérable de kinds (typiquement `Scope.effective_technique_kinds()`).
    """
    allowed = set(enabled_kinds or ())
    kept, dropped, seen = [], [], set()
    for st in (workflow.get("steps") or []):
        k = st.get("kind")
        if not k or k in seen:
            continue
        seen.add(k)
        entry = {"kind": k, "params": (st.get("params") or {})}
        (kept if k in allowed else dropped).append(entry)
    return kept, dropped


# =====================================================================================================
#  WORKFLOWS INTÉGRÉS (builtins) — DÉRIVÉS du registre (toujours à jour). Absorption des « scan-engines »
#  de reNgine / « workflows » d'Osmedeus : des pipelines prêts-à-l'emploi que l'opérateur lance ou clone.
#  Chacun est ORDONNÉ topologiquement (recon < access < exploit + depends_on) par `pipeline_ordered()`.
#  builtin=True -> NON supprimables (la console/CLI refusent la suppression). Un nouveau module @register
#  entre AUTOMATIQUEMENT dans le workflow intégré pertinent (par son profil / sa phase) — zéro câblage.
# =====================================================================================================
def _steps_from_kinds(kinds):
    """Étapes {kind, params:{}} pour une liste de kinds, DANS L'ORDRE du pipeline (recon<access<exploit).
    Filtre les kinds inconnus (robustesse) et dédup. Pur."""
    order = techniques.pipeline_ordered()
    wanted = set(kinds)
    return [{"kind": k, "params": {}} for k in order if k in wanted]


def builtin_workflows():
    """Dict {name: workflow} des workflows INTÉGRÉS, DÉRIVÉS du registre unique (donc toujours à jour) :

      - `recon-surface`  : toute la phase de RECON/cartographie (subdomains/httpx/js_endpoints/…). Le
                           « scan-engine » de découverte pure (miroir reNgine subdomain/screenshot).
      - `bug-bounty-web` : le profil bug_bounty (classes PAYABLES + infra recon) — le pipeline web
                           orienté hacktivity (IDOR/SSRF/XSS/SQLi… + recon). Équivalent Osmedeus « general ».
      - `full-pentest`   : TOUTES les techniques (profil pentest), ordonnées topologiquement — le
                           balayage exhaustif (les étapes exploit restent gatées par le ROE au tir).
    builtin=True. Pur (aucune I/O)."""
    recon = {k for k in techniques.technique_kinds() if techniques.CATALOG[k].phase == "recon"}
    bb = techniques.resolve_enabled_kinds(profile="bug_bounty")
    allk = set(techniques.technique_kinds())
    defs = {
        "recon-surface": ("Découverte & cartographie de surface (recon pur) — absorbe les scan-engines "
                          "de reconnaissance (sous-domaines, HTTP fingerprint, endpoints JS, WAF).", recon),
        "bug-bounty-web": ("Pipeline web bug bounty : classes PAYABLES (IDOR/SSRF/Auth/XSS/SQLi…) + infra "
                           "de recon, ordre hacktivity. Les étapes exploit restent gatées par le ROE.", bb),
        "full-pentest": ("Balayage pentest EXHAUSTIF : toutes les techniques du registre, ordonnées "
                         "topologiquement. Étapes exploit/haut-impact gardées derrière le plancher opt-in.", allk),
    }
    out = {}
    for name, (desc, kinds) in defs.items():
        out[name] = {"name": name, "description": desc, "builtin": True,
                     "steps": _steps_from_kinds(kinds)}
    return out


BUILTIN_NAMES = frozenset(("recon-surface", "bug-bounty-web", "full-pentest"))


class WorkflowStore:
    """Persistance FICHIER optionnelle des workflows (usage CLI standalone + tests). Les workflows
    INTÉGRÉS sont TOUJOURS présents (dérivés du registre) et NON supprimables ; les workflows
    UTILISATEUR vivent dans le fichier (map {name: workflow}). Un nom intégré ne peut pas être
    fantômisé par un fichier (les builtins priment sur leur nom réservé — fail-closed).

    La console (Rust) persiste, elle, dans sa table `settings` (clé `workflows`) — MÊME forme, MÊME
    sémantique de résolution. Ce store est le pendant CLI (aucune dépendance à la console)."""

    def __init__(self, user=None):
        self.user = dict(user or {})

    @classmethod
    def load(cls, path):
        """Charge les workflows UTILISATEUR d'un fichier JSON. Tolère `{name: wf}` ou `{"workflows":
        {name: wf}}`. Fichier absent/illisible -> store vide (builtins seuls). Ne lève jamais sur
        l'absence ; VALIDE chaque entrée (une entrée invalide est ignorée, jamais fatale)."""
        user = {}
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError:
            return cls(user)
        try:
            data = json.loads(raw)
        except ValueError:
            return cls(user)
        if isinstance(data, dict) and isinstance(data.get("workflows"), dict):
            data = data["workflows"]
        if isinstance(data, dict):
            for name, wf in data.items():
                try:
                    v = validate_workflow(wf, name=name)
                    if name not in BUILTIN_NAMES:      # un fichier ne peut pas shadow un builtin
                        user[v["name"]] = v
                except WorkflowError:
                    continue                           # entrée invalide -> ignorée (fail-safe)
        return cls(user)

    def save(self, path):
        """Persiste les workflows UTILISATEUR (map {name: workflow}) — les builtins ne sont jamais
        écrits (dérivés). Crée le dossier parent si besoin."""
        p = Path(path)
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"workflows": self.user}, ensure_ascii=False, indent=2), encoding="utf-8")

    def list(self):
        """Tous les workflows : builtins (dérivés) + utilisateur. Les builtins priment sur leur nom."""
        out = dict(self.user)
        out.update(builtin_workflows())               # builtins priment (nom réservé, non supprimable)
        return out

    def get(self, name):
        """Le workflow `name` (builtin prioritaire), ou None. Ne lève jamais."""
        b = builtin_workflows()
        if name in b:
            return b[name]
        return self.user.get(name)

    def put(self, data, name=None):
        """Crée/édite un workflow UTILISATEUR (validé). Refuse d'écraser un nom INTÉGRÉ (WorkflowError).
        Retourne le workflow normalisé."""
        v = validate_workflow(data, name=name)
        if v["name"] in BUILTIN_NAMES:
            raise WorkflowError(f"nom réservé (workflow intégré non modifiable) : {v['name']}")
        self.user[v["name"]] = v
        return v

    def delete(self, name):
        """Supprime un workflow UTILISATEUR. Refuse de supprimer un builtin (WorkflowError, fail-closed).
        Retourne True si supprimé, False si inconnu."""
        if name in BUILTIN_NAMES:
            raise WorkflowError(f"workflow intégré non supprimable : {name}")
        return self.user.pop(name, None) is not None

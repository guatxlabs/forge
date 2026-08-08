# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vue ACTIONNABLE-D'ABORD du rapport — même corpus, deux rendus (pentest / bounty).

PROBLÈME (évaluation réelle) : une campagne a émis **2410 findings — 2404 INFO, 6 LOW, 0 ≥ MEDIUM**.
Le triage natif (`forge/triage.py`) faisait pourtant son travail (2410 → 77 actionnables, 2333 bruit,
128 clusters) — mais `report.py` rendait ENSUITE `tr.ranked` EN ENTIER, soit 17 424 lignes. Le drapeau
`auto_hide` était lu, stocké dans la synthèse, IMPRIMÉ comme étiquette… et JAMAIS consommé : un knob
mort. Et les **147 findings `skipped`** (« je n'ai PAS pu vérifier ») étaient PÉNALISÉS par le poids
`degraded` du noise-score, donc rabattus en bas du rang (positions 458 → 2387) : l'information la plus
importante d'une cible protégée était la plus enterrée. Ce module inverse ça.

CE QU'IL FAIT — il DÉCIDE d'un PLAN de rendu ; il ne supprime jamais rien :

  1. **BUCKETS** (`bucket_findings`) — quatre seaux DÉRIVÉS du finding, jamais inventés :
     `exploitable` (sévérité ≥ MEDIUM **ou** statut prouvé) · `qualify` (LOW / signalé-par-outil) ·
     `unverified` (statut `skipped` — TROU DE COUVERTURE, PROMU, jamais du bruit) · `recon` (le reste).
     Un finding tombe dans EXACTEMENT un seau (partition ; prouvé par test).
  2. **GROUPES** (`group_items`) — les seaux de tête sont regroupés par `triage.template_key`
     (gabarit : sévérité + technique + titre normalisé) → « 1 vuln × N endpoints » au lieu de N lignes.
     Le représentant est le plus petit index d'origine (déterministe, comme le triage).
  3. **PLAN D'ANNEXE** (`annex_plan`) — porte l'INVARIANT DUR de ce dépôt (« zéro lacune silencieuse ») :
     tout finding est SOIT rendu dans l'annexe, SOIT membre d'un groupe REPLIÉ COMPTÉ ET NOMMÉ.
     `AnnexPlan.check()` vérifie DEUX dérivations INDÉPENDANTES (la comptabilité des groupes repliés vs
     la partition d'indices) — elles doivent coïncider ET couvrir exactement `range(total)`. Une
     divergence n'est pas rattrapée en silence : elle est RENDUE en clair dans le rapport (fail-loud).

VUES (`resolve_view`) — un même corpus, deux publics, PAS deux moteurs :
  · `pentest` (DÉFAUT) — exhaustif : l'annexe rend TOUS les findings (le négatif est une preuve de
    couverture). Rendu historique préservé, `folded == 0`.
  · `bounty` — rejouable seulement : l'annexe ne rend que les REPRÉSENTANTS des groupes de bruit ; les
    membres repliés sont COMPTÉS, NOMMÉS par gabarit, et le rapport dit COMMENT les récupérer.
  Dans les DEUX vues l'en-tête est identique : verdict, actionnables, couverture non vérifiée.

Stdlib pure, déterministe, zéro réseau. N'altère NI les findings, NI le ledger, NI l'ordre du triage.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from .schema import SEVERITIES
from .redact import redact_secrets
from . import triage as _triage

# --- vues ------------------------------------------------------------------------------------------
VIEW_PENTEST = "pentest"
VIEW_BOUNTY = "bounty"
VIEWS = (VIEW_PENTEST, VIEW_BOUNTY)
DEFAULT_VIEW = VIEW_PENTEST

#: variable d'environnement d'override par-run (miroir de `FORGE_INGEST_EVERY` / `FORGE_RESOURCE_PROFILE`).
ENV_VIEW = "FORGE_REPORT_VIEW"

_MEDIUM_RANK = SEVERITIES.index("MEDIUM")
_LOW_RANK = SEVERITIES.index("LOW")

#: statuts qui valent PREUVE (posés uniquement par le chemin sanctionné `Module.finding(_proven=True)`).
PROVEN_STATUSES = frozenset({"vulnerable", "submitted", "accepted"})
#: statut « je n'ai PAS pu vérifier » — trou de couverture, jamais du bruit.
UNVERIFIED_STATUS = "skipped"
#: hit d'un outil tiers sur sa PROPRE sévérité auto-déclarée — à qualifier, JAMAIS présenté comme prouvé.
TOOL_REPORTED_STATUS = "reported_by_tool"

#: bornes d'affichage des LISTES d'occurrences/cibles. Bornent le VOLUME DE TEXTE d'une ligne, jamais
#: le nombre d'items : le total exact est TOUJOURS imprimé à côté (« 6 endpoints » + « +2 autres »).
MAX_OCCURRENCE_EXAMPLES = 8
MAX_REASON_EXAMPLES = 4
#: bornes de la table « planifié jamais tenté » (run interrompu). Même règle : borne le TEXTE, jamais
#: le COMPTE — le nombre total d'actions non tentées est imprimé au-dessus de la table, en entier.
MAX_NOT_ATTEMPTED_ROWS = 25

_STATUS_GLOSS = {
    "vulnerable": "PROUVÉ exploitable par un oracle Forge",
    "submitted": "prouvé, soumis au programme",
    "accepted": "prouvé, accepté par le programme",
    "reported_by_tool": "signalé par un OUTIL TIERS sur sa propre sévérité — **NON validé manuellement**",
    "tested": "testé — **aucune exploitabilité démontrée** par Forge",
    "not_vulnerable": "testé négatif",
    "informative": "informatif",
    "invalid": "invalide",
    "skipped": "**NON VÉRIFIÉ** — le module n'a pas pu s'exécuter",
}


def resolve_view(explicit: Any = None, scope_triage: Any = None) -> str:
    """Vue effective, par PRÉCÉDENCE DÉCROISSANTE (miroir de la doctrine `--param` de la CLI : l'intention
    EXPLICITE de l'opérateur pour CE run prime sur le fichier de scope) :

      1. `explicit` — argument passé à `build_report` (drapeau CLI / appelant programmatique) ;
      2. `$FORGE_REPORT_VIEW` — override d'environnement pour ce run ;
      3. `scope.triage["view"]` — valeur de `scope.json` ;
      4. `scope.triage["auto_hide"] == true` → `bounty`. Ce drapeau EXISTAIT, était documenté « masque
         le bruit », était lu par `TriageConfig`, rangé dans la synthèse, IMPRIMÉ comme étiquette…
         et n'était consommé par AUCUN rendu : poser `auto_hide=true` ne changeait pas un octet du
         rapport. Il est ici RACCORDÉ au seul mécanisme de repli du dépôt (la vue `bounty`), qui
         compte et nomme ce qu'il replie — au lieu de rester un knob mort ;
      5. `DEFAULT_VIEW` (`pentest`, exhaustif) — défaut SÛR : rien n'est replié.

    Une valeur inconnue est IGNORÉE (repli sur le niveau suivant), jamais une erreur. Pur.
    """
    cfg = scope_triage if isinstance(scope_triage, dict) else {}
    auto_hide = VIEW_BOUNTY if cfg.get("auto_hide") is True else None
    for candidate in (explicit, os.environ.get(ENV_VIEW), cfg.get("view"), auto_hide):
        v = str(candidate or "").strip().lower()
        if v in VIEWS:
            return v
    return DEFAULT_VIEW


def _sev_rank(sev: Any) -> int:
    s = str(sev or "").strip().upper()
    return SEVERITIES.index(s) if s in SEVERITIES else 0


def _txt(value: Any) -> str:
    """Texte d'un champ de finding, passé par la surface UNIQUE de rédaction (`forge.redact`).
    Défense en profondeur : le rapport ne peut pas rendre un secret qu'un module aurait laissé passer.
    Idempotent (une double rédaction ne masque jamais moins). Ne lève jamais."""
    return redact_secrets(str(value or ""))


# --- (1) BUCKETS ------------------------------------------------------------------------------------

def bucket_of(f: Any, annotation: dict[str, Any] | None = None) -> str:
    """Seau d'UN finding — DÉRIVÉ de ses champs, jamais inventé. Ordre de test = ordre de PRIORITÉ :

      `unverified`  : statut `skipped` — le module n'a PAS pu conclure. TESTÉ EN PREMIER : un trou de
                      couverture n'est jamais rabattu dans le bruit, quelle que soit sa sévérité.
      `exploitable` : sévérité ≥ MEDIUM **ou** statut prouvé — le plancher que le triage garantit déjà
                      « jamais bruit ». C'est ce qu'un opérateur doit lire EN PREMIER.
      `qualify`     : sévérité ≥ LOW **ou** hit d'outil tiers — signal réel, exploitabilité NON démontrée.
      `recon`       : le reste (INFO de cartographie) — l'annexe.

    `annotation` (triage) est accepté pour la symétrie d'appel ; le seau NE dépend PAS du noise-score
    (sinon un trou de couverture pénalisé par le poids `degraded` retomberait dans le bruit — le bug
    exact que ce module corrige). Pur.
    """
    status = str(getattr(f, "status", "") or "").lower()
    if status == UNVERIFIED_STATUS:
        return "unverified"
    rank = _sev_rank(getattr(f, "severity", ""))
    if rank >= _MEDIUM_RANK or status in PROVEN_STATUSES:
        return "exploitable"
    if rank >= _LOW_RANK or status == TOOL_REPORTED_STATUS:
        return "qualify"
    return "recon"


def bucket_findings(findings: list[Any], tr: Any = None) -> dict[str, list[int]]:
    """PARTITION des indices d'entrée en quatre seaux. Chaque index apparaît dans EXACTEMENT un seau et
    l'union couvre `range(len(findings))` (invariant prouvé par test). Ordre d'entrée préservé."""
    out: dict[str, list[int]] = {"exploitable": [], "qualify": [], "unverified": [], "recon": []}
    for i, f in enumerate(findings):
        ann = tr.annotation_for(f) if tr is not None else None
        out[bucket_of(f, ann)].append(i)
    return out


# --- (2) GROUPES (1 vuln × N endpoints) -------------------------------------------------------------
@dataclass
class Item:
    """Un ITEM de rapport : un gabarit de finding + TOUTES ses occurrences (endpoints touchés).

    `rep` est le finding REPRÉSENTATIF (plus petit index d'origine — déterministe, comme le triage).
    `members` porte les indices d'origine de TOUTES les occurrences : c'est ce qui rend la comptabilité
    vérifiable (aucune occurrence ne peut disparaître sans faire tomber l'invariant)."""
    rep: Any
    members: list[int] = field(default_factory=list)
    key: tuple = ()

    @property
    def count(self) -> int:
        return len(self.members)


def group_items(findings: list[Any], idxs: list[int]) -> list[Item]:
    """Regroupe des findings par GABARIT (`triage.template_key`) → « 1 vuln × N endpoints ».

    Réutilise la clé du triage natif (aucune 2e notion de similarité dans le dépôt). Tri de sortie :
    sévérité DESC, puis nombre d'occurrences DESC, puis index du représentant ASC (déterministe)."""
    groups: dict[tuple, Item] = {}
    for i in idxs:
        f = findings[i]
        key = _triage.template_key(f)
        it = groups.get(key)
        if it is None:
            groups[key] = it = Item(rep=f, members=[], key=key)
        it.members.append(i)
    items = list(groups.values())
    items.sort(key=lambda it: (-_sev_rank(getattr(it.rep, "severity", "")), -it.count, it.members[0]))
    return items


# --- (3) PLAN D'ANNEXE + INVARIANT ANTI-MASQUAGE ----------------------------------------------------
@dataclass
class AnnexPlan:
    """Ce que l'annexe RENDRA, et ce qu'elle REPLIE — avec de quoi le VÉRIFIER.

    `rendered`      : indices d'origine rendus intégralement, dans l'ordre du rang de triage.
    `folded_groups` : groupes REPLIÉS (gabarit, taille, membres, exemple) — comptés ET nommés.
    `total`         : nombre de findings en entrée.
    `view`          : la vue qui a produit ce plan.

    INVARIANT (`check`) : `set(rendered)` et l'union des `members` repliés forment une PARTITION EXACTE
    de `range(total)`. Deux dérivations INDÉPENDANTES sont comparées (somme des tailles de groupes vs
    cardinal de l'union d'indices) : une mutation de l'une SEULE fait diverger le contrôle."""
    rendered: list[int] = field(default_factory=list)
    folded_groups: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    view: str = DEFAULT_VIEW

    @property
    def folded(self) -> int:
        """Nombre de findings repliés — dérivé de la COMPTABILITÉ DES GROUPES (bookkeeping du repli),
        PAS de `total - len(rendered)`. C'est cette indépendance qui rend `check()` capable de rougir."""
        return sum(int(g.get("size", 0)) for g in self.folded_groups)

    def check(self) -> tuple[bool, str]:
        """(ok, explication). Fail-LOUD : l'appelant RENDRA l'explication dans le rapport si `ok` est
        faux — jamais de rattrapage silencieux. Vérifie, dans l'ordre :
          a) aucun doublon dans `rendered` ;
          b) rendus et repliés sont DISJOINTS ;
          c) leur union == `range(total)` (rien n'est perdu, rien n'est inventé) ;
          d) `folded` (somme des tailles déclarées) == cardinal de l'union des membres repliés.
        """
        rendered = list(self.rendered)
        if len(set(rendered)) != len(rendered):
            return False, f"{len(rendered) - len(set(rendered))} finding(s) rendu(s) en double dans l'annexe"
        folded_idx: set[int] = set()
        for g in self.folded_groups:
            folded_idx.update(int(m) for m in (g.get("members") or []))
        overlap = set(rendered) & folded_idx
        if overlap:
            return False, f"{len(overlap)} finding(s) à la fois rendu(s) ET replié(s) (comptés deux fois)"
        union = set(rendered) | folded_idx
        expected = set(range(self.total))
        if union != expected:
            missing = len(expected - union)
            extra = len(union - expected)
            return False, (f"comptabilité CASSÉE : {missing} finding(s) NI rendu(s) NI replié(s) "
                           f"(disparus en silence), {extra} indice(s) inconnu(s)")
        if self.folded != len(folded_idx):
            return False, (f"comptabilité CASSÉE : tailles de groupes repliés déclarées={self.folded} "
                           f"mais {len(folded_idx)} membre(s) distinct(s) listés")
        return True, (f"{len(rendered)} rendu(s) + {self.folded} replié(s) = {self.total} émis "
                      f"(partition exacte, aucune suppression)")


def annex_plan(findings: list[Any], tr: Any, view: str = DEFAULT_VIEW,
               keep_idxs: Any = None) -> AnnexPlan:
    """Construit le plan d'annexe pour `view`.

    `keep_idxs` : indices DÉJÀ rendus en tête (actionnables / non vérifiés). En vue `bounty` ils sont
    exclus du repli (on ne replie jamais ce qui vient d'être présenté comme actionnable) — mais ils
    RESTENT rendus par l'annexe en vue `pentest` (exhaustivité).

    · `pentest` : `rendered` = TOUS les indices, dans l'ordre du rang de triage. `folded == 0`.
    · `bounty`  : `rendered` = les indices `keep_idxs` + UN représentant par gabarit de bruit ; les
      autres membres de chaque gabarit sont REPLIÉS (comptés, nommés, récupérables). Un gabarit
      SINGLETON n'est jamais replié (il n'y a rien à replier).
    """
    n = len(findings)
    order = _rank_order(findings, tr)
    plan = AnnexPlan(total=n, view=view)
    if view != VIEW_BOUNTY:
        plan.rendered = order
        return plan

    keep = set(int(i) for i in (keep_idxs or []))
    seen_rep: dict[tuple, int] = {}
    folded: dict[tuple, dict[str, Any]] = {}
    rendered: list[int] = []
    for i in order:
        if i in keep:
            rendered.append(i)
            continue
        key = _triage.template_key(findings[i])
        if key not in seen_rep:
            seen_rep[key] = i
            rendered.append(i)
            continue
        g = folded.get(key)
        if g is None:
            rep = findings[seen_rep[key]]
            folded[key] = g = {
                "label": _triage.normalize_title(getattr(rep, "title", "")) or "(sans titre)",
                "severity": str(getattr(rep, "severity", "") or "INFO").upper(),
                "representative": seen_rep[key], "members": [], "size": 0,
                "example_target": _txt(getattr(rep, "target", "")),
            }
        g["members"].append(i)
        g["size"] = len(g["members"])
    plan.rendered = rendered
    plan.folded_groups = sorted(folded.values(), key=lambda g: (-g["size"], g["representative"]))
    return plan


def _rank_order(findings: list[Any], tr: Any) -> list[int]:
    """Indices d'origine dans l'ORDRE DU RANG de triage (`tr.ranked`), ou l'ordre d'entrée si le triage
    est absent. Passe par l'IDENTITÉ des objets (Finding n'est pas hashable) ; tout finding non retrouvé
    est ajouté en queue — on ne PERD jamais un indice, même si `ranked` est incomplet."""
    n = len(findings)
    if tr is None or not getattr(tr, "ranked", None):
        return list(range(n))
    pos: dict[int, list[int]] = {}
    for i, f in enumerate(findings):
        pos.setdefault(id(f), []).append(i)
    order, taken = [], set()
    for f in tr.ranked:
        bucket = pos.get(id(f))
        while bucket:
            i = bucket.pop(0)
            if i not in taken:
                taken.add(i)
                order.append(i)
                break
    order.extend(i for i in range(n) if i not in taken)
    return order


# --- (4) RENDU ---------------------------------------------------------------------------------------
_METHOD_RX = re.compile(r"(?:^|\s)-X\s+([A-Za-z]{3,7})\b")
_HEAD_RX = re.compile(r"(?:^|\s)-[a-zA-Z]*I(?:\s|$)")
_BODY_RX = re.compile(r"(?:^|\s)(?:--data(?:-raw|-binary|-urlencode)?|-d|--form|-F)(?:\s|=)")
_URL_IN_POC_RX = re.compile(r"https?://[^\s'\"]+")


def http_method_from_poc(poc: str) -> str:
    """Méthode HTTP DÉDUITE d'une commande PoC `curl`, ou '' si non déductible. Aucune invention : on ne
    rend une méthode que si le PoC la porte explicitement (`-X`), l'implique sans ambiguïté (`-I` → HEAD,
    `-d/--data/-F` → POST) ou est un `curl` nu (→ GET, le défaut de curl). Tout autre outil → ''. Pur."""
    p = str(poc or "")
    m = _METHOD_RX.search(p)
    if m:
        return m.group(1).upper()
    if not re.search(r"(?:^|\s|/)curl(?:\s|$)", p):
        return ""
    if _HEAD_RX.search(p):
        return "HEAD"
    if _BODY_RX.search(p):
        return "POST"
    return "GET"


def request_line(f: Any) -> str:
    """« MÉTHODE URL » quand les DEUX sont déductibles du PoC, sinon ''. L'URL vient du PoC (c'est
    l'endpoint réellement frappé) ; `target` reste rendu à part, verbatim, comme cible enregistrée."""
    poc = _txt(getattr(f, "poc", ""))
    method = http_method_from_poc(poc)
    if not method:
        return ""
    m = _URL_IN_POC_RX.search(poc)
    if not m:
        return ""
    return f"{method} {m.group(0).rstrip(chr(39)).rstrip(chr(34))}"


def _occurrence_line(findings: list[Any], item: Item) -> str:
    """« N endpoint(s) » + jusqu'à `MAX_OCCURRENCE_EXAMPLES` exemples + reste EXPLICITEMENT compté."""
    tgts, seen = [], set()
    for i in item.members:
        t = _txt(getattr(findings[i], "target", "")) or "—"
        if t not in seen:
            seen.add(t)
            tgts.append(t)
    shown = tgts[:MAX_OCCURRENCE_EXAMPLES]
    rest = len(tgts) - len(shown)
    body = ", ".join(f"`{t}`" for t in shown)
    if rest > 0:
        body += f" · **+{rest} autre(s)**"
    return f"{item.count} occurrence(s) sur {len(tgts)} cible(s) distincte(s) : {body}"


def render_item(findings: list[Any], item: Item, num: int, scope_line: str) -> list[str]:
    """Bloc d'UN item actionnable, à la forme attendue par un triager : titre, sévérité, CWE/CVSS,
    endpoint + méthode, étapes de reproduction, COMMANDE REJOUABLE, observation, correctif, occurrences.

    N'assemble QUE des champs EXISTANTS du finding (`poc`, `evidence`, `cwe`, `cvss_vector`, `fix`) — le
    dépôt les produisait déjà et le rapport les jetait. AUCUNE sévérité n'est relevée, aucun impact
    inventé : le statut est rendu tel quel avec sa GLOSE (un `tested` dit explicitement qu'aucune
    exploitabilité n'est démontrée)."""
    f = item.rep
    sev = str(getattr(f, "severity", "") or "INFO").upper()
    title = _txt(getattr(f, "title", "")) or "(sans titre)"
    status = str(getattr(f, "status", "") or "tested").lower()
    gloss = _STATUS_GLOSS.get(status, "")
    cvss_v = _txt(getattr(f, "cvss_vector", ""))
    cvss_s = getattr(f, "cvss_score", 0.0) or 0.0
    cvss = f"{cvss_s} · `{cvss_v}`" if cvss_v else (f"{cvss_s}" if cvss_s else "—")
    poc = _txt(getattr(f, "poc", ""))
    evidence = _txt(getattr(f, "evidence", "")) or "—"
    fix = _txt(getattr(f, "fix", "")) or "—"
    req = request_line(f)

    out = [f"### A{num} · [{sev}] {title}", ""]
    out += ["| | |", "|---|---|",
            f"| **Sévérité** | {sev} |",
            f"| **CWE** | {_txt(getattr(f, 'cwe', '')) or _txt(getattr(f, 'category', '')) or '—'} |",
            f"| **CVSS (base, indicatif)** | {cvss} |",
            f"| **ATT&CK** | {_txt(getattr(f, 'mitre', '')) or '—'} |",
            f"| **Statut** | `{status}` — {gloss or '—'} |",
            f"| **Module** | `{_txt(getattr(f, 'tool', '')) or '—'}` |",
            f"| **Cible** | `{_txt(getattr(f, 'target', '')) or '—'}` |"]
    if req:
        out.append(f"| **Requête** | `{req}` *(méthode déduite du PoC)* |")
    out.append(f"| **Occurrences** | {_occurrence_line(findings, item)} |")
    out.append("")

    out += ["**Reproduction**", ""]
    step = 1
    if scope_line:
        out.append(f"{step}. Se placer sur le périmètre AUTORISÉ de l'engagement : {scope_line}.")
        step += 1
    if poc:
        out.append(f"{step}. Rejouer la commande ci-dessous (telle quelle, elle est celle qu'a tirée Forge).")
        step += 1
    else:
        out.append(f"{step}. _Aucune commande rejouable enregistrée par le module pour ce finding._")
        step += 1
    out.append(f"{step}. Observer : {evidence}")
    out.append("")
    if poc:
        out += ["**Commande rejouable**", "", "```bash", poc, "```", ""]
    out += [f"**Observation (preuve brute)** : {evidence}", ""]
    if status in PROVEN_STATUSES:
        out += ["**Impact** : exploitabilité DÉMONTRÉE (statut prouvé par un oracle Forge). "
                "Voir la preuve ci-dessus.", ""]
    else:
        out += [f"**Impact** : **non démontré** — statut `{status}`. Forge n'a pas prouvé "
                "l'exploitabilité ; à qualifier manuellement avant toute soumission.", ""]
    out += [f"**Correctif suggéré** : {fix}", ""]
    return out


def render_verdict(findings: list[Any], buckets: dict[str, list[int]],
                   items: dict[str, list[Item]], view: str,
                   interruption: "dict[str, Any] | None" = None) -> list[str]:
    """Section **Verdict** — ce qu'un opérateur lit EN PREMIER, en une ligne.

    La ligne de tête est DÉRIVÉE du corpus, jamais gonflée : s'il n'y a aucun finding ≥ MEDIUM ni prouvé,
    elle dit **« rien d'actionnable trouvé »** — franchement, en une ligne, au lieu de se déduire d'un
    défilement de milliers d'entrées.

    `interruption` (fiche `interrupt.interruption_record`, None sur un run complet) CORRIGE cette
    ligne, et c'est la garde la plus importante du lot : sur un run coupé, « rien d'actionnable
    trouvé » est une CONCLUSION FAUSSE — le plan n'a pas tourné en entier. La phrase devient alors
    explicitement bornée à la fraction exécutée, et dit combien d'actions ont tourné sur combien de
    planifiées. Un rapport tronqué qui ressemble à un rapport complet est PIRE que pas de rapport."""
    n = len(findings)
    n_expl = len(buckets["exploitable"])
    n_qual = len(buckets["qualify"])
    n_unver = len(buckets["unverified"])
    n_recon = len(buckets["recon"])
    out = ["## Verdict", ""]
    if n_expl:
        top = items["exploitable"][0].rep
        out += [f"> **{n_expl} finding(s) actionnable(s)** (sévérité ≥ MEDIUM ou exploitabilité prouvée). "
                f"Le plus grave : **[{str(getattr(top, 'severity', '')).upper()}] "
                f"{_txt(getattr(top, 'title', ''))}** sur `{_txt(getattr(top, 'target', ''))}` — "
                f"détail en §« Actionnable — à reporter ».", ""]
    elif interruption:
        out += [f"> **Rien d'actionnable DANS LA FRACTION DU PLAN QUI A TOURNÉ** — et le plan n'a "
                f"**pas** tourné en entier : run **INTERROMPU** ({interruption.get('label') or 'arrêt anticipé'}), "
                f"{coverage_ratio(interruption)}. **Ne pas en conclure « rien trouvé »** : "
                f"ce verdict ne porte que sur les actions exécutées.", ""]
    else:
        out += ["> **Rien d'actionnable trouvé.** Aucun finding de sévérité ≥ MEDIUM, aucune "
                "exploitabilité prouvée. Ce qui suit est du signal à qualifier, des trous de "
                "couverture et du bruit de reconnaissance — présentés comme tels, sans sur-classement.", ""]
    out += [
        f"- **Actionnable** (≥ MEDIUM ou prouvé) : **{n_expl}**"
        + (f" → {len(items['exploitable'])} item(s) distinct(s)" if n_expl else ""),
        f"- **À qualifier** (LOW / signalé par un outil, exploitabilité NON démontrée) : **{n_qual}**"
        + (f" → {len(items['qualify'])} item(s) distinct(s)" if n_qual else ""),
        f"- **Couverture NON vérifiée** (`skipped` — le module n'a pas pu conclure) : **{n_unver}**"
        + (" ⚠️ *ce sont des trous de couverture, pas du bruit*" if n_unver else ""),
        f"- **Bruit de reconnaissance** (INFO) : **{n_recon}** — relégué en annexe, intégralement compté.",
        f"- **Total émis** : **{n}** findings (vue `{view}`).",
    ]
    if interruption:
        # Rappelé DANS la liste de comptage, pas seulement dans la bannière de tête : c'est ici qu'un
        # lecteur pressé lit les chiffres, et un dénominateur incomplet doit se dire là où il est lu.
        out.append(f"- **⚠️ Plan INCOMPLET** : {coverage_ratio(interruption)} — "
                   f"run interrompu ({interruption.get('label') or 'arrêt anticipé'}).")
    out.append("")
    return out


def coverage_ratio(interruption: "dict[str, Any] | None") -> str:
    """« X action(s) exécutée(s) sur Y planifiée(s) » — la phrase de couverture d'un run interrompu.

    N'INVENTE JAMAIS de dénominateur : si le nombre d'actions planifiées est inconnu (interruption
    survenue hors campagne, moteur sans compteur), on dit ce qu'on sait et on dit qu'on ignore le
    reste. Un ratio fabriqué serait exactement le faux réconfort que ce lot combat."""
    if not interruption:
        return ""
    ran = interruption.get("ran")
    planned = interruption.get("planned")
    pending = interruption.get("not_attempted")
    if ran is None:
        return "nombre d'actions exécutées inconnu"
    if not planned:
        return f"**{ran} action(s) exécutée(s)**, total planifié inconnu (plan non finalisé)"
    txt = f"**{ran} action(s) exécutée(s) sur {planned} planifiée(s)**"
    if pending:
        txt += f", **{pending} jamais tentée(s)**"
    return txt


def render_unverified(findings: list[Any], idxs: list[int],
                      not_attempted: "list[Any] | None" = None,
                      interruption: "dict[str, Any] | None" = None) -> list[str]:
    """Section **Couverture non vérifiée** — les `skipped`, PROMUS avant tout le bruit.

    Un `skipped` dit « je n'ai PAS pu vérifier » : sur une cible protégée (WAF, outil absent, réseau
    coupé) c'est l'information la PLUS importante du rapport, parce qu'elle borne ce que l'absence de
    finding permet de conclure. Regroupé PAR MODULE (l'unité du trou), avec les raisons distinctes.

    DEUXIÈME FAMILLE DE TROU, MÊME SECTION (`not_attempted`) : les actions que le planner avait
    ORDONNÉES et que le run n'a jamais atteintes, parce qu'il a été coupé (budget, signal, erreur).
    Elles appartiennent ICI et nulle part ailleurs — c'est exactement le même énoncé (« je n'ai PAS
    vérifié »), à ceci près que le module n'a même pas démarré. On ne crée donc pas un second
    mécanisme de transparence : on étend celui qui existe. Et on n'en fabrique AUCUN verdict — une
    action jamais tentée n'est ni `tested`, ni `not_vulnerable`, ni un finding."""
    out = ["## Couverture NON vérifiée (trous de couverture)", ""]
    if not idxs:
        out += ["_Aucun module n'a échoué à s'exécuter : la couverture annoncée par le plan a été "
                "effectivement tentée._", ""]
        return out + _render_not_attempted(not_attempted, interruption)
    groups: dict[str, dict[str, Any]] = {}
    for i in idxs:
        f = findings[i]
        tool = _txt(getattr(f, "tool", "")) or "(module inconnu)"
        kind = tool.rsplit(":", 1)[-1] if ":" in tool else tool
        g = groups.setdefault(kind, {"n": 0, "reasons": [], "targets": []})
        g["n"] += 1
        reason = _triage.normalize_title(_txt(getattr(f, "title", "")))
        if reason and reason not in g["reasons"]:
            g["reasons"].append(reason)
        t = _txt(getattr(f, "target", ""))
        if t and t not in g["targets"]:
            g["targets"].append(t)
    out += [f"**{len(idxs)} finding(s) `skipped`** — {len(groups)} module(s) n'ont PAS pu conclure. "
            "Une absence de finding sur ces classes ne vaut donc **pas** une absence de vulnérabilité.",
            "", "| Module | Occurrences | Cibles | Raison(s) rapportée(s) |", "|---|---|---|---|"]
    for kind in sorted(groups, key=lambda k: (-groups[k]["n"], k)):
        g = groups[kind]
        reasons = g["reasons"][:MAX_REASON_EXAMPLES]
        more = len(g["reasons"]) - len(reasons)
        rtxt = " ; ".join(r[:90] for r in reasons) + (f" · **+{more} autre(s)**" if more > 0 else "")
        out.append(f"| `{kind}` | {g['n']} | {len(g['targets'])} | {rtxt} |")
    out.append("")
    return out + _render_not_attempted(not_attempted, interruption)


def _render_not_attempted(not_attempted: "list[Any] | None",
                          interruption: "dict[str, Any] | None") -> list[str]:
    """Sous-bloc « planifié mais JAMAIS TENTÉ » de la section des trous de couverture.

    Vide (aucune ligne) quand rien n'a été laissé de côté — un run complet rend donc EXACTEMENT le
    même markdown qu'avant ce lot. Sinon : le compte, la cause, et le détail par module/cible, borné
    en affichage mais TOUJOURS compté en entier (le nombre affiché n'est jamais le nombre tronqué)."""
    pending = list(not_attempted or [])
    if not pending:
        return []
    cause = (interruption or {}).get("label") or "run interrompu"
    groups: dict[str, list[str]] = {}
    for a in pending:
        kind = _txt(getattr(a, "kind", "")) or "(kind inconnu)"
        tgt = _txt(getattr(a, "target", ""))
        tl = groups.setdefault(kind, [])
        if tgt and tgt not in tl:
            tl.append(tgt)
    out = [f"**{len(pending)} action(s) PLANIFIÉE(S) JAMAIS TENTÉE(S)** — {cause}. "
           f"Ces {len(groups)} module(s) n'ont **pas démarré** sur ces cibles : aucun verdict n'a été "
           f"émis pour elles, ni positif ni négatif. Rejouer le run (budget plus large) pour les couvrir.",
           "", "| Module planifié | Actions non tentées | Cible(s) |", "|---|---|---|"]
    for kind in sorted(groups, key=lambda k: (-len(groups[k]), k))[:MAX_NOT_ATTEMPTED_ROWS]:
        tgts = groups[kind]
        shown = ", ".join(f"`{t}`" for t in tgts[:MAX_REASON_EXAMPLES])
        more = len(tgts) - min(len(tgts), MAX_REASON_EXAMPLES)
        out.append(f"| `{kind}` | {len(tgts)} | {shown}"
                   + (f" · **+{more} autre(s)**" if more > 0 else "") + " |")
    hidden = len(groups) - min(len(groups), MAX_NOT_ATTEMPTED_ROWS)
    if hidden > 0:
        out.append(f"| … | | **+{hidden} module(s) non tenté(s) supplémentaire(s)** |")
    out.append("")
    return out


def render_actionable(findings: list[Any], items: list[Item], heading: str, intro: str,
                      scope_line: str, start: int = 1) -> tuple[list[str], int]:
    """Rend une SÉRIE d'items actionnables. Renvoie (lignes, prochain numéro). Aucune borne : un item
    actionnable n'est JAMAIS tronqué (le troncage est réservé aux listes d'exemples, toujours comptées)."""
    out = [heading, ""]
    if not items:
        out += [intro, ""]
        return out, start
    num = start
    for it in items:
        out += render_item(findings, it, num, scope_line)
        num += 1
    return out, num


def render_annex_accounting(plan: AnnexPlan) -> list[str]:
    """Ligne de COMPTABILITÉ de l'annexe — la garde « rien n'est masqué en silence », RENDUE.

    Dit combien de findings l'annexe rend, combien elle replie, et **où les retrouver**. Si l'invariant
    de partition tombe, on n'essaie PAS de rattraper : on l'imprime en clair, en tête de section."""
    ok, why = plan.check()
    out = []
    if not ok:
        out += [f"> ⚠️ **COMPTABILITÉ DE L'ANNEXE CASSÉE — {why}.** Ce rapport ne peut pas garantir "
                "l'exhaustivité de son annexe : traiter le ledger (`kind=finding`) comme source de "
                "vérité et signaler ce bug.", ""]
        return out
    if plan.view == VIEW_BOUNTY and plan.folded:
        out += [f"> **{len(plan.rendered)} finding(s) rendus ici, {plan.folded} repliés** "
                f"(= {plan.total} émis au total). Les repliés sont des occurrences supplémentaires des "
                f"gabarits listés ci-dessous — **aucun n'est supprimé** : les rejouer avec "
                f"`--view pentest` (ou `FORGE_REPORT_VIEW=pentest`), ou les lire dans le ledger signé "
                f"(entrées `kind=finding`).", ""]
        out += ["| Gabarit replié | Sévérité | Occurrences repliées | Exemple de cible |", "|---|---|---|---|"]
        for g in plan.folded_groups:
            out.append(f"| {str(g['label'])[:70]} | {g['severity']} | {g['size']} | `{str(g['example_target'])[:60]}` |")
        out.append("")
    else:
        out += [f"> **{len(plan.rendered)} finding(s) rendus, {plan.folded} repliés** "
                f"(= {plan.total} émis au total) — vue `{plan.view}` : rien n'est replié, l'annexe est "
                "exhaustive.", ""]
    return out

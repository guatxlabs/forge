# SPDX-License-Identifier: AGPL-3.0-or-later
"""Module web — scan par templates nuclei (`web.nuclei`).

Ce fichier n'enregistre plus QUE `web.nuclei`. La classe qualifiante IDOR/BOLA
(`access_control.idor`), qui squattait ici, a été extraite dans `access_control.py` (bâtie sur la
base `Oracle`). nuclei n'apporte AUCUNE preuve d'exploitabilité côté Forge : un hit est signalé sur
la sévérité auto-déclarée par l'outil (`reported_by_tool`), jamais promu `vulnerable`.

MUTUALISATION PAR HÔTE (le verrou d'usage). nuclei recharge SA BASE DE TEMPLATES ENTIÈRE à chaque
invocation — coût FIXE, indépendant du nombre de cibles. Le moteur, lui, propose `web.nuclei` par
CIBLE (host, host:port, scheme://host, …) : sur une campagne réelle, 65 tirs pour **10 hôtes**, donc
55 rechargements de templates payés pour rien. `-u` de nuclei est un `string[]` : il accepte
`-u a,b,c` et n'a besoin NI d'un fichier de liste NI d'un montage docker (`-list <fichier>` serait
invisible dans le conteneur — `runner` lance `docker run --rm --network host` SANS `-v`).

Le module accepte donc un LOT via `action.params["targets"]`, et `coalesce_nuclei()` (ci-dessous)
fusionne les actions d'une vague en UNE par hôte. Les trois invariants du dépôt tiennent :

  · SCOPE-GUARD PAR CIBLE — chaque cible du lot est re-validée UNE PAR UNE contre le périmètre
    injecté. Le lot n'est même pas ACCEPTÉ sans périmètre injecté : la tête (seule cible passée par
    la gate ROE du moteur) est gardée, le reste est REFUSÉ. Grouper ne contourne rien.
  · ÉPINGLAGE IP — le moteur n'épingle que `action.target`. Un lot n'admet donc QUE des cibles du
    MÊME nom d'hôte que la tête : l'épinglage anti-rebinding reste valable pour chaque membre.
  · COUVERTURE DÉMONTRABLE — toute cible du lot ressort avec SON finding : le hit qui la concerne,
    ou « aucun hit », ou un `skipped` NOMMÉ si elle a été écartée. Jamais une troncature muette.

CORRECTION MESURÉE (run réel du 2026-08-08 contre un hôte VIVANT) — « le coût est FIXE » n'est vrai
que sur les cibles MORTES qui ont servi à le calibrer (`tests/bench_nuclei_batch.py` : loopback,
1 cible 26,0 s / 20 cibles 23,7 s). Contre un hôte qui RÉPOND, le coût marginal par cible est du même
ORDRE que l'allocation `_TIMEOUT_PER_TARGET` — il ne reste donc PAS de marge :

    lot de  6  ->  mur 1200 s,  durée mesurée 1202,67 s   (mur ATTEINT)
    lot de 11  ->  mur 1800 s,  durée mesurée 1802,61 s   (mur ATTEINT)
    lot de 17  ->  mur 2520 s,  durée mesurée 2521,68 s   (mur ATTEINT)

Trois lots sur trois ont été TUÉS par `runner.tool` (rc=124), à quelques secondes de frais près. Le
« budget proportionnel » n'est donc pas une marge de sécurité, c'est le POINT D'ÉQUILIBRE : la
moindre variance le franchit. Deux conséquences, toutes deux traitées ici :
  (a) un lot tué rendait « aucun hit » pour les cibles jamais atteintes — un verdict FABRIQUÉ, que
      la garantie de couverture ci-dessus prétendait précisément interdire (cf. `fire`, rc=124) ;
  (b) la borne d'un lot (jusqu'à 3480 s à `MAX_BATCH`) est atteinte pour de vrai, donc le moteur ne
      peut pas la traiter comme improbable : il refuse désormais de DÉMARRER un lot qui ne tient pas
      dans le budget restant, et le module RÉDUIT son lot pour tenir (cf. `_fit_to_budget`).
"""
import json
import urllib.parse

from .registry import register, Module
from ._scopeguard import ScopeGuardMixin
from .. import blindness as _blind
from .. import resource_profile
from .. import runner
from .. import techniques
from ..interrupt import ACTION_BUDGET_PARAM
from .toolspec import FlagAllowlistMixin, check_extra_args, safe_value

#: param d'action portant le LOT de cibles (list[str]). Absent/vide -> comportement historique
#: BYTE-IDENTIQUE (une invocation `-u <action.target>`).
BATCH_PARAM = "targets"

#: séparateur du `string[]` de nuclei (`-u a,b,c`). Une cible qui le contient est REFUSÉE du lot.
BATCH_SEP = ","

#: code de retour que `runner.tool` rend quand il a TUÉ le groupe de process à l'échéance (cf.
#: `runner._spawn_and_wait`). Un tir à 124 a produit une sortie PARTIELLE : ce qu'il n'a pas atteint
#: n'a PAS été testé, et ne doit surtout pas ressortir en « aucun hit ».
TIMEOUT_RC = 124


def host_of(target):
    """Nom d'hôte NORMALISÉ (minuscule, sans port ni scheme) d'une cible, ou None si indérivable.

    C'est la CLÉ DE LOT : `guatx.com`, `https://guatx.com/`, `guatx.com:8443` et `http://guatx.com:80`
    partagent le même hôte, donc la même résolution DNS — donc le MÊME épinglage IP. Regrouper sur
    autre chose (un « site », un domaine enregistrable) casserait l'invariant anti-rebinding.
    Pur, ne lève jamais."""
    s = str(target or "").strip()
    if not s:
        return None
    if "://" not in s:
        s = "//" + s                                   # urlsplit ne peuple .hostname qu'avec un netloc
    try:
        h = urllib.parse.urlsplit(s).hostname
    except ValueError:                                 # netloc/port malformé
        return None
    return (h or "").lower() or None


def unsafe_batch_target(target):
    """Raison de REFUS d'une cible EN LOT, ou None si elle est passable telle quelle dans `-u a,b,c`.

    Plus strict que la cible unique historique : le lot est une liste CSV, donc une virgule y
    fabriquerait une cible fantôme (non gardée par le scope !). Miroir de `unsafe_positional_target` :
    un `-` initial resterait de l'option-smuggling. Pur, ne lève jamais."""
    s = str(target if target is not None else "")
    if not s or s != s.strip():
        return "cible vide ou entourée d'espaces"
    if s.startswith("-"):
        return "cible positionnelle ambiguë (commence par '-')"
    if BATCH_SEP in s:
        return f"cible contenant '{BATCH_SEP}' — séparateur du lot `-u a,b,c`"
    if any(c in s for c in "\x00 \t\r\n"):
        return "cible contenant un espace ou un caractère de contrôle"
    return None


def norm_target(url):
    """Forme COMPARABLE d'une cible ou d'un `matched-at` : minuscule, scheme retiré, '/' final retiré.

    C'est aussi la clé de COUVERTURE : `app.test` et `https://app.test` normalisent pareil parce
    qu'ils désignent LA MÊME surface — un hit sur l'un couvre l'autre, et aucun des deux ne doit
    récolter un « aucun hit » mensonger.

    nuclei ne renvoie PAS la cible d'entrée dans son JSONL : le champ `host` est le NOM D'HÔTE
    (mesuré sur un run réel : entrée `https://guatx.com:8443` -> `host: "guatx.com"`), donc inutile
    pour distinguer deux cibles d'un même hôte. C'est `matched-at` qui porte l'entrée, PRÉFIXÉE
    (entrée `https://guatx.com:8443` -> `matched-at: https://guatx.com:8443/robots.txt`). D'où une
    attribution par PLUS LONG PRÉFIXE sur cette forme normalisée. Pur, ne lève jamais."""
    s = str(url or "").strip().lower()
    for scheme in ("http://", "https://"):
        if s.startswith(scheme):
            s = s[len(scheme):]
            break
    return s.rstrip("/")


def attribute_hit(matched_at, targets):
    """Cible d'ENTRÉE à laquelle attribuer un hit nuclei (`matched-at`), ou None si aucune ne colle.

    PLUS LONG PRÉFIXE, aux frontières `/`, `?` et `:` uniquement — jamais un préfixe de texte nu
    (sans quoi `guatx.com` capterait `guatx.community`). Déterministe. Un hit NON attribué n'est
    JAMAIS perdu : le finding porte de toute façon son `matched-at` comme cible (inchangé), et
    l'entrée concernée ressortira au pire avec un « aucun hit » de plus — on sous-déclare, on ne
    sur-déclare pas. Pur, ne lève jamais."""
    m = norm_target(matched_at)
    if not m:
        return None
    best, best_len = None, -1
    for t in targets:
        n = norm_target(t)
        if not n or len(n) <= best_len:
            continue
        if m == n or m.startswith(n + "/") or m.startswith(n + "?") or m.startswith(n + ":"):
            best, best_len = t, len(n)
    return best


def coalesce_nuclei(actions, max_batch=None):
    """Fusionne les actions `web.nuclei` d'une VAGUE en UNE action par HÔTE (et par tranche).

    C'est le point d'entrée que le MOTEUR appelle sur une vague, juste avant `run()`. Contrat :

      · les actions d'un AUTRE kind sont rendues TELLES QUELLES, dans leur ordre d'origine ;
      · les actions `web.nuclei` d'un même hôte sont repliées sur la PREMIÈRE d'entre elles (la TÊTE),
        qui garde donc sa position dans l'ordre EV du planner et son `action.id` ; les cibles du
        groupe atterrissent dans `params["targets"]` (tête en premier, ordre d'origine, dédupliqué) ;
      · une action dont l'hôte est indérivable, ou déjà porteuse d'un `targets`, n'est JAMAIS repliée ;
      · `max_batch` (défaut `NucleiScan.MAX_BATCH`) borne la taille d'un lot : un hôte à 300 URLs
        redevient plusieurs actions plutôt qu'une seule invocation qui dépasserait le timeout. Chaque
        tranche a sa propre tête, donc un `action.id` distinct (jamais deux fois le même au ledger).

    NE MUTE QUE `params[BATCH_PARAM]` des têtes retenues ; ne construit aucune Action. Déterministe.
    Une liste vide rend une liste vide. Pur (hors la mutation de params), ne lève jamais."""
    cap = NucleiScan.MAX_BATCH if max_batch is None else int(max_batch)
    cap = max(1, cap)
    heads, groups = [], {}                             # hôte -> indices dans `heads` (tranche courante)
    out = []
    for a in actions:
        if getattr(a, "kind", "") != "web.nuclei" or (getattr(a, "params", None) or {}).get(BATCH_PARAM):
            out.append(a)
            continue
        host = host_of(getattr(a, "target", ""))
        if host is None:                               # cible non parsable -> jamais repliée
            out.append(a)
            continue
        head = groups.get(host)
        if head is None or len(head[1]) >= cap:
            head = (a, [a.target])
            groups[host] = head
            heads.append(head)
            out.append(a)
        elif a.target not in head[1]:
            head[1].append(a.target)                   # replié sur la tête : l'action disparaît de la vague
    for action, targets in heads:
        if len(targets) > 1:
            action.params[BATCH_PARAM] = list(targets)
    return out


class _Retargeted:
    """Vue MINIMALE d'une action re-ciblée sur un membre du lot — juste ce que `tool_failed` lit
    (`.target`). Évite de muter l'action réelle (dont `.target` est la tête gatée par le ROE) pour
    émettre un finding d'échec au nom d'une AUTRE cible du lot."""

    __slots__ = ("target",)

    def __init__(self, target):
        self.target = target


@register("web.nuclei")
class NucleiScan(FlagAllowlistMixin, ScopeGuardMixin, Module):
    kind = "web.nuclei"
    exploit = False
    _refuse_category = "nuclei"                   # provenance du finding de refus (mixin) — inchangée
    _refuse_tool = "nuclei"
    mitre = techniques.mitre_for("web.nuclei")   # source de vérité : forge/techniques.py
    description = ("Scan de vulnérabilités par templates nuclei (info→critical par défaut, pour faire "
                   "remonter les expositions info/low : swagger/openapi, panels LLM, exposed-files). "
                   "Mutualisé PAR HÔTE (`-u a,b,c`) : une invocation, N cibles, chacune scope-guardée "
                   "et rendue individuellement. Params UI : severity (allow-listée), templates (-t), "
                   "tags (-tags), extra_args (allowlist).")
    BIN, IMG = "nuclei", "projectdiscovery/nuclei"
    available = property(lambda self: runner.available("nuclei", "projectdiscovery/nuclei", prefer_docker=True))
    _SEV = {"info": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
    _ALLOWED_SEV = ("info", "low", "medium", "high", "critical")
    # Défaut élargi à info,low pour faire remonter les EXPOSITIONS (swagger/openapi, panels LLM,
    # exposed-files) qu'un scan manuel voit et que le filtre medium+ masquait. AUCUNE inflation :
    # la sévérité du finding reste = sévérité RÉELLE du template (INFO template -> finding INFO, cf. _SEV).
    _DEFAULT_SEV = "info,low,medium,high,critical"
    #: taille MAX d'un lot. Borne le dépassement de timeout d'une invocation groupée ET la casse d'un
    #: tir raté (un lot qui échoue emporte AU PLUS `MAX_BATCH` cibles ; elles ressortent toutes en
    #: findings d'échec NOMMÉS, jamais en silence). 10 hôtes x <=25 cibles couvre la campagne mesurée.
    MAX_BATCH = 25
    #: budget d'un tir. `_TIMEOUT_BASE` seul pour UNE cible == la valeur historique (byte-identique) ;
    #: chaque cible SUPPLÉMENTAIRE d'un lot ajoute `_TIMEOUT_PER_TARGET`. Sans cet ajout, mutualiser
    #: échangerait des invocations contre des TIMEOUTS — un gain de temps payé en trous de couverture.
    _TIMEOUT_BASE = 600
    _TIMEOUT_PER_TARGET = 120
    # SCHÉMA servi à l'UI (source unique) — rendu dynamiquement par modules-form.js via `forge modules --json`.
    PARAMS_SCHEMA = [
        {"name": "severity", "type": "select", "label": "severity (filtre templates)", "flag": "-severity",
         "allowed": ["info", "low", "medium", "high", "critical"]},
        {"name": "templates", "type": "text", "label": "templates (-t, ex cves/ ou http/…)", "flag": "-t"},
        {"name": "tags", "type": "text", "label": "tags (-tags, ex cve,rce)", "flag": "-tags"},
        FlagAllowlistMixin.extra_args_param(),
    ]
    # ALLOWLIST des drapeaux acceptés en argument libre (extra_args) — tout flag hors liste est REFUSÉ.
    FLAG_ALLOWLIST = ("-severity", "-t", "-tags", "-etags", "-itags", "-rl", "-c", "-timeout",
                      "-retries", "-silent", "-jsonl", "-no-color", "-nc")

    def _severity(self, action):
        """Niveaux de sévérité (param UI/console `severity`), filtrés contre la liste blanche nuclei.

        PRÉCÉDENCE : param `severity` explicite (override, str CSV ou liste) > profil de ressources
        (`FORGE_RESOURCE_PROFILE`, levier `nuclei_severity`) > défaut-code info,low,medium,high,critical.
        `balanced` == le défaut -> profil non défini byte-identique ; `low` restreint aux templates lourds
        (medium,high,critical). Un param explicite INVALIDE (aucune sévérité connue) retombe sur le profil.
        La valeur de profil est RE-FILTRÉE contre l'allow-list nuclei — jamais d'élargissement de capacité :
        c'est un filtre de templates, pas une bascule ROE."""
        raw = action.params.get("severity")
        override = None
        if isinstance(raw, str):
            wanted = [s.strip().lower() for s in raw.split(",")]
            override = ",".join(s for s in wanted if s in self._ALLOWED_SEV) or None
        elif isinstance(raw, (list, tuple)):
            wanted = [str(s).strip().lower() for s in raw]
            override = ",".join(s for s in wanted if s in self._ALLOWED_SEV) or None
        resolved = resource_profile.resolve("nuclei_severity", override=override, default=self._DEFAULT_SEV)
        # filtre défensif : la valeur (profil comprise) reste allow-listée (fail-closed sur garbage).
        levels = [s.strip().lower() for s in str(resolved).split(",") if s.strip().lower() in self._ALLOWED_SEV]
        return ",".join(levels) if levels else self._DEFAULT_SEV

    def _batch(self, action):
        """(cibles RETENUES, [(cible, raison) REFUSÉES]) pour ce tir. FAIL-CLOSED.

        `action.target` est TOUJOURS la tête : c'est la seule cible passée par la gate ROE du moteur
        (scope + résolution + épinglage). Toute cible SUPPLÉMENTAIRE de `params['targets']` doit
        franchir QUATRE portes, chacune capable de la refuser SEULE :

          1. **périmètre injecté** — sans `in_scope`/`out_scope` dans les params, le scope-guard local
             serait PERMISSIF (`ScopeGuardMixin._scope`) : le lot ENTIER est alors refusé et le tir
             retombe sur la seule tête gatée par le ROE. C'est ce qui empêche qu'un lot devienne un
             contournement du scope-guard si le moteur oublie d'injecter le périmètre ;
          2. **scope-guard PAR CIBLE** — `_in_scope` une par une, jamais « la tête est in-scope donc
             le lot l'est » ;
          3. **même nom d'hôte que la tête** — le moteur n'épingle QUE `action.target` ; une cible d'un
             autre hôte se connecterait à une IP NON épinglée (fenêtre de rebinding) ;
          4. **argv-safe** — pas de virgule (elle fabriquerait une cible fantôme dans `-u a,b,c`),
             pas de `-` initial, pas d'espace ni de caractère de contrôle.

        Une cible refusée n'est jamais SUPPRIMÉE en silence : `fire()` en émet un finding `skipped`
        NOMMÉ (seau `unverified` du rapport = trou de couverture, pas du bruit).

        CINQUIÈME PORTE, ET ELLE N'EST PAS DE SÉCURITÉ : le BUDGET DE TEMPS restant, quand le moteur
        l'a posé (`ACTION_BUDGET_PARAM`). Voir `_fit_to_budget` — un lot trop gros pour le temps qui
        reste est RÉDUIT au plus grand qui tienne, jamais tronqué en vol."""
        head = action.target
        raw = (action.params or {}).get(BATCH_PARAM)
        if not isinstance(raw, (list, tuple)) or not raw:
            return [head], []                          # chemin historique : une cible, zéro refus
        enforce, _sc = self._scope(action)
        head_host = host_of(head)
        kept, rejected, seen = [head], [], {str(head)}
        for cand in raw:
            t = str(cand)
            if t in seen:
                continue
            seen.add(t)
            if not enforce:
                rejected.append((t, "lot refusé : aucun périmètre injecté — le scope-guard du module "
                                    "serait permissif (fail-closed)"))
            elif (reason := unsafe_batch_target(t)) is not None:
                rejected.append((t, reason))
            elif not self._in_scope(action, t):
                rejected.append((t, "hors périmètre (scope-guard par cible)"))
            elif host_of(t) != head_host:
                rejected.append((t, f"hôte '{host_of(t)}' != hôte épinglé '{head_host}' — "
                                    "l'épinglage IP du moteur ne couvre que la tête du lot"))
            else:
                kept.append(t)
        return self._fit_to_budget(action, kept, rejected)

    def _timeout_for(self, n_targets):
        """Borne DURE d'un tir pour `n_targets` cibles. UNE SEULE définition, lue par `fire()` (ce
        qu'on passe à `runner.tool`) ET par `max_runtime()` (ce qu'on ANNONCE au moteur) : les deux ne
        peuvent pas diverger, et c'est ce qui rend la gate de budget du moteur exacte plutôt
        qu'approximative."""
        return self._TIMEOUT_BASE + self._TIMEOUT_PER_TARGET * (max(1, int(n_targets)) - 1)

    def _fits(self, remaining):
        """Plus grand lot dont la borne `_timeout_for` tient dans `remaining` secondes — 0 si même une
        cible seule ne tient pas, None si aucun budget n'a été posé (-> aucune réduction)."""
        if remaining is None:
            return None
        try:
            r = float(remaining)
        except (TypeError, ValueError):
            return None
        if r != r:                                     # NaN -> pas d'information
            return None
        if r < self._TIMEOUT_BASE:
            return 0
        return 1 + int((r - self._TIMEOUT_BASE) // self._TIMEOUT_PER_TARGET)

    def _fit_to_budget(self, action, kept, rejected):
        """RÉDUIT le lot au plus grand qui tienne dans le budget de temps RESTANT, et NOMME chaque
        cible retirée. Le moteur ne DÉMARRE pas une action dont la borne dépasse le temps restant
        (`Engine._budget_gate`) : sans cette réduction, un lot de 17 URLs (borne 2520 s) serait écarté
        ENTIER dès qu'il reste moins de 42 min — 0 cible couverte. Avec, il en couvre 3 et DIT les 14
        autres. Mesuré sur le run du 2026-08-08 : c'est exactement la situation du tir fautif (946 s
        restants pour une borne de 2520 s).

        POURQUOI RÉDUIRE ET NON RABOTER LE TIMEOUT. Un tir raboté est TUÉ en vol : nuclei rend alors
        une sortie PARTIELLE, et toute cible qu'il n'a pas atteinte ressortait en `tested`/« aucun
        hit » — un verdict négatif FABRIQUÉ (15 sur 17 dans la reproduction du tir réel). Réduire le
        lot AVANT de lancer donne le même temps de calcul sans jamais mentir : ce qui est scanné l'est
        en entier, ce qui ne l'est pas est un `skipped` nommé.

        NO-OP STRICT sans budget posé (aucun param) : `kept`/`rejected` rendus tels quels."""
        cap = self._fits((action.params or {}).get(ACTION_BUDGET_PARAM))
        if cap is None or cap >= len(kept):
            return kept, rejected                      # pas de budget, ou le lot tient déjà
        # `cap == 0` (il reste moins que `_TIMEOUT_BASE`) : on garde quand même la TÊTE — le module ne
        # décide pas de renoncer, il ANNONCE au moteur la borne la plus PETITE qu'il puisse porter
        # (600 s). C'est le moteur qui écarte l'action entière (`Engine._budget_gate`), et son SKIP
        # nommé couvre alors toutes les cibles d'un coup : mieux qu'une borne de 2520 s annoncée pour
        # un lot qu'on n'aurait de toute façon pas lancé.
        keep = max(1, cap)
        left = float((action.params or {}).get(ACTION_BUDGET_PARAM))
        for t in kept[keep:]:
            rejected.append((t, f"lot réduit au budget de temps restant ({left:.0f}s) — {keep} cible(s) "
                                f"sur {len(kept)} tiennent dans une invocation "
                                f"({self._timeout_for(keep)}s) ; celle-ci n'a PAS été scannée"))
        return kept[:keep], rejected

    def max_runtime(self, action):
        """Borne DURE que ce module ANNONCE au moteur pour cette action (protocole optionnel lu par
        `Engine._runtime_bound`). C'est la borne du lot RÉELLEMENT retenu — réduction au budget
        comprise — donc exactement ce que `fire()` passera à `runner.tool`. Un module qui annonce
        moins qu'il ne prend rendrait la gate de budget mensongère ; la source unique
        (`_timeout_for`) et le `_batch()` partagé l'interdisent."""
        kept, _ = self._batch(action)
        return self._timeout_for(len(kept))

    def _args(self, action, targets=None):
        p = action.params or {}
        # `-u` de nuclei est un string[] : `-u a,b,c` charge N cibles pour UNE seule invocation
        # (donc UN seul chargement de templates). Une seule cible -> argv BYTE-IDENTIQUE à l'historique.
        argv = ["-u", BATCH_SEP.join(targets or [action.target]), "-severity", self._severity(action)]
        templates = p.get("templates")
        if templates is not None and safe_value(str(templates)):
            argv += ["-t", str(templates)]
        tags = p.get("tags")
        if tags is not None and safe_value(str(tags)):
            argv += ["-tags", str(tags)]
        try:                                              # débit -> -rl <n> (opt-in ; absent = rien)
            rl = int(p.get("rate"))
            if rl > 0:
                argv += ["-rl", str(rl)]
        except (TypeError, ValueError):
            pass
        _, extra = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)  # tokens VALIDÉS (fire gate en amont)
        argv += extra
        argv += ["-jsonl", "-silent", "-no-color"]
        return argv

    def dry(self, action):
        targets, _ = self._batch(action)
        return runner.cmdline(self.BIN, self.IMG, self._args(action, targets), prefer_docker=True)

    def _skipped(self, target, reason):
        """Finding `skipped` NOMMÉ pour une cible ÉCARTÉE du lot — jamais un silence. `skipped` la place
        dans le seau `unverified` du rapport (« je n'ai PAS pu vérifier »), qui est PROMU, pas replié."""
        return self.finding(
            target=target, title=f"nuclei: cible non scannée — {reason}", severity="INFO",
            category="nuclei", status="skipped", tool="nuclei",
            evidence=f"{reason}. Cible retirée du lot avant tout lancement (fail-closed).")

    def fire(self, action):
        if str(action.target).startswith("-"):
            return self._refuse(action, "cible positionnelle ambiguë (commence par '-')")
        if (refused := self.gate_extra_args(action)):     # extra_args gouvernés (mixin, fail-closed)
            return refused
        targets, rejected = self._batch(action)
        poc = runner.cmdline(self.BIN, self.IMG, self._args(action, targets), prefer_docker=True)
        # BUDGET PROPORTIONNEL : une invocation groupée fait le travail de N — lui laisser le budget
        # d'UNE seule échangerait des invocations contre des timeouts (== des trous de couverture).
        # MÊME SOURCE que ce que `max_runtime()` annonce au moteur (cf. `_timeout_for`).
        timeout = self._timeout_for(len(targets))
        rc, out, err = runner.tool(self.BIN, self.IMG, self._args(action, targets),
                                   timeout=timeout, prefer_docker=True)
        # PROPAGATION CROISÉE : si la sortie porte l'interstitiel, l'hôte est marqué CHALLENGED pour
        # les modules qui passeront après (miroir de `ExternalToolModule.fire`). Sans secret, scope-guardé.
        _blind.note_tool_output(action.target, out, err)
        # Parser stdout d'ABORD : nuclei peut sortir rc!=0 sur condition bénigne tout en ayant
        # émis du JSONL valide. On ne renvoie le finding d'échec QUE si aucune ligne ne parse.
        findings = []
        hit_surfaces = set()                              # SURFACES d'entrée (normalisées) ayant un hit
        for line in (out or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except ValueError:
                continue
            info = j.get("info", {})
            sev = self._SEV.get(str(info.get("severity", "info")).lower(), "INFO")
            matched = j.get("matched-at", action.target)
            # RÉ-ATTRIBUTION : le hit reste porté par SON `matched-at` (identique au mode non groupé) ;
            # l'attribution ne sert qu'à la COMPTABILITÉ DE COUVERTURE (quelle cible d'entrée a produit
            # quelque chose). Un hit non attribuable ne fait donc perdre AUCUN finding.
            if (owner := attribute_hit(matched, targets)) is not None:
                hit_surfaces.add(norm_target(owner))
            # Pas de sur-classement : un hit nuclei est signalé PAR L'OUTIL sur sa sévérité
            # auto-déclarée, sans preuve d'exploitabilité côté Forge. On conserve la sévérité
            # (priorisation) mais on émet `reported_by_tool` plutôt que `vulnerable` — la
            # promotion en `vulnerable` est réservée aux oracles à preuve (IDOR, origine vérifiée).
            findings.append(self.finding(
                target=matched,
                title=f"nuclei: {info.get('name', j.get('template-id', '?'))}",
                severity=sev, category=j.get("template-id", "nuclei"),
                mitre="", status="reported_by_tool" if sev in ("HIGH", "CRITICAL") else "tested",
                tool="nuclei", evidence=line[:1500], poc=poc))
        if not findings:
            failed = self.tool_failed(action, rc, out, err, "nuclei", category="nuclei")
            if failed:
                # L'ÉCHEC VAUT POUR TOUT LE LOT : chaque cible embarquée ressort avec SON finding
                # d'échec. Sans ça, mutualiser transformerait N tirs ratés VISIBLES en un seul —
                # les N-1 autres cibles disparaîtraient du rapport sans avoir été testées.
                out_f = [failed]
                for t in targets[1:]:
                    out_f.append(self.tool_failed(_Retargeted(t), rc, out, err,
                                                  "nuclei", category="nuclei"))
                # `tool_failed` rend un `tested` — « j'ai vérifié, rien trouvé » — même quand nuclei
                # ne s'est PAS LANCÉ. Mesuré dans `gxrun2` : « [FTL] Could not run nuclei: no
                # templates provided for scan », rc=1, ZÉRO octet sur stdout, et un finding `tested`
                # pour chaque cible du lot. Un scanner qui n'a pas démarré n'a rien vérifié.
                if _blind.tool_did_not_run(rc, out):
                    out_f = _blind.downgrade_did_not_run(out_f, rc)
                return out_f + [self._skipped(t, r) for t, r in rejected]
        # COUVERTURE PAR CIBLE, DÉMONTRABLE : chaque cible du lot SANS hit attribué ressort avec son
        # « aucun hit » — exactement la ligne qu'elle aurait produite seule. Le rapport ne peut donc pas
        # perdre une cible parce qu'elle a voyagé dans un lot.
        #
        # SAUF SI LE TIR A ÉTÉ TUÉ À SON MUR (rc=124, `runner.tool`). C'est un TROU MESURÉ, pas une
        # hypothèse : sur le run du 2026-08-08, le dernier lot (17 URLs, mur à 2520 s) a été tué à
        # 2521,68 s. nuclei avait DÉJÀ émis du JSONL, donc `findings` n'était pas vide, donc le
        # `tool_failed` ci-dessus n'a pas été atteint — et les 4 cibles jamais scannées sont sorties
        # en `tested` « aucun hit ». Un verdict négatif FABRIQUÉ, produit par la garantie même
        # (« couverture par URL démontrable ») qui prétendait l'empêcher. Reproduit à l'unité : 15
        # cibles sur 17 mentaient. Désormais une troncature rend un `skipped` NOMMÉ — « je n'ai pas
        # vérifié », qui va au seau `unverified` du rapport, jamais au seau « vérifié ».
        truncated = (rc == TIMEOUT_RC)
        for t in targets:
            if norm_target(t) in hit_surfaces:
                continue
            if truncated:
                findings.append(self._skipped(
                    t, f"scan TRONQUÉ — nuclei tué à son échéance de {timeout}s (rc=124) avant "
                       f"d'avoir rendu un verdict pour cette cible"))
            else:
                # « aucun hit » DERRIÈRE UN MUR ne veut pas dire « rien à trouver » : nuclei ne rend
                # ni code ni corps, il rend 0 résultat — INDISCERNABLE d'une cible saine. La preuve du
                # mur, elle, existe ailleurs : l'hôte est marqué CHALLENGED (par `Oracle._http`, par
                # `recon.httpx`, ou par un outil passé plus tôt) ou l'interstitiel figure dans la
                # sortie. On la lit ICI plutôt que d'affirmer une absence. 23 findings de `gxrun2`.
                # Le témoin est construit PAR CIBLE : l'état de franchissement est par-hôte, et une
                # cible saine n'en porte aucun -> `tested` inchangé.
                none_found = [self.finding(
                    target=t, title="nuclei: aucun hit", severity="INFO",
                    category="nuclei", status="tested", tool="nuclei", poc=poc)]
                findings += _blind.downgrade(_blind.tool_witness(t), none_found)
        return findings + [self._skipped(t, r) for t, r in rejected]

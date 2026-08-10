# SPDX-License-Identifier: AGPL-3.0-or-later
"""origin.find — trouver l'IP d'origine derrière un CDN/WAF.

Le gros levier : si l'origine réelle est joignable hors-Cloudflare, on contourne TOUT le WAF.
Pipeline : candidats d'hôtes (subfinder + PRÉFIXES PASSIFS révélateurs d'origine) → résolution DNS →
drop des IP en plage Cloudflare → VÉRIFICATION (httpx avec en-tête Host) que l'IP sert bien le site
AVANT de flaguer HIGH.

STRENGTHEN (reachability autorisée, méthodes PASSIVES / low-noise) : au-delà des sous-domaines de
subfinder, on ajoute une liste de PRÉFIXES couramment révélateurs de l'origine (`origin.`, `direct.`,
`cpanel.`, `mail.`, `dev.`, `staging.`…) + le domaine nu. Ce sont de simples CANDIDATS de chaînes
(génération hors-ligne, ZÉRO scan actif) résolus par le MÊME seam DNS (socket.gethostbyname) — donc
low-noise. Un IP hors-CF vers lequel PLUSIEURS hôtes convergent est un candidat d'origine plus solide
(compte de convergence dans l'evidence). Cela élargit la découverte sans bruit actif ni élargissement
de périmètre : chaque IP résolue reste RE-VALIDÉE fail-closed contre le scope avant toute connexion.

Ce module incarne le pattern d'or du moteur : « pas de finding sans preuve » (vérifier
l'exploitabilité avant d'élever la sévérité) → évite les findings aspirationnels. exploit=False (découverte). Réseau -> gaté par le ROE.

DÉGRADATION GRACIEUSE : subfinder indisponible/en échec (rc!=0) -> finding `status='skipped'`
(offline-safe), on ne tente PAS de résolution DNS passive à sa place (éviterait le seam et
frapperait le réseau réel). httpx indisponible/timeout sur une candidate -> finding `skipped`
(verif non concluante), jamais de faux HIGH.

SÛRETÉ — re-validation fail-closed du périmètre : un sous-domaine peut résoudre vers une IP
hors-scope (infra tierce/mutualisée/takeover). Le ROE gate le DOMAINE de l'action, pas les IP
résolues à runtime. AVANT chaque connexion httpx, on revérifie `Scope.is_in_scope(ip)` (le
scope est injecté dans action.params par l'engine, miroir de l'injection IDOR engine.py:130-134).
Une IP hors-scope -> finding INFO, AUCUNE connexion. Pas de scope dans les params -> fail-closed
(rien n'est en scope), on ne connecte pas : on n'élargit jamais le périmètre par omission.

BORNE DE DURÉE D'UN TIR — POURQUOI ELLE VIT ICI, ET POURQUOI C'EST L'ÉCHÉANCE QUI PORTE
---------------------------------------------------------------------------------------
Sur la campagne de référence (H1 public `kong`, 3 cibles, budget 3 600 s de mur), UN tir de ce
module a coûté **1 799 s** — 51 % du budget, 24 % de tout le travail mesuré. Module NATIF, donc
SANS `spec.timeout` : il ne déclarait AUCUNE borne, et `Engine._budget_gate` fail-open sans borne
déclarée. La part de budget par kind (`interrupt.KindShare`) le borne en RÉPÉTITION — jamais sur
son PREMIER débordement, qu'aucune mesure antérieure ne permet de prédire.

D'OÙ VENAIT LE TEMPS — MESURÉ, PAS SUPPOSÉ. Le rapport de ce tir porte **429 findings
`origin-exposure`, et les 429 sont « IP résolue HORS-SCOPE — connexion refusée »**. Cette branche
`continue` AVANT tout httpx, et la baseline de corrélation est PARESSEUSE (résolue au 1er candidat
in-scope, donc jamais ici) : **zéro requête httpx n'a été émise**. Le tir se décompose donc en
subfinder (≤ 120 s, borné) + la BOUCLE DE RÉSOLUTION DNS, séquentielle et bloquante, sur toute la
sortie de subfinder — soit ≥ 1 679 s de `socket.gethostbyname`.

CE QUI NE PORTE PAS : un PLAFOND SUR LE NOMBRE DE CANDIDATS. Il borne la boucle DNS (c'est le coût
observé ce jour-là) et rien d'autre : sur une cible dont les IP sont IN-SCOPE, les mêmes 429
candidates partent en vérification httpx à 30 s chacune — 12 870 s — et un plafond de 300 en
laisserait encore 9 000. La forme du travail décide de quel étage explose ; une borne qui ne
couvre qu'un étage ne borne donc pas le tir. Mesuré au banc `tests/bench_origin_bound.py`.

CE QUI PORTE : une ÉCHÉANCE GLOBALE DE TIR (`MAX_RUNTIME`), consultée à CHAQUE itération des DEUX
boucles et qui RABOTE le timeout de chaque sous-processus (subfinder comme httpx) au temps restant.
Elle est en outre DÉCLARÉE au moteur (`max_runtime()`, protocole lu par `Engine._runtime_bound`) —
même contrat que `web.nuclei` : ce qu'on annonce est EXACTEMENT ce que `fire()` peut prendre. Quand
le moteur pose le temps restant (`ACTION_BUDGET_PARAM`), l'échéance s'y ADAPTE au lieu d'être
écartée, exactement comme nuclei réduit son lot.

UN TIR COUPÉ NE FABRIQUE JAMAIS DE VERDICT. Ce qui n'a pas été résolu/vérifié ressort en `skipped`
NOMMÉ (« borne de durée atteinte »), et le constat d'ABSENCE « Aucune origine hors-CDN trouvée »
(`tested`) n'est émis QUE si rien n'a été coupé — c'est le défaut exact réparé sur les lots nuclei
tués à leur mur, où chaque cible non atteinte ressortait en « aucun hit ».

RÉSIDU NOMMÉ, PAS CORRIGÉ : la résolution CONSOMME l'échéance avant la vérification. Sur une
énumération assez large ET dont les IP sont in-scope, les 600 s peuvent partir ENTIÈREMENT en DNS et
aucune candidate n'est sondée (banc : forme `in-scope`, 480 résolutions, 0 httpx). Ce n'est pas un
verdict faux — les 429 candidates sortent en `skipped` COMPTÉES — mais c'est une perte de couverture
réelle. On ne pose PAS de réservation de temps pour l'étage de vérification : aucun tir observé n'a
cette forme (429/429 des IP du run de référence étaient HORS périmètre), et ce dépôt a déjà payé
plusieurs mécanismes ajoutés pour une forme jamais mesurée. À rouvrir le jour où un artefact la porte.
"""
import re
import socket
import time

from .registry import register, Module
from .. import runner
from ..interrupt import ACTION_BUDGET_PARAM
from ..roe import Scope
from .toolspec import FlagAllowlistMixin, check_extra_args, safe_value

# sous-ensemble des plages Cloudflare (dérive dans le temps — rafraîchir périodiquement)
CF_RANGES = [
    "104.16.0.0/12", "172.64.0.0/13", "131.0.72.0/22", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "173.245.48.0/20", "103.21.244.0/22", "141.101.64.0/18",
]

# Préfixes de sous-domaine couramment révélateurs de l'IP d'origine (bypass CDN). PASSIF : on ne fait
# que GÉNÉRER des noms d'hôtes candidats (résolus ensuite par le seam DNS) — aucun scan actif.
ORIGIN_PREFIXES = (
    "origin", "origin-www", "www-origin", "direct", "direct-connect", "cpanel", "whm",
    "webmail", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh", "vpn", "remote",
    "dev", "development", "staging", "stage", "test", "uat", "preprod", "old", "legacy",
    "backend", "api", "internal", "portal", "admin", "cdn-origin", "server", "host",
)


#: BORNE DURE de durée d'UN tir (s). C'est la valeur MAISON des modules qui portent une borne :
#: `ToolSpec.timeout` vaut 600 s pour nikto/testssl/wpscan/zap/sqlmap, et `web.nuclei._TIMEOUT_BASE`
#: vaut 600 s pour une cible. Un module natif qui n'annonçait RIEN annonce désormais la MÊME chose
#: qu'eux — 17 % d'un budget de référence de 3 600 s, au lieu des 51 % mesurés.
MAX_RUNTIME = 600
#: bornes des sous-processus (INCHANGÉES) — rabotées au temps restant dans l'échéance de tir.
SUBFINDER_TIMEOUT = 120
HTTPX_TIMEOUT = 30


class _Deadline:
    """Échéance MONOTONE d'un tir. Le temps passe par `time.monotonic` du module (`origin.time`),
    donc les tests l'INJECTENT au lieu de dormir. Pur, ne lève jamais."""

    def __init__(self, budget):
        self.budget = max(0.0, float(budget))
        self.end = time.monotonic() + self.budget

    def left(self):
        return self.end - time.monotonic()

    def expired(self):
        return self.left() <= 0

    def slice(self, want):
        """Timeout à passer à `runner.tool` : `want`, RABOTÉ au temps restant (jamais < 1 s — un
        timeout nul ferait tuer le process avant qu'il ne démarre). Appeler après `expired()`."""
        return max(1, int(min(float(want), max(0.0, self.left()))))


def _in_cf(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(c) for c in CF_RANGES)


def _passive_candidates(domain):
    """Hôtes candidats PASSIFS (génération de chaînes, ZÉRO réseau) : domaine nu + préfixes
    couramment révélateurs d'origine. Résolus ensuite via le même seam DNS (socket.gethostbyname)."""
    return [domain] + [f"{p}.{domain}" for p in ORIGIN_PREFIXES]


# M7 — corrélation de CONTENU. Un code de statut seul (surtout 403) ne prouve PAS qu'une IP sert le site :
# vhost par défaut, shared-hosting, WAF deny-by-default renvoient couramment 200/403 à un Host arbitraire.
# On EXIGE une corrélation de contenu positive (title normalisé identique à la baseline CDN) avant de
# promouvoir un finding en HIGH/vulnerable. Ces helpers parsent la sortie httpx (`-status-code -title`).
_HTTPX_BRACKET = re.compile(r"\[([^\]]*)\]")
_STATUS_RE = re.compile(r"\d{3}(?:,\d{3})*")


def _httpx_fields(text):
    """Extrait (status, title) de la 1re ligne httpx `-status-code -title -silent -no-color`
    (ex. `http://1.2.3.4 [200] [Example Domain]`). Le premier groupe `[...]` purement numérique est
    le statut (1er code si chaîne de redirections `[301,200]`) ; le premier groupe non numérique est le
    title. Champs absents -> chaînes vides. PURE, sans réseau."""
    raw = (text or "").strip()
    line = raw.splitlines()[0] if raw else ""
    status, title = "", ""
    for g in _HTTPX_BRACKET.findall(line):
        gg = g.strip()
        if not gg:
            continue
        if _STATUS_RE.fullmatch(gg):
            if not status:
                status = gg.split(",")[0]
        elif not title:
            title = gg
    return status, title


def _norm_title(t):
    """Normalise un title pour comparaison : espaces compactés + casefold. Vide -> ''."""
    return " ".join((t or "").split()).casefold()


@register("origin.find")
class OriginFind(FlagAllowlistMixin, Module):
    kind = "origin.find"
    exploit = False
    mitre = "T1590.005"
    description = ("Trouve l'IP d'origine derrière un CDN/WAF (subfinder + préfixes passifs → DNS → "
                  "drop-CF → vérif Host-header) — bypass WAF si l'origine est joignable. Params UI : "
                  "sources (-sources), timeout (-timeout), rate (-rl), extra_args (allowlist) — tunent subfinder.")
    SUB, SUB_IMG = "subfinder", "projectdiscovery/subfinder"
    HX, HX_IMG = "httpx", "projectdiscovery/httpx"

    # SCHÉMA servi à l'UI — tune l'énumération subfinder de l'étape 1. Rendu par modules-form.js.
    PARAMS_SCHEMA = [
        {"name": "sources", "type": "text", "label": "sources subfinder (-sources)", "flag": "-sources"},
        {"name": "timeout", "type": "number", "label": "timeout par source (-timeout s)", "flag": "-timeout"},
        {"name": "rate", "type": "number", "label": "rate-limit subfinder (-rl req/s)", "flag": "-rl"},
        FlagAllowlistMixin.extra_args_param(label="extra args subfinder (allowlist)"),
    ]
    # ALLOWLIST des drapeaux subfinder acceptés en argument libre — tout flag hors liste est REFUSÉ.
    # EXCLUS : -o/-oJ/-oD (écriture fichier), -config/-pc (lecture fichier de config/provider arbitraire).
    FLAG_ALLOWLIST = ("-all", "-recursive", "-nW", "-sources", "-rl", "-timeout", "-max-time", "-silent")

    @property
    def available(self):
        return (runner.available(self.SUB, self.SUB_IMG, prefer_docker=True)
                and runner.available(self.HX, self.HX_IMG, prefer_docker=True))

    def _subfinder_args(self, domain, params):
        """Argv subfinder de l'étape 1 : défaut `-d <domain> -silent` (BYTE-IDENTIQUE sans params) +
        knobs optionnels (sources/timeout/rate) + extra_args VALIDÉS (le gate fire() refuse en amont)."""
        p = params or {}
        argv = ["-d", domain, "-silent"]
        sources = p.get("sources")
        if sources is not None and safe_value(str(sources)):
            argv += ["-sources", str(sources)]
        timeout = p.get("timeout")
        if timeout not in (None, "") and safe_value(str(timeout)):
            argv += ["-timeout", str(timeout)]
        rate = p.get("rate")
        if rate not in (None, "") and safe_value(str(rate)):
            argv += ["-rl", str(rate)]
        _, extra = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)
        return argv + extra

    def _runtime_budget(self, action):
        """Budget de temps de CE tir (s) — SOURCE UNIQUE lue par `max_runtime()` (ce qu'on ANNONCE au
        moteur) ET par `_fire()` (l'échéance qu'on TIENT). Les deux ne peuvent donc pas diverger, et
        c'est ce qui rend la gate de budget du moteur exacte plutôt qu'approximative (même contrat que
        `NucleiScan._timeout_for`).

        `MAX_RUNTIME`, RABOTÉ au temps restant quand le moteur l'a posé (`ACTION_BUDGET_PARAM`) : le
        module S'ADAPTE au lieu d'être écarté en entier, comme nuclei réduit son lot. Aucun budget posé
        (appel programmatique, CLI sans `--run-timeout`) -> `MAX_RUNTIME`, donc rien ne change. Pur."""
        left = (action.params or {}).get(ACTION_BUDGET_PARAM)
        try:
            r = float(left)
        except (TypeError, ValueError):
            return float(MAX_RUNTIME)
        if r != r:                                        # NaN -> pas d'information -> borne pleine
            return float(MAX_RUNTIME)
        return max(0.0, min(float(MAX_RUNTIME), r))

    def max_runtime(self, action):
        """Borne DURE que ce module ANNONCE au moteur (protocole optionnel lu par
        `Engine._runtime_bound`). Un module natif n'en déclarait AUCUNE : la gate absolue ET la part
        de budget travaillaient donc à l'aveugle sur le tir le plus lourd du run de référence."""
        return self._runtime_budget(action)

    @staticmethod
    def _domain_of(target):
        """HÔTE de la cible (scheme/port/chemin/userinfo retirés) — `origin.find` énumère un DOMAINE,
        pas une URL. La cible peut arriver sous forme d'URL COMPLÈTE quand elle est CHAÎNÉE depuis un
        endpoint découvert : `subfinder -d <url>` et surtout `socket.gethostbyname(<url>)` n'ont alors
        aucun sens — et l'IDNA REFUSE tout label > 63 octets, ce qui a fait planter le module sur
        `https://…/cdn-cgi/challenge-platform/h/b/fo/<long token>` (UnicodeEncodeError('idna', …,
        'label too long') — une exception qui n'est PAS une OSError, donc non couverte par le
        `except OSError` de la boucle de résolution). Délègue à `Scope._host` (source unique de la
        canonicalisation d'hôte du moteur : aucune 2e implémentation à faire diverger). Pur."""
        return Scope._host(target)

    def dry(self, action):
        domain = self._domain_of(action.target) or action.target
        return (f"subfinder -d {domain} -silent + préfixes passifs (origin./direct./cpanel.…) "
                f"| resolve | drop-CF | httpx -H 'Host: {domain}' (vérifie l'origine avant flag HIGH)")

    def _skipped(self, action, title, evidence):
        """Dégradation gracieuse : outil (subfinder/httpx) ou réseau indisponible -> finding
        INFO `status='skipped'` (offline-safe), jamais de crash ni de faux positif."""
        return self.finding(
            target=action.target, title=title, severity="INFO", category="origin-exposure",
            mitre="T1590.005", status="skipped", tool="subfinder+httpx",
            evidence=(evidence or "")[:500], poc=self.dry(action))

    def _cut(self, action, deadline, unresolved, unverified):
        """Findings `skipped` NOMMÉS de ce que l'ÉCHÉANCE a coupé — un par étage coupé, aucun sinon.

        « Coupé » n'est PAS « vérifié » : chaque hôte non résolu / chaque candidate non vérifiée est
        un TROU DE COUVERTURE, et il est COMPTÉ. C'est la leçon des lots nuclei tués à leur mur, où
        les cibles jamais atteintes ressortaient en « aucun hit » — un verdict fabriqué."""
        out = []
        if unresolved:
            out.append(self._skipped(
                action, f"{self.kind} — borne de durée atteinte : {len(unresolved)} hôte(s) non résolu(s)",
                f"Échéance de tir ({deadline.budget:.0f}s) atteinte pendant la résolution DNS : "
                f"{len(unresolved)} nom(s) d'hôte candidat(s) n'ont PAS été résolus (ex. "
                f"{', '.join(unresolved[:5])}{' …' if len(unresolved) > 5 else ''}). Ils ne sont ni "
                f"testés ni innocentés — relancer avec plus de budget pour les couvrir."))
        if unverified:
            out.append(self._skipped(
                action, f"{self.kind} — borne de durée atteinte : {len(unverified)} candidate(s) non vérifiée(s)",
                f"Échéance de tir ({deadline.budget:.0f}s) atteinte pendant la vérification Host-header : "
                f"{len(unverified)} IP hors-CF n'ont PAS été sondées (ex. "
                f"{', '.join(ip for _s, ip in unverified[:5])}{' …' if len(unverified) > 5 else ''}). "
                f"Aucune conclusion n'est tirée sur elles."))
        return out

    def _refuse(self, action, reason):
        """Refus fail-closed du mixin, routé vers l'émetteur propre à origin (`_skipped` :
        category=origin-exposure, tool=subfinder+httpx, poc) — sortie BYTE-IDENTIQUE à l'ancien refus."""
        return [self._skipped(action, f"{self.kind} non exécuté — {reason}",
                              "Aucun processus lancé (fail-closed).")]

    def fire(self, action):
        """GARDE GÉNÉRIQUE — une exception au tir devient un `skipped` NOMMÉ, jamais une remontée brute.

        Le reste du moteur tient déjà ce contrat (chaque module dégrade en `status='skipped'` quand son
        outil/réseau lâche) ; `origin.find` y échappait par un chemin : la boucle de résolution ne
        rattrapait que `OSError`, et `socket.gethostbyname` lève un `UnicodeEncodeError` (IDNA, label
        > 63 octets) sur une cible URL. Sur 1573 tirs d'un run réel, c'était la SEULE exception remontée
        — devenue un `ERROR` opaque au lieu d'un « je n'ai pas pu vérifier » exploitable.

        La garde est ICI, pas dans l'engine : l'engine transforme déjà une exception de tir en
        `ExecResult(ERROR)` traçable (il ne PERD rien), mais un ERROR ne porte NI finding, NI statut
        `skipped`, donc il n'entre ni dans la mémoire de dédup ni dans le rapport de findings. Le rendre
        `skipped` ICI le fait apparaître LÀ OÙ ON LIT ce qui n'a pas été vérifié. `except Exception` est
        délibérément large : le contrat est « aucune exception ne sort du tir », pas « ces exceptions-là »."""
        try:
            return self._fire(action)
        except Exception as e:                            # noqa: BLE001 — contrat : rien ne sort brut du tir
            return [self._skipped(
                action, f"{self.kind} non exécuté — exception au tir ({type(e).__name__})",
                f"Exception CAPTURÉE pendant le tir sur {action.target!r} : {e!r}. "
                f"Dégradation gracieuse : non testé (aucun verdict aveugle).")]

    def _fire(self, action):
        # HÔTE, jamais l'URL : une cible chaînée depuis un endpoint découvert arrive sous forme d'URL
        # complète. Le pipeline (subfinder -d, socket.gethostbyname, en-tête Host) attend un NOM D'HÔTE.
        domain = self._domain_of(action.target)
        # EXTRA_ARGS gouvernés : un drapeau subfinder libre hors allowlist (ou non-liste) -> refus fail-closed.
        if (refused := self.gate_extra_args(action)):
            return refused
        if not domain:                                    # cible sans hôte exploitable -> jamais de tir aveugle
            return [self._skipped(action, f"{self.kind} non exécuté — cible sans hôte résoluble",
                                  f"Aucun nom d'hôte extractible de {action.target!r} "
                                  f"(aucun processus lancé, aucune résolution tentée).")]
        # Scope reconstruit depuis les params injectés par l'engine (miroir IDOR engine.py:130-134).
        # Quand le scope EST fourni (chemin de production : l'engine injecte TOUJOURS in_scope/out_scope),
        # on applique un filtre FAIL-CLOSED sur chaque IP résolue : in_scope vide => is_in_scope()==False
        # => aucune connexion. `enforce` distingue « scope fourni » de « module appelé en direct sans
        # scope » (dev/test) — le seul chemin qui touche le réseau est l'engine, qui injecte toujours.
        enforce = "in_scope" in action.params or "out_scope" in action.params
        guard = Scope({"in_scope": action.params.get("in_scope", []),
                       "out_scope": action.params.get("out_scope", [])})
        # ÉCHÉANCE DE TIR (cf. le bloc de doctrine en tête de module) — la MÊME valeur que celle
        # annoncée au moteur. Budget nul (le moteur n'a plus de temps) -> on ne lance RIEN.
        deadline = _Deadline(self._runtime_budget(action))
        if deadline.expired():
            return [self._skipped(action, f"{self.kind} non exécuté — borne de durée épuisée avant le tir",
                                  "Aucun processus lancé : le budget de temps restant est nul "
                                  "(non testé, pas « rien trouvé »).")]
        rc, out, err = runner.tool(self.SUB, self.SUB_IMG, self._subfinder_args(domain, action.params),
                                   timeout=deadline.slice(SUBFINDER_TIMEOUT), prefer_docker=True)
        # DÉGRADATION : subfinder indisponible/en échec -> skipped. On NE bascule PAS en résolution DNS
        # passive « à sa place » : cela frapperait le réseau réel hors du seam d'énumération (et
        # masquerait la panne). Le module se neutralise proprement (offline-safe).
        if rc != 0:
            reason = {127: "outil indisponible", 124: "timeout"}.get(rc, f"échec (rc={rc})")
            return [self._skipped(action, f"subfinder — {reason}",
                                  ((err or out) or "").strip() or reason)]
        subs = [s.strip() for s in (out or "").splitlines() if s.strip()] or [domain]

        # STRENGTHEN : fusionne les sous-domaines subfinder + les candidats PASSIFS révélateurs
        # d'origine (génération hors-ligne). Dédup des noms d'hôtes en préservant l'ordre (subfinder
        # d'abord). Chaque hôte est ensuite résolu par le seam DNS et re-validé fail-closed.
        hostnames, seen_h = [], set()
        for h in list(subs) + _passive_candidates(domain):
            h = h.strip().casefold()
            if h and h not in seen_h:
                seen_h.add(h)
                hostnames.append(h)

        # BOUCLE DE RÉSOLUTION — L'ÉTAGE QUI A EXPLOSÉ (≥ 1 679 s des 1 799 s mesurés) : séquentielle,
        # bloquante, sans timeout propre (`socket.gethostbyname` n'en accepte pas), sur TOUTE la sortie
        # de subfinder. L'échéance est consultée AVANT chaque résolution : ce qui reste est NOMMÉ.
        seen_ip, candidates, ip_sources = set(), [], {}
        unresolved = []
        for i, s in enumerate(hostnames):
            if deadline.expired():
                unresolved = hostnames[i:]
                break
            try:
                ip = socket.gethostbyname(s)
            except OSError:
                continue
            ip_sources.setdefault(ip, []).append(s)          # convergence : combien d'hôtes -> cet IP
            if ip in seen_ip or _in_cf(ip):
                continue
            seen_ip.add(ip)
            candidates.append((s, ip))

        # M7 — BASELINE CDN de corrélation de contenu : title du site tel que SERVI PAR LE CDN. Une IP
        # candidate n'est promue HIGH que si SON contenu (title) MATCHE cette baseline. Résolue PARESSEUSE-
        # MENT (None -> fetch au 1er candidat IN-SCOPE réellement vérifié) pour ne JAMAIS émettre de requête
        # si aucun candidat ne passe le scope-guard. Baseline vide/indisponible => aucune corrélation
        # possible => AUCUN HIGH (fail-closed : on préfère un faux négatif à un faux HIGH).
        base_title = None                                     # None = pas encore résolue (lazy)

        def _baseline_title():
            nonlocal base_title
            if base_title is None:
                if deadline.expired():                        # plus de temps -> pas de baseline -> AUCUN HIGH
                    base_title = ""
                    return base_title
                rcb, bo, _be = runner.tool(self.HX, self.HX_IMG,
                                           ["-u", f"http://{domain}", "-title", "-status-code",
                                            "-silent", "-no-color"],
                                           timeout=deadline.slice(HTTPX_TIMEOUT), prefer_docker=True)
                _bt = _httpx_fields(bo or "")[1] if rcb == 0 else ""
                base_title = _norm_title(_bt)
            return base_title

        findings = []
        unverified = []
        for s, ip in candidates:
            converge = len(ip_sources.get(ip, [s]))           # nb d'hôtes convergeant vers cet IP (confiance)
            # FAIL-CLOSED : l'IP résolue est-elle bien dans le périmètre autorisé ? Un sous-domaine
            # peut pointer vers de l'infra tierce/mutualisée -> on ne s'y connecte JAMAIS. Finding INFO,
            # on passe à la candidate suivante (jamais de httpx hors-scope).
            if enforce and not guard.is_in_scope(ip):
                findings.append(self.finding(
                    target=ip,
                    title="IP résolue HORS-SCOPE — connexion refusée (fail-closed)",
                    severity="INFO", category="origin-exposure", mitre="T1590.005",
                    status="tested", tool="subfinder",
                    evidence=(f"{s} -> {ip} hors du périmètre autorisé (in_scope) — "
                              f"aucune requête httpx émise (infra tierce/mutualisée possible)."),
                    poc=f"# {ip} hors-scope : ne pas connecter ; ajouter au scope si autorisé"))
                continue
            # SECOND ÉTAGE BORNÉ PAR LA MÊME ÉCHÉANCE : sur une cible dont les IP sont IN-SCOPE, c'est
            # LUI qui explose (429 candidates x 30 s = 12 870 s) — un plafond de candidats ne le borne
            # pas, l'échéance si (cf. le bloc de doctrine et `tests/bench_origin_bound.py`).
            #
            # LA GARDE EST *ICI*, PAS EN TÊTE DE BOUCLE, ET C'EST MESURÉ : le refus hors-scope
            # ci-dessus ne COÛTE RIEN (aucune requête). Le placer avant lui faisait perdre les 429
            # constats gratuits du tir de référence pour économiser 0 s — on ne borne que ce qui PAIE.
            # `continue` (et non `break`) : les candidates suivantes gardent leur constat gratuit.
            if deadline.expired():
                unverified.append((s, ip))
                continue
            # VÉRIFICATION avant flag : l'IP sert-elle le site avec l'en-tête Host ? On demande AUSSI le
            # title (`-title`) pour la corrélation de contenu M7.
            rc2, vo, ve = runner.tool(self.HX, self.HX_IMG,
                                      ["-u", f"http://{ip}", "-H", f"Host: {domain}",
                                       "-status-code", "-title", "-silent", "-no-color"],
                                      timeout=deadline.slice(HTTPX_TIMEOUT), prefer_docker=True)
            ip_status, ip_title = _httpx_fields(vo or "")
            # M7 — 403 RETIRÉ du set « joignable » (un WAF deny-by-default le renvoie à tout Host : jamais
            # une preuve). Seuls 200/301/302 comptent comme joignables.
            reachable = ip_status in ("200", "301", "302")
            # M7 — CORRÉLATION DE CONTENU : promotion HIGH SEULEMENT si le title de l'IP MATCHE la baseline
            # CDN (non vide des deux côtés). Un match de statut seul ne suffit plus.
            base = _baseline_title()
            content_ok = bool(base) and _norm_title(ip_title) == base
            verified = reachable and content_ok
            reachable_only = reachable and not content_ok      # joignable mais contenu NON corrélé
            # Distinguer l'échec d'outil (httpx indisponible/timeout) d'un vrai négatif : un rc2!=0
            # sans statut joignable n'est PAS la preuve que l'origine ne sert pas le site — pas de HIGH.
            # DÉGRADATION : verif non concluante par outil indisponible -> `status='skipped'`.
            tool_ko = (rc2 != 0 and not reachable)
            if verified:
                sev, st = "HIGH", "vulnerable"
                title = "Origine exposée derrière CDN (VÉRIFIÉE, contenu corrélé) — bypass WAF"
            elif reachable_only:
                # joignable mais aucune corrélation de contenu -> NE PAS promouvoir en HIGH (M7). MEDIUM :
                # piste à confirmer manuellement (vhost par défaut / shared-hosting / WAF non exclus).
                sev, st = "MEDIUM", "tested"
                title = "IP hors-CDN joignable — contenu NON corrélé à la baseline (origine NON confirmée)"
            elif tool_ko:
                sev, st = "INFO", "skipped"
                title = "IP hors-CDN — verif non concluante: httpx indisponible/timeout"
            else:
                sev, st = "INFO", "tested"
                title = "IP hors-CDN (origine non confirmée)"
            findings.append(self.finding(
                _proven=bool(verified),                  # PREUVE concrète (statut joignable + contenu corrélé)
                target=ip,
                title=title,
                severity=sev,
                category="origin-exposure", mitre="T1590.005",
                fix=("Restreindre l'accès à l'IP d'origine au seul CDN/WAF : allowlist des plages IP du "
                     "fournisseur (ex: Cloudflare) au niveau pare-feu/groupe de sécurité et refuser tout "
                     "trafic direct, afin de rendre l'origine non joignable hors du CDN (et de fermer le "
                     "contournement de WAF)."),
                status=st,
                tool="subfinder+httpx",
                evidence=(f"{s} -> {ip} (convergence: {converge} hôte(s)) ; statut={ip_status or 'n/a'} "
                          f"joignable={reachable} ; title-match baseline={content_ok} "
                          f"(ip_title={ip_title!r}) ; "
                          + (f"verif non concluante (rc={rc2}): {((ve or vo) or '').strip()[:160]}"
                             if tool_ko else (vo or "").strip()[:160])),
                poc=f"curl -sI -H 'Host: {domain}' http://{ip}"))
        # CE QUE LA BORNE A COUPÉ — `skipped` NOMMÉ, jamais un verdict. Émis AVANT le constat d'absence
        # ci-dessous, qui devient donc inatteignable dès qu'un étage a été coupé : un tir tronqué ne
        # peut PAS ressortir en « Aucune origine hors-CDN trouvée » (`tested`).
        findings += self._cut(action, deadline, unresolved, unverified)
        if not findings:
            findings.append(self.finding(
                # `action.target` (et non l'hôte canonicalisé) : la cible du finding reste EXACTEMENT
                # celle de l'action — le nœud du graphe/la dédup ne bougent pas d'un iota.
                target=action.target, title="Aucune origine hors-CDN trouvée", severity="INFO",
                category="origin-exposure", status="tested", tool="subfinder+httpx", poc=self.dry(action)))
        return findings

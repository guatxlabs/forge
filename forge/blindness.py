# SPDX-License-Identifier: AGPL-3.0-or-later
"""CÉCITÉ CONSTATÉE — « je n'ai pas pu vérifier » ne doit JAMAIS s'écrire « j'ai vérifié, rien trouvé ».

CE QUI A ÉTÉ MESURÉ (campagne `gxrun2`, ledger signé de 11 Mo, infra de production autorisée
entièrement derrière un tunnel Cloudflare — aucun service sur 80/443, les 7 hôtes rendent un
interstitiel de défi à tout client HTTP) :

  - **4 839 findings `tested`** ont été émis alors que le moteur n'a JAMAIS vu une seule page de
    l'application. `tested` signifie « j'ai vérifié, rien trouvé » : un mur a donc produit des
    milliers d'AFFIRMATIONS DE NON-VULNÉRABILITÉ sur des cibles jamais regardées. C'est la forme la
    plus dangereuse du faux négatif — elle RESSEMBLE à de la couverture.
  - La garde existait pourtant déjà (`clearance.response_is_challenge`, câblée dans
    `clientflow._challenge_degraded`). Elle N'A PAS TIRÉ : `cache_poisoning.probe` et
    `header_injection.probe`, qui la portent, ont rendu **49 `tested` chacun** sur les hôtes que
    `curl` voyait répondre `403 cf-mitigated: challenge`, et **ZÉRO dégradation**.

POURQUOI ELLE N'A PAS TIRÉ — LA CAUSE RACINE, NOMMÉE
----------------------------------------------------
`Oracle._http` **JETTE le corps** sur `HTTPError` (`return e.code, "", e.headers`). Or l'interstitiel
Cloudflare — 5 229 octets de « Just a moment… » + `/cdn-cgi/challenge-platform`, la signature la plus
fiable qui soit, celle que `httpx` a enregistrée 19 fois dans ce même ledger — vit EXACTEMENT là. La
détection n'avait donc plus qu'une voie, l'en-tête `cf-mitigated` ; et cet en-tête, vu par `curl` en
HTTP/2, n'a démontrablement PAS atteint le chemin urllib (HTTP/1.1) : d'où les 49 + 49 `tested`.
La signature était sur la table, jamais servie.

CE QUE FAIT CE MODULE
---------------------
Un TÉMOIN par action (thread-local, exactement le patron de `throttle`/`session`/`pin`), alimenté au
CHOKEPOINT où la réponse ENTRE dans l'oracle (`Oracle._http`), et lu une seule fois à la frontière de
`fire()`. Deux compteurs, rien d'autre :

  - `challenges` : réponses portant une signature EXPLICITE de défi managé ;
  - `contents`   : réponses PROUVANT que l'application a été vue (`clearance.reach_is_content`).

Verdict d'AVEUGLEMENT (`blind()`) = `challenges > 0 ET contents == 0` : « un mur s'est interposé, et
je n'ai vu l'application à AUCUN moment de cette action ».

LA LIGNE À NE PAS FRANCHIR — pourquoi la conjonction, et pas moins
------------------------------------------------------------------
Le seul acquis solide du dépôt, sur deux campagnes réelles, est le **ZÉRO faux positif**. Ce chantier
peut le détruire dans les deux sens, et les deux bornes sont ici :

  1. `challenges > 0` exige une signature EXPLICITE (`clearance.response_is_challenge` : en-tête
     `cf-mitigated`/DataDome, ou interstitiel dans le corps) — JAMAIS un simple code de statut. Un
     **401/403 NU reste un verdict applicatif** : c'est le signal NORMAL d'un contrôle d'accès qui
     fonctionne, et c'est précisément ce qu'un oracle IDOR doit pouvoir juger. Confondre les deux
     rendrait forge aveugle à sa classe de vulnérabilité la plus payante.
  2. `contents == 0` : si UNE SEULE réponse de l'action a prouvé qu'on voyait l'application, l'oracle
     n'était PAS aveugle et son verdict est GARDÉ INTACT — même si une autre sonde a tapé un mur.
     Sans cette borne, un différentiel d'autorisation dont un seul côté est filtré par le WAF perdrait
     un verdict parfaitement valide.

Résiduel ASSUMÉ et NOMMÉ : un mur SANS signature (la règle d'edge `www` -> apex qui rend `301` corps
vide, mesurée sur `www.guatx.com`) reste indétectable ici — un `3xx` nu est trop ambigu pour taire un
oracle. `reach_is_content` refuse déjà d'y voir une réussite ; c'est au franchissement
(`evasion`/`clearance`) de l'ouvrir, pas à ce témoin de le deviner.

LE SECOND LOT — LES OUTILS EXTERNES, OÙ LA SIGNATURE N'ARRIVE JAMAIS
--------------------------------------------------------------------
Le témoin ci-dessus se nourrit de `Oracle._http` : un code, un corps, des en-têtes. **2 553 des
4 839 `tested` ne passent PAS par là** — ce sont des sorties d'outils externes (`runner.tool`) et de
modules de surface. Le problème y est de NATURE différente, et c'est ce qui rend le premier remède
inapplicable tel quel : un outil ne rend qu'un **rc et du texte**. Derrière un mur, nuclei ne dit pas
« challenge » — il dit **0 résultat**, ce qui est INDISCERNABLE d'une cible saine. La signature
n'arrive jamais jusqu'à la décision.

CE QUE LA MESURE A RÉELLEMENT MONTRÉ (décompte des 2 553, cf. `tests/test_blindness_tools.py`) —
« ils concluent tous sur un mur » est FAUX pour 96 % d'entre eux :

  - 1 594 sont des **OBSERVATIONS**, pas des verdicts : une ligne de sortie = un finding
    (`curl: cf-mitigated: challenge`, `nuclei: WAF Detection`, `WAF/CDN identifié : Cloudflare`).
    Elles ne prétendent RIEN sur l'absence de vulnérabilité — elles CONSIGNENT ce que le mur a
    répondu. Les déclasser détruirait la preuve MÊME de l'existence du mur, et noierait le seau
    `unverified` du rapport sous 1 594 entrées. **Intouchables.**
  - 669 jugent AUTRE CHOSE que du HTTP : `dig`/`dnsx`/`subfinder` jugent du DNS, `naabu`/`masscan`/
    `nmap` jugent des PORTS, `crt.sh`/Wayback interrogent des TIERS. Un interstitiel HTTP ne les
    aveugle pas. **Intouchables.**
  - 205 n'émettent AUCUN paquet (avis de catalogue `network.smb`/`network.ssh`, module `demo`,
    intercept sans params). C'est le piège du premier lot (1 750 `skip()` sans réseau) sous un autre
    nom : compter ces 205 comme « conclusions sur un mur » aurait faussé tout le chiffrage.
  - **105 seulement** sont de VRAIES affirmations d'absence rendues alors qu'un mur s'était
    interposé (`nuclei: aucun hit` 23, `evasion.discover — aucun endpoint` 23, zap-baseline 16,
    curl 17, `recon.js_endpoints` 24, katana 2).
  - **251 de plus** — DÉCOUVERTES par cette mesure, et plus nombreuses que le mur lui-même — sont
    des affirmations d'absence rendues alors que **l'outil n'a jamais tourné** : `gobuster rc=1
    "invalid value for flag -d"`, `masscan rc=1 "unknown command-line parameter"`, `dnsx rc=1
    "missing wordlist flag"`, `theHarvester rc=125 "pull access denied"`. Un argv faux ou une image
    docker absente ressortait en « j'ai vérifié, rien trouvé ». Même maladie, cause différente.

OÙ L'INFORMATION SURVIT ENCORE (on ne devine pas — on RÉUTILISE)
----------------------------------------------------------------
  1. **L'état `CHALLENGED` du `SessionStore`** — celui que le PREMIER LOT alimente désormais depuis
     `Oracle._http`, et que `recon.httpx` (qui a vu le `403 / "Just a moment…"` **19 fois** dans ce
     même ledger, AVANT tout autre outil) sème maintenant lui aussi. C'est la voie principale : elle
     ne coûte aucune requête et son verdict a DÉJÀ exigé une signature explicite pour être posé.
  2. **La sortie de l'outil lui-même** — `curl -i` DÉVERSE l'interstitiel et l'en-tête
     `cf-mitigated`. L'outil qui voit le mur le SIGNALE donc au store (`note_tool_output`), et les
     outils qui passent APRÈS en bénéficient. C'est la propagation croisée qui manquait.

LA MÊME BORNE, PAS UNE PLUS LARGE. `challenge.looks_like_challenge` traite tout 403/429/503 comme un
défi : c'est un bon signal pour BASCULER la recon, et un très mauvais pour taire un verdict. On
n'utilise donc ICI AUSSI que `clearance.response_is_challenge` (en-tête de défi OU interstitiel dans
le corps) — **un 403 NU reste un verdict applicatif**. Et la contre-preuve du premier lot
(`contents == 0`, « qui a vu la cible garde son verdict ») est conservée sous une forme PLUS FORTE :
STRUCTURELLE. Les seuls points d'appel de l'abstention sont les branches d'ABSENCE, atteintes
uniquement quand AUCUN hit n'a survécu ; un outil qui a produit quoi que ce soit est déjà reparti
avec ses findings intacts, sans qu'aucun témoin n'ait été construit.

DEUXIÈME BORNE, PROPRE À CE LOT — **`speaks_http`** (cf. `toolspec.ToolSpec`). Un défi managé aveugle
ce qui parle HTTP, et rien d'autre. Au premier rejeu du corpus, l'abstention posée sur l'état de
l'hôte a fait taire **53 constats valides** (`dig` 12, `subfinder` 18, `gobuster` 23) : des verdicts
DNS et OSINT qu'un interstitiel n'aveugle pas. Le discriminant est dérivé de l'argv du spec, pas
d'une liste tenue à la main.

SECRET : ce module ne retient QUE des compteurs, des codes de statut et des hostnames. Jamais une
valeur de cookie, jamais un en-tête d'authentification, jamais un fragment de corps.
"""
import threading

from . import clearance as _clearance
from . import session as _session

_state = threading.local()

_MAX_HOSTS = 6                   # borne de l'évidence (des noms d'hôtes, pas un inventaire)
# Prélèvement BORNÉ de la sortie d'un outil pour y CHERCHER une signature de défi. Une sortie d'outil
# peut peser des mégaoctets (nuclei/zap) ; l'interstitiel, lui, tient dans ses premiers octets. On
# regarde donc la TÊTE et la QUEUE (une erreur de transport arrive en fin de flux), jamais le milieu.
_MAX_OUTPUT_PEEK = 8192


class Witness:
    """Compteurs d'une SEULE action. Ne lève jamais : une entrée hostile est comptée comme « rien vu »."""

    __slots__ = ("responses", "challenges", "contents", "hosts", "statuses")

    def __init__(self):
        self.responses = 0
        self.challenges = 0
        self.contents = 0
        self.hosts = []              # hostnames challengés (ordre stable, bornés) — AUCUN secret
        self.statuses = []           # codes de statut challengés (bornés)

    def note(self, status, body="", headers=None, host=""):
        """Enregistre UNE réponse entrée dans l'oracle. Retourne True si elle porte une signature
        EXPLICITE de défi managé (l'appelant s'en sert pour propager l'état au store gouverné)."""
        self.responses += 1
        try:
            challenged = _clearance.response_is_challenge(status, body, headers)
        except Exception:            # noqa: BLE001 (entrée hostile : jamais d'exception au chokepoint)
            challenged = False
        if challenged:
            self.challenges += 1
            h = str(host or "")
            if h and h not in self.hosts and len(self.hosts) < _MAX_HOSTS:
                self.hosts.append(h)
            if len(self.statuses) < _MAX_HOSTS:
                self.statuses.append(status)
            return True
        try:
            if _clearance.reach_is_content(status, body, headers):
                self.contents += 1
        except Exception:            # noqa: BLE001
            pass
        return False

    def blind(self):
        """L'action s'est-elle déroulée DERRIÈRE un mur, sans jamais voir l'application ?
        Conjonction STRICTE (cf. les deux bornes en tête de module)."""
        return self.challenges > 0 and self.contents == 0

    def why(self):
        """Explication SÛRE (compteurs + statuts + hostnames) pour l'évidence d'un finding."""
        hosts = ", ".join(self.hosts) or "—"
        codes = ", ".join(str(s) for s in self.statuses) or "—"
        return (f"{self.challenges}/{self.responses} réponse(s) portaient une signature de défi managé "
                f"(HTTP {codes} sur {hosts}) et AUCUNE n'a prouvé que l'application était visible")


# Préfixe d'évidence apposé à un finding DÉCLASSÉ : il NOMME le mur et ce que le statut veut dire.
DOWNGRADE_PREFIX = (
    "NON VÉRIFIÉ — un challenge/WAF managé s'est interposé : {why}. Ce constat ne vient donc PAS de "
    "l'application mais du mur, et il ne peut RIEN affirmer ; le statut passe de `tested` "
    "(« j'ai vérifié, rien trouvé ») à `skipped` (« je n'ai pas pu vérifier »). Router le "
    "franchissement (`evasion.turnstile`/`evasion.discover` récoltent la clearance vers la session "
    "gouvernée), puis rejouer. Constat d'origine, conservé tel quel ci-dessous : ")


def downgrade(witness, findings):
    """Déclasse `tested` -> `skipped` les findings d'une action rendue AVEUGLE. Rend `findings` (muté
    en place : `Finding` est une dataclass mutable, et rien d'autre que le statut/l'évidence ne change
    — cwe/fix/CVSS déjà dérivés restent EXACTS).

    Ne touche JAMAIS :
      - un `vulnerable` : une PREUVE obtenue reste une preuve, on ne supprime pas un positif ;
      - un `skipped` déjà posé (idempotent) ni aucun autre statut ;
      - quoi que ce soit si l'action n'était pas aveugle (`blind()` False) -> retour à l'identique,
        BYTE pour BYTE. C'est ce qui garantit que les tests hors-mur restent inchangés.
    Ne lève jamais (une liste hostile est rendue telle quelle)."""
    if witness is None or not witness.blind():
        return findings
    why = witness.why()
    try:
        for f in findings or []:
            if getattr(f, "status", None) != "tested":
                continue
            f.status = "skipped"
            f.evidence = DOWNGRADE_PREFIX.format(why=why) + (getattr(f, "evidence", "") or "")
    except Exception:                # noqa: BLE001 (jamais d'exception au retour d'un fire())
        return findings
    return findings


def current():
    """Témoin lié au thread courant, ou None (hors contexte -> aucun suivi). Ne lève jamais."""
    return getattr(_state, "witness", None)


def note(status, body="", headers=None, host=""):
    """Enregistre une réponse sur le témoin courant. **No-op strict hors contexte** (dev/test/appel
    direct de `Oracle._http`) : retourne False sans rien faire. Ne lève jamais."""
    w = current()
    if w is None:
        return False
    return w.note(status, body, headers, host)


class using:
    """Lie un témoin le temps d'un `fire()`. RÉENTRANT PAR RÉUTILISATION : si un témoin est déjà lié
    (oracle imbriqué), on rend CELUI-LÀ au lieu d'en créer un second — les sondes de l'appel interne
    sont ainsi comptées dans l'action englobante, et le déclassement se décide sur la vue COMPLÈTE de
    l'action (jamais sur une vue partielle, qui pourrait déclarer aveugle un oracle qui a vu la cible
    par un autre chemin). `owned` dit à l'appelant s'il est PROPRIÉTAIRE du témoin : seul le
    propriétaire déclasse, un appel imbriqué ne juge jamais sur une vue partielle."""

    def __init__(self):
        self.owned = current() is None
        self.witness = Witness() if self.owned else current()

    def __enter__(self):
        if self.owned:
            self.prev = getattr(_state, "witness", None)
            _state.witness = self.witness
        return self.witness

    def __exit__(self, *a):
        if self.owned:
            _state.witness = self.prev
        return False


# =================================================================================================
#  BRAS « OUTIL EXTERNE » — un rc et du texte, jamais une réponse HTTP structurée
#
#  Aucune de ces fonctions ne fait de réseau, n'alloue de témoin thread-local, ni ne lève. Elles ne
#  décident RIEN toutes seules : elles ne sont appelées qu'aux points d'émission d'un constat
#  d'ABSENCE, atteints uniquement quand aucun hit n'a survécu. La contre-preuve du premier lot
#  (`contents == 0`) est donc portée par la STRUCTURE du site d'appel, pas par un drapeau qu'on
#  pourrait oublier de passer.
# =================================================================================================
def _peek(text):
    """Tête + queue BORNÉES d'une sortie d'outil (l'interstitiel vit en tête ; une erreur de
    transport arrive en queue). Rend '' pour toute entrée illisible. Ne lève jamais."""
    try:
        s = str(text or "")
    except Exception:            # noqa: BLE001 (entrée hostile)
        return ""
    if len(s) <= 2 * _MAX_OUTPUT_PEEK:
        return s
    return s[:_MAX_OUTPUT_PEEK] + s[-_MAX_OUTPUT_PEEK:]


# --- Signatures admissibles DANS LA SORTIE D'UN OUTIL (sous-ensemble STRICT de la liste de `challenge`)
#
# POURQUOI PLUS ÉTROIT QUE POUR UN CORPS DE RÉPONSE. `challenge.CHALLENGE_BODY_SIGNATURES` juge un
# CORPS : un corps qui contient « datadome » est un corps servi par DataDome. Une sortie d'OUTIL, elle,
# est un texte de scanner — et un scanner NOMME les fournisseurs qu'il détecte. Sur une cible
# parfaitement SAINE, `nuclei` émet des templates comme « WAF Detection » ou « Cloudflare Turnstile
# detect », et `wafw00f` écrit le nom du WAF : retenir « turnstile » ou « datadome » comme preuve de
# mur ferait taire les verdicts d'une cible qui répond très bien. C'est EXACTEMENT l'excès inverse que
# ce chantier doit éviter.
#
# Ne restent donc que les chaînes qui n'apparaissent QUE dans une réponse de défi RÉELLEMENT servie :
# un chemin d'orchestration d'edge, un en-tête de mitigation, le titre/le texte de l'interstitiel.
# Aucune n'est un nom de produit. `test_blindness_tools` VERROUILLE l'inclusion dans la liste amont
# (une renommée en amont casse le test au lieu de rendre la détection silencieusement inerte).
_TOOL_OUTPUT_SIGNATURES = (
    "/cdn-cgi/challenge-platform",   # URL d'orchestration servie DANS l'interstitiel Cloudflare
    "cf-mitigated",                  # en-tête de réponse posé par la mitigation (jamais un nom de produit)
    "__cf_chl",                      # cookie/paramètre du flux de défi
    "cf_chl_opt",                    # objet JS injecté dans l'interstitiel
    "just a moment",                 # titre de l'interstitiel Cloudflare
    "checking your browser",         # variante historique du même interstitiel
    "captcha-delivery",              # hôte de livraison du défi DataDome (pas le nom « datadome »)
    "please enable javascript and cookies",          # texte de l'interstitiel
    "please stand by, while we are checking",        # texte de l'interstitiel
)


def output_is_challenge(stdout="", stderr=""):
    """La sortie d'un outil porte-t-elle une signature EXPLICITE de défi managé RÉELLEMENT SERVI ?

    Pas de code de statut : la sortie d'un outil n'EST pas une réponse HTTP, et un « 403 » qui traîne
    dans du texte ne doit RIEN faire taire. Pas de nom de fournisseur non plus (cf.
    `_TOOL_OUTPUT_SIGNATURES`) : un scanner NOMME les WAF qu'il détecte sur des cibles saines. Ne
    reste que l'interstitiel lui-même — ce que `curl -i` a déversé 7 fois dans le ledger `gxrun2`.
    Pur, ne lève jamais."""
    try:
        low = (_peek(stdout) + "\n" + _peek(stderr)).lower()
    except Exception:            # noqa: BLE001 (entrée hostile)
        return False
    return any(sig in low for sig in _TOOL_OUTPUT_SIGNATURES)


def note_tool_output(target, stdout="", stderr="", store=None):
    """PROPAGATION CROISÉE : un outil dont la sortie DÉVERSE l'interstitiel (c'est le cas de
    `curl -i`, qui a consigné `cf-mitigated: challenge` 7 fois dans le ledger `gxrun2`) MARQUE l'hôte
    `CHALLENGED` dans le store gouverné. Les outils qui passent APRÈS — nuclei, zap-baseline, katana —
    n'ont alors plus besoin de redécouvrir le mur : ils LISENT l'état.

    C'est la voie de propagation qu'`Oracle._http` alimente déjà côté urllib (`oracle._witness`) ;
    ici c'est son pendant côté `runner.tool`. Scope-guardé et SANS SECRET par construction : le store
    refuse tout hôte hors périmètre et ne retient qu'un hostname et un mot.

    Retourne True si l'état a été posé. No-op strict hors moteur (aucun store lié). Ne lève jamais."""
    if not output_is_challenge(stdout, stderr):
        return False
    st = store if store is not None else _session.current()
    if st is None:
        return False
    try:
        return bool(st.mark_challenged(str(target or "")))
    except Exception:            # noqa: BLE001 (le suivi ne doit jamais avorter une action)
        return False


class ToolWitness:
    """Témoin d'UNE exécution d'outil externe — l'analogue de `Witness` quand il n'y a ni code, ni
    corps, ni en-têtes à compter.

    UN SEUL FAIT, ET C'EST VOULU : `challenged` — « un défi managé est constaté sur cet hôte ». La
    preuve, elle, a été établie AILLEURS et une seule fois : l'interstitiel qu'un outil déverse est
    versé à l'état de franchissement par `note_tool_output`, exactement comme `Oracle._http` y verse
    ce qu'il voit. Le témoin LIT cet état ; il ne re-juge pas la sortie. Une seule route, donc un
    seul endroit à auditer — et pas de second chemin qui pourrait diverger du premier.

    LA CONTRE-PREUVE DU PREMIER LOT (`contents == 0` : « qui a vu la cible garde son verdict ») n'est
    PAS un champ ici, elle est STRUCTURELLE et c'est plus fort : les deux seuls points d'appel sont
    les branches d'ABSENCE, atteintes uniquement quand aucun hit n'a survécu. Un outil qui a produit
    ne serait-ce qu'un résultat est déjà reparti avec ses findings intacts, sans jamais construire de
    témoin. `TestObservationsAreNeverDowngraded` verrouille cette propriété."""

    __slots__ = ("host", "challenged")

    def __init__(self, host="", challenged=False):
        self.host = str(host or "")
        self.challenged = bool(challenged)

    def blind(self):
        return self.challenged

    def why(self):
        """Explication SÛRE (hostname + provenance), sans un octet de la sortie de l'outil."""
        return (f"l'outil n'a produit AUCUN résultat sur {self.host or '—'} alors que cet hôte est "
                f"marqué CHALLENGED dans le périmètre gouverné (défi managé constaté et non franchi)")


def tool_witness(target, store=None):
    """Témoin de cécité d'une exécution d'outil externe sur `target`. À appeler UNIQUEMENT au point
    d'émission d'un constat d'ABSENCE.

    La preuve du mur est EXPLICITE et vient de l'état `CHALLENGED` du store — jamais d'un code de
    statut. Cet état n'est posé que par des chemins qui ont déjà exigé une signature explicite :
    `Oracle._http` (premier lot), `recon.httpx`, `recon_surface._http_get`, et `note_tool_output`
    pour l'outil qui déverse l'interstitiel. Hors moteur (aucun store lié) le témoin n'est JAMAIS
    aveugle -> comportement historique préservé pour tout appel direct/dev/test. Ne lève jamais."""
    st = store if store is not None else _session.current()
    if st is None:
        return ToolWitness(host=str(target or ""), challenged=False)
    try:
        challenged = st.clearance_state(str(target or "")) == st.CHALLENGED
    except Exception:        # noqa: BLE001
        challenged = False
    return ToolWitness(host=str(target or ""), challenged=challenged)


# Préfixe d'évidence apposé à un constat d'ABSENCE rendu par un outil qui N'A PAS TOURNÉ (argv refusé
# par l'outil, image docker absente, échec de lancement). Mesuré : 251 findings du ledger `gxrun2`
# disaient « j'ai vérifié, rien trouvé » alors que le processus s'était arrêté sur `invalid value for
# flag -d` / `pull access denied`. Le rc et la sortie d'erreur étaient là, sous la main, inutilisés.
DID_NOT_RUN_PREFIX = (
    "NON VÉRIFIÉ — l'outil n'a produit AUCUNE sortie et s'est arrêté en erreur (rc={rc}) : il n'a "
    "donc rien pu observer, et son silence ne peut RIEN affirmer sur la cible. Le statut passe de "
    "`tested` (« j'ai vérifié, rien trouvé ») à `skipped` (« je n'ai pas pu vérifier »). Corriger "
    "l'invocation (argv/binaire/image) puis rejouer. Sortie d'erreur, conservée telle quelle : ")


def tool_did_not_run(rc, stdout=""):
    """L'outil s'est-il arrêté SANS RIEN PRODUIRE ? (`rc != 0` ET stdout VIDE)

    BORNE FACTUELLE, pas une heuristique de mots-clés : un outil qui a écrit ne serait-ce qu'un octet
    sur stdout a produit une observation, et son constat est GARDÉ INTACT — même à rc non nul (nikto
    et testssl sortent en erreur tout en ayant rendu leurs résultats, et `parse_output` ne lit QUE
    stdout : un rc non nul avec du stdout est un cas de parsing, pas de non-exécution). Un outil qui
    a tourné correctement et n'a simplement rien trouvé sort à **rc == 0** — il n'est jamais concerné.
    Ne lève jamais."""
    try:
        if int(rc) == 0:
            return False
    except (TypeError, ValueError):
        return False
    try:
        return not str(stdout or "").strip()
    except Exception:            # noqa: BLE001
        return False


def downgrade_did_not_run(findings, rc, stderr=""):
    """Déclasse `tested` -> `skipped` un constat rendu par un outil qui N'A PAS TOURNÉ. Mêmes règles
    que `downgrade` : jamais un `vulnerable`, jamais un `skipped` déjà posé, jamais une exception."""
    why = DID_NOT_RUN_PREFIX.format(rc=rc)
    try:
        for f in findings or []:
            if getattr(f, "status", None) != "tested":
                continue
            f.status = "skipped"
            f.evidence = why + (getattr(f, "evidence", "") or "")
    except Exception:            # noqa: BLE001
        return findings
    return findings

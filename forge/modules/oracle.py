# SPDX-License-Identifier: AGPL-3.0-or-later
"""Base commune des modules-oracles à PREUVE (`Oracle`) — factorise le squelette répété par les
quatre vérificateurs à preuve : `access_control.idor`, `ssrf.callback`, `auth.takeover`,
`cors.credentials`.

Contrat commun (le « pas de preuve => tested » est ici la loi, pas une convention par module) :
  - PREUVE obtenue  -> `proof(proven=True, ...)`  -> status='vulnerable' (sévérité HIGH/CRITICAL) ;
  - PAS de preuve    -> `proof(proven=False, ...)` -> status='tested' (jamais 'vulnerable' à l'aveugle) ;
  - config manquante -> `skip(...)`               -> finding INFO 'tested', AUCUN réseau émis.

Ce que la base fournit (chaque oracle concret se réduit à : métadonnées + logique de sonde/jugement) :
  - `proof(...)` / `skip(...)` : construction UNIFORME de Finding qui estampille kind/mitre/cwe/category/
    tool/fix et applique le toggle de statut (preuve => vulnerable, sinon tested) ;
  - `_http(...)` : le CÂBLAGE urllib partagé (Request + urlopen + gestion HTTPError/transport). Chaque
    oracle garde son `_fetch` (le seam monkeypatché par les tests) mais l'adosse à `_http` ;
  - `_curl(...)` : PoC curl rejouable (un `-H` par en-tête), partagé par IDOR/SSRF/ATO.

Aucune capacité n'est élargie ici : les flags exploit/destructive/web_allowed restent déclarés par
chaque module concret et restent gardés par le ROE.
"""
import functools
import hashlib
import urllib.error
import urllib.parse
import urllib.request

from ._scopeguard import ScopeGuardMixin
from .registry import Module
from .. import blindness as _blind
from .. import pin as _pin
from .. import session as _session
from .. import throttle as _throttle

_MAX_REDIRECTS = 5               # borne du suivi de redirection scope-checké opt-in (anti-boucle)
# Prélèvement BORNÉ du corps d'une réponse d'ERREUR, à des fins de CLASSIFICATION UNIQUEMENT (jamais
# rendu à l'appelant). 8 Kio suffisent très largement : l'interstitiel Cloudflare porte sa signature
# (`<title>Just a moment…`, `/cdn-cgi/challenge-platform`) dans ses 500 premiers octets.
_ERROR_BODY_PEEK = 8192
_MAX_BACKOFF = 3                 # borne des ré-essais 429/503 (back-off exponentiel, JAMAIS infini)
_BACKOFF_BASE = 0.5             # délai initial du back-off (s) si pas de Retry-After
_BACKOFF_CAP = 8.0             # plafond du délai de back-off / d'un Retry-After honoré (s)


def _is_throttled(err):
    """True si une HTTPError est une réponse de THROTTLING/WAF (429 Too Many Requests / 503). Ne lève jamais."""
    try:
        return err.code in (429, 503)
    except Exception:            # noqa: BLE001
        return False


def _retry_after(err, fallback):
    """Délai de back-off (s) : `Retry-After` (secondes entières) s'il est lisible, sinon `fallback`.
    Une date HTTP (format non-numérique) est ignorée -> fallback. Borné à `_BACKOFF_CAP`. Ne lève jamais."""
    ra = None
    try:
        ra = err.headers.get("Retry-After")
    except Exception:            # noqa: BLE001
        ra = None
    delay = fallback
    if ra:
        try:
            delay = float(int(str(ra).strip()))
        except (TypeError, ValueError):
            delay = fallback
    return max(0.0, min(delay, _BACKOFF_CAP))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Handler qui NE SUIT PAS les redirections : `redirect_request` -> None fait remonter la 3xx
    telle quelle (HTTPError avec le header Location intact). Indispensable à l'oracle open-redirect
    (lire la cible de redirection SANS émettre de requête vers l'hôte attaquant hors-scope) et,
    plus généralement, garde-fou de SÛRETÉ : une redirection vers un hôte hors périmètre ne doit
    JAMAIS être suivie automatiquement (le scope-guard resterait aveugle à l'I/O sortante). C'est le
    comportement PAR DÉFAUT de tout fetch d'oracle (`_http(follow_redirects=False)`)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401,N802
        return None


def _host_of(url):
    """Hôte (lowercase) d'une URL, '' si illisible. Ne lève jamais."""
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except Exception:            # noqa: BLE001
        return ""


def _peek_error_body(err):
    """Prélèvement BORNÉ (`_ERROR_BODY_PEEK`) du corps d'une `HTTPError`, **à des fins de
    classification uniquement**. Ne lève JAMAIS ('' si le flux est fermé/absent/illisible).

    POURQUOI CE PRÉLÈVEMENT EXISTE — le défaut mesuré. `_http` rend `("", …)` sur `HTTPError` : le
    corps de la réponse d'erreur est JETÉ. Or l'interstitiel de défi Cloudflare (5 229 octets,
    « Just a moment… », `/cdn-cgi/challenge-platform`) vit exactement là, et c'est la signature la
    plus fiable dont on dispose — la seule qui ne dépende pas de la version HTTP négociée. Sur la
    campagne `gxrun2`, la garde de challenge n'avait plus que la voie en-tête (`cf-mitigated`), qui
    n'atteint pas le chemin urllib : deux modules qui la portaient ont rendu 49 `tested` chacun sur
    un mur. On lit donc ce corps ICI, on s'en sert POUR JUGER, et on ne le rend PAS : le contrat
    public de `_http` (corps vide sur HTTPError) reste BYTE-IDENTIQUE pour les ~19 oracles."""
    try:
        return err.read(_ERROR_BODY_PEEK).decode("utf-8", "replace")
    except Exception:            # noqa: BLE001 (flux déjà consommé/fermé : aucune importance)
        return ""


def _witness(status, body, headers, url, store):
    """Verse UNE réponse au témoin de cécité de l'action courante et propage l'état au store gouverné.

    Deux effets, tous deux no-op hors contexte gouverné (dev/test/appel direct de `_http`) :
      - `blindness.note(...)` compte « défi managé constaté » vs « application réellement vue » ;
      - si la réponse porte une signature EXPLICITE de défi, l'hôte passe à `CHALLENGED` dans le
        `SessionStore` (scope-guardé, sans secret). C'est la voie de propagation qui existait DÉJÀ
        mais que SEUL `evasion` alimentait : les modules sans corps à juger (sonde de TIMING du
        smuggling) la lisent pour s'abstenir. Ne lève jamais."""
    try:
        host = (urllib.parse.urlsplit(url).hostname or "") if url else ""
    except Exception:            # noqa: BLE001
        host = ""
    challenged = _blind.note(status, body, headers, host)
    if challenged and store is not None:
        try:
            store.mark_challenged(url)
        except Exception:        # noqa: BLE001 (le suivi ne doit jamais avorter une requête)
            pass
    return challenged


def _redirect_target(cur_url, location, store):
    """URL absolue du PROCHAIN saut de redirection SI le suivi est autorisé, sinon None (fail-closed).

    Refuse (None -> la 3xx remonte telle quelle, AUCUNE requête vers la cible) si :
      - pas de `Location` ou schéma non http(s) ;
      - AUCUN périmètre gouverné lié (dev/test/offline) — on ne suit jamais à l'aveugle ;
      - destination HORS périmètre — le matériel secret et le réseau ne peuvent PHYSIQUEMENT pas
        quitter le périmètre déclaré, même via une redirection dérivée à runtime (c'était la faille :
        un hôte in-scope 302-ant vers 127.0.0.1/interne recevait sinon la session gouvernée)."""
    if not location:
        return None
    nxt = urllib.parse.urljoin(cur_url, str(location))
    if not nxt.lower().startswith(("http://", "https://")):
        return None
    scope = getattr(store, "scope", None) if store is not None else None
    if scope is None or not scope.is_in_scope(nxt):
        return None
    return nxt


# =================================================================================================
#  SONDE DE CONTRÔLE « CATCH-ALL » — un 200 sur un chemin DEVINÉ ne prouve rien si la cible ne
#  DISCRIMINE PAS ses routes.
#
#  MESURÉ (campagne `kong`, ledger signé, `.../tmp/kong/ledger.jsonl`) : `cloud.konghq.com` est une
#  SPA qui rend son `index.html` — **3 427 octets IDENTIQUES, HTTP 200** — pour `/wp-admin`,
#  `/.git/config`, `/server-status` et `/zzz-chemin-inexistant-12345`. `framework.exposure` y a émis
#  **8 findings HIGH `vulnerable` distincts** (`/actuator/beans`, `/heapdump`, `/threaddump`,
#  `/httptrace`, `/trace`, + variantes Boot 1.x). Aucun actuator n'existe sur cette cible.
#
#  LE DÉFAUT EST DE CLASSE, PAS D'INSTANCE. Tout oracle qui DEVINE un chemin puis lit le STATUT de la
#  réponse comme « ce chemin existe » est faux sur une cible catch-all — et une SPA est le cas
#  MAJORITAIRE du web moderne. La sonde de contrôle est le seul discriminant qui ne coûte rien : on
#  demande un chemin qu'AUCUNE application ne peut servir ; s'il répond en 2xx, la cible ne
#  discrimine pas ses routes et TOUT 2xx sur un chemin deviné est NON CONCLUANT.
#
#  DEUX BORNES, SYMÉTRIQUES DE CELLES DE `blindness` (on ne fabrique pas l'excès inverse) :
#    1. La sonde ne PROMEUT jamais : son seul pouvoir est de faire TAIRE un verdict (`tested`/
#       `vulnerable` -> `skipped`). Le 2xx y est lu sur un chemin que L'APPELANT a fabriqué et dont
#       il SAIT qu'il ne peut pas exister : c'est une preuve POSITIVE de non-discrimination, pas une
#       déduction depuis l'absence.
#    2. DEUX chemins de contrôle, pas un : un seul 2xx pourrait être une collision (un chemin de
#       contrôle qui existe pour de vrai). L'ambiguïté résiduelle est NOMMÉE : une cible qui rend un
#       2xx sur deux jetons aléatoires DISTINCTS et n'a pourtant pas de catch-all n'existe pas en
#       pratique ; et si elle existait, le coût serait un `skipped` (« pas vérifié »), jamais un faux
#       négatif silencieux.
#
#  La FORME du contrôle doit MIROITER la forme des chemins devinés (extension, profondeur) : une SPA
#  peut très bien catch-all les chemins sans extension et rendre 404 sur `/x.json`. D'où
#  `probe_paths` (l'appelant fournit ses propres gabarits quand il devine autre chose que des
#  segments nus).
# =================================================================================================
CATCHALL_PREFIX = (
    "NON VÉRIFIÉ — la cible NE DISCRIMINE PAS ses routes (catch-all) : {why}. Un code 200 sur un "
    "chemin DEVINÉ n'y prouve donc RIEN — ni que le chemin existe, ni que la surface est exposée. "
    "Le statut passe à `skipped` (« je n'ai pas pu vérifier ») plutôt que `tested`/`vulnerable`. "
    "Rejouer sur une surface qui discrimine, ou exiger une signature de CORPS propre à la surface "
    "recherchée.")


class PathDiscrimination:
    """Verdict d'une sonde de contrôle « catch-all ». Ne lève jamais.

    `verdict` : True  -> la cible DISCRIMINE (au moins un chemin de contrôle est refusé) ;
                False -> CATCH-ALL constaté (tous les chemins de contrôle répondent 2xx) ;
                None  -> INDÉTERMINÉ (aucune réponse, ou sonde non émise) — l'appelant garde son
                         comportement historique (c'est sa propre dégradation réseau qui parlera).

    Ne retient que des chemins fabriqués par l'appelant, des codes de statut et des tailles : aucun
    fragment de corps, aucun secret."""

    __slots__ = ("verdict", "probes", "same_body")

    def __init__(self, verdict=None, probes=(), same_body=False):
        self.verdict = verdict
        self.probes = list(probes)          # [(path, status, len(body))] — bornée par construction
        self.same_body = bool(same_body)

    @property
    def catchall(self):
        """True UNIQUEMENT sur un catch-all CONSTATÉ (jamais sur l'indéterminé)."""
        return self.verdict is False

    def why(self):
        """Explication SÛRE (chemins de contrôle + statuts + tailles), pour l'évidence d'un finding."""
        bits = ", ".join(f"{p} -> HTTP {s} ({n} o)" for p, s, n in self.probes) or "—"
        return (f"sonde(s) de contrôle sur des chemins qui NE PEUVENT PAS exister : {bits}"
                + (" ; corps IDENTIQUES entre les contrôles" if self.same_body else ""))


class Oracle(Module):
    """Base des oracles à preuve. Un oracle concret déclare ses métadonnées (kind/mitre/cwe/fix/tool)
    et surcharge une petite méthode de sonde/jugement — toute la plomberie Finding/HTTP vit ici."""

    web_allowed = True          # interaction web (réseau) -> gardée par le ROE (commun aux 4 oracles)
    available = True            # urllib stdlib -> toujours disponible
    cwe = ""                    # CWE canonique de l'oracle (ex "CWE-918") : sert de category ET de cwe
    fix = ""                    # remédiation par défaut de l'oracle (le fix explicite d'un finding prime)
    tool = ""                   # chaîne de provenance estampillée sur les findings
    MAXLEN = 200000             # troncature du corps lu par `_fetch_body` (cas commun ; surchargée par oracle)

    # =============================================================================================
    #  FRONTIÈRE DE `fire()` — UN mur ne doit pas produire des milliers d'AFFIRMATIONS de non-vuln.
    #
    #  MESURÉ (`gxrun2`) : 4 839 findings `tested` — « j'ai vérifié, rien trouvé » — émis sur des
    #  hôtes dont le moteur n'a JAMAIS vu le contenu. C'est le faux négatif le plus dangereux : il
    #  RESSEMBLE à de la couverture.
    #
    #  POURQUOI ICI, ET PAS QUARANTE RUSTINES. Les ~19 modules-oracles n'ont RIEN en commun côté
    #  jugement : `security_headers` appelle `self.finding(status='tested')` sans passer par
    #  `proof()`, `business_logic` n'émet aucune requête, `access_control` construit un différentiel
    #  multi-comptes. Ce qu'ils partagent, c'est (1) `Oracle._http` en entrée — le chokepoint où la
    #  réponse ENTRE — et (2) `fire(action)` en sortie. Poser la mesure en (1) et la décision en (2)
    #  couvre TOUS les oracles, y compris `web.py:access_control.idor` que ce lot ne modifie pas,
    #  et se prouve en UN endroit. Quarante correctifs indépendants dériveraient et se
    #  contrediraient ; celui-ci ne peut pas diverger — il n'y en a qu'un.
    #
    #  Le déclassement lui-même (`blindness.downgrade`) ne touche QUE `status='tested'` -> `skipped` :
    #  jamais un `vulnerable` (une preuve reste une preuve), jamais quoi que ce soit si l'action n'a
    #  pas été jugée AVEUGLE (signature EXPLICITE de défi ET application jamais vue).
    # =============================================================================================
    def __init_subclass__(cls, **kw):
        """Enveloppe le `fire()` de CHAQUE oracle concret : témoin de cécité lié pendant l'appel,
        déclassement appliqué au retour. Idempotent (un `fire` déjà enveloppé ne l'est pas deux fois)
        et transparent (`functools.wraps` : nom, docstring et signature conservés pour la console et
        le catalogue). Un sous-classement qui n'apporte PAS son propre `fire` hérite du parent déjà
        enveloppé — l'enveloppe n'est donc jamais empilée."""
        super().__init_subclass__(**kw)
        fn = cls.__dict__.get("fire")
        if fn is None or getattr(fn, "_forge_blindness_wrapped", False):
            return

        @functools.wraps(fn)
        def _fire_with_blindness_witness(self, action, *a, **k):
            ctx = _blind.using()
            with ctx as witness:
                findings = fn(self, action, *a, **k)
            # SEUL le propriétaire du témoin juge : un oracle imbriqué (aucun aujourd'hui, mais la
            # garde est gratuite) ne déclasserait jamais sur une vue PARTIELLE de l'action.
            return _blind.downgrade(witness if ctx.owned else None, findings)

        _fire_with_blindness_witness._forge_blindness_wrapped = True
        cls.fire = _fire_with_blindness_witness

    # --- construction UNIFORME de Finding (le coeur factorisé) ---
    def proof(self, *, target, proven, title, severity, evidence, poc, fix=None):
        """Finding sur le CHEMIN DE PREUVE. Estampille category=self.cwe, cwe=self.cwe, mitre=self.mitre,
        tool=self.tool, fix (self.fix par défaut, override par argument). `proven` applique le contrat :
        True -> status='vulnerable', False -> status='tested' (jamais vulnerable sans preuve)."""
        return self.finding(
            _proven=bool(proven),                        # marqueur de PREUVE sanctionné (cf. Module.finding)
            target=target, title=title, severity=severity,
            category=self.cwe, cwe=self.cwe, mitre=self.mitre,
            fix=self.fix if fix is None else fix,
            status="vulnerable" if proven else "tested",
            tool=self.tool, evidence=evidence, poc=poc)

    def skip(self, *, target, title, evidence, poc, severity="INFO"):
        """Finding « non testé / config manquante » : `status='skipped'`, category=self.cwe,
        tool=self.tool, et AUCUN mitre/cwe/fix estampillé (le schema dérive cwe depuis category et
        fix depuis le mapping). Sert aussi aux refus fail-closed (ex : write IDOR non autorisé) —
        INFO, aucun réseau émis.

        ⚠️ CETTE MÉTHODE ÉMETTAIT `status='tested'`. La méthode LITTÉRALEMENT NOMMÉE `skip`, dont le
        docstring disait « non testé », affirmait donc « **j'ai vérifié, rien trouvé** » — le contraire
        exact de ce qu'elle veut dire, et sur la plus grosse population du moteur : **1 750 findings
        mesurés sur une campagne réelle**, répartis sur 25 kinds. Aucun octet n'avait été émis pour
        aucun d'eux.

        C'est le même défaut que celui réparé partout ailleurs dans ce dépôt — une affirmation plus
        large que ce qu'elle recouvre — mais c'était ici le plus coûteux : un rapport listant
        « access_control.idor : tested » sur une cible pour laquelle aucun compte de test n'était
        configuré se lit comme une absence de vulnérabilité. C'est précisément le mode d'échec qui a
        déjà coûté une campagne (rapport propre et vide == « cible saine »).

        `skipped` est le vocabulaire déjà en place pour « je n'ai pas pu vérifier » (cf. `degraded`),
        et la vue de rapport le remonte en section « Couverture NON vérifiée » au lieu de le noyer
        dans le bruit de reconnaissance."""
        return self.finding(
            target=target, title=title, severity=severity,
            category=self.cwe, status="skipped", tool=self.tool,
            evidence=evidence, poc=poc)

    def degraded(self, *, target, title, evidence, poc):
        """Finding de DÉGRADATION GRACIEUSE (`status='skipped'`) : scope-refus, outil optionnel absent
        ou réseau indisponible. Estampille kind/mitre/cwe/tool/fix comme un finding normal (INFO).

        Défini sur `Oracle` et non sur `ScopeGuardedOracle` : tout oracle qui rend un verdict à partir
        d'une réponse doit pouvoir dire « je n'ai pas pu vérifier », y compris ceux qui n'ont pas de
        scope-guard propre (`SsrfCallback`). La distinction avec `skip()` porte sur le STATUS, et c'est
        elle qui compte pour l'opérateur : `skipped` = pas vérifié, `tested` = vérifié, rien trouvé."""
        return self.finding(
            target=target, title=title, severity="INFO",
            category=self.cwe, cwe=self.cwe, mitre=self.mitre,
            fix=self.fix, status="skipped", tool=self.tool,
            evidence=evidence, poc=poc)

    # =============================================================================================
    #  MATÉRIEL D'AUTHENTIFICATION MORT => AUCUN VERDICT (jumeau de « cible injoignable »)
    #
    #  Le matériel d'auth ARME les oracles de contrôle d'accès. Quand il n'authentifie plus, les
    #  conjonctions de preuve s'effondrent toutes à False et `proof(proven=False, …)` estampille
    #  `status='tested'` avec un titre qui AFFIRME l'absence de vulnérabilité : le rapport est PROPRE
    #  et VIDE, indiscernable d'une cible saine. C'est le mode d'échec le plus cher du projet — le
    #  même défaut de classe que « cible injoignable », mais silencieux au lieu d'être muet.
    #
    #  DEUX signaux, aucun n'émet la moindre requête supplémentaire :
    #    (1) PÉREMPTION LISIBLE — le jeton porte un `exp` dépassé (`session.headers_expired`). Connue
    #        AVANT tout réseau : on ne tire même pas.
    #    (2) MATÉRIEL INERTE — la cible répond au compte authentifié EXACTEMENT comme à la sonde
    #        ANONYME (même statut de BARRIÈRE + même corps), sur les sondes DÉJÀ tirées.
    #
    #  POURQUOI LA BARRIÈRE, ET PAS N'IMPORTE QUEL STATUT. `_AUTH_BARRIER` ne retient que les statuts
    #  qui signifient « tu n'es pas autorisé » (401/403) ou « va t'authentifier » (3xx vers un login).
    #  Un 404/5xx identique des deux côtés dit « l'objet n'existe pas / le serveur casse », PAS que la
    #  session est morte — le retenir aurait transformé tout vrai négatif en aveuglement (c'est le
    #  contrôle négatif de `tests/test_unreachable_no_verdict.py`). Un 2xx est exclu pour la raison
    #  SYMÉTRIQUE : le compte a bien obtenu de l'accès (et une ressource PUBLIQUE répond 200 à tout le
    #  monde sans que rien ne soit mort — cf. `test_no_false_positive_on_public_200`).
    #
    #  AMBIGUÏTÉ RÉSIDUELLE, ASSUMÉE ET NOMMÉE. « 403 identique pour l'attaquant et pour l'anonyme »
    #  peut aussi être une cible DURCIE qui ne discrimine pas ses refus (session vivante, accès
    #  légitimement refusé). Les deux cas sont INDISTINGUABLES depuis la réponse — et c'est
    #  exactement pourquoi le verdict honnête est « je n'ai pas pu tester » (`skipped`) et non
    #  « testé, rien trouvé » (`tested`). L'evidence NOMME les deux lectures possibles.
    # =============================================================================================
    _AUTH_BARRIER = (401, 403, 301, 302, 303, 307, 308)

    WHY_EXPIRED = ("le jeton porte une date d'expiration (`exp`) DÉPASSÉE — il ne peut plus "
                   "authentifier ; AUCUNE requête n'a été émise avec ce matériel")
    WHY_INERT = ("la cible a répondu au compte authentifié EXACTEMENT comme à la sonde ANONYME "
                 "(même statut de refus, même corps) — le matériel n'a acheté AUCUN accès")

    @staticmethod
    def auth_expired(headers, now=None):
        """(1) Le matériel porte-t-il une échéance LISIBLE et DÉPASSÉE ? Délègue à la source unique
        `session.headers_expired`. INCONNU (cookie opaque, aucun JWT) -> False : jamais d'accusation
        sans preuve — le signal (2) prendra le relais au tir."""
        return _session.headers_expired(headers, now=now)

    @classmethod
    def auth_inert(cls, auth_resp, anon_resp):
        """(2) Le matériel d'auth n'a-t-il RIEN acheté ? `auth_resp`/`anon_resp` = `(status, body)`.

        True SEULEMENT si : les deux sondes ont répondu, le statut du compte authentifié est une
        BARRIÈRE d'authentification/autorisation, il est IDENTIQUE à celui de l'anonyme, et le corps
        est identique. Tout le reste -> False (comportement historique préservé : une différence avec
        l'anonyme PROUVE que la session est reconnue).

        `_AUTH_BARRIER` est le SEUL filtre de statut, et il porte les DEUX exclusions : un 2xx (le
        compte a OBTENU de l'accès — session vivante, et une ressource publique répond 200 à tout le
        monde) et un 404/5xx (l'objet ou le serveur, pas la session) n'y sont pas. Une seconde garde
        « st_a in (200, 206) » a existé ici : la mutation l'a montrée INERTE (le filtre de barrière la
        subsumait), donc supprimée — une garde qui ne peut pas tirer n'est pas de la défense en
        profondeur, c'est un leurre pour l'auditeur."""
        st_a, body_a = auth_resp
        st_anon, body_anon = anon_resp
        if st_a is None or st_anon is None:      # cible injoignable : couvert par l'autre garde
            return False
        if st_a not in cls._AUTH_BARRIER:        # ni accès obtenu (2xx), ni 404/5xx
            return False
        return st_a == st_anon and (body_a or "") == (body_anon or "")

    @classmethod
    def expired_account(cls, *accounts):
        """LABEL du 1er compte SÉRIALISÉ `{label, headers}` dont le matériel porte une échéance
        LISIBLE et DÉPASSÉE, sinon None. Sert aux chemins MULTI-COMPTES (différentiel 2 comptes IDOR,
        write, privesc) : UN seul jeton périmé suffit à priver le différentiel de son sens, et le
        constat se fait AVANT toute requête. SECRET : rend un LABEL (`''` si le compte n'en porte
        pas), jamais un fragment de matériel."""
        for a in accounts:
            if cls.auth_expired((a or {}).get("headers", {})):
                return str((a or {}).get("label", ""))
        return None

    @classmethod
    def auth_inert_among(cls, probes, anon_resp):
        """Variante MULTI-COMPTES : LABEL du 1er compte INERTE parmi `probes` = [(label, (status,
        body))], ou None.

        GARDE ANTI-FAUX-POSITIF (c'est elle qui rend le signal utilisable sur une cible DURCIE) : si
        UN des comptes du MÊME jeu de sondes a OBTENU DE L'ACCÈS (2xx) sur la MÊME URL, on ne rend
        AUCUN verdict d'inertie. Une cible qui laisse entrer l'un et refuse l'autre DISCRIMINE
        démontrablement, et la lecture honnête du refus est alors l'AUTORISATION, pas une session
        morte — c'est le cas d'un privesc correctement bloqué (admin 200 / bas-privilège 403) ou d'un
        IDOR correctement bloqué (A 200 / B 403). Le verdict d'inertie est réservé au cas où PERSONNE
        n'entre et où tout le monde ressemble à l'anonyme : la lecture « le contexte d'authentification
        est mort » domine alors (les comptes d'une campagne sont capturés ensemble et expirent
        ensemble). Résiduel ASSUMÉ : un SEUL compte mort parmi plusieurs, sans `exp` lisible, reste
        indétectable au tir — seule la péremption lisible (`auth_expired`) le rattrape."""
        if any(st in (200, 206) for _lbl, (st, _b) in probes):
            return None
        for label, r in probes:
            if cls.auth_inert(r, anon_resp):
                return label
        return None

    def auth_dead(self, *, target, title, label, why, poc):
        """Finding `status='skipped'` : l'oracle est DÉSARMÉ, il refuse de rendre un verdict.

        SECRET : n'expose QUE le LABEL du compte (jamais un en-tête, un cookie, un bearer, ni un
        fragment de jeton) — le contrat du bloc `auth` (labels + compteurs, rien d'autre) tient
        jusque dans les findings de dégradation."""
        return self.degraded(
            target=target, title=title,
            evidence=(f"compte {label or '<sans label>'!r} : {why}. Un oracle de contrôle d'accès "
                      "DÉSARMÉ ne peut RIEN conclure : rendre « rien trouvé » serait un faux négatif "
                      "silencieux (rapport propre et vide sur une cible jamais testée). Ce finding "
                      "dit « je n'ai pas pu tester » (status=skipped). Lecture alternative possible : "
                      "cible durcie qui ne discrimine pas ses refus — indistinguable depuis la "
                      "réponse, d'où le refus de conclure. Remède : rafraîchir le matériel de ce "
                      "compte dans le bloc `auth` de l'engagement, puis relancer."),
            poc=poc)

    # --- seam réseau bas-niveau : UN SEUL saut, SANS suivi auto de redirection ---
    @staticmethod
    def _raw_open(req, timeout=15):
        """Ouvre UNE requête via un opener local `_NoRedirect` : AUCUNE redirection n'est suivie
        automatiquement (une 3xx remonte en `HTTPError`, `Location` intact). C'est le POINT DE PATCH
        RÉSEAU unique des tests (au lieu de `urlopen`) ET le garde-fou de sûreté : le suivi de
        redirection est TOUJOURS explicite et scope-checké dans `_http`, jamais délégué à urllib à
        l'aveugle (qui re-poste les en-têtes — dont le matériel de session — vers l'hôte cible)."""
        return urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)

    @staticmethod
    def _pinned_open(req, pin_ip, timeout=15):
        """ANTI-REBINDING END-TO-END : comme `_raw_open` (opener no-follow, une 3xx remonte en HTTPError)
        MAIS la connexion TCP est établie vers `pin_ip` (l'IP ÉPINGLÉE par le ROE au fire-time) AU LIEU de
        re-résoudre le hostname de `req` — la couche connexion urllib re-résolvait sinon, rouvrant la
        fenêtre de DNS-rebinding entre la résolution du ROE et le connect.

        La logique de connexion PAR-IP (sous-classes HTTPConnection/HTTPSConnection + handlers, SNI/cert
        préservés) vit en SOURCE UNIQUE dans `pin.build_pinned_opener` (partagée avec recon_surface). On y
        passe `override_ip=pin_ip` (l'appelant fournit l'IP explicitement) + `_NoRedirect` (aucun suivi
        auto). TLS NON affaibli : `self.host` reste l'HÔTE D'ORIGINE -> `Host:` header ET, en HTTPS, SNI +
        validation du certificat restent l'hôte d'origine (jamais l'IP). On ne change QUE la CIBLE du connect."""
        opener = _pin.build_pinned_opener(override_ip=pin_ip, extra_handlers=(_NoRedirect,))
        return opener.open(req, timeout=timeout)

    # --- câblage HTTP partagé (les `_fetch` concrets adaptent la forme du tuple retourné) ---
    @staticmethod
    def _http(url, *, headers=None, timeout=15, method="GET", data=None, maxlen=200000,
              follow_redirects=False):
        """Requête urllib partagée -> (status, body, resp_headers).

        - succès        : (r.status, corps décodé tronqué à maxlen, r.headers) ;
        - HTTPError     : (e.code, "", e.headers | None) — corps vide, en-têtes si disponibles ;
        - erreur transport (réseau hostile) : (None, "", None) — on ne crashe jamais.
        Chaque oracle en dérive sa propre forme (content-type, dict d'en-têtes…) dans son `_fetch`.

        `follow_redirects` — DÉFAUT False (garde-fou de SÛRETÉ) : une 3xx N'EST PAS suivie et remonte
        telle quelle (HTTPError, `Location` intact — ce que lisent les oracles open-redirect/OAuth/
        cache-poison). En suivant à l'aveugle, urllib RE-POSTERAIT les en-têtes de la requête — dont le
        matériel de session SECRET — vers l'hôte de destination : un hôte in-scope 302-ant vers
        127.0.0.1/interne exfiltrerait ainsi cookie/Authorization gouvernés HORS périmètre. Le suivi est
        donc OPT-IN et scope-checké : à True, chaque saut est re-validé (`_redirect_target` — arrêt au
        1er `Location` HORS périmètre ou sans scope gouverné lié) et, sur un saut CROSS-ORIGIN, le
        matériel secret de l'appelant (Cookie/Authorization) est RETIRÉ avant de re-tirer ; la session
        gouvernée est re-fusionnée scope-guardée POUR LE NOUVEL hôte (jamais celle de l'hôte précédent).

        SESSION GOUVERNÉE : si un `SessionStore` est lié (par le moteur autour de fire()), le matériel
        d'authentification SECRET applicable à l'URL COURANTE — et UNIQUEMENT si elle est IN-SCOPE
        (scope-guard du store) — est fusionné SOUS les en-têtes de l'appelant dans la requête sortante.
        Il n'est JAMAIS renvoyé ni exposé : l'appelant bâtit ses PoC depuis SES propres en-têtes
        (`_curl`), pas depuis la requête. Sans store lié (dev/test/offline) -> aucun matériel injecté.

        RÔLE DE SONDE ANONYME (`session.anonymous_probe()`) : sous cette portée, la fusion est
        SUSPENDUE — la requête part avec les SEULS en-têtes de l'appelant. C'est la correction du
        défaut D1 du banc : un dict d'en-têtes VIDE ne veut pas dire « anonyme », il veut dire « rien
        à ajouter » ; la sonde de contrôle des oracles de contrôle d'accès partait donc AUTHENTIFIÉE
        et son 401 attendu devenait un 200, éteignant l'oracle IDOR EN SILENCE. La suspension est
        PAR-PORTÉE, jamais globale : dans le même `fire()`, les sondes attaquant/propriétaire/admin
        gardent leur session. Le store reste LIÉ (scope-guard des redirections, `mark_challenged`,
        témoin de cécité inchangés) : seule la fusion du matériel d'auth est suspendue."""
        caller_headers = dict(headers or {})
        payload = data.encode("utf-8") if isinstance(data, str) else data
        store = _session.current()
        anon_role = _session.probe_is_anonymous()
        bucket = _throttle.current()             # THROTTLE lié par l'engine autour de fire() ; None => no-op
        cur_url, cur_method, cur_payload = url, method, payload
        for _hop in range(_MAX_REDIRECTS + 1):
            req_headers = dict(caller_headers)
            # `anon_role` : sonde DÉCLARÉE anonyme -> AUCUNE fusion, à AUCUN saut (une redirection ne
            # doit pas ré-authentifier une sonde de contrôle en cours de route).
            if store is not None and not anon_role:  # scope-guard PAR-URL : {} si url courante hors-scope
                for k, v in store.headers_for(cur_url).items():
                    req_headers.setdefault(k, v)     # les en-têtes explicites de l'appelant priment
            # BACK-OFF 429/503 borné : re-tente la MÊME requête après Retry-After / back-off exponentiel,
            # SANS consommer un hop de redirection. Le throttle (min-interval) s'applique avant CHAQUE tir.
            backoff_left, backoff_delay, e = _MAX_BACKOFF, _BACKOFF_BASE, None
            while True:
                if bucket is not None:
                    bucket.wait()                    # respect du débit (rate) avant chaque requête sortante
                # ANTI-REBINDING : le ROE a épinglé l'IP de CET hôte au fire-time (moteur -> pin.using).
                # Si un pin s'applique à `cur_url`, on se connecte PAR-IP (Host/SNI/cert = hôte d'origine) ;
                # sinon (pas de pin lié, ou hôte non épinglé -> ex redirect cross-origin) résolution NORMALE
                # (byte-identique à l'historique, et c'est `_raw_open` que les tests monkeypatchent).
                pin_ip = _pin.ip_for(cur_url)
                try:
                    # `Request()` est construit DANS le try : une URL sans scheme (`host`/`host:port`,
                    # normalement normalisée EN AMONT par `web_url_candidates`) ferait lever
                    # `ValueError: unknown url type` au CONSTRUCTEUR — traitée comme tout échec transport
                    # -> (None,"",None) offline-safe, JAMAIS de crash. URL valide -> byte-identique.
                    req = urllib.request.Request(cur_url, headers=req_headers, method=cur_method, data=cur_payload)
                    resp = (Oracle._pinned_open(req, pin_ip, timeout=timeout) if pin_ip
                            else Oracle._raw_open(req, timeout=timeout))
                    with resp as r:
                        st_ok = r.status
                        body_ok = r.read(maxlen).decode("utf-8", "replace")
                        # CHOKEPOINT : la réponse ENTRE dans l'oracle -> témoin de cécité (no-op hors
                        # contexte). Un 200 « Just a moment… » est un DÉFI, pas du contenu.
                        _witness(st_ok, body_ok, r.headers, cur_url, store)
                        return st_ok, body_ok, r.headers
                except urllib.error.HTTPError as he:
                    e = he
                    if backoff_left > 0 and _is_throttled(he):
                        _throttle._sleep(_retry_after(he, backoff_delay))   # attendre (Retry-After ou exp)
                        backoff_left -= 1
                        backoff_delay = min(backoff_delay * 2, _BACKOFF_CAP)
                        continue                     # RE-tente (budget borné : jamais infini)
                    break                            # succès impossible : gérer redirection/throttling ci-dessous
                except Exception:                # noqa: BLE001  (réseau hostile : on ne crashe pas)
                    return None, "", None
            # e est une HTTPError (3xx no-follow, ou 4xx/5xx dont un 429/503 persistant après back-off).
            if follow_redirects and 300 <= e.code < 400:
                loc = None
                try:
                    loc = e.headers.get("Location")
                except Exception:            # noqa: BLE001
                    loc = None
                nxt = _redirect_target(cur_url, loc, store)
                if nxt is not None:
                    follow = True
                    if _host_of(nxt) != _host_of(cur_url):
                        # saut CROSS-ORIGIN : on NE re-poste JAMAIS le secret de l'appelant vers le
                        # nouvel hôte ; la session gouvernée du nouvel hôte (scope-guardée) sera
                        # re-fusionnée au tour suivant via headers_for(nxt).
                        caller_headers = {k: v for k, v in caller_headers.items()
                                          if k.lower() not in ("cookie", "authorization")}
                        # ANTI-REBINDING (résidu T8 fermé) : le ROE n'a épinglé QUE l'hôte de la cible
                        # d'origine. Sous un contexte de pin gouverné, un hôte cross-host N'EST PAS épinglé
                        # -> la couche connexion RE-RÉSOUDRAIT (fenêtre de rebinding). On RÉSOUT le nouvel
                        # hôte sous les MÊMES règles fail-closed que le ROE (`Scope.safe_pinned_ip` :
                        # privé/out_scope/timeout/inconnu => None) et on l'ÉPINGLE ; None => on REFUSE de
                        # suivre (la 3xx remonte telle quelle). Hors contexte gouverné (dev/test/offline) =>
                        # aucun pin lié => suivi NORMAL byte-identique (le scope-guard hostname a déjà gaté nxt).
                        if _pin.current() is not None and _pin.ip_for(nxt) is None:
                            scope = getattr(store, "scope", None) if store is not None else None
                            safe_ip = scope.safe_pinned_ip(nxt) if scope is not None else None
                            if safe_ip is None:
                                follow = False           # fail-closed : hôte dérivé non épinglable
                            else:
                                _pin.bind(nxt, safe_ip)  # épingle l'hôte dérivé -> connexion PAR-IP au tour suivant
                    if follow:
                        if e.code not in (307, 308):     # 301/302/303 -> GET sans corps (convention)
                            cur_method, cur_payload = "GET", None
                        cur_url = nxt
                        continue
            # THROTTLING PERSISTANT (429/503 après back-off) : marque le bucket -> l'engine surface un
            # marqueur « rate-limited » au run (au lieu d'empties silencieux). Puis la réponse telle quelle.
            if _is_throttled(e) and bucket is not None:
                bucket.mark_blocked()
            # CHOKEPOINT (réponse d'ERREUR) : on PRÉLÈVE le corps pour JUGER — c'est là que vit
            # l'interstitiel de défi — puis on rend le corps VIDE comme avant. Le corps prélevé ne
            # sort JAMAIS d'ici : contrat public de `_http` inchangé, byte pour byte.
            err_headers = getattr(e, "headers", None)
            _witness(e.code, _peek_error_body(e), err_headers, cur_url, store)
            # pas de suivi (défaut, hors-scope, sans scope lié, ou budget épuisé) : réponse telle quelle.
            try:
                return e.code, "", e.headers
            except Exception:            # noqa: BLE001
                return e.code, "", None
        return None, "", None                # budget de redirections épuisé (défense en profondeur)

    # --- fetch (status, body) PARTAGÉ (seam `_fetch` monkeypatché par les tests) ---
    @classmethod
    def _fetch_body(cls, url, headers=None, timeout=15, method="GET", data=None):
        """(status, body) — adosse le câblage urllib partagé (Oracle._http), en tronquant le corps à
        `cls.MAXLEN` (100000/200000/300000 selon l'oracle). Source UNIQUE des ~10 `_fetch` (st, body)
        recopiés dans ssrf/tokenapi/rce/business_logic/xxe/race/rfi/injection/exposure/takeover : ils ne
        divergeaient QUE par le maxlen. Le SessionStore gouverné (scope-guardé) est fusionné par `_http`
        UNIQUEMENT sur des URL in-scope. Exposé aussi sous le nom `_fetch` (seam patché par les tests)."""
        st, body, _ = Oracle._http(url, headers=headers, timeout=timeout, method=method,
                                   data=data, maxlen=cls.MAXLEN)
        return st, body

    # Nom historique du seam : les modules concrets appellent `self._fetch(...)` et les tests le
    # monkeypatchent par classe. Résout vers la méthode hoistée ci-dessus (par héritage/alias).
    _fetch = _fetch_body

    def _fetch_anonymous(self, *a, **kw):
        """SONDE DE CONTRÔLE ANONYME : `self._fetch(...)` tiré sous la portée `anonymous_probe()` —
        le matériel de session GOUVERNÉ n'est PAS fusionné, la requête part avec les SEULS en-têtes
        passés par l'appelant (typiquement `{}`).

        POURQUOI CE POINT D'APPEL EXISTE (défaut D1). Un oracle de contrôle d'accès conclut « la
        ressource est protégée » en lisant le REFUS de sa sonde de contrôle. Si cette sonde emporte
        la session gouvernée, elle n'est PAS un contrôle : elle mesure le même accès que la sonde
        authentifiée, le refus attendu n'arrive jamais, et l'oracle rend « non confirmé » sur un vrai
        IDOR. Le rôle doit donc être DÉCLARÉ au point d'appel, pas déduit d'un dict vide.

        Passe par le seam `_fetch` de l'oracle concret : arité, content-type, monkeypatch des tests,
        throttle, pin et témoin de cécité s'appliquent EXACTEMENT comme à une sonde normale — seule
        la fusion du matériel d'auth est suspendue, et seulement pour la durée de cet appel."""
        with _session.anonymous_probe():
            return self._fetch(*a, **kw)

    # =============================================================================================
    #  SONDE DE CONTRÔLE « CATCH-ALL » (cf. le bloc de doctrine en tête de module)
    # =============================================================================================
    CATCHALL_PROBES = 2          # nombre de chemins de contrôle (deux : anti-collision, cf. borne 2)
    CATCHALL_MAXLEN = 4096       # on ne lit du contrôle que de quoi comparer deux corps (jamais tout)

    @staticmethod
    def _origin_of(url):
        """`scheme://netloc` d'une cible (schéma https supposé si absent), sans chemin ni requête.
        La sonde de contrôle s'adresse à la RACINE : c'est le routeur de l'application qu'on teste,
        pas une sous-arborescence. Pur, ne lève jamais."""
        s = str(url or "").strip()
        if "://" not in s:
            s = "https://" + s
        try:
            sp = urllib.parse.urlsplit(s)
            if sp.scheme and sp.netloc:
                return f"{sp.scheme}://{sp.netloc}"
        except Exception:            # noqa: BLE001 (URL hostile : jamais d'exception ici)
            pass
        return s.rstrip("/")

    @classmethod
    def catchall_paths(cls, origin, n=None, template="/{token}"):
        """Chemins de CONTRÔLE DÉTERMINISTES (dérivés de l'origine par SHA-256) qu'aucune application
        ne peut servir. Déterministes pour être REJOUABLES par l'opérateur et stables en test ; le
        gabarit est paramétrable car le contrôle doit MIROITER la forme des chemins devinés."""
        n = cls.CATCHALL_PROBES if n is None else max(1, int(n))
        seed = hashlib.sha256(str(origin or "").encode("utf-8", "replace")).hexdigest()
        return [str(template).format(token=f"forge-catchall-{seed[i * 12:(i + 1) * 12]}")
                for i in range(n)]

    def path_discrimination(self, action, target, timeout=15, probe_paths=None):
        """La cible DISCRIMINE-t-elle ses routes ? -> `PathDiscrimination` (jamais d'exception).

        Émet `CATCHALL_PROBES` GET en lecture seule sur des chemins FABRIQUÉS qui ne peuvent pas
        exister. CATCH-ALL constaté (`verdict=False`) ssi TOUS répondent 2xx. Un seul refus (404/4xx/
        3xx/5xx) suffit à conclure que la cible discrimine (`verdict=True`). Aucune réponse ->
        `verdict=None` : l'appelant garde son comportement historique.

        SCOPE-GUARD : chaque chemin de contrôle est RE-VALIDÉ in-scope quand l'appelant en porte un
        (`ScopeGuardMixin`) ; hors périmètre -> aucune requête, verdict INDÉTERMINÉ (fail-closed).
        Passe par le seam `_fetch` de l'oracle appelant : session gouvernée, throttle, pin, témoin de
        cécité et monkeypatch des tests s'appliquent EXACTEMENT comme aux sondes normales."""
        origin = self._origin_of(target)
        paths = list(probe_paths) if probe_paths else self.catchall_paths(origin)
        in_scope = getattr(self, "_in_scope", None)
        probes, all_2xx, bodies = [], True, []
        for path in paths:
            url = origin + (path if str(path).startswith("/") else "/" + str(path))
            if in_scope is not None and not in_scope(action, url):
                return PathDiscrimination(None, probes, False)      # fail-closed : aucune requête
            st, body = self._probe(url, timeout=timeout)
            if st is None:
                continue                                            # transport muet : ne juge pas
            probes.append((path, st, len(body or "")))
            bodies.append((body or "")[:self.CATCHALL_MAXLEN])
            if not (200 <= int(st) < 300):
                all_2xx = False
        same = len(bodies) > 1 and len(set(bodies)) == 1
        if not all_2xx:
            return PathDiscrimination(True, probes, same)           # un refus suffit : elle discrimine
        # CATCH-ALL : exige que les DEUX contrôles aient RÉPONDU (borne anti-collision). Une réponse
        # unique — l'autre sonde muette — ne suffit pas : on rend INDÉTERMINÉ, jamais un catch-all
        # déduit d'un seul chemin (ce serait l'excès inverse, un `skipped` sur une cible saine).
        if len(probes) >= 2:
            return PathDiscrimination(False, probes, same)
        return PathDiscrimination(None, probes, same)               # preuve partielle -> indéterminé

    def _probe(self, url, timeout=15):
        """(status, body) d'une sonde de CONTRÔLE, quel que soit l'arité du `_fetch` de l'oracle
        concret (2-uplet (st, body) ou 3-uplet (st, body, headers/pairs)). Ne lève jamais : une sonde
        de contrôle qui casse ne doit JAMAIS faire tomber l'oracle qu'elle protège."""
        try:
            res = self._fetch(url, timeout=timeout)
        except Exception:            # noqa: BLE001 (seam hostile / signature exotique)
            return None, ""
        if isinstance(res, tuple) and len(res) >= 2:
            return res[0], res[1]
        return None, ""

    def catchall_degraded(self, *, target, what, disc, poc):
        """Finding de NON-VÉRIFICATION posé quand la cible ne discrimine pas ses routes. Réutilise
        `degraded()` (status='skipped') : le vocabulaire « je n'ai pas pu vérifier » existe déjà."""
        return self.degraded(
            target=target,
            title=f"{what} non testé — la cible ne DISCRIMINE PAS ses routes (catch-all)",
            evidence=CATCHALL_PREFIX.format(why=disc.why()),
            poc=poc)

    @staticmethod
    def _content_type(headers):
        """Content-Type NORMALISÉ (type/sous-type minuscule, paramètres retirés) depuis un mapping
        d'en-têtes (ou None). '' si absent/illisible. Source unique de l'extraction recopiée dans
        access_control (cadre la comparaison différentielle : html vs json ≠ même objet). Ne lève jamais."""
        ct = ""
        if headers is not None:
            try:
                ct = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
            except Exception:            # noqa: BLE001
                ct = ""
        return ct

    # =============================================================================================
    #  FORME DE LA REQUÊTE D'INJECTION — UN SEUL endroit (défaut D6 du banc de détection)
    #
    #  QUATRE implémentations INDÉPENDANTES du MÊME geste vivaient dans `injection.py::_send`,
    #  `clientflow.py::_send_h`, `rce.py::_send` et `ssrf.py::_inject`, toutes bâties ainsi :
    #
    #      sep = "&" if "?" in action.target else "?"
    #      url  = f"{action.target}{sep}{urlencode({param: payload})}"     # GET  : AJOUTE
    #      data = urlencode({param: payload})                             # POST : REMPLACE TOUT
    #
    #  DEUX faux négatifs MESURÉS, chacun INVISIBLE sur une seule cible (ils dépendent du PARSEUR) :
    #
    #    - GET, parseur PREMIER-GAGNANT. `…?id=1&Submit=Submit` + payload donne `…&id=<payload>` ;
    #      Werkzeug 2.2.3 — la pile réelle de VAmPI — rend
    #      `MultiDict(parse_qsl("id=1&Submit=Submit&id=INJECTION")).get("id") == "1"` (mesuré DANS
    #      le conteneur de l'app). La charge n'atteint JAMAIS le sink et l'oracle rend malgré tout
    #      « non confirmé ». En PHP c'est le DERNIER qui gagne, donc la même sonde marche : le défaut
    #      est structurellement indétectable sur un échantillon d'une seule pile.
    #
    #    - POST, corps REMPLACÉ. Le corps ne portait QUE le paramètre injecté. DVWA exige le
    #      co-paramètre `Submit` (`isset($_POST['Submit'])`). Mesuré sur l'application :
    #      `ip=127.0.0.1;echo FORGEMARK123` -> 0 occurrence ; le MÊME payload avec `&Submit=Submit`
    #      -> 1 occurrence (commande exécutée). Il n'existait AUCUN canal pour porter un
    #      co-paramètre : la RCE était hors d'atteinte PAR CONSTRUCTION, pas seulement manquée.
    #
    #  LE GESTE JUSTE, ÉCRIT UNE FOIS : REMPLACER la valeur du paramètre ciblé en PRÉSERVANT les
    #  autres paramètres de la requête — le MÊME geste en GET et en POST. « Les autres » sont ceux
    #  que l'action DÉCRIT, c'est-à-dire la query string de sa cible : c'est déjà ainsi que le
    #  cerveau décrit un endpoint injectable (`brain._query_params` dérive `param`/`value` de cette
    #  même query). Aucun vocabulaire nouveau, aucun champ de params supplémentaire.
    #
    #  POURQUOI ICI. Ces quatre modules n'ont en commun QUE cette base : `Oracle` porte déjà `_http`
    #  (l'entrée réseau) et `_curl` (la forme rejouable de la requête). La forme ÉMISE est le pendant
    #  exact de la forme rejouée — elle appartient au même endroit. Quatre correctifs séparés
    #  rediverger*aient* ; celui-ci ne peut pas : il n'y en a qu'un.
    #
    #  AUCUNE CAPACITÉ ÉLARGIE. La méthode HTTP n'est pas choisie ici (elle vient de `params.method`),
    #  le scope-guard et le ROE restent en amont, et un POST qui porte désormais ses co-paramètres
    #  reste EXACTEMENT la requête que l'action décrivait — `allow_destructive` continue de gater les
    #  méthodes d'écriture, inchangé.
    # =============================================================================================
    @staticmethod
    def _merge_param(pairs, param, payload):
        """Paires (nom, valeur) où `param` porte `payload` : REMPLACÉ EN PLACE s'il est présent (sa
        POSITION d'origine est conservée, et ses éventuels DOUBLONS sont collapsés en une seule
        valeur — un parseur premier-gagnant et un parseur dernier-gagnant doivent lire la MÊME
        chose), AJOUTÉ en queue sinon. Toutes les autres paires sont préservées, dans l'ordre.
        Pur, ne lève jamais."""
        name, val, out, placed = str(param), str(payload), [], False
        for k, v in pairs:
            if k != name:
                out.append((k, v))
            elif not placed:
                out.append((k, val))
                placed = True
        if not placed:
            out.append((name, val))
        return out

    @classmethod
    def inject_request(cls, target, param, payload, method="GET"):
        """(url, data) de LA requête d'injection — SOURCE UNIQUE de la forme (cf. bloc ci-dessus).

        - `method` GET -> (URL dont la query porte `param=payload` À LA PLACE de sa valeur d'origine,
          les AUTRES paramètres intacts et dans l'ordre ; `data=None`) ;
        - toute autre méthode -> (`target` INCHANGÉ, corps urlencodé portant les paramètres de la
          query de `target` PLUS `param=payload`). L'URL n'est délibérément PAS réécrite : le routage
          de la cible reste exactement celui d'aujourd'hui ; c'est le CORPS — qui ne portait que le
          paramètre injecté — qui gagne les co-paramètres que l'action déclare.

        Sur une cible SANS query — le cas courant — les deux branches sont BYTE-IDENTIQUES à l'ancien
        code. Ne lève JAMAIS : une URL illisible retombe sur la concaténation historique."""
        tgt = str(target or "")
        is_get = str(method or "GET").upper() == "GET"
        try:
            sp = urllib.parse.urlsplit(tgt)
            body = urllib.parse.urlencode(cls._merge_param(
                urllib.parse.parse_qsl(sp.query, keep_blank_values=True), param, payload))
        except Exception:            # noqa: BLE001 (URL hostile : jamais d'exception dans un oracle)
            qs = urllib.parse.urlencode({param: payload})
            return ((f"{tgt}{'&' if '?' in tgt else '?'}{qs}", None) if is_get else (tgt, qs))
        if is_get:
            return urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, body, sp.fragment)), None
        return tgt, body

    # --- PoC curl partagé (IDOR / SSRF / ATO) — un drapeau -H par en-tête (commande rejouable) ---
    @staticmethod
    def _curl(url, headers, method="GET", data=None):
        """PoC curl valide : un `-H` par en-tête (jamais un repr de dict), `-X` si non-GET,
        `--data` si corps, URL quotée en dernier. Sortie identique pour IDOR/SSRF/ATO."""
        parts = ["curl", "-sS"]
        if method and method.upper() != "GET":
            parts += ["-X", method.upper()]
        for k, v in (headers or {}).items():
            parts += ["-H", f"'{k}: {v}'"]
        if data is not None:
            parts += ["--data", f"'{data}'"]
        parts.append(f"'{url}'")
        return " ".join(parts)


class ScopeGuardedOracle(ScopeGuardMixin, Oracle):
    """Base des oracles à VÉRIFICATION qui portent un SCOPE-GUARD NATIF fail-closed (défense en
    profondeur : l'engine gate déjà en Couche 2, on re-valide localement AVANT tout réseau) + une
    DÉGRADATION GRACIEUSE uniforme (`status='skipped'` quand le réseau/outil optionnel est absent,
    pour que les tests offline passent). Ce mixin ne porte AUCUNE capacité élargie : exploit/
    destructive restent déclarés par chaque module concret et gardés par le ROE.

    Le scope-guard (`_scope`/`_in_scope`) vit dans `ScopeGuardMixin` (source UNIQUE à auditer)."""

    def _scope_refused(self, action):
        """Refus fail-closed : cible hors périmètre -> Finding `skipped` INFO, AUCUNE requête émise.
        Le matériel secret et le réseau ne peuvent physiquement pas quitter le périmètre déclaré."""
        return self.degraded(
            target=action.target,
            title=f"{self.kind} non testé — cible hors périmètre (scope-guard fail-closed)",
            evidence="La cible n'appartient pas au périmètre in-scope ; aucune requête émise (fail-closed).",
            poc=self.dry(action))

    # `degraded()` vit désormais sur `Oracle` (héritée telle quelle, corps identique) : les oracles
    # sans scope-guard propre en ont besoin aussi pour refuser de conclure sur un réseau muet.

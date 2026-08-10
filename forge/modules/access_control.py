# SPDX-License-Identifier: AGPL-3.0-or-later
"""access_control.idor — la classe qualifiante n°1 : IDOR/BOLA (oracle différentiel 2-comptes).

Oracle différentiel (A possède l'objet, B le récupère-t-il ?
unauth refusé ?). exploit=True -> exige allow_exploit dans le ROE. Pur urllib (stdlib). Lit
comptes+URLs depuis action.params (injectés par la CLI depuis le scope).

DURCISSEMENT (LOT ORACLES) — l'oracle naïf (abs(len)<=5% ET corps[:500] identiques) produisait
des FAUX POSITIFS (un token CSRF/horodatage/nonce différent à chaque réponse cassait l'égalité de
préfixe — ou pire, deux pages d'erreur 200 « accès refusé » au corps quasi-identique passaient pour
identiques) et des FAUX NÉGATIFS (le moindre champ volatile dans les 500 premiers octets niait un vrai
IDOR). Le nouvel oracle NORMALISE le corps (retire CSRF/nonces/horodatages/UUID/CSP-nonce) puis compare
status + content-type + HASH du corps normalisé ENTIER (pas un préfixe brut). Promotion `vulnerable`
réservée à la preuve cross-account NETTE : B obtient le même corps normalisé que A (statuts 2xx) ET
l'anonyme est refusé. Tout le reste -> `tested` (jamais `vulnerable` à l'aveugle).

Ce module a été SORTI de `web.py` (qui n'enregistre plus que `web.nuclei`) et rebâti sur la base
`Oracle` (construction Finding + curl partagés). Le chemin `tool=` des findings reste la chaîne
historique `forge/modules/web.py:access_control.idor` pour préserver une sortie byte-à-byte stable.
"""
import hashlib
import re

from .. import techniques
from .. import session as _session
from ..redact import redact_secrets
from .oracle import Oracle, ScopeGuardedOracle
from .registry import register

# Tokens volatils à neutraliser AVANT comparaison de corps : un IDOR réel renvoie le MÊME objet à A
# et B, mais les anti-CSRF/horodatages/nonces/UUID/ETags diffèrent à chaque réponse. Sans cette
# normalisation, deux rendus du MÊME objet paraissent différents (faux négatif) — et l'égalité de
# préfixe brut laissait passer deux pages d'erreur distinctes (faux positif). On remplace chaque motif
# par un jeton stable : on compare la STRUCTURE/DONNÉE, pas le bruit de session.
_VOLATILE = [
    # csrf / xsrf / authenticity / nonce — clés JSON ou champs de formulaire cachés
    (re.compile(r'(?i)("?(?:csrf[_-]?token|xsrf[_-]?token|authenticity_token|_token|nonce|request[_-]?id|requestid)"?\s*[:=]\s*)"?[A-Za-z0-9._\-+/=]+"?'), r'\1"<TOK>"'),
    (re.compile(r'(?i)(name=["\']?(?:csrf[_-]?token|authenticity_token|_token|__RequestVerificationToken)["\']?[^>]*value=["\'])[^"\']+'), r'\1<TOK>'),
    # nonce CSP dans une balise script/style
    (re.compile(r'(?i)\bnonce=["\'][A-Za-z0-9+/=_\-]+["\']'), 'nonce="<NONCE>"'),
    # UUID v1-5
    (re.compile(r'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'), '<UUID>'),
    # horodatages ISO-8601 (avec ou sans Z/offset)
    (re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?\b'), '<TS>'),
    # epoch (10/13 chiffres) en valeur JSON de clé temporelle
    (re.compile(r'(?i)("?(?:timestamp|ts|time|date|expires?|iat|exp|generated[_-]?at)"?\s*[:=]\s*)\d{10,13}'), r'\1<TS>'),
    # ETag / Last-Modified embarqués
    (re.compile(r'(?i)\bETag:\s*"[^"]+"'), 'ETag: "<ETAG>"'),
]


def _normalize_body(body):
    """Retire les tokens volatils (CSRF/nonce/UUID/horodatages) pour comparer le CONTENU, pas le bruit.
    Idempotent et pur. Le corps vide reste vide (un refus 401/403 a typiquement un corps vide/court)."""
    if not body:
        return ""
    out = body
    for rx, repl in _VOLATILE:
        out = rx.sub(repl, out)
    # collapse des blancs (indentation/pagination cosmétique ne doit pas casser l'égalité)
    return re.sub(r'\s+', ' ', out).strip()


def _body_hash(body):
    return hashlib.sha256(_normalize_body(body).encode("utf-8", "replace")).hexdigest()


class _ContentTypedOracle:
    """Mixin partagé portant le seul `_fetch` renvoyant `(status, body, content_type)` — le seam
    monkeypatché par les tests. Factorise le fetch IDENTIQUE de `IdorDifferential` et `PrivEsc` (le
    câblage urllib partagé `Oracle._http` + normalisation du content-type). Mixin pur (hérite
    d'`object`) : n'ajoute AUCUNE capacité, chaque oracle garde sa base et ses flags gardés par le ROE."""

    @staticmethod
    def _fetch(url, headers, timeout=15, method="GET", body=None):
        """(status, body, content_type). content_type cadre la comparaison : deux corps de types
        différents (html vs json) ne sont jamais « le même objet ». body peut être None.
        Adosse le câblage urllib partagé (Oracle._http) — seam monkeypatché par les tests."""
        st, txt, h = Oracle._http(url, headers=headers, timeout=timeout, method=method, data=body, maxlen=200000)
        return st, txt, Oracle._content_type(h)


@register("access_control.idor")
class IdorDifferential(_ContentTypedOracle, ScopeGuardedOracle):
    # MRO : _ContentTypedOracle (mixin object) -> ScopeGuardedOracle -> ScopeGuardMixin -> Oracle. Le
    # scope-guard fail-closed reste EN AMONT d'Oracle (ScopeGuardMixin prime), comme pour PrivEsc.
    kind = "access_control.idor"
    exploit = True                       # accède à l'objet d'un autre user -> exige allow_exploit
    destructive = False                  # GET = lecture ; les méthodes write sont gardées (voir _is_write)
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = "T1190"                      # Exploit Public-Facing Application (CWE-639)
    cwe = techniques.cwe_for("access_control.idor")   # source de vérité : forge/techniques.py (CWE-639)
    tool = "forge/modules/web.py:access_control.idor"  # chaîne historique — sortie byte-à-byte stable
    description = ("Oracle différentiel IDOR/BOLA à PREUVE sur 2 comptes : A possède l'objet, "
                  "B obtient-il le MÊME corps normalisé (anon refusé) ? Énumère aussi des IDs. CWE-639.")

    # Remédiations spécifiques (le fix lecture diffère du fix écriture — passés explicitement à proof()).
    _FIX_READ = ("Contrôle d'ownership côté serveur : vérifier que l'utilisateur authentifié possède "
                 "bien l'objet ciblé avant toute lecture (ne pas se fier à l'identifiant fourni par le "
                 "client) ; préférer des identifiants non énumérables (UUID) et une autorisation "
                 "centralisée deny-by-default.")
    _FIX_WRITE = ("Contrôle d'ownership côté serveur sur les écritures : vérifier que l'utilisateur "
                  "authentifié possède l'objet avant toute mutation (PUT/PATCH/DELETE) ; refuser "
                  "deny-by-default si la ressource n'appartient pas au compte ; identifiants non "
                  "énumérables (UUID).")

    # Statuts considérés comme « accès accordé » (lecture du contenu de l'objet)
    _OK = (200, 206)
    # Statuts considérés comme « accès refusé » côté anonyme (preuve que la ressource est protégée)
    _DENY = (401, 403)

    def dry(self, action):
        urls = list(action.params.get("urls", []))
        ids = action.params.get("enum_ids")
        method = str(action.params.get("method", "GET")).upper()
        n = len(urls) or "?"
        enum = f" ; énumération IDs={list(ids)[:5]}{'…' if ids and len(list(ids)) > 5 else ''}" if ids else ""
        if self._is_write(method):
            return (f"# IDOR write-oracle {method} sur {n} URL(s) de A : B tente {method}, on RELIT en A "
                    f"(GET) ; flag si l'effet de B est visible chez A (corps normalisé modifié){enum}")
        return (f"# différentiel IDOR 2-comptes sur {n} URL(s) possédées par A : GET en A, B, anon ; "
                f"flag si B obtient le même corps NORMALISÉ que A et anon refusé{enum}")

    @staticmethod
    def _is_write(method):
        return method in ("POST", "PUT", "PATCH", "DELETE")

    @staticmethod
    def _same_object(resp_a, resp_b):
        """Preuve « B lit l'objet de A » : status accordé des deux côtés, MÊME content-type, et
        MÊME hash de corps NORMALISÉ (CSRF/nonce/horodatages retirés). On refuse un corps vide
        (un 200 sans corps n'est pas une preuve de lecture)."""
        sa, ba, ca = resp_a
        sb, bb, cb = resp_b
        if sa not in IdorDifferential._OK or sb not in IdorDifferential._OK:
            return False
        if ca != cb:                     # types divergents -> pas le même objet
            return False
        na = _normalize_body(ba)
        if not na:                       # pas de contenu à comparer -> pas de preuve
            return False
        return _body_hash(ba) == _body_hash(bb)

    @staticmethod
    def _attacker_headers(accounts):
        """En-têtes du compte ATTAQUANT (labellisé 'attacker' sinon le 1er). DÉLÈGUE à la SOURCE UNIQUE
        `session.attacker_headers_from_params` (convention partagée byte-identique avec AuthTakeover)."""
        return _session.attacker_headers_from_params(accounts)

    def _fire_auth_targets(self, action, accounts, targets):
        """R5 — SLICE CROSS-COMPTE via CONTEXTE AUTH PAR-ENGAGEMENT. Pour chaque idor_target
        {url, owner, marker} : l'ATTAQUANT (session de l'opérateur) récupère la ressource POSSÉDÉE par
        la victime ; PREUVE NETTE = le marqueur (donnée de la victime) apparaît dans SA réponse (statut
        2xx), OU — sans marqueur — il obtient un 2xx là où l'anonyme est REFUSÉ (401/403). Lecture
        seule (GET). Scope-guard fail-closed PAR-URL (aucune requête hors périmètre). Le PoC/evidence
        est RÉDIGÉ à la source (les en-têtes de l'attaquant y affleureraient sinon)."""
        attacker = self._attacker_headers(accounts)
        attacker_label = _session.attacker_label_from_params(accounts)
        findings = []
        for t in targets:
            url = (t or {}).get("url")
            if not url:
                continue
            marker = str((t or {}).get("marker") or "")
            owner = str((t or {}).get("owner") or "victim")
            # SCOPE-GUARD PAR-URL fail-closed — une idor_target hors périmètre : AUCUN I/O vers elle
            # (le matériel d'auth secret ne peut physiquement pas quitter le périmètre déclaré).
            if not self._in_scope(action, url):
                findings.append(self.degraded(
                    target=url,
                    title="IDOR non testé — idor_target hors périmètre (scope-guard fail-closed)",
                    evidence="Cette idor_target n'est pas in-scope ; aucune requête émise (fail-closed).",
                    poc=self.dry(action)))
                continue
            if attacker is None:
                findings.append(self.skip(
                    target=url, title="IDOR non testé — compte attaquant manquant",
                    evidence=("Requiert au moins un compte (auth.accounts) fournissant les en-têtes de "
                              "l'attaquant pour rejouer la requête cross-compte."),
                    poc=self.dry(action)))
                continue
            # MATÉRIEL PÉRIMÉ => AUCUN VERDICT, AUCUNE REQUÊTE. Un `exp` dépassé est une preuve
            # AUTONOME que l'oracle est désarmé : tirer produirait trois refus et un « IDOR non
            # confirmé » qui certifierait un test cross-compte jamais réellement authentifié.
            if self.auth_expired(attacker):
                findings.append(self.auth_dead(
                    target=url, label=attacker_label, why=self.WHY_EXPIRED,
                    title="IDOR non testé — matériel d'authentification de l'attaquant EXPIRÉ",
                    poc=self.dry(action)))
                continue
            r_att = self._fetch(url, attacker)               # (status, body, content_type)
            # SONDE DE CONTRÔLE : rôle ANONYME DÉCLARÉ (D1/D2). Sans ce marquage, la session
            # gouvernée (`scope.session`) partait AVEC elle et son 401 attendu devenait un 200 :
            # `anon_refusé=False` était IMPRIMÉ dans l'evidence de findings par ailleurs corrects
            # (Juice Shop : `/rest/basket/1` répond 401 à un vrai anonyme, l'evidence disait 200),
            # et un relecteur y lisait « ressource publique » sur un vrai positif.
            r_anon = self._fetch_anonymous(url, {})
            # CIBLE INJOIGNABLE => AUCUN VERDICT (att_ok/anon_denied/marker_hit tous faux sur un corps
            # vide -> « IDOR non confirmé » pour une requête jamais partie).
            if r_att[0] is None or r_anon[0] is None:
                findings.append(self.degraded(
                    target=url,
                    title="IDOR non testé — cible injoignable (aucune réponse)",
                    evidence=(f"Au moins une sonde n'a pas répondu (attaquant={r_att[0]}, "
                              f"anonyme={r_anon[0]}) : le différentiel cross-compte n'a pas pu être évalué."),
                    poc=self.dry(action)))
                continue
            # MATÉRIEL INERTE => AUCUN VERDICT. La cible traite l'attaquant EXACTEMENT comme un
            # anonyme : sa session n'est pas reconnue, donc l'absence de marqueur victime ne prouve
            # rien du contrôle d'accès (elle ne fait que refléter une requête non authentifiée).
            if self.auth_inert((r_att[0], r_att[1]), (r_anon[0], r_anon[1])):
                findings.append(self.auth_dead(
                    target=url, label=attacker_label, why=self.WHY_INERT,
                    title="IDOR non testé — matériel d'authentification de l'attaquant SANS EFFET",
                    poc=self.dry(action)))
                continue
            att_ok = r_att[0] in self._OK
            anon_denied = r_anon[0] in self._DENY
            marker_hit = bool(marker) and att_ok and (marker in (r_att[1] or ""))
            # =====================================================================================
            #  D3 — LE MARQUEUR EST-IL LISIBLE SANS AUCUNE SESSION ? (véto de PUBLICITÉ)
            #
            #  `proven = marker_hit` seul promouvait un HIGH « l'attaquant lit la ressource de la
            #  victime » sur une ressource PUBLIQUE. Contre-épreuve du banc : `GET /users/v1` de
            #  VAmPI répond 200 à un anonyme PAR CONCEPTION et liste tous les utilisateurs ; déclaré
            #  en `idor_target {owner: victim, marker: "victim1"}`, il rendait « IDOR CONFIRMÉ ».
            #  Un marqueur trouvé dans une ressource publique ne prouve AUCUNE appartenance : la
            #  session de l'attaquant n'a rien acheté.
            #
            #  LE DISCRIMINANT N'EST PAS « ANON REFUSÉ ». Exiger `anon_denied` pour promouvoir serait
            #  l'EXCÈS INVERSE : il tuerait les vrais IDOR sur les ressources qui répondent 2xx à
            #  tout le monde mais dont le CONTENU privé n'apparaît qu'authentifié (l'anonyme obtient
            #  une vue générique/vide — le marqueur, lui, reste hors de sa portée). Ce qui doit être
            #  prouvé est plus étroit et plus juste : **la donnée de la victime n'était pas
            #  atteignable sans session**. On ne regarde donc pas le STATUT de l'anonyme, on regarde
            #  si LE MARQUEUR est revenu dans SA réponse — quel que soit ce statut (un marqueur servi
            #  dans un corps de 403 est tout aussi public).
            #
            #  La sonde qui porte ce véto est celle de D1 : sans le rôle anonyme déclaré ci-dessus,
            #  elle emportait la session gouvernée, voyait le marqueur pour cette SEULE raison, et le
            #  véto se serait retourné en faux négatif. Les deux correctifs sont indissociables.
            # =====================================================================================
            marker_public = bool(marker) and (marker in (r_anon[1] or ""))
            # status-delta = corroborateur FAIBLE, JAMAIS promouvant : « attaquant 2xx / anon refusé »
            # prouve seulement que l'endpoint REQUIERT une auth — c'est VRAI pour tout endpoint
            # per-user que l'attaquant possède LÉGITIMEMENT (/api/me, /api/settings). Il ne démontre
            # AUCUN accès cross-compte (aucune requête n'est faite avec la session du PROPRIÉTAIRE,
            # aucune donnée d'autrui n'est observée). Sans marqueur victime et sans différentiel
            # propriétaire, ce chemin ne PROMEUT donc PAS (jadis `proven = att_ok and anon_denied` ->
            # faux HIGH « IDOR CONFIRMÉ » sur un accès à sa propre ressource).
            status_delta = att_ok and anon_denied
            # PREUVE SAINE (seule à promouvoir ici) : le marqueur de la victime (donnée d'AUTRUI)
            # présent dans la réponse de l'attaquant ET **hors de portée d'un anonyme** (véto D3 —
            # sans lui, une ressource publique portant le marqueur promeut un faux HIGH). Le
            # différentiel de contenu à session propriétaire vit dans _fire_read (2 comptes) ; ce
            # slice cross-compte ne l'exerce pas.
            proven = marker_hit and not marker_public
            if proven:
                title = "IDOR CONFIRMÉ — l'attaquant lit la ressource de la victime (accès cross-compte)"
                severity = "HIGH"
                how = ("marqueur de la victime présent dans la réponse de l'attaquant ET ABSENT de la "
                       "réponse à la sonde ANONYME (la donnée exigeait bien une session)")
            elif marker_public:
                # Le marqueur revient AUSSI sans aucune session : la ressource est publique pour cette
                # donnée. La session de l'attaquant n'a rien acheté -> AUCUNE appartenance prouvée.
                title = ("IDOR non confirmé — marqueur LISIBLE ANONYMEMENT (ressource publique) : "
                         "aucune appartenance prouvée")
                severity = "INFO"
                how = ("marqueur présent AUSSI dans la réponse de la sonde ANONYME — la donnée est "
                       "publique, la session de l'attaquant n'achète aucun accès cross-compte")
            elif status_delta:
                title = ("IDOR non confirmé — endpoint requiert une auth ; accès cross-compte NON prouvé "
                         "(ni marqueur victime, ni différentiel propriétaire)")
                severity = "INFO"
                how = ("status-delta SEUL (attaquant 2xx / anon 401/403) — prouve seulement que l'endpoint "
                       "requiert une auth, PAS l'accès cross-compte ; corroborateur faible, non-promouvant")
            else:
                title = "IDOR non confirmé (cross-compte auth)"
                severity = "INFO"
                how = "aucun signal cross-compte concluant"
            # RÉDACTION à la source : le PoC embarque les en-têtes de l'attaquant (Cookie/Authorization)
            # et l'evidence pourrait refléter du matériel — on masque AVANT de figer dans le finding,
            # pour que même le ledger brut (`finding` append non rédigé) ne porte aucun secret.
            poc = redact_secrets(self._curl(url, attacker))
            evidence = redact_secrets(
                f"attaquant={r_att[0]}/{r_att[2] or '?'} anon={r_anon[0]} owner={owner!r} "
                f"marqueur={'présent' if marker_hit else ('absent' if marker else 'n/a')} "
                f"marqueur_lisible_anonymement={marker_public} (véto de PUBLICITÉ : un marqueur "
                f"servi sans session ne prouve aucune appartenance) "
                f"status-delta={status_delta} (corroborateur faible, non-promouvant) "
                f"anon_refusé={anon_denied} ; sonde anonyme tirée SANS matériel de session gouverné ; "
                f"preuve={how} ; compte attaquant DÉTENU par l'opérateur "
                "(jamais un tiers) ; matériel d'auth rédigé")
            findings.append(self.proof(
                target=url, proven=proven,
                title=title,
                severity=severity,
                fix=self._FIX_READ,
                evidence=evidence, poc=poc))
        return findings

    def fire(self, action):
        # SCOPE-GUARD fail-closed sur la cible primaire — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        accounts = action.params.get("accounts", [])
        findings = []
        # R5 — CONTEXTE AUTH PAR-ENGAGEMENT : des idor_targets STRUCTURÉS {url, owner, marker} injectés
        # par l'engine depuis `scope.auth` déclenchent le slice cross-compte à MARQUEUR (rejeu avec la
        # session de l'attaquant). Ne consomme QUE le compte attaquant. L'oracle ato/takeover consomme
        # les MÊMES `accounts` (R5b, cf. auth.py::_fire_auth_context). ABSENT => chemin
        # historique inchangé (différentiel 2-comptes sur `urls`, ou skip « config manquante »).
        auth_targets = action.params.get("idor_targets")
        if auth_targets:
            findings.extend(self._fire_auth_targets(action, accounts, list(auth_targets)))
        # FIX B3 — UNION (plus d'early-return) : une action IDOR CHAÎNÉE sur un endpoint découvert porte
        # `urls=[endpoint]` (edge C) EN PLUS des idor_targets injectés par l'engine. L'ancien early-return
        # sur `idor_targets` laissait cette surface DÉCOUVERTE sans AUCUN test IDOR. On teste donc AUSSI
        # `urls` via le différentiel 2-comptes, dédupliqué par URL vs les idor_targets déjà couvertes.
        base_urls = list(action.params.get("urls", []))
        method = str(action.params.get("method", "GET")).upper()
        # Énumération d'IDs : on substitue chaque id dans un template d'URL contenant `{id}`.
        # (ne crée pas de capacité — ce sont des GET/écritures déjà gardés par le ROE ; juste plus d'objets).
        enum_ids = action.params.get("enum_ids") or []
        templates = action.params.get("url_template")
        urls = list(base_urls)
        if templates and enum_ids:
            tlist = templates if isinstance(templates, (list, tuple)) else [templates]
            for t in tlist:
                for i in enum_ids:
                    urls.append(str(t).replace("{id}", str(i)))
        # dédupe : préserver l'ordre + retirer les URL déjà testées comme idor_target (pas de double tir).
        covered = {str((t or {}).get("url")) for t in (auth_targets or []) if isinstance(t, dict)}
        urls = [u for u in dict.fromkeys(urls) if str(u) not in covered]
        if not urls:
            # rien à tester en plus des idor_targets : renvoyer leurs findings, sinon skip « config manquante »
            # (byte-identique à l'historique quand il n'y a ni urls ni idor_targets).
            return findings or [self.skip(
                target=action.target, title="IDOR non testé — config manquante",
                evidence=("Requiert params.accounts (>=2 : A propriétaire, B attaquant) et "
                          "params.urls (ou params.url_template avec {id} + params.enum_ids)."),
                poc=self.dry(action))]
        if len(accounts) < 2:
            # des URL restent à tester mais pas 2 comptes pour le différentiel : si des idor_targets ont
            # déjà été testées, on renvoie leurs findings ; sinon skip « config manquante » (historique).
            return findings or [self.skip(
                target=action.target, title="IDOR non testé — config manquante",
                evidence=("Requiert params.accounts (>=2 : A propriétaire, B attaquant) et "
                          "params.urls (ou params.url_template avec {id} + params.enum_ids)."),
                poc=self.dry(action))]
        A, B = accounts[0], accounts[1]
        if self._is_write(method):
            # FAIL-CLOSED capacité : le module se déclare destructive=False (le chemin par défaut, GET,
            # est en lecture seule). Le chemin write MUTE l'objet d'un autre user -> on REFUSE de tirer
            # tant que l'action n'a pas été explicitement autorisée comme destructive par le ROE
            # (allow_destructive => engine pose action.destructive=True). Sinon : finding INFO, AUCUNE
            # requête write émise. Le module ne s'auto-élargit jamais une capacité non gardée.
            if not getattr(action, "destructive", False):
                findings.append(self.skip(
                    target=action.target,
                    title=f"IDOR write {method} non tiré — capacité destructive non autorisée",
                    evidence=(f"La méthode {method} mute l'objet (destructif). Requiert allow_destructive "
                              f"dans le ROE + action.destructive=True. Aucune requête write émise (fail-closed)."),
                    poc=self.dry(action)))
                return findings
            findings.extend(self._fire_write(action, A, B, urls, method))
            return findings
        findings.extend(self._fire_read(action, A, B, urls))
        return findings

    def _fire_read(self, action, A, B, urls):
        """Oracle IDOR par DIFFÉRENTIEL de CONTENU (2 comptes) : B lit le corps normalisé identique à A
        et l'anon est refusé -> IDOR.

        ⚠️ LIMITATION (faux positif possible) — le différentiel de CONTENU seul ne peut pas distinguer
        « B accède à la ressource PRIVÉE de A » de « A et B sont TOUS DEUX légitimement autorisés à lire
        une ressource PARTAGÉE » (doc d'équipe, objet public-authentifié…) : dans les deux cas `same` est
        vrai et l'anon refusé. Contrat d'usage : les `urls` (et les `idor_targets`) DOIVENT désigner des
        ressources auxquelles le compte ATTAQUANT (B) n'est PAS habilité (possédées par A seul). Le chemin
        à MARQUEUR (`_fire` sur `idor_targets={url, owner, marker}`, où B doit voir un marqueur PROPRE à A)
        est PRÉFÉRÉ : il prouve l'appartenance à A et élimine ce faux positif de ressource partagée."""
        findings = []
        dead = self.expired_account(A, B)        # matériel PÉRIMÉ d'un des deux comptes (aucun réseau)
        for url in urls:
            # SCOPE-GUARD PAR-URL fail-closed — une URL (souvent une IDOR chaînée/énumérée) hors
            # périmètre : AUCUN I/O vers elle (le matériel secret ne peut pas quitter le périmètre).
            if not self._in_scope(action, url):
                findings.append(self.degraded(
                    target=url,
                    title="IDOR non testé — URL hors périmètre (scope-guard fail-closed)",
                    evidence="Cette URL n'est pas in-scope ; aucune requête émise (fail-closed).",
                    poc=self.dry(action)))
                continue
            # MATÉRIEL PÉRIMÉ => AUCUN VERDICT, AUCUNE REQUÊTE. Le différentiel exige DEUX sessions
            # vivantes : si celle de A (propriétaire) ou celle de B (attaquant) est morte, « corps
            # identiques » et « anon refusé » ne décrivent plus un contrôle d'accès.
            if dead is not None:
                findings.append(self.auth_dead(
                    target=url, label=dead, why=self.WHY_EXPIRED,
                    title="IDOR non testé — matériel d'authentification EXPIRÉ (différentiel 2 comptes)",
                    poc=self.dry(action)))
                continue
            ra = self._fetch(url, A.get("headers", {}))
            rb = self._fetch(url, B.get("headers", {}))
            # SONDE DE CONTRÔLE : rôle ANONYME DÉCLARÉ (D1). C'est ELLE qui porte le véto `anon_denied`
            # de la promotion `vuln = same and anon_denied` : authentifiée par la session gouvernée,
            # elle rendait 200 au lieu de 401 et ÉTEIGNAIT l'oracle IDOR — sans aucun signal.
            ru = self._fetch_anonymous(url, {})
            # CIBLE INJOIGNABLE => AUCUN VERDICT. Le différentiel exige les TROIS réponses ; sans elles
            # `same` et `anon_denied` sont faux par construction et l'oracle rendrait « IDOR non
            # confirmé » pour des requêtes jamais parties. Absence de réponse != absence de vuln.
            if ra[0] is None or rb[0] is None or ru[0] is None:
                findings.append(self.degraded(
                    target=url,
                    title="IDOR non testé — cible injoignable (aucune réponse)",
                    evidence=(f"Au moins une des trois sondes n'a pas répondu (A={ra[0]}, B={rb[0]}, "
                              f"anon={ru[0]}) : le différentiel de contenu exige les trois."),
                    poc=self.dry(action)))
                continue
            # MATÉRIEL INERTE => AUCUN VERDICT. Si un des deux comptes est traité comme un anonyme,
            # « B lit la même chose que A » ne dit plus rien du contrôle d'accès : les deux peuvent
            # simplement lire la même page de refus.
            inert = self.auth_inert_among(
                [(str(A.get("label", "")), (ra[0], ra[1])), (str(B.get("label", "")), (rb[0], rb[1]))],
                (ru[0], ru[1]))
            if inert is not None:
                findings.append(self.auth_dead(
                    target=url, label=inert, why=self.WHY_INERT,
                    title="IDOR non testé — matériel d'authentification SANS EFFET (différentiel 2 comptes)",
                    poc=self.dry(action)))
                continue
            same = self._same_object(ra, rb)
            anon_denied = ru[0] in self._DENY
            # PREUVE NETTE requise : B lit l'objet de A (même corps normalisé) ET l'anon est refusé.
            # Tout le reste (ressource publique, B refusé, verif non concluante) -> `tested`, jamais vuln.
            vuln = same and anon_denied
            findings.append(self.proof(
                target=url, proven=vuln,
                title=("IDOR CONFIRMÉ — B lit l'objet de A (corps normalisé identique, anon refusé)"
                       if vuln else "IDOR non confirmé (lecture)"),
                severity=("HIGH" if vuln else "INFO"),
                fix=self._FIX_READ,
                evidence=(f"A={ra[0]}/{ra[2] or '?'} B={rb[0]}/{rb[2] or '?'} anon={ru[0]} "
                          f"même_objet={same} anon_refusé={anon_denied} "
                          f"(hash normalisé A={_body_hash(ra[1])[:12]} B={_body_hash(rb[1])[:12]})"),
                poc=self._curl(url, B.get("headers", {}))))
        return findings

    def _fire_write(self, action, A, B, urls, method):
        """Oracle d'EFFET pour les méthodes write : B exécute l'écriture sur l'objet de A, puis on
        RELIT l'objet en A (GET). Preuve = le corps normalisé vu par A a CHANGÉ après l'action de B
        (l'écriture de B a muté l'objet d'un autre user). write -> destructif : gardé par le ROE."""
        body = action.params.get("body")
        findings = []
        dead = self.expired_account(A, B)        # matériel PÉRIMÉ d'un des deux comptes (aucun réseau)
        for url in urls:
            # SCOPE-GUARD PAR-URL fail-closed — jamais d'écriture vers une URL hors périmètre.
            if not self._in_scope(action, url):
                findings.append(self.degraded(
                    target=url,
                    title="IDOR write non testé — URL hors périmètre (scope-guard fail-closed)",
                    evidence="Cette URL n'est pas in-scope ; aucune requête émise (fail-closed).",
                    poc=self.dry(action)))
                continue
            # MATÉRIEL PÉRIMÉ => AUCUNE ÉCRITURE ÉMISE. L'oracle d'effet conclurait « write non
            # confirmé » sur une mutation cross-compte que la session morte n'a jamais pu tenter.
            # (Ce chemin n'a PAS de sonde anonyme : seule la péremption lisible est détectable ici.)
            if dead is not None:
                findings.append(self.auth_dead(
                    target=url, label=dead, why=self.WHY_EXPIRED,
                    title=f"IDOR write {method} non testé — matériel d'authentification EXPIRÉ",
                    poc=self.dry(action)))
                continue
            before = self._fetch(url, A.get("headers", {}), method="GET")
            wb = self._fetch(url, B.get("headers", {}), method=method, body=body)
            after = self._fetch(url, A.get("headers", {}), method="GET")
            # CIBLE INJOIGNABLE => AUCUN VERDICT. L'oracle d'EFFET compare avant/après : sans les trois
            # réponses, `mutated` est faux par construction et le « IDOR write non confirmé » (chemin
            # CRITICAL) certifierait une écriture cross-compte jamais tentée.
            if before[0] is None or wb[0] is None or after[0] is None:
                findings.append(self.degraded(
                    target=url,
                    title=f"IDOR write {method} non testé — cible injoignable (aucune réponse)",
                    evidence=(f"Au moins une sonde n'a pas répondu (avant={before[0]}, "
                              f"write_B={wb[0]}, après={after[0]}) : l'oracle d'effet exige les trois."),
                    poc=self.dry(action)))
                continue
            # B a-t-il été accepté ? (2xx) et l'objet de A a-t-il muté ?
            b_accepted = wb[0] in (200, 201, 202, 204, 206)
            mutated = (before[0] in self._OK and after[0] in self._OK
                       and _body_hash(before[1]) != _body_hash(after[1]))
            vuln = b_accepted and mutated
            findings.append(self.proof(
                target=url, proven=vuln,
                title=(f"IDOR write CONFIRMÉ — {method} de B a muté l'objet de A"
                       if vuln else f"IDOR write non confirmé ({method})"),
                severity=("CRITICAL" if vuln else "INFO"),
                fix=self._FIX_WRITE,
                evidence=(f"{method} B={wb[0]} accepté={b_accepted} ; A avant={before[0]}/"
                          f"{_body_hash(before[1])[:12]} après={after[0]}/{_body_hash(after[1])[:12]} "
                          f"muté={mutated}"),
                poc=self._curl(url, B.get("headers", {}), method=method, data=body)))
        return findings


# =================================================================================================
#  access_control.privesc — élévation de privilège VERTICALE / function-level à PREUVE DEUX-COMPTES-
#  OPÉRATEUR (T1068 / CWE-269) — NON DESTRUCTIF (lecture ; les méthodes write sont gardées destructive)
# =================================================================================================
@register("access_control.privesc")
class PrivEsc(_ContentTypedOracle, ScopeGuardedOracle):
    """Oracle d'élévation de privilège VERTICALE (function/object-level) à preuve, avec le contexte
    DEUX-COMPTES DE L'OPÉRATEUR : le compte BAS-PRIVILÈGE (accounts[0]) atteint-il une fonction/objet
    ADMIN-ONLY (accounts[1] = le compte privilégié de l'opérateur) qui DEVRAIT lui être refusé ?

    Preuve NETTE (jamais un verdict aveugle) : le compte bas-privilège obtient la fonction privilégiée
    (marqueur admin fourni par l'opérateur PRÉSENT dans SA réponse, OU même corps NORMALISÉ que le
    compte admin — statuts 2xx), le compte ADMIN l'obtient aussi (c'est bien une fonction privilégiée
    RÉELLE, pas une 404) ET l'anonyme est REFUSÉ (la fonction est bien protégée). Tout le reste ->
    `tested`. Comptes A(bas) et B(admin) DÉTENUS par l'opérateur — JAMAIS un tiers réel.

    Garde-fous : scope-guard fail-closed (cible + CHAQUE admin_url re-validés, hors-scope -> aucun I/O) ;
    non destructif (GET ; une méthode write MUTE -> gardée `destructive`, refusée sans allow_destructive) ;
    session gouvernée scope-guardée jamais journalisée."""

    kind = "access_control.privesc"
    exploit = True                       # atteint une fonction admin-only -> exige allow_exploit
    destructive = False                  # GET = lecture ; les méthodes write sont gardées (voir _is_write)
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("access_control.privesc")   # source de vérité : techniques.py (T1068)
    cwe = techniques.cwe_for("access_control.privesc")       # CWE-269 (Improper Privilege Management)
    tool = "forge/modules/access_control.py:access_control.privesc"
    fix = ("Contrôle d'accès FONCTION-PAR-FONCTION côté serveur (deny-by-default) : vérifier le RÔLE/les "
           "droits du principal authentifié sur CHAQUE fonction et objet admin-only avant de répondre ou "
           "d'agir ; ne jamais dériver le niveau de privilège d'un identifiant/paramètre fourni par le "
           "client ni de la seule présence d'un lien UI ; centraliser l'autorisation (RBAC) (CWE-269).")
    description = ("Oracle privesc VERTICALE (function-level) à PREUVE 2-comptes opérateur : le compte "
                   "bas-privilège atteint-il une fonction admin-only (compte admin = baseline, anon "
                   "refusé) ? Comptes DÉTENUS par l'opérateur. Sinon tested. CWE-269.")

    _OK = (200, 206)
    _DENY = (401, 403)

    @staticmethod
    def _is_write(method):
        return method in ("POST", "PUT", "PATCH", "DELETE")

    def _admin_urls(self, action):
        """Fonctions/objets ADMIN-ONLY à sonder : params.admin_urls (liste) + params.admin_url (single) +
        params.urls (compat). Dédupliqué en préservant l'ordre."""
        urls = list(action.params.get("admin_urls") or [])
        u = action.params.get("admin_url")
        if u:
            urls.append(u)
        urls += list(action.params.get("urls") or [])
        return list(dict.fromkeys(urls))

    def dry(self, action):
        method = str(action.params.get("method", "GET")).upper()
        n = len(self._admin_urls(action)) or "?"
        marker = action.params.get("admin_marker")
        how = (f"marqueur admin '{marker}'" if marker else "même corps NORMALISÉ que le compte admin")
        return (f"# privesc VERTICALE {method} sur {n} fonction(s) admin-only : le compte BAS-PRIVILÈGE "
                f"de l'opérateur les demande ; PREUVE = il obtient la fonction ({how}), le compte admin "
                f"l'obtient (baseline) ET l'anonyme est refusé ; comptes-opérateur uniquement ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed sur la cible primaire — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        accounts = action.params.get("accounts", [])
        urls = self._admin_urls(action)
        if len(accounts) < 2 or not urls:
            return [self.skip(
                target=action.target, title="Privesc non testé — config manquante",
                evidence=("Requiert params.accounts (>=2 : [0]=compte BAS-PRIVILÈGE opérateur, [1]=compte "
                          "ADMIN opérateur — jamais un tiers) et params.admin_urls (fonctions/objets "
                          "admin-only). Optionnel : params.admin_marker (chaîne unique de la fonction "
                          "privilégiée), params.method."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        # FAIL-CLOSED capacité : le chemin write MUTE (privesc via action admin) -> destructif. Refusé
        # tant que le ROE n'a pas autorisé (allow_destructive => action.destructive=True). Aucune requête.
        if self._is_write(method) and not getattr(action, "destructive", False):
            return [self.skip(
                target=action.target,
                title=f"Privesc write {method} non tiré — capacité destructive non autorisée",
                evidence=(f"La méthode {method} exécute une action privilégiée (destructif). Requiert "
                          f"allow_destructive dans le ROE + action.destructive=True. Aucune requête émise "
                          f"(fail-closed)."),
                poc=self.dry(action))]
        low, admin = accounts[0], accounts[1]
        marker = action.params.get("admin_marker")
        findings = []
        # MATÉRIEL PÉRIMÉ d'un des deux comptes-opérateur (aucun réseau) : la preuve de privesc exige
        # le compte BAS-PRIVILÈGE vivant (il doit atteindre la fonction) ET l'ADMIN vivant (baseline).
        dead = self.expired_account(low, admin)
        for url in urls:
            # (1bis) SCOPE-GUARD PAR-URL fail-closed — une admin_url hors périmètre : AUCUN I/O vers elle.
            if not self._in_scope(action, url):
                findings.append(self.degraded(
                    target=url,
                    title="Privesc non testé — fonction admin hors périmètre (scope-guard fail-closed)",
                    evidence="Cette fonction admin-only n'est pas in-scope ; aucune requête émise (fail-closed).",
                    poc=self.dry(action)))
                continue
            if dead is not None:
                findings.append(self.auth_dead(
                    target=url, label=dead, why=self.WHY_EXPIRED,
                    title="Privesc non testée — matériel d'authentification EXPIRÉ",
                    poc=self.dry(action)))
                continue
            r_low = self._fetch(url, low.get("headers", {}), method=method)
            r_admin = self._fetch(url, admin.get("headers", {}), method=method)
            # SONDE DE CONTRÔLE : rôle ANONYME DÉCLARÉ. MÊME défaut de classe que D1 sur l'IDOR —
            # `anon_denied` est un CONJOINT de la promotion privesc (`proven = low_reached and
            # baseline and anon_denied`), donc une sonde de contrôle authentifiée éteignait aussi
            # cet oracle-ci. Le banc ne l'a pas mesuré (aucune privesc amorcée) ; le défaut est le
            # même et se corrige au même endroit.
            r_anon = self._fetch_anonymous(url, {}, method=method)
            # CIBLE INJOIGNABLE => AUCUN VERDICT. Le titre négatif affirme « fonction non atteinte par le
            # bas-privilège » — une conclusion sur l'autorisation, alors qu'aucune requête n'a abouti.
            if r_low[0] is None or r_admin[0] is None or r_anon[0] is None:
                findings.append(self.degraded(
                    target=url,
                    title="Privesc non testée — fonction injoignable (aucune réponse)",
                    evidence=(f"Au moins une sonde n'a pas répondu (bas-priv={r_low[0]}, "
                              f"admin={r_admin[0]}, anon={r_anon[0]}) : la preuve exige les trois."),
                    poc=self.dry(action)))
                continue
            # MATÉRIEL INERTE => AUCUN VERDICT : un compte traité comme un anonyme ne peut ni
            # atteindre la fonction (bas-priv) ni servir de baseline (admin).
            inert = self.auth_inert_among(
                [(str(low.get("label", "")), (r_low[0], r_low[1])),
                 (str(admin.get("label", "")), (r_admin[0], r_admin[1]))],
                (r_anon[0], r_anon[1]))
            if inert is not None:
                findings.append(self.auth_dead(
                    target=url, label=inert, why=self.WHY_INERT,
                    title="Privesc non testée — matériel d'authentification SANS EFFET",
                    poc=self.dry(action)))
                continue
            low_ok = r_low[0] in self._OK
            admin_ok = r_admin[0] in self._OK
            anon_denied = r_anon[0] in self._DENY
            if marker:
                # PREUVE marqueur : la fonction privilégiée renvoie un marqueur admin unique. Le compte
                # bas-privilège l'obtient (il a exécuté la fonction admin) ET l'admin aussi (baseline).
                low_reached = low_ok and (marker in (r_low[1] or ""))
                baseline = admin_ok and (marker in (r_admin[1] or ""))
            else:
                # PREUVE différentielle : le compte bas-privilège obtient le MÊME corps NORMALISÉ que
                # l'admin (retire CSRF/nonce/horodatages) — même fonction privilégiée servie aux deux.
                low_reached = (low_ok and admin_ok and _normalize_body(r_low[1])
                               and _body_hash(r_low[1]) == _body_hash(r_admin[1]))
                baseline = admin_ok
            proven = bool(low_reached) and bool(baseline) and anon_denied
            findings.append(self.proof(
                target=url, proven=proven,
                title=("Privesc VERTICALE CONFIRMÉE — le compte bas-privilège atteint une fonction "
                       "admin-only (admin=baseline, anon refusé)" if proven
                       else "Privesc non confirmée — fonction non atteinte par le bas-privilège (ou non protégée)"),
                severity=("HIGH" if proven else "INFO"),
                evidence=(f"bas-priv={r_low[0]}/{r_low[2] or '?'} admin={r_admin[0]}/{r_admin[2] or '?'} "
                          f"anon={r_anon[0]} ; bas-priv_atteint={bool(low_reached)} baseline_admin={bool(baseline)} "
                          f"anon_refusé={anon_denied} ; preuve="
                          + (f"marqueur admin '{marker}'" if marker else "corps normalisé identique à l'admin")
                          + " ; comptes bas-priv ET admin DÉTENUS par l'opérateur (jamais un tiers) ; "
                          "session gouvernée non journalisée"),
                poc=self._curl(url, low.get("headers", {}), method=method)))
        return findings

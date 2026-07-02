"""access_control.idor — la classe qualifiante n°1 : IDOR/BOLA (oracle différentiel 2-comptes).

Porté de `secpipe/access_control.py` : oracle différentiel (A possède l'objet, B le récupère-t-il ?
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
from .oracle import Oracle
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


@register("access_control.idor")
class IdorDifferential(Oracle):
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
    def _fetch(url, headers, timeout=15, method="GET", body=None):
        """(status, body, content_type). content_type cadre la comparaison : deux corps de types
        différents (html vs json) ne sont jamais « le même objet ». body peut être None.
        Adosse le câblage urllib partagé (Oracle._http) — seam monkeypatché par les tests."""
        st, txt, h = Oracle._http(url, headers=headers, timeout=timeout, method=method, data=body, maxlen=200000)
        ct = ""
        if h is not None:
            try:
                ct = (h.get("Content-Type") or "").split(";")[0].strip().lower()
            except Exception:            # noqa: BLE001
                ct = ""
        return st, txt, ct

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

    def fire(self, action):
        accounts = action.params.get("accounts", [])
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
        if len(accounts) < 2 or not urls:
            return [self.skip(
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
                return [self.skip(
                    target=action.target,
                    title=f"IDOR write {method} non tiré — capacité destructive non autorisée",
                    evidence=(f"La méthode {method} mute l'objet (destructif). Requiert allow_destructive "
                              f"dans le ROE + action.destructive=True. Aucune requête write émise (fail-closed)."),
                    poc=self.dry(action))]
            return self._fire_write(action, A, B, urls, method)
        return self._fire_read(action, A, B, urls)

    def _fire_read(self, action, A, B, urls):
        findings = []
        for url in urls:
            ra = self._fetch(url, A.get("headers", {}))
            rb = self._fetch(url, B.get("headers", {}))
            ru = self._fetch(url, {})
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
        for url in urls:
            before = self._fetch(url, A.get("headers", {}), method="GET")
            wb = self._fetch(url, B.get("headers", {}), method=method, body=body)
            after = self._fetch(url, A.get("headers", {}), method="GET")
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

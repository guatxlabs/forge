"""LOT TOKEN/API — oracles de VÉRIFICATION token/API à PREUVE COMPTE-OPÉRATEUR
(`jwt.weakness`, `graphql.access`).

Contrat commun (calqué sur les oracles à preuve existants + garde-fous de la tâche) :
  (1) SCOPE-GUARD : une cible hors périmètre est REFUSÉE avant tout réseau (`status='skipped'`,
      AUCUNE requête émise — le seam `_fetch` monkeypatché lève si appelé) ;
  (2) PREUVE MINIMALE, BÉNIGNE & COMPTE-OPÉRATEUR : une fixture positive contre le compte de
      l'OPÉRATEUR (jeton forgé accepté pour SON self_marker / objet d'un SECOND compte détenu lu
      cross-compte) -> `status='vulnerable'` ; une fixture négative (jeton rejeté, objet public,
      objet protégé) -> `status='tested'` (jamais de verdict à l'aveugle). JAMAIS un tiers ;
  (3) NON DESTRUCTIF : exploit=False, destructive=False ; payload JWT inchangé, requêtes GraphQL en
      lecture ; le plancher exploit/destructif du ROE reste OFF par défaut ;
  (4) SESSION SECRÈTE : le JWT/la session gouvernée et les jetons forgés ne fuient JAMAIS dans
      l'evidence/le poc/le titre d'un finding ;
  (5) DÉGRADATION GRACIEUSE : réseau indisponible -> `status='skipped'` (offline-safe) ; jwt : aucun
      vecteur accepté -> `status='tested'`.

Tests HERMÉTIQUES : on monkeypatch le `_fetch` de chaque module (zéro réseau), sauf les tests de
secret de session qui monkeypatchent `urllib.request.urlopen` pour exercer le VRAI chemin `_http`
(fusion de la session gouvernée) et prouver que le secret est attaché mais ABSENT des findings.
"""
import io
import json
import sys
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                     # noqa: E402
from forge import modules as mods                                # noqa: E402
from forge import techniques                                     # noqa: E402
from forge import cli                                            # noqa: E402
from forge import session as sessionmod                          # noqa: E402
from forge.roe import Scope                                      # noqa: E402
from forge.session import SessionStore                           # noqa: E402
from forge.modules.oracle import Oracle, ScopeGuardedOracle      # noqa: E402
from forge.modules import tokenapi                               # noqa: E402
from forge.modules.tokenapi import (                             # noqa: E402
    TokenApiOracle, JwtWeakness, GraphqlAccess, _b64url, _dumps, _hs256, _parts, _json_seg)

SELF = "operator-self-8a2b"          # marqueur du compte de l'OPÉRATEUR (jamais un tiers)
STRONG = "Zx9!strong-not-in-wordlist-7f3a2e"    # secret HS FORT (absent de la liste bornée)


def _patch(cls, fn):
    """Remplace cls._fetch par fn (staticmethod) et restaure PROPREMENT (delattr si hérité) pour ne
    jamais laisser un attribut de classe « plain function » qui se lierait à self par erreur."""
    had = "_fetch" in cls.__dict__
    orig = cls.__dict__.get("_fetch")
    cls._fetch = staticmethod(fn)

    def restore():
        if had:
            cls._fetch = orig
        else:
            try:
                delattr(cls, "_fetch")
            except AttributeError:
                pass
    return restore


def _boom(*a, **k):
    raise AssertionError("réseau émis alors qu'aucun ne devait l'être (scope-guard / config)")


def _mkjwt(header, payload, secret):
    """JWT HS compact signé avec `secret` (helper de test)."""
    hb, pb = _b64url(_dumps(header)), _b64url(_dumps(payload))
    return f"{hb}.{pb}.{_hs256(f'{hb}.{pb}', secret)}"


def _mkjwt_raw(header, payload, sig="c2lnbmF0dXJl"):
    """JWT à signature ARBITRAIRE (pour un algo asymétrique dont le serveur de test se moque)."""
    return f"{_b64url(_dumps(header))}.{_b64url(_dumps(payload))}.{sig}"


def _bearer(headers):
    """Le jeton porté par Authorization: Bearer dans les en-têtes d'une requête de test, ou None."""
    for k, v in (headers or {}).items():
        if str(k).lower() == "authorization":
            sp = str(v).split(None, 1)
            if len(sp) == 2:
                return sp[1]
    return None


def _accept(marker=SELF):
    """Corps de réponse « accepté » contenant le marqueur du compte opérateur."""
    return f'{{"data":{{"me":{{"id":"{marker}","email":"{marker}@op.test"}}}}}}'


def _bound(jwt):
    """SessionStore gouverné (scope app.test) portant `jwt` comme bearer par défaut."""
    return SessionStore(Scope({"in_scope": ["app.test"]}), default={"bearer": jwt})


# =================================================================================================
class TestTokenApiRegistration(unittest.TestCase):
    KINDS = ("jwt.weakness", "graphql.access")

    def test_all_registered(self):
        for k in self.KINDS:
            self.assertIn(k, mods.kinds())
            self.assertIsInstance(mods.get(k), TokenApiOracle, f"{k} devrait hériter de TokenApiOracle")
            self.assertIsInstance(mods.get(k), ScopeGuardedOracle, f"{k} devrait hériter de ScopeGuardedOracle")
            self.assertIsInstance(mods.get(k), Oracle, f"{k} devrait hériter d'Oracle")

    def test_mitre_and_cwe_match_table(self):
        # aucune dérive : le module déclare EXACTEMENT le mitre/cwe de la table unique (techniques.py).
        for k in self.KINDS:
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")
            self.assertEqual(mods.get(k).cwe, techniques.cwe_for(k), f"cwe dérive pour {k}")
        self.assertEqual(mods.get("jwt.weakness").cwe, "CWE-347")
        self.assertEqual(mods.get("jwt.weakness").mitre, "T1606")
        self.assertEqual(mods.get("graphql.access").cwe, "CWE-639")
        self.assertEqual(mods.get("graphql.access").mitre, "T1190")

    def test_capability_flags_benign_non_destructive(self):
        # sondes de VÉRIFICATION bénignes : non-exploit, non-destructives, web gardé par le ROE.
        for k in self.KINDS:
            m = mods.get(k)
            self.assertFalse(m.exploit, f"{k} est une sonde bénigne -> exploit=False")
            self.assertFalse(m.destructive, f"{k} lecture/vérif seule -> destructive=False")
            self.assertTrue(getattr(m, "web_allowed", False), f"{k} devrait être web_allowed")

    def test_catalog_phase_and_capability(self):
        for k in self.KINDS:
            t = techniques.technique_for(k)
            self.assertIsNotNone(t, k)
            self.assertEqual(t.phase, "access", k)
            self.assertEqual(t.capability, "active", k)
            self.assertTrue(t.proof_required, f"{k} doit exiger une preuve pour être promu")
            self.assertIn(k, techniques.by_capability("active"))
            self.assertIn(k, techniques.by_phase("access"))

    def test_listed_in_cli_modules_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_modules(type("A", (), {"json": True})())
        self.assertEqual(rc, 0)
        rows = {r["kind"]: r for r in json.loads(buf.getvalue())}
        for k in self.KINDS:
            self.assertIn(k, rows, f"{k} absent de `forge modules --json`")
            self.assertTrue(rows[k]["web_allowed"], k)
            self.assertFalse(rows[k]["exploit"], k)
        self.assertEqual(rows["jwt.weakness"]["mitre"], "T1606")
        self.assertEqual(rows["graphql.access"]["mitre"], "T1190")


# =================================================================================================
class TestJwtWeaknessOracle(unittest.TestCase):
    TGT = "https://app.test/api/me"
    BASE = {"self_marker": SELF, "in_scope": ["app.test"]}

    def _fire(self, fake, jwt=None, params=None, bind=True):
        restore = _patch(JwtWeakness, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            act = Action("jwt.weakness", self.TGT, params=p)
            if bind and jwt is not None:
                with sessionmod.using(_bound(jwt)):
                    return JwtWeakness().fire(act)
            return JwtWeakness().fire(act)
        finally:
            restore()

    # --- positifs (preuve compte-opérateur) ---
    def test_vulnerable_alg_none_accepted(self):
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": SELF}, STRONG)   # secret FORT -> pas de crack

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            tok = _bearer(headers)
            h = _json_seg(_parts(tok)[0]) if tok and _parts(tok) else {}
            return (200, _accept()) if str(h.get("alg", "")).lower() == "none" else (401, "denied")
        f = self._fire(fake, jwt)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-347")
        self.assertEqual(f[0].mitre, "T1606")
        self.assertIn("alg-none", f[0].evidence)

    def test_vulnerable_weak_hmac_secret_cracked_offline(self):
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": SELF}, "secret")   # secret FAIBLE (liste)

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (401, "denied")        # le RÉSEAU rejette tout -> seul le craquage HORS-LIGNE prouve
        f = self._fire(fake, jwt)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("weak-hmac-secret", f[0].evidence)
        self.assertIn("craqué hors-ligne", f[0].evidence)

    def test_vulnerable_rs256_hs256_confusion(self):
        jwt = _mkjwt_raw({"alg": "RS256", "typ": "JWT"}, {"sub": SELF})
        PUB = "-----BEGIN PUBLIC KEY-----FAKEPUB-----END PUBLIC KEY-----"

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            tok = _bearer(headers)
            parts = _parts(tok)
            h = _json_seg(parts[0]) if parts else {}
            if h.get("alg") == "HS256" and "kid" not in h:          # jeton de confusion (pas kid)
                si = f"{parts[0]}.{parts[1]}"
                if _hs256(si, PUB) == parts[2]:                     # signé avec la CLÉ PUBLIQUE
                    return (200, _accept())
            return (401, "denied")
        f = self._fire(fake, jwt, params={"public_key": PUB})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("alg-confusion-rs256-hs256", f[0].evidence)

    def test_vulnerable_kid_injection_empty_key(self):
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": SELF}, STRONG)   # pas de crack

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            tok = _bearer(headers)
            parts = _parts(tok)
            h = _json_seg(parts[0]) if parts else {}
            if "kid" in h and h.get("alg") == "HS256":
                si = f"{parts[0]}.{parts[1]}"
                if _hs256(si, "") == parts[2]:                     # clé VIDE (kid -> /dev/null)
                    return (200, _accept())
            return (401, "denied")
        f = self._fire(fake, jwt)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("kid-injection", f[0].evidence)

    # --- négatifs / garde-fous ---
    def test_tested_when_all_forgeries_rejected(self):
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": SELF}, STRONG)

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (401, "denied")        # rien accepté + secret fort -> aucune preuve
        f = self._fire(fake, jwt)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("aucune faiblesse", f[0].title.lower())

    def test_own_account_only_marker_required(self):
        # le serveur ACCEPTE un jeton forgé mais renvoie l'identité d'un TIERS (pas self_marker) ->
        # on NE promeut PAS (preuve limitée au compte de l'opérateur).
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": SELF}, STRONG)

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, _accept("third-party-victim-9z"))         # marqueur d'un TIERS, pas self_marker
        f = self._fire(fake, jwt)
        self.assertEqual(f[0].status, "tested", "acceptation sans self_marker ne doit pas promouvoir")

    def test_scope_guard_out_of_scope(self):
        restore = _patch(JwtWeakness, _boom)
        try:
            f = JwtWeakness().fire(Action("jwt.weakness", "https://evil.example/x",
                                          params={"self_marker": SELF, "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        restore = _patch(JwtWeakness, _boom)
        try:
            f = JwtWeakness().fire(Action("jwt.weakness", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)

    def test_no_session_jwt_is_skip(self):
        # self_marker présent mais AUCUNE session gouvernée liée -> pas de JWT à analyser -> skip.
        restore = _patch(JwtWeakness, _boom)
        try:
            f = JwtWeakness().fire(Action("jwt.weakness", self.TGT, params=dict(self.BASE)))
        finally:
            restore()
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucun JWT", f[0].title)

    def test_network_down_degrades_to_skipped(self):
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": SELF}, STRONG)   # pas de crack

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (None, "")             # transport indisponible pour chaque jeton
        f = self._fire(fake, jwt)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)

    def test_wordlist_is_bounded(self):
        # « small bounded wordlist » : la liste effective est plafonnée (jamais un brute-force abusif).
        act = Action("jwt.weakness", self.TGT, params=dict(self.BASE, hmac_wordlist=["x"] * 5000))
        self.assertLessEqual(len(JwtWeakness()._wordlist(act)), tokenapi._MAX_WORDLIST)


# =================================================================================================
class TestJwtSessionSecrecy(unittest.TestCase):
    """Garde-fou (4) : le JWT de la session gouvernée ET les jetons forgés ne fuitent JAMAIS dans un
    finding. On exerce le chemin hermétique (le `_fetch` capture les jetons envoyés) puis on vérifie
    qu'aucun d'eux — ni le JWT d'origine — n'apparaît dans l'evidence/le poc/le titre."""

    TGT = "https://app.test/api/me"

    def test_forged_tokens_and_jwt_never_leaked(self):
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": SELF}, STRONG)
        sent = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            tok = _bearer(headers)
            sent.append(tok)
            h = _json_seg(_parts(tok)[0]) if tok and _parts(tok) else {}
            return (200, _accept()) if str(h.get("alg", "")).lower() == "none" else (401, "denied")

        restore = _patch(JwtWeakness, fake)
        try:
            with sessionmod.using(_bound(jwt)):
                f = JwtWeakness().fire(Action("jwt.weakness", self.TGT,
                                              params={"self_marker": SELF, "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "vulnerable")           # la session a bien été consultée+forgée
        self.assertTrue(any(t for t in sent), "au moins un jeton forgé aurait dû être émis")
        for fd in f:
            blob = f"{fd.title} {fd.evidence} {fd.poc}"
            self.assertNotIn(jwt, blob, "le JWT d'origine a fuité dans le finding")
            for tok in sent:                                  # aucun jeton forgé ne doit apparaître
                if tok:
                    self.assertNotIn(tok, blob, "un jeton forgé a fuité dans le finding")

    def test_session_material_attached_via_http_but_not_leaked(self):
        # VRAI chemin `_http` : urlopen monkeypatché capture les en-têtes sortants et lève (réseau nul).
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": SELF}, STRONG)
        seen = []

        class _Cap:
            def __call__(self, req, timeout=None, *a, **k):
                seen.append(" ".join(str(v) for v in req.headers.values()))
                raise urllib.error.URLError("captured (no network in test)")

        with patch("forge.modules.oracle.Oracle._raw_open", _Cap()), sessionmod.using(_bound(jwt)):
            f = JwtWeakness().fire(Action("jwt.weakness", self.TGT,
                                          params={"self_marker": SELF, "in_scope": ["app.test"]}))
        # des requêtes ont bien été émises (jetons forgés attachés) mais le réseau lève -> skipped.
        self.assertTrue(seen, "des requêtes de vérification auraient dû partir")
        self.assertEqual(f[0].status, "skipped")
        # le JWT BRUT n'est jamais envoyé (l'en-tête explicite du jeton forgé prime) ni exposé au finding.
        for blob in seen:
            self.assertNotIn(jwt, blob, "le JWT brut a fuité sur le réseau (devrait être un jeton forgé)")
        for fd in f:
            self.assertNotIn(jwt, f"{fd.title} {fd.evidence} {fd.poc}")


# =================================================================================================
class TestGraphqlAccessOracle(unittest.TestCase):
    TGT = "https://app.test/graphql"
    BMARK = "SECRET-object-B-9f1c"        # champ unique d'un objet du SECOND compte DÉTENU par l'op.
    BASE = {"b_marker": BMARK, "query": 'query{node(id:"B"){secretField}}', "in_scope": ["app.test"]}

    def _fire(self, fake, params=None, bind=True, target=None):
        restore = _patch(GraphqlAccess, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            act = Action("graphql.access", target or self.TGT, params=p)
            if bind:
                with sessionmod.using(_bound_a()):
                    return GraphqlAccess().fire(act)
            return GraphqlAccess().fire(act)
        finally:
            restore()

    def _bola(self, auth_returns_b, anon_returns_b, introspection=True):
        """Fabrique un `_fetch` : introspection (on/off) + objet B visible ou non selon (auth/anon)."""
        def fake(url, headers=None, timeout=15, method="POST", data=None):
            d = data or ""
            if "__schema" in d:
                return ((200, '{"data":{"__schema":{"queryType":{"name":"Query"}}}}') if introspection
                        else (200, '{"errors":[{"message":"introspection disabled"}]}'))
            authed = sessionmod.current() is not None        # anon = session déliée (using(None))
            returns_b = auth_returns_b if authed else anon_returns_b
            if returns_b:
                return (200, f'{{"data":{{"node":{{"secretField":"{self.BMARK}"}}}}}}')
            return (200, '{"errors":[{"message":"Not authorized"}]}')
        return fake

    def test_vulnerable_bola_cross_account(self):
        # A(authentifié) lit l'objet de B ; anonyme refusé -> BOLA cross-compte CONFIRMÉ.
        f = self._fire(self._bola(auth_returns_b=True, anon_returns_b=False))
        bola = [x for x in f if "BOLA" in x.title or "access-control" in x.title]
        self.assertTrue(bola)
        self.assertEqual(bola[0].status, "vulnerable")
        self.assertEqual(bola[0].severity, "HIGH")
        self.assertEqual(bola[0].cwe, "CWE-639")
        self.assertIn("objet_B_présent=True", bola[0].evidence)

    def test_tested_when_object_is_public(self):
        # anonyme voit AUSSI l'objet -> donnée publique, pas un BOLA -> tested.
        f = self._fire(self._bola(auth_returns_b=True, anon_returns_b=True))
        bola = [x for x in f if x.cwe == "CWE-639" and "introspection" not in x.title.lower()]
        self.assertEqual(bola[0].status, "tested")
        self.assertEqual(bola[0].severity, "INFO")

    def test_tested_when_object_protected_from_A_too(self):
        # même A ne lit pas l'objet de B -> pas de preuve -> tested.
        f = self._fire(self._bola(auth_returns_b=False, anon_returns_b=False))
        bola = [x for x in f if x.cwe == "CWE-639" and "introspection" not in x.title.lower()]
        self.assertEqual(bola[0].status, "tested")

    def test_introspection_reported_as_informative(self):
        f = self._fire(self._bola(True, False, introspection=True))
        intro = [x for x in f if "introspection" in x.title.lower()]
        self.assertTrue(intro)
        self.assertEqual(intro[0].status, "tested")           # informatif seul, jamais promu
        self.assertIn("activée", intro[0].title.lower())

    def test_introspection_off_detected(self):
        f = self._fire(self._bola(True, False, introspection=False))
        intro = [x for x in f if "introspection" in x.title.lower()]
        self.assertTrue(intro)
        self.assertIn("désactivée", intro[0].title.lower())

    def test_query_template_substitution(self):
        # sans `query` brute : query_template + b_object_id (id d'un objet DÉTENU par l'opérateur).
        f = self._fire(self._bola(True, False),
                       params={"query": None, "query_template": 'query{node(id:"{id}"){secretField}}',
                               "b_object_id": "B", "introspection": False})
        bola = [x for x in f if x.cwe == "CWE-639" and "introspection" not in x.title.lower()]
        self.assertEqual(bola[0].status, "vulnerable")

    def test_scope_guard_out_of_scope(self):
        restore = _patch(GraphqlAccess, _boom)
        try:
            f = GraphqlAccess().fire(Action("graphql.access", "https://evil.example/graphql",
                                            params=dict(self.BASE)))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        restore = _patch(GraphqlAccess, _boom)
        try:
            f = GraphqlAccess().fire(Action("graphql.access", self.TGT,
                                            params={"in_scope": ["app.test"]}))   # ni b_marker ni query
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)

    def test_network_down_degrades_to_skipped(self):
        def fake(url, headers=None, timeout=15, method="POST", data=None):
            return (None, "")
        f = self._fire(fake, params={"introspection": False})
        self.assertTrue(any(x.status == "skipped" for x in f))
        deg = next(x for x in f if x.status == "skipped")
        self.assertIn("réseau indisponible", deg.title)


# =================================================================================================
def _bound_a():
    """SessionStore gouverné pour le COMPTE A (secret) — bearer opaque non journalisé."""
    return SessionStore(Scope({"in_scope": ["app.test"]}), default={"bearer": GQL_SECRET})


GQL_SECRET = "S3CR3T-graphql-accountA-4b7e2d"


class TestGraphqlSessionSecrecy(unittest.TestCase):
    """Garde-fou (4) : la session du compte A (gouvernée) est attachée aux requêtes in-scope par le VRAI
    chemin `_http` mais n'apparaît JAMAIS dans un finding. urlopen monkeypatché capture les en-têtes."""

    TGT = "https://app.test/graphql"

    def test_account_a_session_attached_but_not_leaked(self):
        seen = []

        class _Cap:
            def __call__(self, req, timeout=None, *a, **k):
                seen.append(" ".join(str(v) for v in req.headers.values()))
                raise urllib.error.URLError("captured (no network in test)")

        params = {"b_marker": "SECRET-object-B", "query": 'query{node(id:"B"){f}}',
                  "in_scope": ["app.test"]}
        with patch("forge.modules.oracle.Oracle._raw_open", _Cap()), sessionmod.using(_bound_a()):
            f = GraphqlAccess().fire(Action("graphql.access", self.TGT, params=params))
        # la session du compte A a bien été attachée à AU MOINS une requête in-scope (introspection).
        self.assertTrue(any(GQL_SECRET in v for v in seen),
                        "la session du compte A aurait dû être attachée aux requêtes in-scope")
        # ... mais elle ne fuite NULLE PART dans les findings.
        for fd in f:
            blob = f"{fd.title} {fd.evidence} {fd.poc}"
            self.assertNotIn(GQL_SECRET, blob, "la session du compte A a fuité dans le finding")


if __name__ == "__main__":
    unittest.main(verbosity=2)

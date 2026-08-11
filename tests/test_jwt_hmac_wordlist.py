# SPDX-License-Identifier: AGPL-3.0-or-later
"""D12 — la liste HMAC par défaut de `jwt.weakness` était le facteur limitant, pas le mécanisme.

LE DÉFAUT MESURÉ. La liste faisait 16 entrées. Le secret de VAmPI est `'random'`
(`/vampi/config.py` : `vuln_app.app.config['SECRET_KEY'] = 'random'`, lu DANS le conteneur du banc)
et n'y figurait pas -> faux négatif sur un oracle parfaitement fonctionnel. Avec `random` présent, le
MÊME oracle rend **HIGH · vulnerable · « secret HMAC faible craqué hors-ligne »**.

CE QUE CES TESTS VERROUILLENT — et surtout ce qu'ils EMPÊCHENT :

  1. le gain : un jeton VAmPI-réel (HS256/`random`) est craqué, `status=vulnerable` ;
  2. le coût est du CPU, PAS du réseau : allonger la liste n'émet AUCUNE requête supplémentaire —
     `_crack_hmac` est HORS-LIGNE. Le test COMPTE les requêtes et exige l'égalité stricte entre une
     liste d'1 entrée et une liste au plafond ;
  3. la liste reste BORNÉE (`_MAX_WORDLIST`) et CONFIGURABLE (`params.hmac_wordlist`), y compris
     quand l'opérateur en fournit une plus longue que le plafond — forge ne devient pas un cracker ;
  4. aucun faux positif : un secret FORT n'est pas craqué, quelle que soit la longueur de la liste.

Hermétique : `_fetch` monkeypatché, ZÉRO octet émis.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action, Scope                                   # noqa: E402
from forge.session import SessionStore                                # noqa: E402
from forge import session as sessionmod                               # noqa: E402
from forge.modules import tokenapi                                    # noqa: E402
from forge.modules.tokenapi import (                                  # noqa: E402
    JwtWeakness, _b64url, _dumps, _hs256, _DEFAULT_HMAC_WORDLIST, _MAX_WORDLIST)

SELF = "op-marker-7Q3"
#: Le secret RÉEL de VAmPI (`config.py`), la cause exacte du faux négatif consigné au banc.
VAMPI_SECRET = "random"
STRONG = "e3f1b0c9a74d4e2f8b6a15c30d9e7f2a41b8c6d5e0f39a72b1c4d8e6f0a95b3c7"


def _mkjwt(header, payload, secret):
    hb, pb = _b64url(_dumps(header)), _b64url(_dumps(payload))
    return f"{hb}.{pb}.{_hs256(f'{hb}.{pb}', secret)}"


def _patch_fetch(cls, fn):
    had = "_fetch" in cls.__dict__
    orig = cls.__dict__.get("_fetch")
    cls._fetch = staticmethod(fn)

    def restore():
        if had:
            cls._fetch = orig
        else:
            delattr(cls, "_fetch")
    return restore


class _DenyCounter:
    """Serveur factice qui REFUSE tout et COMPTE les requêtes : seul un craquage HORS-LIGNE peut
    prouver quoi que ce soit, et le compteur mesure le coût RÉSEAU de la liste."""

    def __init__(self):
        self.n = 0

    def __call__(self, url, headers=None, timeout=15, method="GET", data=None, **kw):
        self.n += 1
        return 401, "denied"


class _Harness(unittest.TestCase):
    TGT = "https://app.test/users/v1/login"
    BASE = {"self_marker": SELF, "in_scope": ["app.test"]}

    def _fire(self, jwt, params=None, server=None):
        srv = server or _DenyCounter()
        restore = _patch_fetch(JwtWeakness, srv)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            store = SessionStore(Scope({"in_scope": ["app.test"]}), default={"bearer": jwt})
            with sessionmod.using(store):
                return JwtWeakness().fire(Action("jwt.weakness", self.TGT, params=p)), srv
        finally:
            restore()


class TestDefaultWordlistShape(unittest.TestCase):
    def test_bounded_and_deduplicated(self):
        self.assertLessEqual(len(_DEFAULT_HMAC_WORDLIST), _MAX_WORDLIST,
                             "la liste par défaut doit rester SOUS le plafond dur")
        self.assertEqual(len(_DEFAULT_HMAC_WORDLIST), len(set(_DEFAULT_HMAC_WORDLIST)),
                         "un doublon coûte du CPU sans rien apporter")
        self.assertTrue(all(isinstance(s, str) and s for s in _DEFAULT_HMAC_WORDLIST))

    def test_contains_the_measured_miss(self):
        self.assertIn(VAMPI_SECRET, _DEFAULT_HMAC_WORDLIST)

    def test_historical_core_is_still_first(self):
        """Le noyau historique reste EN TÊTE : un secret déjà craqué garde le même index dans
        l'evidence (« candidat #N de la liste bornée ») — la sortie ne change pas rétroactivement."""
        self.assertEqual(_DEFAULT_HMAC_WORDLIST[:16], [
            "secret", "password", "changeme", "admin", "jwt", "token", "key", "test", "1234567890",
            "default", "supersecret", "secretkey", "your-256-bit-secret", "private", "qwerty",
            "s3cr3t"])


class TestVampiSecretIsNowCracked(_Harness):
    def test_hs256_random_is_confirmed(self):
        """LE gain mesuré : le jeton que VAmPI émet réellement (HS256 signé avec 'random')."""
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": "attacker1"}, VAMPI_SECRET)
        findings, srv = self._fire(jwt)
        self.assertEqual(findings[0].status, "vulnerable", findings[0].title)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].cwe, "CWE-347")
        self.assertIn("craqué hors-ligne", findings[0].evidence)
        self.assertIn("weak-hmac-secret", findings[0].evidence)
        self.assertGreater(srv.n, 0, "le réseau a bien été sollicité par les jetons FORGÉS")

    def test_the_secret_itself_never_leaks(self):
        """Le finding nomme un INDEX, jamais le secret : la discipline « pas de matériel dans un
        finding » vaut aussi pour un secret trivial."""
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": "attacker1"}, VAMPI_SECRET)
        findings, _ = self._fire(jwt)
        blob = " ".join([findings[0].title, findings[0].evidence, findings[0].poc or ""])
        self.assertNotIn(jwt, blob)
        self.assertIn(f"#{_DEFAULT_HMAC_WORDLIST.index(VAMPI_SECRET)}", findings[0].evidence)

    def test_a_strong_secret_is_still_not_cracked(self):
        """CONTRE-ÉPREUVE — allonger la liste ne fabrique pas de faux positif."""
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": "attacker1"}, STRONG)
        findings, _ = self._fire(jwt)
        self.assertEqual(findings[0].status, "tested")
        self.assertIn("aucune faiblesse de signature confirmée", findings[0].title)


class TestCostIsCpuNotNetwork(_Harness):
    """« Une liste plus longue est une charge réseau plus longue » — FAUX, et il faut le PROUVER."""

    def test_wordlist_length_does_not_change_the_request_count(self):
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": "attacker1"}, STRONG)
        _f1, s1 = self._fire(jwt, params={"hmac_wordlist": ["zzz"]})
        _f2, s2 = self._fire(jwt, params={"hmac_wordlist": [f"c{i}" for i in range(_MAX_WORDLIST)]})
        _f3, s3 = self._fire(jwt)                       # liste par défaut (49 entrées)
        self.assertEqual((s1.n, s2.n), (s2.n, s3.n),
                         "le nombre de requêtes doit être INDÉPENDANT de la longueur de la liste")

    def test_cracking_emits_nothing(self):
        """`_crack_hmac` est PUR : aucun I/O, quelle que soit la taille de la liste."""
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": "x"}, VAMPI_SECRET)
        h, p, s = jwt.split(".")
        restore = _patch_fetch(JwtWeakness, lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("le craquage HORS-LIGNE a émis une requête")))
        try:
            idx = JwtWeakness._crack_hmac(h, p, s, list(_DEFAULT_HMAC_WORDLIST))
        finally:
            restore()
        self.assertEqual(idx, _DEFAULT_HMAC_WORDLIST.index(VAMPI_SECRET))


class TestWordlistStaysBoundedAndConfigurable(_Harness):
    def test_operator_list_is_capped(self):
        act = Action("jwt.weakness", self.TGT,
                     params=dict(self.BASE, hmac_wordlist=["x"] * 5000))
        self.assertLessEqual(len(JwtWeakness()._wordlist(act)), _MAX_WORDLIST)

    def test_operator_list_replaces_the_default(self):
        act = Action("jwt.weakness", self.TGT, params=dict(self.BASE, hmac_wordlist=["only"]))
        self.assertEqual(JwtWeakness()._wordlist(act), ["only"])

    def test_operator_list_can_reach_a_secret_absent_from_the_default(self):
        secret = "engagement-specific-9Z4K"
        self.assertNotIn(secret, _DEFAULT_HMAC_WORDLIST)
        jwt = _mkjwt({"alg": "HS256", "typ": "JWT"}, {"sub": "x"}, secret)
        findings, _ = self._fire(jwt, params={"hmac_wordlist": [secret]})
        self.assertEqual(findings[0].status, "vulnerable")

    def test_cap_constant_is_unchanged(self):
        self.assertEqual(tokenapi._MAX_WORDLIST, 50,
                         "le plafond DUR est le garde-fou anti-cracker : il ne bouge pas")


if __name__ == "__main__":
    unittest.main()

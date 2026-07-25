"""Durcissement SÛRETÉ-CRITIQUE (audit F1/F2/F3/L2/L3) — tests hermétiques (zéro réseau réel).

  F1  scope-guard de REDIRECTION : le seam de fetch des oracles (`Oracle._http`) NE SUIT PAS les
      redirections par défaut ; en opt-in, chaque saut est re-validé contre le scope et le matériel
      secret ne peut PHYSIQUEMENT pas partir vers un hôte hors périmètre (un 302 in-scope vers
      127.0.0.1 n'exfiltre JAMAIS la session gouvernée).
  F2  les oracles IDOR / auth.takeover / cors.credentials portent un scope-guard PAR-URL fail-closed
      (une URL dérivée de params hors périmètre -> skipped, ZÉRO requête).
  F3  discipline de preuve SCHEMA-ENFORCED : `status='vulnerable'` n'est atteignable que via le chemin
      de preuve sanctionné ; un statut inconnu est ramené à 'tested'.
  L2  anti-injection d'ARGUMENT : une cible positionnelle résolue commençant par '-' est refusée.
  L3  décodeur msgpack robuste : trame tronquée / trop imbriquée -> ValueError (jamais IndexError/
      struct.error/RecursionError non interceptées).
"""
import email.message
import io
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import session as sessionmod                        # noqa: E402
from forge.session import SessionStore                         # noqa: E402
from forge.roe import Scope, Action                            # noqa: E402
from forge.schema import Finding                               # noqa: E402
from forge.modules.registry import Module                      # noqa: E402
from forge.modules.oracle import Oracle                        # noqa: E402
from forge.modules.access_control import IdorDifferential      # noqa: E402
from forge.modules.auth import AuthTakeover                    # noqa: E402
from forge.modules.cors import CorsCredentials                 # noqa: E402
from forge.modules._msgpack import mp_pack, mp_unpack          # noqa: E402
from forge.modules.toolspec import ToolSpec, make_module, unsafe_positional_target  # noqa: E402

SECRET = "S3CR3T-redir-a1b2c3"
INTERNAL = "INTERNAL-LOOPBACK-DATA-xyz"


class _FakeResp:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body.encode("utf-8")
        m = email.message.Message()
        for k, v in (headers or []):
            m[k] = v
        self.headers = m

    def read(self, n=-1):
        return self._body[:n] if (n is not None and n >= 0) else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(url, location):
    h = email.message.Message()
    h["Location"] = location
    return urllib.error.HTTPError(url, 302, "Found", h, io.BytesIO(b""))


# =================================================================================================
class TestRedirectScopeGuard(unittest.TestCase):
    """F1 — un hôte in-scope 302-ant vers un hôte hors périmètre (loopback/interne) ne doit JAMAIS être
    suivi ni voir le matériel de session gouverné quitter le périmètre."""

    class _Sim:
        """Simule : *.app.test -> 302 Location: http://127.0.0.1/internal ; 127.0.0.1 -> 200 (secret).
        Enregistre chaque URL RÉELLEMENT contactée + les valeurs d'en-tête (dont un éventuel secret)."""
        def __init__(self):
            self.contacted = {}      # url -> " ".join(header values)

        def __call__(self, req, timeout=None):
            self.contacted[req.full_url] = " ".join(str(v) for v in req.headers.values())
            if "app.test" in req.full_url:
                raise _http_error(req.full_url, "http://127.0.0.1/internal")
            return _FakeResp(200, INTERNAL, [("Content-Type", "text/plain")])   # loopback (interdit)

    def _store(self):
        return SessionStore(Scope({"in_scope": ["app.test"]}), default={"cookies": f"sid={SECRET}"})

    def test_default_no_follow_never_reaches_redirect_target(self):
        sim = self._Sim()
        with patch.object(Oracle, "_raw_open", sim), sessionmod.using(self._store()):
            st, body, _ = Oracle._http("https://app.test/redir")          # défaut = no-follow
        self.assertEqual(st, 302)                                          # la 3xx remonte telle quelle
        self.assertNotIn("127.0.0.1", " ".join(sim.contacted))            # loopback JAMAIS contacté
        self.assertNotIn(INTERNAL, body or "")
        self.assertIn(SECRET, sim.contacted["https://app.test/redir"])    # secret attaché à l'in-scope

    def test_optin_follow_stops_at_out_of_scope_hop_no_secret_egress(self):
        sim = self._Sim()
        with patch.object(Oracle, "_raw_open", sim), sessionmod.using(self._store()):
            st, body, _ = Oracle._http("https://app.test/redir", follow_redirects=True)
        # le hop hors-scope (loopback) n'est JAMAIS suivi -> jamais contacté, jamais de secret exfiltré
        for url, vals in sim.contacted.items():
            self.assertNotIn("127.0.0.1", url, "loopback hors-scope contacté (fuite)")
            self.assertNotIn(SECRET, vals if "app.test" not in url else "")
        self.assertNotIn(INTERNAL, body or "")
        self.assertEqual(st, 302)                                         # arrêt fail-closed -> 3xx remonte

    def test_optin_follow_cross_origin_in_scope_strips_caller_and_session_secret(self):
        # a.test (session par-hôte SECRET) -> 302 -> b.test (in-scope, SANS session). Sur ce saut
        # cross-origin, ni le secret de session d'a.test ni le Cookie/Authorization de l'appelant ne
        # doivent être re-postés à b.test.
        scope = Scope({"in_scope": ["a.test", "b.test"]})
        store = SessionStore(scope, per_host={"a.test": {"cookies": f"sid={SECRET}"}})
        rec = {}

        def sim(req, timeout=None):
            rec[req.full_url] = " ".join(str(v) for v in req.headers.values())
            if "a.test" in req.full_url:
                raise _http_error(req.full_url, "https://b.test/next")
            return _FakeResp(200, "B-BODY", [("Content-Type", "text/plain")])

        with patch.object(Oracle, "_raw_open", sim), sessionmod.using(store):
            st, _, _ = Oracle._http("https://a.test/start",
                                    headers={"Authorization": "Bearer CALLER"}, follow_redirects=True)
        self.assertEqual(st, 200)                                    # b.test suivi (in-scope)
        self.assertIn(SECRET, rec["https://a.test/start"])           # a.test : secret + appelant OK
        self.assertNotIn(SECRET, rec["https://b.test/next"])         # b.test : PAS le secret d'a.test
        self.assertNotIn("Bearer CALLER", rec["https://b.test/next"])  # PAS l'auth appelant (cross-origin)


# =================================================================================================
class TestOraclePerUrlScopeGuard(unittest.TestCase):
    """F2 — IDOR / auth.takeover / cors.credentials : une URL hors périmètre -> skipped, ZÉRO requête."""

    def _boom(self):
        def _b(req, timeout=None):
            raise AssertionError("aucune requête ne devait être émise (fail-closed)")
        return _b

    def test_idor_out_of_scope_url_skipped_zero_request(self):
        act = Action("access_control.idor", "app.test",
                     params={"accounts": [{"headers": {}}, {"headers": {}}],
                             "urls": ["https://evil.test/obj"],
                             "in_scope": ["app.test"], "out_scope": ["evil.test"]})
        with patch.object(Oracle, "_raw_open", self._boom()):
            f = IdorDifferential().fire(act)
        self.assertTrue(f and all(x.status == "skipped" for x in f))
        self.assertTrue(any("hors périmètre" in x.title for x in f))

    def test_idor_out_of_scope_target_skipped(self):
        act = Action("access_control.idor", "evil.test",
                     params={"accounts": [{"headers": {}}, {"headers": {}}],
                             "urls": ["https://app.test/x"],
                             "in_scope": ["app.test"], "out_scope": ["evil.test"]})
        with patch.object(Oracle, "_raw_open", self._boom()):
            f = IdorDifferential().fire(act)
        self.assertTrue(any(x.status == "skipped" for x in f))

    def test_auth_takeover_out_of_scope_whoami_skipped(self):
        act = Action("auth.takeover", "app.test",
                     params={"whoami_url": "https://evil.test/me", "victim_marker": "V",
                             "in_scope": ["app.test"], "out_scope": ["evil.test"]})
        with patch.object(Oracle, "_raw_open", self._boom()):
            f = AuthTakeover().fire(act)
        self.assertTrue(any(x.status == "skipped" for x in f))

    def test_cors_out_of_scope_target_skipped(self):
        act = Action("cors.credentials", "https://evil.test/api",
                     params={"attacker_origin": "https://atk.example",
                             "in_scope": ["app.test"], "out_scope": ["evil.test"]})
        with patch.object(Oracle, "_raw_open", self._boom()):
            f = CorsCredentials().fire(act)
        self.assertTrue(any(x.status == "skipped" for x in f))

    def test_scopeguard_mro_keeps_mixin_ahead_of_oracle(self):
        from forge.modules._scopeguard import ScopeGuardMixin
        for cls in (IdorDifferential, AuthTakeover, CorsCredentials):
            mro = cls.__mro__
            self.assertLess(mro.index(ScopeGuardMixin), mro.index(Oracle),
                            f"{cls.__name__}: ScopeGuardMixin doit primer sur Oracle")


# =================================================================================================
class TestProofStatusSchemaEnforced(unittest.TestCase):
    """F3 — 'vulnerable' n'est atteignable que via le chemin de preuve sanctionné."""

    def test_direct_module_finding_vulnerable_is_clamped(self):
        f = Module.finding(target="t", title="x", status="vulnerable")
        self.assertEqual(f.status, "tested")                       # forgé sans preuve -> tested

    def test_oracle_proof_proven_yields_vulnerable(self):
        f = IdorDifferential().proof(target="t", proven=True, title="x", severity="HIGH",
                                     evidence="e", poc="p")
        self.assertEqual(f.status, "vulnerable")                   # chemin de preuve sanctionné
        f2 = IdorDifferential().proof(target="t", proven=False, title="x", severity="INFO",
                                      evidence="e", poc="p")
        self.assertEqual(f2.status, "tested")

    def test_unknown_status_coerced_to_tested(self):
        self.assertEqual(Finding(target="t", title="x", status="bogus-status").status, "tested")

    def test_known_non_vulnerable_status_preserved(self):
        for s in ("tested", "skipped", "reported_by_tool", "not_vulnerable", "submitted"):
            self.assertEqual(Module.finding(target="t", title="x", status=s).status, s)


# =================================================================================================
class TestToolspecArgInjection(unittest.TestCase):
    """L2 — une cible positionnelle résolue commençant par '-' est refusée (option smuggling)."""

    def test_unsafe_positional_target_detects_dash(self):
        spec = ToolSpec("recon.argtest", "Recon", "true", ("scan", "{target}"))
        self.assertIsNotNone(unsafe_positional_target(spec, "--config=/etc/passwd"))
        self.assertIsNotNone(unsafe_positional_target(spec, "-oProxyCommand=x"))
        self.assertIsNone(unsafe_positional_target(spec, "http://app.test"))   # URL légitime
        self.assertIsNone(unsafe_positional_target(spec, "app.test"))

    def test_flag_valued_target_not_flagged(self):
        # {target} en VALEUR d'un flag (-u{target}) n'est pas un positionnel -> pas de refus
        spec = ToolSpec("recon.argtest2", "Recon", "true", ("-u{target}",))
        self.assertIsNone(unsafe_positional_target(spec, "--config=x"))

    def test_fire_refuses_dash_target_before_running(self):
        spec = ToolSpec("recon.argtest3", "Recon", "true", ("{target}",))
        mod = make_module(spec)()                              # non enregistré (pas de pollution REGISTRY)
        f = mod.fire(Action("recon.argtest3", "--config=evil"))   # sans in_scope -> permissif dev
        self.assertTrue(any(x.status == "skipped" and "injection" in x.title.lower() for x in f))


# =================================================================================================
class TestMsgpackRobustness(unittest.TestCase):
    """L3 — trame msfrpcd tronquée / trop imbriquée -> ValueError (interceptable), jamais crash brut."""

    def test_valid_frames_roundtrip_unchanged(self):
        for o in (None, True, False, 0, 127, -1, 255, 65535, "hi", [1, 2, [3]], {"a": 1, "b": [2, 3]}):
            self.assertEqual(mp_unpack(mp_pack(o)), o)

    def test_truncated_frames_raise_valueerror(self):
        # tronquées de façon à déclencher IndexError (élément/tête manquant) ou struct.error (entier
        # incomplet) — toutes converties en ValueError. (Une str tronquée est tolérée par slicing, pas
        # un crash : hors périmètre de ce test.)
        for bad in (b"\x91", b"\xdc\x00\x05", b"\xcd\x00", b"\x82\xa1a"):
            with self.assertRaises(ValueError):
                mp_unpack(bad)

    def test_deeply_nested_frame_raises_valueerror_not_recursionerror(self):
        deep = b"\x91" * 500                                   # 500 arrays imbriqués (puis tronqué)
        with self.assertRaises(ValueError):
            mp_unpack(deep)
        # une trame valide reste décodée normalement APRÈS le durcissement
        self.assertEqual(mp_unpack(mp_pack({"a": [1, 2, 3]})), {"a": [1, 2, 3]})


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Preuves fail-closed de la gate ROE. `python -m unittest -v` (stdlib, zéro dépendance)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Roe, Action, VETO, DRY_RUN, FIRE  # noqa: E402


def mk(in_scope=("app.test",), exploit=False, destructive=False):
    return Scope({"mode": "grey", "in_scope": list(in_scope),
                  "allow_exploit": exploit, "allow_destructive": destructive})


class TestFailClosed(unittest.TestCase):
    def test_out_of_scope_is_veto(self):
        roe = Roe(mk())
        self.assertEqual(roe.decide(Action("demo.fingerprint", "evil.example")).verdict, VETO)

    def test_empty_scope_vetoes_everything(self):
        roe = Roe(mk(in_scope=[]))               # in_scope vide => rien n'est en scope
        self.assertEqual(roe.decide(Action("demo.fingerprint", "app.test")).verdict, VETO)

    def test_exploit_requires_allow_exploit(self):
        roe = Roe(mk(exploit=False))
        roe.arm(); a = Action("x", "app.test", exploit=True); roe.approve(a.id)
        self.assertEqual(roe.decide(a).verdict, VETO)   # capacité non autorisée -> VETO dur

    def test_destructive_requires_allow_destructive(self):
        roe = Roe(mk(destructive=False))
        roe.arm(); a = Action("x", "app.test", destructive=True); roe.approve(a.id)
        self.assertEqual(roe.decide(a).verdict, VETO)

    def test_in_scope_unarmed_is_dry_run(self):
        roe = Roe(mk())
        self.assertEqual(roe.decide(Action("demo.fingerprint", "app.test")).verdict, DRY_RUN)

    def test_armed_but_unapproved_is_dry_run(self):
        roe = Roe(mk()); roe.arm()
        self.assertEqual(roe.decide(Action("demo.fingerprint", "app.test")).verdict, DRY_RUN)

    def test_armed_and_approved_fires(self):
        roe = Roe(mk()); roe.arm()
        a = Action("demo.fingerprint", "app.test"); roe.approve(a.id)
        self.assertEqual(roe.decide(a).verdict, FIRE)

    def test_auto_mode_fires_without_per_action_approval(self):
        roe = Roe(mk(), mode="auto"); roe.arm()
        self.assertEqual(roe.decide(Action("demo.fingerprint", "app.test")).verdict, FIRE)

    def test_exploit_in_scope_with_allow_and_armed_fires(self):
        roe = Roe(mk(exploit=True)); roe.arm()
        a = Action("x", "app.test", exploit=True); roe.approve(a.id)
        self.assertEqual(roe.decide(a).verdict, FIRE)

    def test_decide_never_raises_failclosed(self):
        roe = Roe(mk())
        # cible None -> is_in_scope gère, mais on force aussi un objet bancal
        class Bad:
            kind = "x"; target = None; exploit = False; destructive = False; id = "bad"
        self.assertEqual(roe.decide(Bad()).verdict, VETO)


class TestScopeMembership(unittest.TestCase):
    """is_in_scope : out_scope l'emporte sur un glob in_scope ; patterns non-string ignorés."""

    def test_out_scope_overrides_wildcard_in_scope(self):
        # in_scope large (*.test) mais secret.test explicitement exclu -> hors scope
        s = Scope({"mode": "grey", "in_scope": ["*.test"], "out_scope": ["secret.test"]})
        self.assertFalse(s.is_in_scope("http://secret.test"))     # exclu malgré le wildcard
        self.assertFalse(s.is_in_scope("secret.test"))            # idem sans scheme
        self.assertTrue(s.is_in_scope("http://app.test"))         # couvert par *.test, non exclu

    def test_out_scope_overrides_with_path_and_port(self):
        s = Scope({"mode": "grey", "in_scope": ["*.test"], "out_scope": ["secret.test"]})
        self.assertFalse(s.is_in_scope("https://secret.test:443/admin?x=1"))

    def test_non_string_pattern_ignored_failclosed(self):
        # un pattern non-string dans in_scope est ignoré (fail-closed), n'autorise rien
        s = Scope({"mode": "grey", "in_scope": [123, None, {"x": 1}]})
        self.assertFalse(s.is_in_scope("app.test"))
        # mêlé à un pattern valide : seul le valide compte
        s2 = Scope({"mode": "grey", "in_scope": [123, "app.test"]})
        self.assertTrue(s2.is_in_scope("app.test"))
        self.assertFalse(s2.is_in_scope("other.test"))

    def test_non_string_out_scope_pattern_ignored(self):
        # un out_scope non-string est ignoré et ne bloque pas une cible in_scope
        s = Scope({"mode": "grey", "in_scope": ["app.test"], "out_scope": [None, 42]})
        self.assertTrue(s.is_in_scope("app.test"))

    def test_empty_target_is_out(self):
        s = Scope({"mode": "grey", "in_scope": ["*.test"]})
        self.assertFalse(s.is_in_scope(""))
        self.assertFalse(s.is_in_scope(None))


class TestCidrScopeBypass(unittest.TestCase):
    """RÉGRESSION sûreté : le match CIDR/IP testait le `target` BRUT (URL/host:port) -> ip_address()
    levait ValueError -> aucun match -> une IP out_scope était CONTOURNÉE via une URL ou un host:port.
    Le fix teste l'HÔTE CANONIQUE. out_scope l'emporte toujours -> ces formes doivent être HORS scope."""

    def setUp(self):
        # 10.0.0.5 explicitement exclu, tout 10/8 et le reste autorisé
        self.s = Scope({"mode": "grey", "in_scope": ["10.0.0.0/8", "*"], "out_scope": ["10.0.0.5/32"]})

    def test_url_form_does_not_bypass_out_scope(self):
        self.assertFalse(self.s.is_in_scope("http://10.0.0.5/admin"))   # PoC du bug : doit être HORS scope

    def test_host_port_form_does_not_bypass_out_scope(self):
        self.assertFalse(self.s.is_in_scope("10.0.0.5:8080"))           # host:port : doit rester HORS scope

    def test_bare_ip_still_out(self):
        self.assertFalse(self.s.is_in_scope("10.0.0.5"))               # IP nue : déjà hors scope (non régressé)

    def test_other_in_subnet_ip_in_scope_via_url(self):
        # une autre IP du subnet (non exclue) reste in-scope, y compris en forme URL
        self.assertTrue(self.s.is_in_scope("http://10.0.0.6/admin"))
        self.assertTrue(self.s.is_in_scope("10.0.0.6:8080"))

    def test_cidr_in_scope_matches_canonical_host(self):
        # in_scope CIDR doit matcher l'hôte canonique d'une URL (pas seulement une IP nue)
        s = Scope({"mode": "grey", "in_scope": ["192.168.0.0/16"]})
        self.assertTrue(s.is_in_scope("https://192.168.1.10:8443/x"))
        self.assertFalse(s.is_in_scope("https://10.0.0.1/x"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

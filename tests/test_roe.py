"""Preuves fail-closed de la gate ROE. `python -m unittest -v` (stdlib, zéro dépendance)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unittest.mock as _mock                                 # noqa: E402
import forge.roe as _roe_mod                                  # noqa: E402
from forge.roe import Scope, Roe, Action, VETO, DRY_RUN, FIRE  # noqa: E402


# --- DÉTERMINISME DNS (anti-flake) — neutralise le SEUL point d'I/O réseau de la gate ROE ------------
# La résolution AU POINT DE TIR (`roe._resolve_ips` -> socket.getaddrinfo) frappait le VRAI resolver pour
# les hôtes RFC 6761 `.test`/`.example`. Ces TLD sont RÉSERVÉS et ne résolvent JAMAIS : le chemin nominal
# est donc NXDOMAIN -> `[]` -> hôte inconnu, non-privé -> FIRE (pin vide). MAIS sous charge, le lookup peut
# STALLER > `_RESOLVE_TIMEOUT` (5s) -> `_ResolveTimeout` -> VETO fail-closed, faisant FLIPPER de façon non
# déterministe les tests qui attendent FIRE (flake ~1/5-8 corrélé aux runs lents/chargés). On force ici un
# NXDOMAIN IMMÉDIAT (gaierror) — exactement le résultat GARANTI d'un `.test`/`.example`, mais instantané :
# hermétique, déterministe, ZÉRO réseau, ZÉRO stall. Le chemin ROE reste PLEINEMENT exercé (résolution ->
# branche hôte-inconnu -> verdict). Les tests qui vérifient une résolution SPÉCIFIQUE (privé / IP publique /
# timeout / out_scope) re-patchent `getaddrinfo` LOCALEMENT : leur `with mock.patch.object` prime puis
# restaure CE défaut à la sortie (imbrication propre) -> ces preuves-là restent intactes et significatives.
_gai_patch = None


def setUpModule():
    global _gai_patch
    _gai_patch = _mock.patch.object(_roe_mod.socket, "getaddrinfo",
                                    side_effect=_roe_mod.socket.gaierror("mocked NXDOMAIN (.test/.example)"))
    _gai_patch.start()


def tearDownModule():
    if _gai_patch is not None:
        _gai_patch.stop()


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


class TestNetworkPolicyPrivate(unittest.TestCase):
    """POLITIQUE RÉSEAU (privé/LAN/loopback) — enforcement AUTORITATIF fail-closed du moteur.
    Contrat : scope.json porte `allow_private` (bool). OFF (défaut) => toute cible qui EST une IP
    privée OU qui RÉSOUT vers une IP privée est VÉTOÉE, MÊME in-scope. ON => elle tire (soumise au reste)."""
    import forge.roe as _roe

    def _armed_auto(self, in_scope, allow_private):
        s = Scope({"mode": "grey", "in_scope": list(in_scope), "allow_private": allow_private})
        roe = Roe(s, mode="auto"); roe.arm()
        return roe

    def test_default_is_fail_closed_absent_field(self):
        # champ absent du scope => allow_private False (fail-closed) : IP privée in-scope => VETO.
        s = Scope({"mode": "grey", "in_scope": ["127.0.0.1"]})
        self.assertFalse(s.allow_private)
        roe = Roe(s, mode="auto"); roe.arm()
        self.assertEqual(roe.decide(Action("demo.fingerprint", "127.0.0.1")).verdict, VETO)

    def test_literal_private_ips_vetoed_when_off(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9",
                   "169.254.1.1", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1"):
            roe = self._armed_auto([ip], allow_private=False)
            d = roe.decide(Action("demo.fingerprint", ip))
            self.assertEqual(d.verdict, VETO, f"{ip} devait être VÉTOÉ (politique OFF)")
            self.assertTrue(any("politique réseau" in r for r in d.reasons), ip)

    def test_ipv4_mapped_v6_private_vetoed(self):
        # ::ffff:127.0.0.1 : le verdict se décide sur l'IPv4 embarquée -> privé.
        roe = self._armed_auto(["::ffff:127.0.0.1"], allow_private=False)
        self.assertEqual(roe.decide(Action("x", "::ffff:127.0.0.1")).verdict, VETO)

    def test_hostname_resolving_to_private_is_vetoed_antirebinding(self):
        # hostname d'apparence publique qui RÉSOUT vers 127.0.0.1 -> VETO (anti-rebinding/SSRF).
        import unittest.mock as mock
        fake = [(2, 1, 6, "", ("127.0.0.1", 0))]
        roe = self._armed_auto(["rebind.example"], allow_private=False)
        with mock.patch.object(self._roe.socket, "getaddrinfo", return_value=fake) as gai:
            d = roe.decide(Action("demo.fingerprint", "rebind.example"))
            self.assertTrue(gai.called, "getaddrinfo doit être consulté pour un hostname")
        self.assertEqual(d.verdict, VETO)
        self.assertTrue(any("politique réseau" in r for r in d.reasons))

    def test_hostname_resolving_to_private_among_many_addrs_vetoed(self):
        # une SEULE adresse privée parmi plusieurs résolues suffit à véto (on vérifie TOUT).
        import unittest.mock as mock
        fake = [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("10.1.2.3", 0))]
        roe = self._armed_auto(["mixed.example"], allow_private=False)
        with mock.patch.object(self._roe.socket, "getaddrinfo", return_value=fake):
            self.assertEqual(roe.decide(Action("x", "mixed.example")).verdict, VETO)

    def test_private_fires_when_policy_on(self):
        # allow_private True => l'IP privée in-scope tire (soumise au reste du ROE).
        roe = self._armed_auto(["127.0.0.1"], allow_private=True)
        self.assertEqual(roe.decide(Action("demo.fingerprint", "127.0.0.1")).verdict, FIRE)

    def test_hostname_resolving_private_fires_when_policy_on(self):
        import unittest.mock as mock
        fake = [(2, 1, 6, "", ("127.0.0.1", 0))]
        roe = self._armed_auto(["rebind.example"], allow_private=True)
        with mock.patch.object(self._roe.socket, "getaddrinfo", return_value=fake):
            self.assertEqual(roe.decide(Action("x", "rebind.example")).verdict, FIRE)

    def test_public_target_unaffected_when_off(self):
        # une cible PUBLIQUE (IP + hostname résolvant public) n'est JAMAIS bloquée par cette politique.
        import unittest.mock as mock
        roe = self._armed_auto(["93.184.216.34", "public.example"], allow_private=False)
        self.assertEqual(roe.decide(Action("x", "93.184.216.34")).verdict, FIRE)
        fake = [(2, 1, 6, "", ("93.184.216.34", 0))]
        with mock.patch.object(self._roe.socket, "getaddrinfo", return_value=fake):
            self.assertEqual(roe.decide(Action("x", "public.example")).verdict, FIRE)

    def test_unresolvable_hostname_not_flagged_private(self):
        # résolution qui échoue => non-privé (aucune connexion possible) ; le scope-guard reste juge.
        import unittest.mock as mock
        import socket as _socket
        roe = self._armed_auto(["nxdomain.example"], allow_private=False)
        with mock.patch.object(self._roe.socket, "getaddrinfo", side_effect=_socket.gaierror):
            # in-scope + non-privé (non résolu) => tire (le tir échouera au niveau réseau, pas au ROE).
            self.assertEqual(roe.decide(Action("x", "nxdomain.example")).verdict, FIRE)


class TestAntiRebindingFireTime(unittest.TestCase):
    """ANTI-REBINDING — la TOCTOU sur le VERDICT est fermée : la résolution a lieu AU POINT DE TIR
    (pas en plan/dry) et le verdict est rendu CONTRE l'IP résolue, ensuite ÉPINGLÉE sur la Decision."""
    import forge.roe as _roe

    def _armed_auto(self, in_scope, allow_private=False, out_scope=()):
        s = Scope({"mode": "grey", "in_scope": list(in_scope),
                   "out_scope": list(out_scope), "allow_private": allow_private})
        roe = Roe(s, mode="auto"); roe.arm()
        return roe

    def test_public_then_private_is_vetoed_at_fire(self):
        # Un résolveur qui change ENTRE le plan et le tir : public d'abord, PRIVÉ ensuite. Le ROE ne
        # résolvant qu'au tir, c'est l'IP PRIVÉE (127.0.0.1) qui décide -> VETO (rebinding attrapé).
        import unittest.mock as mock
        public = [(2, 1, 6, "", ("93.184.216.34", 0))]
        private = [(2, 1, 6, "", ("127.0.0.1", 0))]
        roe = self._armed_auto(["rebind.example"], allow_private=False)
        with mock.patch.object(self._roe.socket, "getaddrinfo",
                               side_effect=[public, private]) as gai:
            # Plan (non armé) : AUCUNE résolution (chemin inerte) -> la 1re réponse mockée reste intacte.
            plan_roe = Roe(Scope({"mode": "grey", "in_scope": ["rebind.example"]}))
            plan_roe.decide(Action("x", "rebind.example"))
            self.assertEqual(gai.call_count, 0, "le plan/dry ne doit PAS résoudre (opsec/L3)")
            # Tir : résout MAINTENANT -> obtient l'IP publique (1re réponse). Rebind : 2e décision (cache
            # neuf sur un nouveau scope) obtient l'IP privée -> VETO.
            d1 = roe.decide(Action("x", "rebind.example"))
            self.assertEqual(d1.verdict, FIRE)
            self.assertEqual(d1.pinned_ips, ["93.184.216.34"], "l'IP résolue doit être ÉPINGLÉE")
            roe2 = self._armed_auto(["rebind.example"], allow_private=False)
            d2 = roe2.decide(Action("x", "rebind.example"))
            self.assertEqual(d2.verdict, VETO, "rebind vers privé au tir -> VETO")
            self.assertTrue(any("politique réseau" in r for r in d2.reasons))

    def test_no_dns_resolution_in_plan_or_dry(self):
        # Un hostname (non armé) ne doit JAMAIS déclencher getaddrinfo : chemin inerte, pas de fuite opsec.
        import unittest.mock as mock
        s = Scope({"mode": "grey", "in_scope": ["host.example"]})
        roe = Roe(s)                                          # NON armé -> DRY_RUN
        with mock.patch.object(self._roe.socket, "getaddrinfo",
                               return_value=[(2, 1, 6, "", ("127.0.0.1", 0))]) as gai:
            d = roe.decide(Action("x", "host.example"))
            self.assertEqual(d.verdict, DRY_RUN)
            self.assertEqual(gai.call_count, 0, "aucune résolution DNS hors du point de tir")

    def test_resolution_timeout_is_veto_failclosed(self):
        # Une résolution qui DÉPASSE la deadline -> VETO fail-closed (on ne peut pas prouver « public »).
        import unittest.mock as mock
        import time
        def _stall(*a, **k):
            time.sleep(2.0); return [(2, 1, 6, "", ("93.184.216.34", 0))]
        roe = self._armed_auto(["slow.example"], allow_private=False)
        with mock.patch.object(self._roe, "_RESOLVE_TIMEOUT", 0.2), \
             mock.patch.object(self._roe.socket, "getaddrinfo", side_effect=_stall):
            d = roe.decide(Action("x", "slow.example"))
        self.assertEqual(d.verdict, VETO)
        self.assertTrue(any("expirée" in r for r in d.reasons))

    def test_dns_cache_resolves_once_per_run(self):
        # Le cache DNS par-run : le même hôte n'est résolu QU'UNE fois (stabilité du verdict + anti-stall).
        import unittest.mock as mock
        roe = self._armed_auto(["cached.example"], allow_private=False)
        fake = [(2, 1, 6, "", ("93.184.216.34", 0))]
        with mock.patch.object(self._roe.socket, "getaddrinfo", return_value=fake) as gai:
            roe.decide(Action("a", "cached.example"))
            roe.decide(Action("b", "cached.example"))
            self.assertEqual(gai.call_count, 1, "résolution mémoïsée : un seul getaddrinfo pour 2 décisions")

    def test_hostname_resolving_into_out_scope_cidr_vetoed(self):
        # L4 : un hostname qui RÉSOUT dans une plage out_scope (CIDR) est VÉTOÉ (symétrie avec le veto privé).
        import unittest.mock as mock
        fake = [(2, 1, 6, "", ("203.0.113.7", 0))]           # dans 203.0.113.0/24 (out_scope)
        roe = self._armed_auto(["cdn.example"], allow_private=True, out_scope=["203.0.113.0/24"])
        with mock.patch.object(self._roe.socket, "getaddrinfo", return_value=fake):
            d = roe.decide(Action("x", "cdn.example"))
        self.assertEqual(d.verdict, VETO)
        self.assertTrue(any("out_scope" in r for r in d.reasons))

    def test_pinned_ips_empty_on_non_fire(self):
        # Une Decision non-FIRE ne porte JAMAIS d'IP épinglée (pas de résolution -> pas de pin).
        roe = Roe(Scope({"mode": "grey", "in_scope": ["app.test"]}))   # non armé -> DRY_RUN
        d = roe.decide(Action("x", "app.test"))
        self.assertEqual(d.verdict, DRY_RUN)
        self.assertEqual(d.pinned_ips, [])


class TestLogFailSafe(unittest.TestCase):
    """L5 — un échec d'écriture du ledger dans `_log` ne doit JAMAIS altérer/annuler un verdict."""

    def test_log_raising_does_not_change_verdict(self):
        class _BoomLedger:
            def append(self, *a, **k):
                raise IOError("disque plein / WORM verrouillé")
        s = Scope({"mode": "grey", "in_scope": ["app.test"]})
        roe = Roe(s, ledger=_BoomLedger(), mode="auto"); roe.arm()
        d = roe.decide(Action("demo.fingerprint", "app.test"))
        # le ledger explose à chaque append, mais le verdict reste CORRECT (FIRE) et non corrompu.
        self.assertEqual(d.verdict, FIRE)

    def test_log_raising_preserves_veto(self):
        class _BoomLedger:
            def append(self, *a, **k):
                raise RuntimeError("boom")
        s = Scope({"mode": "grey", "in_scope": ["app.test"]})
        roe = Roe(s, ledger=_BoomLedger())
        d = roe.decide(Action("x", "evil.example"))          # hors scope -> VETO malgré le ledger cassé
        self.assertEqual(d.verdict, VETO)


if __name__ == "__main__":
    unittest.main(verbosity=2)

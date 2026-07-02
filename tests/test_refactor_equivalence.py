"""GARDE-FOU du refactor de dédup (base Oracle + registre unique techniques.py).

Ce fichier est la PREUVE que le refactor n'a RIEN changé d'observable :
  (a) le MÊME ensemble de kinds reste enregistré (pinné littéralement + snapshot JSON figé) ;
  (b) l'ensemble QUALIFYING du planner == l'ancien (pinné littéralement) + DEFAULT_CHECKLIST ;
  (c) schema.DEFAULT_FIXES == snapshot pré-refactor pour CHAQUE clé (rien n'a dérivé) ;
  (d) chaque oracle émet un Finding équivalent au snapshot pré-refactor (réseau mocké — zéro I/O) ;
  (e) anti-drift : le mitre/cwe déclaré par chaque module == la table techniques.py (source unique) ;
  (f) le câblage HTTP partagé Oracle._http renvoie la forme exacte attendue par chaque `_fetch`
      (les autres tests monkeypatchent `_fetch` et ne couvriraient pas une régression de `_http`).

Les snapshots (`tests/_snapshots/*.json`) ont été CAPTURÉS sur le code PRÉ-refactor : ce sont eux
l'oracle de non-régression, pas la table (comparaison non circulaire).
"""
import email.message
import io
import json
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import schema, planner, purple, techniques           # noqa: E402
from forge import modules as mods                                # noqa: E402
from forge.roe import Action                                     # noqa: E402
from forge.modules.oracle import Oracle                          # noqa: E402
from forge.modules.ssrf import SsrfCallback                      # noqa: E402
from forge.modules.auth import AuthTakeover                      # noqa: E402
from forge.modules.cors import CorsCredentials                   # noqa: E402
from forge.modules.access_control import IdorDifferential        # noqa: E402

SNAP = Path(__file__).resolve().parent / "_snapshots"


def _snap(name):
    return json.loads((SNAP / name).read_text(encoding="utf-8"))


def _strip(d):
    d = dict(d)
    d.pop("ts", None)                        # seul champ volatile (horodatage)
    return d


def _patch(cls, fn):
    orig = cls._fetch
    cls._fetch = staticmethod(fn)
    return lambda: setattr(cls, "_fetch", orig)


# Ensemble de kinds attendu — pinné LITTÉRALEMENT. Additif : les 5 modules PASSIFS de cartographie
# de surface (recon_surface.py) + les 3 modules ACTIFS de reachability (recon_active.py) sont des
# kinds LIVRÉS au même titre que recon.httpx/recon.nmap.
EXPECTED_KINDS = {
    "access_control.idor", "auth.takeover", "burp.scan", "cors.credentials", "demo.fingerprint",
    "evasion.idor_intercept", "evasion.turnstile", "evasion.xhr", "msf.module", "origin.find",
    "recon.httpx", "recon.nmap", "ssrf.callback", "web.nuclei",
    "recon.subdomains", "recon.dns", "recon.js_endpoints", "recon.urls", "recon.tech",
    "recon.content", "recon.secrets", "recon.waf",
    # oracles d'injection server-side à preuve bénigne (injection.py)
    "ssti.eval", "path.traversal", "sqli.probe",
    # oracles client-side / flux de requête à preuve minimale (clientflow.py)
    "xss.reflected", "redirect.open", "csrf.state_change",
    # oracles token/API à preuve compte-opérateur (tokenapi.py)
    "jwt.weakness", "graphql.access",
}
# Ensemble QUALIFYING attendu — pinné LITTÉRALEMENT (ancien planner.QUALIFYING codé en dur).
EXPECTED_QUALIFYING = {
    "idor", "bola", "access_control", "auth", "auth_bypass", "ato",
    "rce", "sqli", "ssrf", "business_logic", "biz", "privesc",
}
EXPECTED_CHECKLIST = ["access_control", "auth", "ato", "ssrf", "sqli", "rce", "business_logic"]


class TestModuleKindSetUnchanged(unittest.TestCase):
    def test_kind_set_matches_literal_pin(self):
        self.assertEqual(set(mods.kinds()), EXPECTED_KINDS)

    def test_idor_lives_in_access_control_not_web(self):
        # access_control.idor a bien été SORTI de web.py vers access_control.py
        import forge.modules.web as webmod
        import forge.modules.access_control as acmod
        self.assertFalse(hasattr(webmod, "IdorDifferential"))     # plus dans web.py
        self.assertTrue(hasattr(acmod, "IdorDifferential"))       # dans access_control.py
        self.assertIs(mods.get("access_control.idor").__class__, acmod.IdorDifferential)
        # web.py n'enregistre plus QUE web.nuclei
        web_kinds = [k for k, c in mods.REGISTRY.items() if c.__module__ == webmod.__name__]
        self.assertEqual(web_kinds, ["web.nuclei"])

    def test_oracles_build_on_base(self):
        for k in ("access_control.idor", "ssrf.callback", "auth.takeover", "cors.credentials"):
            self.assertIsInstance(mods.get(k), Oracle, f"{k} devrait hériter d'Oracle")


class TestPlannerQualifyingUnchanged(unittest.TestCase):
    def test_qualifying_equals_literal_pin(self):
        self.assertEqual(set(planner.QUALIFYING), EXPECTED_QUALIFYING)

    def test_qualifying_derived_from_table(self):
        self.assertEqual(set(planner.QUALIFYING), techniques.qualifying_classes())

    def test_checklist_unchanged(self):
        self.assertEqual(planner.DEFAULT_CHECKLIST, EXPECTED_CHECKLIST)


class TestSchemaRemediationUnchanged(unittest.TestCase):
    def test_default_fixes_equals_pre_refactor_snapshot(self):
        # (c) — pour CHAQUE clé connue, la remédiation est identique au pré-refactor.
        before = _snap("default_fixes.json")
        self.assertEqual(schema.DEFAULT_FIXES, before)
        self.assertEqual(set(schema.DEFAULT_FIXES), set(before))
        for k in before:
            self.assertEqual(schema.DEFAULT_FIXES[k], before[k], f"remédiation dérivée pour {k}")

    def test_default_fix_for_stable_for_every_known_key(self):
        # default_fix_for(cwe=clé) renvoie exactement la remédiation de la table pour chaque clé.
        for k, v in _snap("default_fixes.json").items():
            self.assertEqual(schema.default_fix_for(cwe=k), v, f"default_fix_for({k})")


class TestPurpleMitreUnchanged(unittest.TestCase):
    def test_mitre_by_kind_equals_snapshot(self):
        self.assertEqual(purple.DEFAULT_MITRE_BY_KIND, _snap("mitre_by_kind.json"))


class TestNoTaxonomyDrift(unittest.TestCase):
    """(e) — chaque module déclare EXACTEMENT le mitre/cwe de la table unique (aucune dérive possible)."""

    def test_module_mitre_matches_table(self):
        for key, t in techniques.TECHNIQUES.items():
            if "." not in key:                          # seuls les KINDS de module (clé pointée)
                continue
            self.assertEqual(mods.get(key).mitre, t.mitre, f"mitre dérive pour {key}")

    def test_oracle_cwe_matches_table(self):
        for k in ("access_control.idor", "ssrf.callback", "auth.takeover", "cors.credentials"):
            self.assertEqual(mods.get(k).cwe, techniques.cwe_for(k), f"cwe dérive pour {k}")


class TestBrainClsExploitDerivedFromTable(unittest.TestCase):
    """Le cerveau dérive cls/exploit de la table — pins littéraux du comportement historique."""

    EXPECT = {
        "access_control.idor": ("access_control", True),
        "ssrf.callback": ("ssrf", True),
        "auth.takeover": ("auth", True),
        "cors.credentials": ("access_control", True),
        "web.nuclei": ("", False), "recon.httpx": ("", False),
        "origin.find": ("", False), "recon.nmap": ("", False),
    }

    def test_action_class_and_exploit(self):
        for kind, (cls, exp) in self.EXPECT.items():
            self.assertEqual(techniques.action_class(kind), cls, kind)
            self.assertEqual(techniques.action_exploit(kind), exp, kind)

    def test_brain_proposes_expected_cls_exploit(self):
        from forge.brain import HeuristicBrain
        from forge.schema import Target
        acts = {a.kind: a for a in HeuristicBrain().propose([Target("app.test", kind="app")])}
        # cors.credentials est classé 'access_control' (plancher planner) et exploit=True
        self.assertEqual(acts["cors.credentials"].cls, "access_control")
        self.assertTrue(acts["cors.credentials"].exploit)
        self.assertEqual(acts["ssrf.callback"].cls, "ssrf")
        self.assertEqual(acts["access_control.idor"].cls, "access_control")
        # recon.httpx : pas d'override -> Action dérive le suffixe 'httpx', non-exploit
        self.assertEqual(acts["recon.httpx"].cls, "httpx")
        self.assertFalse(acts["recon.httpx"].exploit)


class TestOracleFindingsMatchSnapshot(unittest.TestCase):
    """(d) — chaque oracle émet un Finding équivalent au pré-refactor (réseau mocké)."""

    def _cases(self):
        cases = {}
        tok = SsrfCallback._token("https://app.test/fetch", "url")
        base = {"param": "url", "callback_base": "http://cb.test", "callback_check_url": "http://cb.test/seen"}
        r = _patch(SsrfCallback, lambda url, headers=None, timeout=15, method="GET", data=None:
                   (200, f"seen {tok}") if "cb.test/seen" in url else (200, "ok"))
        cases["ssrf_proof"] = _strip(SsrfCallback().fire(Action("ssrf.callback", "https://app.test/fetch", params=base))[0].to_dict()); r()
        r = _patch(SsrfCallback, lambda url, headers=None, timeout=15, method="GET", data=None:
                   (200, "no cb") if "cb.test/seen" in url else (200, "ok"))
        cases["ssrf_negative"] = _strip(SsrfCallback().fire(Action("ssrf.callback", "https://app.test/fetch", params=base))[0].to_dict()); r()
        cases["ssrf_skip"] = _strip(SsrfCallback().fire(Action("ssrf.callback", "https://app.test", params={"param": "url"}))[0].to_dict())

        r = _patch(AuthTakeover, lambda url, headers=None, timeout=15, method="GET", data=None:
                   (200, '{"email":"victim@corp.test","id":777}', {}))
        cases["auth_proof"] = _strip(AuthTakeover().fire(Action("auth.takeover", "https://app.test", params={
            "whoami_url": "https://app.test/me", "victim_marker": "victim@corp.test",
            "attacker_marker": "attacker@corp.test", "attacker_session_headers": {"Cookie": "s=forged"}}))[0].to_dict()); r()
        r = _patch(AuthTakeover, lambda url, headers=None, timeout=15, method="GET", data=None:
                   (200, '{"email":"attacker@corp.test"}', {}))
        cases["auth_negative"] = _strip(AuthTakeover().fire(Action("auth.takeover", "https://app.test", params={
            "whoami_url": "https://app.test/me", "victim_marker": "victim@corp.test",
            "attacker_marker": "attacker@corp.test"}))[0].to_dict()); r()
        cases["auth_skip"] = _strip(AuthTakeover().fire(Action("auth.takeover", "https://app.test", params={}))[0].to_dict())

        r = _patch(CorsCredentials, lambda url, headers=None, timeout=15:
                   (200, '{"balance":42}', {"access-control-allow-origin": "https://attacker.example",
                                            "access-control-allow-credentials": "true"}))
        cases["cors_high"] = _strip(CorsCredentials().fire(Action("cors.credentials", "https://api.app.test/account",
                                    params={"attacker_origin": "https://attacker.example"}))[0].to_dict()); r()
        r = _patch(CorsCredentials, lambda url, headers=None, timeout=15:
                   (200, '{"email":"victim@corp.test"}', {"access-control-allow-origin": "https://attacker.example",
                                                          "access-control-allow-credentials": "true"}))
        cases["cors_critical"] = _strip(CorsCredentials().fire(Action("cors.credentials", "https://api.app.test/account",
                                        params={"attacker_origin": "https://attacker.example",
                                                "session_marker": "victim@corp.test", "auth_headers": {"Cookie": "s=victim"}}))[0].to_dict()); r()
        r = _patch(CorsCredentials, lambda url, headers=None, timeout=15:
                   (200, "{}", {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}))
        cases["cors_negative"] = _strip(CorsCredentials().fire(Action("cors.credentials", "https://api.app.test/account",
                                        params={"attacker_origin": "https://attacker.example"}))[0].to_dict()); r()
        cases["cors_skip"] = _strip(CorsCredentials().fire(Action("cors.credentials", "https://api.app.test/account", params={}))[0].to_dict())

        A = {"headers": {"Cookie": "a"}}
        B = {"headers": {"Cookie": "b"}}

        def idor_read(url, headers, timeout=15, method="GET", body=None):
            return (200, '{"owner":"A","data":"secret"}', "application/json") if headers.get("Cookie") in ("a", "b") else (403, "", "")
        r = _patch(IdorDifferential, idor_read)
        cases["idor_read_proof"] = _strip(IdorDifferential().fire(Action("access_control.idor", "https://app.test",
                                          params={"accounts": [A, B], "urls": ["https://app.test/orders/1"]}))[0].to_dict()); r()

        def idor_neg(url, headers, timeout=15, method="GET", body=None):
            if headers.get("Cookie") == "a":
                return (200, "X" * 600, "application/json")
            return (403, "", "")
        r = _patch(IdorDifferential, idor_neg)
        cases["idor_read_negative"] = _strip(IdorDifferential().fire(Action("access_control.idor", "https://app.test",
                                             params={"accounts": [A, B], "urls": ["https://app.test/orders/1"]}))[0].to_dict()); r()

        state = {"n": 0}

        def idor_write(url, headers, timeout=15, method="GET", body=None):
            if method == "GET":
                return (200, f'{{"v":{state["n"]}}}', "application/json")
            state["n"] += 1
            return (200, "", "application/json")
        r = _patch(IdorDifferential, idor_write)
        act = Action("access_control.idor", "https://app.test",
                     params={"accounts": [A, B], "urls": ["https://app.test/orders/1"], "method": "PATCH"})
        act.destructive = True
        cases["idor_write_proof"] = _strip(IdorDifferential().fire(act)[0].to_dict()); r()
        cases["idor_skip"] = _strip(IdorDifferential().fire(Action("access_control.idor", "https://app.test",
                                    params={"accounts": [{"headers": {}}], "urls": []}))[0].to_dict())
        cases["idor_write_failclosed"] = _strip(IdorDifferential().fire(Action("access_control.idor", "https://app.test",
                                                params={"accounts": [A, B], "urls": ["https://app.test/o/1"], "method": "PUT"}))[0].to_dict())
        return cases

    def test_every_oracle_finding_matches_snapshot(self):
        before = _snap("oracle_findings.json")
        after = self._cases()
        self.assertEqual(set(after), set(before))
        for name in sorted(before):
            self.assertEqual(after[name], before[name], f"Finding '{name}' a changé (régression observable)")


# --- (f) garde du câblage HTTP partagé Oracle._http (seam non couvert par les autres tests) ---
def _mkheaders(d):
    m = email.message.Message()
    for k, v in d.items():
        m[k] = v
    return m


class _FakeResp:
    def __init__(self, status, body, headers):
        self.status = status
        self._body = body.encode("utf-8")
        self.headers = _mkheaders(headers)

    def read(self, n=-1):
        return self._body[:n] if (n is not None and n >= 0) else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestSharedHttpWiring(unittest.TestCase):
    """Oracle._http + chaque `_fetch` réel : forme du tuple exacte sur succès / HTTPError / transport."""

    def _with_urlopen(self, fn):
        orig = urllib.request.urlopen
        urllib.request.urlopen = fn
        self.addCleanup(lambda: setattr(urllib.request, "urlopen", orig))

    def test_success_shapes(self):
        self._with_urlopen(lambda req, timeout=15: _FakeResp(200, '{"a":1}', {"Content-Type": "application/json; charset=utf-8"}))
        self.assertEqual(IdorDifferential._fetch("http://x", {}), (200, '{"a":1}', "application/json"))
        self.assertEqual(SsrfCallback._fetch("http://x"), (200, '{"a":1}'))
        st, body, h = AuthTakeover._fetch("http://x")
        self.assertEqual((st, body), (200, '{"a":1}'))
        self.assertEqual(h.get("Content-Type"), "application/json; charset=utf-8")   # dict d'en-têtes
        st, body, h = CorsCredentials._fetch("http://x")
        self.assertEqual((st, body), (200, '{"a":1}'))
        self.assertEqual(h.get("content-type"), "application/json; charset=utf-8")   # clés minuscules

    def test_httperror_shapes(self):
        def boom(req, timeout=15):
            # fp réel (BytesIO) -> pas de SpooledTemporaryFile implicite (évite un ResourceWarning 3.14)
            err = urllib.error.HTTPError("http://x", 403, "Forbidden",
                                         _mkheaders({"Content-Type": "text/html"}), io.BytesIO(b""))
            self.addCleanup(err.close)
            raise err
        self._with_urlopen(boom)
        self.assertEqual(IdorDifferential._fetch("http://x", {}), (403, "", "text/html"))
        self.assertEqual(SsrfCallback._fetch("http://x"), (403, ""))
        self.assertEqual(AuthTakeover._fetch("http://x")[:2], (403, ""))
        self.assertEqual(CorsCredentials._fetch("http://x")[:2], (403, ""))

    def test_transport_error_shapes(self):
        def boom(req, timeout=15):
            raise urllib.error.URLError("connection refused")
        self._with_urlopen(boom)
        self.assertEqual(IdorDifferential._fetch("http://x", {}), (None, "", ""))
        self.assertEqual(SsrfCallback._fetch("http://x"), (None, ""))
        self.assertEqual(AuthTakeover._fetch("http://x"), (None, "", {}))
        self.assertEqual(CorsCredentials._fetch("http://x"), (None, "", {}))


if __name__ == "__main__":
    unittest.main(verbosity=2)

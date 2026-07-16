"""LOT SCHEMA/FIX — remédiation (`fix`) + CWE dédié + CVSS de base sur le modèle Finding.

Couvre :
  - schema : auto-dérivation de `cwe` depuis `category`, repli `fix` par mapping, CVSS de base par
    sévérité, et — surtout — la NON-régression (le fix/cwe explicite d'un module PRIME, category reste).
  - modules à preuve (IDOR lecture+write, SSRF, ATO, CORS, origine vérifiée) : les findings ÉMIS sur
    le chemin de preuve portent un `fix` non vide ET un `cwe` non vide.
  - rétro-compat : to_dict() porte les nouveaux champs, sérialise toujours, et les champs historiques
    (category/mitre/severity) sont intacts.

Hermétique : on monkeypatch les `_fetch` des oracles réseau (zéro I/O).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import schema                                       # noqa: E402
from forge.schema import Finding, default_fix_for, extract_cwe, cvss_base_for  # noqa: E402
from forge.roe import Action                                   # noqa: E402
from forge.modules.ssrf import SsrfCallback                    # noqa: E402
from forge.modules.auth import AuthTakeover                    # noqa: E402
from forge.modules.cors import CorsCredentials                 # noqa: E402
from forge.modules.access_control import IdorDifferential      # noqa: E402


def _patch(cls, fn):
    orig = cls._fetch
    cls._fetch = staticmethod(fn)
    return lambda: setattr(cls, "_fetch", orig)


class TestSchemaHelpers(unittest.TestCase):
    def test_extract_cwe_variants(self):
        self.assertEqual(extract_cwe("CWE-639"), "CWE-639")
        self.assertEqual(extract_cwe("cwe_918 something"), "CWE-918")
        self.assertEqual(extract_cwe("access_control.idor"), "")   # pas de CWE -> vide
        self.assertEqual(extract_cwe(""), "")

    def test_default_fix_by_cwe_and_category(self):
        self.assertTrue(default_fix_for(cwe="CWE-639"))
        self.assertTrue(default_fix_for(category="CWE-918"))       # CWE niché dans category
        self.assertTrue(default_fix_for(category="origin-exposure"))
        self.assertTrue(default_fix_for(category="cors.credentials"))  # token 'cors'
        self.assertEqual(default_fix_for(category="inconnu-zzz"), "")  # pas de mapping -> vide

    def test_cvss_base_by_severity(self):
        v, s = cvss_base_for("CRITICAL")
        self.assertTrue(v.startswith("CVSS:3.1/"))
        self.assertGreater(s, 9.0)
        self.assertEqual(cvss_base_for("INFO"), ("", 0.0))
        self.assertEqual(cvss_base_for("???"), ("", 0.0))          # inconnu -> fail-open


class TestFindingPostInit(unittest.TestCase):
    def test_cwe_derived_from_category(self):
        f = Finding(target="t", title="x", category="CWE-639")
        self.assertEqual(f.cwe, "CWE-639")                         # rétro-compat : dérivé de category

    def test_explicit_cwe_wins(self):
        f = Finding(target="t", title="x", category="recon", cwe="CWE-200")
        self.assertEqual(f.cwe, "CWE-200")                         # cwe explicite prime

    def test_fix_autofilled_when_empty(self):
        f = Finding(target="t", title="x", category="CWE-918")
        self.assertTrue(f.fix)                                     # repli mapping
        self.assertIn("allowlist", f.fix.lower())

    def test_explicit_fix_priming(self):
        f = Finding(target="t", title="x", category="CWE-639", fix="conseil spécifique du module")
        self.assertEqual(f.fix, "conseil spécifique du module")    # le fix du module PRIME

    def test_no_fix_when_no_mapping(self):
        f = Finding(target="t", title="x", category="DEMO")
        self.assertEqual(f.fix, "")                                # pas de mapping -> reste vide

    def test_cvss_autofilled_from_severity(self):
        f = Finding(target="t", title="x", severity="HIGH")
        self.assertTrue(f.cvss_vector.startswith("CVSS:3.1/"))
        self.assertGreater(f.cvss_score, 0.0)

    def test_explicit_cvss_priming(self):
        f = Finding(target="t", title="x", severity="HIGH",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_score=9.1)
        self.assertEqual(f.cvss_score, 9.1)

    def test_info_has_no_cvss(self):
        f = Finding(target="t", title="x", severity="INFO")
        self.assertEqual((f.cvss_vector, f.cvss_score), ("", 0.0))

    def test_out_of_range_severity_clamps_to_info(self):
        # L16 : une sévérité hors SEVERITIES (typo/plugin hostile/valeur forgée) est RABATTUE sur INFO
        # (fail-closed, miroir du clamp `status`). Ne crashe pas, ne propage pas la valeur arbitraire.
        for bad in ("SUPER-CRITICAL", "urgent", "", "9", "None", "  "):
            f = Finding(target="t", title="x", severity=bad)
            self.assertEqual(f.severity, "INFO", f"{bad!r} devait être rabattu sur INFO")
            self.assertEqual(f.sev_rank(), 0)
            self.assertEqual((f.cvss_vector, f.cvss_score), ("", 0.0))   # CVSS dérivé APRÈS le clamp

    def test_lowercase_severity_normalized_not_clamped(self):
        # une sévérité VALIDE mais en minuscules est NORMALISÉE (upper), pas rabattue sur INFO.
        f = Finding(target="t", title="x", severity="high")
        self.assertEqual(f.severity, "HIGH")
        self.assertTrue(f.cvss_vector.startswith("CVSS:3.1/"))

    def test_retrocompat_to_dict_carries_new_fields_and_keeps_old(self):
        f = Finding(target="t", title="x", category="CWE-639", severity="HIGH", mitre="T1190")
        d = f.to_dict()
        for k in ("cwe", "fix", "cvss_vector", "cvss_score"):
            self.assertIn(k, d)                                    # nouveaux champs sérialisés
        self.assertEqual(d["category"], "CWE-639")                 # historique intact
        self.assertEqual(d["mitre"], "T1190")
        self.assertEqual(d["severity"], "HIGH")


class TestProofModulesCarryFixAndCwe(unittest.TestCase):
    """Sur le chemin de PREUVE, chaque oracle émet un finding fix+cwe non vides."""

    def _assert_fix_cwe(self, f):
        self.assertEqual(f.status, "vulnerable", f.title)
        self.assertTrue(f.fix, f"{f.title} : fix vide")
        self.assertTrue(f.cwe, f"{f.title} : cwe vide")
        self.assertTrue(f.cwe.upper().startswith("CWE-"), f"{f.title} : cwe={f.cwe!r}")

    def test_ssrf_proof_carries_fix_cwe(self):
        base = {"param": "url", "callback_base": "http://cb.test",
                "callback_check_url": "http://cb.test/seen"}
        token = SsrfCallback._token("https://app.test/fetch", "url")

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, f"seen {token}") if "cb.test/seen" in url else (200, "ok")
        restore = _patch(SsrfCallback, fake)
        try:
            f = SsrfCallback().fire(Action("ssrf.callback", "https://app.test/fetch", params=base))[0]
        finally:
            restore()
        self._assert_fix_cwe(f)
        self.assertEqual(f.cwe, "CWE-918")

    def test_ato_proof_carries_fix_cwe(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, '{"email":"victim@corp.test"}', {})
        restore = _patch(AuthTakeover, fake)
        try:
            f = AuthTakeover().fire(Action("auth.takeover", "https://app.test", params={
                "whoami_url": "https://app.test/me", "victim_marker": "victim@corp.test"}))[0]
        finally:
            restore()
        self._assert_fix_cwe(f)
        self.assertEqual(f.cwe, "CWE-287")

    def test_cors_proof_carries_fix_cwe(self):
        def fake(url, headers=None, timeout=15):
            return (200, '{"email":"victim@corp.test"}', {
                "access-control-allow-origin": "https://attacker.example",
                "access-control-allow-credentials": "true"})
        restore = _patch(CorsCredentials, fake)
        try:
            f = CorsCredentials().fire(Action("cors.credentials", "https://api.app.test/account",
                                              params={"attacker_origin": "https://attacker.example"}))[0]
        finally:
            restore()
        self._assert_fix_cwe(f)
        self.assertEqual(f.cwe, "CWE-942")

    def test_idor_read_proof_carries_fix_cwe(self):
        A = {"headers": {"Cookie": "a"}}
        B = {"headers": {"Cookie": "b"}}

        def fake(url, headers, timeout=15, method="GET", body=None):
            # A et B reçoivent le MÊME objet (2xx, même corps) ; anon refusé (403).
            if headers.get("Cookie") in ("a", "b"):
                return (200, '{"owner":"A","data":"secret"}', "application/json")
            return (403, "", "")
        restore = _patch(IdorDifferential, fake)
        try:
            f = IdorDifferential().fire(Action("access_control.idor", "https://app.test", params={
                "accounts": [A, B], "urls": ["https://app.test/orders/1"]}))[0]
        finally:
            restore()
        self._assert_fix_cwe(f)
        self.assertEqual(f.cwe, "CWE-639")

    def test_idor_write_proof_carries_fix_cwe(self):
        A = {"headers": {"Cookie": "a"}}
        B = {"headers": {"Cookie": "b"}}
        state = {"n": 0}

        def fake(url, headers, timeout=15, method="GET", body=None):
            if method == "GET":
                # le corps lu par A change après l'écriture de B (mutation visible)
                return (200, f'{{"v":{state["n"]}}}', "application/json")
            state["n"] += 1                       # B mute l'objet
            return (200, "", "application/json")
        restore = _patch(IdorDifferential, fake)
        try:
            act = Action("access_control.idor", "https://app.test", params={
                "accounts": [A, B], "urls": ["https://app.test/orders/1"], "method": "PATCH"})
            act.destructive = True                # capacité write autorisée par le ROE
            f = IdorDifferential().fire(act)[0]
        finally:
            restore()
        self._assert_fix_cwe(f)
        self.assertEqual(f.severity, "CRITICAL")
        self.assertEqual(f.cwe, "CWE-639")


if __name__ == "__main__":
    unittest.main(verbosity=2)

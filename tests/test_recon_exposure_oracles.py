"""LOT RECON/EXPOSURE/TAKEOVER — les trois oracles NATIFS ajoutés (`subdomain.takeover`,
`framework.exposure`, `ssrf.cloud_metadata`) : chacun

  (A) apparaît AUTOMATIQUEMENT dans le catalogue groupé (`by_vuln_class`), le bon profil (`profile_set`
      / `resolve_enabled_kinds`), le pipeline (`pipeline_ordered`) et `forge modules --json`, SANS câblage
      par-technique (contrat « drop-in technique ») ;
  (B) respecte les INVARIANTS : scope-guard fail-closed (refus hors-scope = ZÉRO I/O), preuve MINIMALE &
      BÉNIGNE (positif -> vulnerable ; négatif -> tested ; jamais de verdict aveugle), non destructif
      (aucune réclamation de ressource / aucun vol de secret — valeurs RÉDIGÉES), dégradation offline, et
      le secret de session n'est JAMAIS fuité dans un finding.

Tous les tests sont HERMÉTIQUES : on monkeypatch les seams (`_resolve_cname`/`_fetch`) — zéro réseau réel ;
le test de secret de session monkeypatch `urllib.request.urlopen`.
"""
import io
import json
import sys
import unittest
import urllib.error
import urllib.parse
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action, Scope                            # noqa: E402
from forge import modules as mods                              # noqa: E402
from forge import techniques                                   # noqa: E402
from forge import cli                                          # noqa: E402
from forge import session as sessionmod                        # noqa: E402
from forge.session import SessionStore                         # noqa: E402
from forge.modules.oracle import Oracle, ScopeGuardedOracle    # noqa: E402
from forge.modules.takeover import SubdomainTakeover           # noqa: E402
from forge.modules.exposure import FrameworkExposure           # noqa: E402
from forge.modules.ssrf import SsrfCloudMetadata               # noqa: E402

NEW_NATIVE = ("subdomain.takeover", "framework.exposure", "ssrf.cloud_metadata")


def _set(cls, name, fn):
    """Remplace un attribut staticmethod de `cls` par `fn` et renvoie un restaurateur préservant EXACTEMENT
    le descripteur d'origine (staticmethod) — ou retirant l'override si l'attribut était HÉRITÉ."""
    had = name in cls.__dict__
    orig = cls.__dict__.get(name)
    setattr(cls, name, staticmethod(fn))

    def restore():
        if had:
            setattr(cls, name, orig)
        else:
            delattr(cls, name)
    return restore


def _boom(*a, **k):
    raise AssertionError("réseau/DNS émis alors qu'aucun ne devait l'être (scope-guard / config)")


# =================================================================================================
class TestNativeAutoIntegration(unittest.TestCase):
    """(A) Le contrat derive-everywhere pour les 3 oracles natifs."""

    def test_registered_with_vuln_class(self):
        for k in NEW_NATIVE:
            self.assertIn(k, mods.kinds(), f"{k} non enregistré")
            t = techniques.technique_for(k)
            self.assertIsNotNone(t, f"{k} absent de techniques.py")
            self.assertTrue(t.vuln_class, f"{k} sans vuln_class")

    def test_registered_set_equals_technique_kinds(self):
        self.assertEqual(set(mods.kinds()), set(techniques.technique_kinds()))

    def test_by_vuln_class_groups(self):
        bvc = techniques.by_vuln_class()
        self.assertIn("subdomain.takeover", bvc["SubdomainTakeover"])
        self.assertIn("framework.exposure", bvc["Exposure"])
        self.assertIn("ssrf.cloud_metadata", bvc["SSRF"])       # cohabite avec ssrf.callback/xspa
        self.assertIn("ssrf.callback", bvc["SSRF"])

    def test_bug_bounty_profile_membership(self):
        bb = techniques.profile_set("bug_bounty")
        pentest = techniques.profile_set("pentest")
        enabled_bb = techniques.resolve_enabled_kinds(profile="bug_bounty")
        for k in NEW_NATIVE:
            self.assertIn(k, bb, f"{k} devrait être bug_bounty_eligible")
            self.assertIn(k, pentest)
            self.assertIn(k, enabled_bb, f"{k} devrait être activé dans le profil bug_bounty (fire-time)")

    def test_profile_flags_coherent(self):
        for k in NEW_NATIVE:
            t = techniques.technique_for(k)
            self.assertTrue(t.bug_bounty_eligible)
            self.assertFalse(t.pentest_only)
            self.assertNotEqual(t.bug_bounty_eligible, t.pentest_only)
            self.assertEqual(t.stage, t.phase)

    def test_pipeline_ordered_includes(self):
        order = techniques.pipeline_ordered()
        for k in NEW_NATIVE:
            self.assertIn(k, order)

    def test_mitre_cwe_match_table(self):
        for k in NEW_NATIVE:
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")
        self.assertEqual(mods.get("subdomain.takeover").cwe, "CWE-350")
        self.assertEqual(mods.get("framework.exposure").cwe, "CWE-200")
        self.assertEqual(mods.get("ssrf.cloud_metadata").cwe, "CWE-918")

    def test_cli_modules_json_lists(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_modules(type("A", (), {"json": True})())
        self.assertEqual(rc, 0)
        rows = {r["kind"]: r for r in json.loads(buf.getvalue())}
        for k in NEW_NATIVE:
            self.assertIn(k, rows, f"{k} absent de `forge modules --json`")
            self.assertEqual(rows[k]["vuln_class"], techniques.technique_for(k).vuln_class)
            self.assertTrue(rows[k]["bug_bounty_eligible"])

    def test_build_on_scope_guarded_base(self):
        for k in NEW_NATIVE:
            m = mods.get(k)
            self.assertIsInstance(m, ScopeGuardedOracle, f"{k} devrait hériter de ScopeGuardedOracle")
            self.assertIsInstance(m, Oracle)


# =================================================================================================
class TestSubdomainTakeover(unittest.TestCase):
    TGT = "app.example.com"
    BASE = {"in_scope": ["*.example.com", "example.com"]}

    def _fire(self, cname_ret, fetch_ret=(404, ""), params=None):
        r_dns = _set(SubdomainTakeover, "_resolve_cname", lambda host: cname_ret)
        r_ft = _set(SubdomainTakeover, "_fetch",
                    lambda url, headers=None, timeout=15: fetch_ret)
        p = dict(self.BASE)
        if params:
            p.update(params)
        try:
            return SubdomainTakeover().fire(Action("subdomain.takeover", self.TGT, params=p))
        finally:
            r_ft(); r_dns()

    def test_vulnerable_dangling_cname_fingerprint(self):
        # CNAME -> Heroku (service connu), la cible résout MAIS le service renvoie « No such app ».
        f = self._fire(("myapp.herokuapp.com", True, True), fetch_ret=(404, "No such app"))
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-350")
        self.assertEqual(f[0].mitre, "T1584.001")
        self.assertIn("Subdomain takeover CONFIRMÉ", f[0].title)
        self.assertIn("Heroku", f[0].evidence)
        self.assertIn("JAMAIS", f[0].evidence)               # ressource jamais réclamée

    def test_vulnerable_dangling_cname_nxdomain(self):
        # CNAME -> S3 (service connu) et la cible NE résout PAS (NXDOMAIN) -> takeover confirmé.
        f = self._fire(("bucket.s3.amazonaws.com", False, True), fetch_ret=(200, "welcome"))
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("AWS S3", f[0].evidence)
        self.assertIn("nxdomain=True", f[0].evidence)

    def test_tested_cname_service_claimed(self):
        # CNAME -> Heroku mais l'app SERT normalement (pas de fingerprint, cible résout) -> pas de takeover.
        f = self._fire(("app.herokuapp.com", True, True), fetch_ret=(200, "my running app"))
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)

    def test_tested_no_cname(self):
        f = self._fire(("", False, True))
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucun CNAME", f[0].title)

    def test_tested_unknown_service(self):
        f = self._fire(("internal.corp.example", True, True))
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non reconnue", f[0].title)

    def test_offline_degrades_skipped(self):
        f = self._fire(("", False, False))                    # ok=False -> résolution DNS indisponible
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("résolution DNS indisponible", f[0].title)

    def test_scope_guard_out_of_scope(self):
        r_dns = _set(SubdomainTakeover, "_resolve_cname", _boom)
        r_ft = _set(SubdomainTakeover, "_fetch", _boom)
        try:
            f = SubdomainTakeover().fire(Action("subdomain.takeover", "evil.example",
                                                params={"in_scope": ["*.example.com", "example.com"]}))
        finally:
            r_ft(); r_dns()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_non_exploit_flags(self):
        m = mods.get("subdomain.takeover")
        self.assertFalse(m.exploit)                           # lecture DNS + GET bénin, ressource jamais réclamée
        self.assertFalse(m.destructive)


# =================================================================================================
class TestFrameworkExposure(unittest.TestCase):
    TGT = "app.test"
    BASE = {"in_scope": ["app.test"]}
    ENV_LEAK = ('{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties",'
                '"properties":{"db.password":"s3cr3t-value-xyz"}}]}')

    def _fire(self, fake, params=None):
        r_ft = _set(FrameworkExposure, "_fetch", fake)
        p = dict(self.BASE)
        if params:
            p.update(params)
        try:
            return FrameworkExposure().fire(Action("framework.exposure", self.TGT, params=p))
        finally:
            r_ft()

    def test_vulnerable_actuator_env_leak_redacted(self):
        def fake(url, headers=None, timeout=15):
            if url.endswith("/actuator/env"):
                return (200, self.ENV_LEAK)
            if url.endswith("/"):
                return (200, "<html>ok</html>")
            return (404, "")
        f = self._fire(fake)
        vuln = [x for x in f if x.status == "vulnerable"]
        self.assertTrue(vuln, "l'endpoint actuator sensible qui fuit doit être vulnerable")
        s = vuln[0]
        self.assertEqual(s.severity, "HIGH")
        self.assertEqual(s.cwe, "CWE-200")
        self.assertIn("Actuator", s.title)
        # REDACTION : la valeur du secret ne fuite jamais dans le finding.
        self.assertNotIn("s3cr3t-value-xyz", s.evidence)
        self.assertIn("redacted", s.evidence.lower())

    def test_vulnerable_next_data_runtimeconfig_redacted(self):
        html = ('<html><head><script id="__NEXT_DATA__" type="application/json">'
                '{"runtimeConfig":{"apiSecret":"TOPSECRET-runtime-9z"},"props":{}}'
                '</script></head><body>hi</body></html>')

        def fake(url, headers=None, timeout=15):
            if url.endswith("/"):
                return (200, html)
            return (404, "")
        f = self._fire(fake)
        nx = [x for x in f if "Next.js" in x.title and x.status == "vulnerable"]
        self.assertTrue(nx, "runtimeConfig serveur fuité -> vulnerable")
        self.assertEqual(nx[0].severity, "MEDIUM")
        self.assertNotIn("TOPSECRET-runtime-9z", nx[0].evidence)

    def test_vulnerable_laravel_telescope_unauth(self):
        def fake(url, headers=None, timeout=15):
            if url.endswith("/telescope"):
                return (200, '<html><title>Laravel Telescope</title><div id="telescope"></div></html>')
            if url.endswith("/"):
                return (200, "<html>ok</html>")
            return (404, "")
        f = self._fire(fake)
        tel = [x for x in f if "Telescope" in x.title and x.status == "vulnerable"]
        self.assertTrue(tel, "Telescope non authentifié -> vulnerable")
        self.assertEqual(tel[0].severity, "HIGH")

    def test_tested_actuator_index_only_no_leak(self):
        def fake(url, headers=None, timeout=15):
            if url.endswith("/actuator"):
                return (200, '{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"}}}')
            if url.endswith("/"):
                return (200, "<html>ok</html>")
            return (404, "")
        f = self._fire(fake)
        self.assertTrue(f)
        self.assertTrue(all(x.status == "tested" for x in f), "index actuator non sensible -> tested")
        self.assertIn("présente", " ".join(x.title for x in f))

    def test_no_exposure_tested(self):
        def fake(url, headers=None, timeout=15):
            if url.endswith("/"):
                return (200, "<html>plain site</html>")
            return (404, "")
        f = self._fire(fake)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("aucune surface de framework sensible", f[0].title)

    def test_offline_degrades_skipped(self):
        f = self._fire(lambda url, headers=None, timeout=15: (None, ""))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)

    def test_scope_guard_out_of_scope(self):
        r_ft = _set(FrameworkExposure, "_fetch", _boom)
        try:
            f = FrameworkExposure().fire(Action("framework.exposure", "evil.example",
                                                params={"in_scope": ["app.test"]}))
        finally:
            r_ft()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_non_exploit_flags(self):
        m = mods.get("framework.exposure")
        self.assertFalse(m.exploit)
        self.assertFalse(m.destructive)


# =================================================================================================
class TestSsrfCloudMetadata(unittest.TestCase):
    TGT = "https://app.test/fetch"
    BASE = {"param": "url", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        r_ft = _set(SsrfCloudMetadata, "_fetch", fake)
        p = dict(self.BASE)
        if params:
            p.update(params)
        try:
            return SsrfCloudMetadata().fire(Action("ssrf.cloud_metadata", self.TGT, params=p))
        finally:
            r_ft()

    def test_vulnerable_inband_aws_credential_redacted(self):
        aws_body = ("ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\nsecurity-groups\n"
                    "AccessKeyId=AKIAEXAMPLE123456\n")

        def fake(url, headers=None, timeout=10, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url or "")
            if "169.254.169.254/latest/meta-data" in dec:
                return (200, aws_body)
            return (200, "pong")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertEqual(f[0].cwe, "CWE-918")
        self.assertIn("AWS", f[0].evidence)
        self.assertIn("SSRF cloud-metadata CONFIRMÉ", f[0].title)
        # credential RÉDIGÉ : jamais la valeur brute.
        self.assertNotIn("AKIAEXAMPLE123456", f[0].evidence)

    def test_vulnerable_inband_azure(self):
        azure = ('{"compute":{"azEnvironment":"AzurePublicCloud","vmId":"abc-123",'
                 '"subscriptionId":"sub-x","resourceGroupName":"rg1"},"network":{}}')

        def fake(url, headers=None, timeout=10, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url or "")
            if "metadata/instance" in dec:
                return (200, azure)
            return (200, "pong")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("Azure", f[0].evidence)

    def test_vulnerable_out_of_band_callback(self):
        token = SsrfCloudMetadata._token(self.TGT, "url")
        check_url = "https://collector.op/poll"

        def fake(url, headers=None, timeout=10, method="GET", data=None):
            if url == check_url:
                return (200, f"collector saw token {token}")
            return (200, "blocked")                            # aucune signature métadonnées in-band
        f = self._fire(fake, params={"callback_base": "https://collector.op",
                                     "callback_check_url": check_url})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertIn("out-of-band", f[0].title)

    def test_reflection_neutralised_no_false_positive(self):
        # l'app REFLÈTE l'URL injectée -> après neutralisation, aucun marqueur de contenu -> pas de FP.
        def fake(url, headers=None, timeout=10, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url or "")
            return (200, f"you asked to fetch {dec}")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested", "le reflet de l'URL ne doit pas passer pour une atteinte")

    def test_tested_no_signature_no_callback(self):
        f = self._fire(lambda url, headers=None, timeout=10, method="GET", data=None: (200, "pong"))
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)

    def test_offline_degrades_skipped(self):
        f = self._fire(lambda url, headers=None, timeout=10, method="GET", data=None: (None, ""))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)

    def test_scope_guard_out_of_scope(self):
        r_ft = _set(SsrfCloudMetadata, "_fetch", _boom)
        try:
            f = SsrfCloudMetadata().fire(Action("ssrf.cloud_metadata", "https://evil.example/fetch",
                                                params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            r_ft()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_skip(self):
        r_ft = _set(SsrfCloudMetadata, "_fetch", _boom)
        try:
            f = SsrfCloudMetadata().fire(Action("ssrf.cloud_metadata", self.TGT,
                                                params={"in_scope": ["app.test"]}))
        finally:
            r_ft()
        self.assertIn("config manquante", f[0].title)

    def test_non_exploit_flags(self):
        m = mods.get("ssrf.cloud_metadata")
        self.assertFalse(m.exploit)                           # bénin (chemins index, valeurs rédigées)
        self.assertFalse(m.destructive)


# =================================================================================================
class TestSessionSecrecy(unittest.TestCase):
    """Invariant : le matériel d'auth gouverné, attaché aux requêtes IN-SCOPE par `Oracle._http`, ne
    fuite JAMAIS dans un finding des nouveaux oracles natifs. On exerce le VRAI chemin `_http` (urlopen
    monkeypatché) via framework.exposure : le secret DOIT partir sur les requêtes in-scope mais être
    ABSENT des findings."""

    SECRET = "S3CR3T-exposure-7a3f"

    class _Capture:
        def __init__(self):
            self.seen = []

        def __call__(self, req, timeout=None, *a, **k):
            self.seen.append(" ".join(str(v) for v in req.headers.values()))
            raise urllib.error.URLError("captured (no network in test)")

    def test_session_material_attached_but_not_leaked(self):
        cap = self._Capture()
        scope = Scope({"in_scope": ["app.test"]})
        store = SessionStore(scope, default={"bearer": self.SECRET})
        with patch("urllib.request.urlopen", cap), sessionmod.using(store):
            f = FrameworkExposure().fire(Action("framework.exposure", "app.test",
                                                params={"in_scope": ["app.test"]}))
        self.assertTrue(any(self.SECRET in v for v in cap.seen),
                        "le matériel de session aurait dû être attaché aux requêtes in-scope")
        for fd in f:
            blob = f"{fd.title} {fd.evidence} {fd.poc}"
            self.assertNotIn(self.SECRET, blob, "le secret de session a fuité dans un finding")


if __name__ == "__main__":
    unittest.main(verbosity=2)

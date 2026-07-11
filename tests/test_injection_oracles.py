"""LOT INJECTION — oracles de VÉRIFICATION d'injection server-side à PREUVE BÉNIGNE
(`ssti.eval`, `path.traversal`, `sqli.probe`).

Contrat commun (calqué sur les oracles à preuve existants + garde-fous de la tâche) :
  (1) SCOPE-GUARD : une cible hors périmètre est REFUSÉE avant tout réseau (`status='skipped'`,
      AUCUNE requête émise — le seam `_fetch` monkeypatché lève si appelé) ;
  (2) PREUVE MINIMALE & BÉNIGNE : une fixture positive -> `status='vulnerable'` avec la preuve minimale
      (produit arithmétique échoé / canari bénin renvoyé / différentiel booléen / version SGBD) ;
      une fixture négative -> `status='tested'` (jamais de verdict à l'aveugle) ;
  (3) NON DESTRUCTIF : exploit=False, destructive=False ;
  (4) SESSION SECRÈTE : le matériel d'auth gouverné attaché aux requêtes IN-SCOPE ne fuite ni dans
      l'evidence ni dans le PoC du finding ;
  (5) DÉGRADATION GRACIEUSE : dépendance optionnelle absente (sqlmap) -> `status='skipped'` (offline-safe).

Tous les tests sont HERMÉTIQUES : on monkeypatch le `_fetch` de chaque module (zéro réseau), sauf le
test de secret de session qui monkeypatch `urllib.request.urlopen` pour capturer les en-têtes sortants.
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
from forge.roe import Action                                     # noqa: E402
from forge import modules as mods                                # noqa: E402
from forge import techniques                                     # noqa: E402
from forge import cli                                            # noqa: E402
from forge import session as sessionmod                          # noqa: E402
from forge.roe import Scope                                      # noqa: E402
from forge.session import SessionStore                           # noqa: E402
from forge.modules.oracle import Oracle                          # noqa: E402
from forge.modules.injection import InjectionOracle, SstiEval, PathTraversal, SqliProbe  # noqa: E402

SECRET = "S3CR3T-inj-4a7b2c"                                     # jeton témoin de session, cherché partout


def _patch(cls, fn):
    """Remplace cls._fetch par fn (staticmethod) et renvoie un restaurateur."""
    orig = cls._fetch
    cls._fetch = staticmethod(fn)
    return lambda: setattr(cls, "_fetch", orig)


def _boom(*a, **k):
    raise AssertionError("réseau émis alors qu'aucun ne devait l'être (scope-guard / config)")


# =================================================================================================
class TestInjectionRegistration(unittest.TestCase):
    KINDS = ("ssti.eval", "path.traversal", "sqli.probe")

    def test_all_registered(self):
        for k in self.KINDS:
            self.assertIn(k, mods.kinds())
            self.assertIsInstance(mods.get(k), InjectionOracle, f"{k} devrait hériter d'InjectionOracle")
            self.assertIsInstance(mods.get(k), Oracle, f"{k} devrait hériter d'Oracle")

    def test_mitre_and_cwe_match_table(self):
        # aucune dérive : le module déclare EXACTEMENT le mitre/cwe de la table unique (techniques.py).
        for k in self.KINDS:
            self.assertEqual(mods.get(k).mitre, techniques.mitre_for(k), f"mitre dérive pour {k}")
            self.assertEqual(mods.get(k).mitre, "T1190", k)
            self.assertEqual(mods.get(k).cwe, techniques.cwe_for(k), f"cwe dérive pour {k}")
        self.assertEqual(mods.get("ssti.eval").cwe, "CWE-1336")
        self.assertEqual(mods.get("path.traversal").cwe, "CWE-22")
        self.assertEqual(mods.get("sqli.probe").cwe, "CWE-89")

    def test_capability_flags_benign_non_destructive(self):
        # sondes de VÉRIFICATION bénignes : non-exploit, non-destructives, interaction web gardée par le ROE.
        for k in self.KINDS:
            m = mods.get(k)
            self.assertFalse(m.exploit, f"{k} est une sonde bénigne -> exploit=False")
            self.assertFalse(m.destructive, f"{k} lecture/vérif seule -> destructive=False")
            self.assertTrue(getattr(m, "web_allowed", False), f"{k} devrait être web_allowed")

    def test_catalog_phase_and_capability(self):
        # catalogue structuré : phase=access, capability=active, preuve requise pour promouvoir.
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
            self.assertEqual(rows[k]["mitre"], "T1190", k)
            self.assertTrue(rows[k]["web_allowed"], k)
            self.assertFalse(rows[k]["exploit"], k)


# =================================================================================================
class TestSstiEvalOracle(unittest.TestCase):
    TGT = "https://app.test/render"
    BASE = {"param": "name", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _patch(SstiEval, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return SstiEval().fire(Action("ssti.eval", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_when_product_evaluated(self):
        n, m, product = SstiEval._marker(self.TGT, "name")

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, f"<h1>Hello {product}</h1>")           # le moteur a ÉVALUÉ N*M
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-1336")
        self.assertEqual(f[0].mitre, "T1190")
        self.assertIn("SSTI CONFIRMÉ", f[0].title)
        self.assertIn(str(product), f[0].evidence)

    def test_tested_when_raw_reflection_only(self):
        # l'app REFLÈTE le payload brut (`{{n*m}}`) mais NE l'ÉVALUE PAS -> le produit n'apparaît pas -> tested.
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "reflected input verbatim: " + urllib.parse.unquote_plus(url))
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non confirmé", f[0].title)

    def test_scope_guard_out_of_scope(self):
        restore = _patch(SstiEval, _boom)
        try:
            f = SstiEval().fire(Action("ssti.eval", "https://evil.example/x",
                                       params={"param": "name", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        restore = _patch(SstiEval, _boom)
        try:
            f = SstiEval().fire(Action("ssti.eval", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)

    def test_marker_is_deterministic_and_distinctive(self):
        n1, m1, p1 = SstiEval._marker(self.TGT, "name")
        n2, m2, p2 = SstiEval._marker(self.TGT, "name")
        self.assertEqual((n1, m1, p1), (n2, m2, p2))          # reproductible (rejouable)
        self.assertEqual(p1, n1 * m1)
        self.assertGreater(p1, 10 ** 9)                       # produit distinctif (anti-coïncidence)
        # une autre cible/param -> un autre marqueur (unique par cible)
        self.assertNotEqual(SstiEval._marker(self.TGT, "other")[2], p1)


# =================================================================================================
class TestPathTraversalOracle(unittest.TestCase):
    TGT = "https://app.test/download"
    MARK = "FORGE-CANARY-benign-6b1f9"
    BASE = {"param": "file", "canary_marker": MARK, "in_scope": ["app.test"]}

    def _fire(self, fake, params=None):
        restore = _patch(PathTraversal, fake)
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return PathTraversal().fire(Action("path.traversal", self.TGT, params=p))
        finally:
            restore()

    def test_vulnerable_when_benign_canary_returned(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            # le paramètre lit le CANARI BÉNIGN via traversal -> le marqueur bénin revient.
            return (200, f"...{self.MARK}...") if "forge-canary.txt" in url else (200, "not found")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-22")
        self.assertIn("Path traversal CONFIRMÉ", f[0].title)

    def test_tested_when_canary_absent(self):
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "404 not found")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")

    def test_payloads_never_target_sensitive_files(self):
        # garde-fou bénin : les payloads générés ne ciblent JAMAIS un fichier système/credential.
        payloads = PathTraversal()._payloads(Action("path.traversal", self.TGT, params=self.BASE))
        joined = " ".join(payloads).lower()
        for forbidden in ("etc/passwd", "etc/shadow", "win.ini", "boot.ini", "id_rsa", ".ssh", "web.config"):
            self.assertNotIn(forbidden, joined, f"payload sensible interdit: {forbidden}")
        self.assertTrue(all("forge-canary.txt" in p for p in payloads))

    def test_scope_guard_out_of_scope(self):
        restore = _patch(PathTraversal, _boom)
        try:
            f = PathTraversal().fire(Action("path.traversal", "https://evil.example/x",
                                            params=dict(self.BASE, in_scope=["app.test"])))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        restore = _patch(PathTraversal, _boom)
        try:
            f = PathTraversal().fire(Action("path.traversal", self.TGT,
                                            params={"param": "file", "in_scope": ["app.test"]}))  # pas de marker
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)


# =================================================================================================
class TestSqliProbeOracle(unittest.TestCase):
    TGT = "https://app.test/item"
    BASE = {"param": "id", "in_scope": ["app.test"]}

    def _fire(self, fake, params=None, sqlmap_available=None, sqlmap_run=None):
        restore = _patch(SqliProbe, fake)
        r_av = r_run = None
        if sqlmap_available is not None:
            orig_av = SqliProbe._sqlmap_available
            SqliProbe._sqlmap_available = staticmethod(sqlmap_available)
            r_av = lambda: setattr(SqliProbe, "_sqlmap_available", staticmethod(orig_av))
        if sqlmap_run is not None:
            orig_run = SqliProbe._run_sqlmap
            SqliProbe._run_sqlmap = staticmethod(sqlmap_run)
            r_run = lambda: setattr(SqliProbe, "_run_sqlmap", staticmethod(orig_run))
        try:
            p = dict(self.BASE)
            if params:
                p.update(params)
            return SqliProbe().fire(Action("sqli.probe", self.TGT, params=p))
        finally:
            restore()
            if r_av:
                r_av()
            if r_run:
                r_run()

    def test_vulnerable_via_boolean_differential(self):
        # VRAI (`AND '1'='1`) ~= baseline ; FAUX (`AND '1'='2`) diffère -> différentiel booléen fiable.
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            if "'1'='2" in dec or "1=2" in dec:
                return (200, "FALSE-BRANCH-empty-results")
            return (200, "BASELINE-BRANCH-full-content")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-89")
        self.assertIn("différentiel booléen", f[0].title)

    def test_vulnerable_via_error_based_version_only(self):
        # un guillemet provoque une erreur SGBD (avec version) ABSENTE de la baseline -> injection error-based.
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            if "AND" not in dec and dec.rstrip().endswith("'"):
                return (200, "You have an error in your SQL syntax; check MariaDB 10.5.8 server manual")
            return (200, "BASELINE-identical-content")        # baseline == vrai == faux -> pas de diff booléen
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertIn("error-based", f[0].title)
        self.assertIn("mariadb 10.5.8", f[0].evidence.lower())  # VERSION seule (aucun dump)
        # garde-fou : aucune donnée de table/ligne dans l'evidence (version seule)
        self.assertIn("aucun dump", f[0].evidence.lower())

    def test_tested_when_no_signal(self):
        # aucun différentiel, aucune erreur SGBD -> tested (pas de verdict aveugle).
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "STATIC-benign-page-always-identical")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")

    def test_scope_guard_out_of_scope(self):
        restore = _patch(SqliProbe, _boom)
        try:
            f = SqliProbe().fire(Action("sqli.probe", "https://evil.example/x",
                                        params={"param": "id", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_missing_config_is_skip(self):
        restore = _patch(SqliProbe, _boom)
        try:
            f = SqliProbe().fire(Action("sqli.probe", self.TGT, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)

    def test_sqlmap_absent_degrades_to_skipped(self):
        # DÉGRADATION GRACIEUSE : sqlmap demandé (opt-in) mais absent -> finding `skipped` ; la détection
        # native reste la source de vérité (ici : pas de signal -> native `tested`).
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "STATIC-benign")
        f = self._fire(fake, params={"sqlmap": True}, sqlmap_available=lambda: False)
        self.assertEqual(f[0].status, "tested")                # native
        self.assertTrue(any(x.status == "skipped" for x in f), "corroboration sqlmap devrait dégrader en skipped")
        skipped = next(x for x in f if x.status == "skipped")
        self.assertIn("sqlmap", skipped.title.lower())

    def test_sqlmap_present_corroborates_as_info(self):
        # sqlmap présent : corroboration INFO `tested` (la promotion vulnerable vient de la preuve native).
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "STATIC-benign")

        def run(url, param, method, timeout):
            return (0, "Parameter 'id' is vulnerable. ... back-end DBMS: MySQL", "")
        f = self._fire(fake, params={"sqlmap": True},
                       sqlmap_available=lambda: True, sqlmap_run=run)
        corro = [x for x in f if "sqlmap" in x.title.lower()]
        self.assertTrue(corro)
        self.assertEqual(corro[0].status, "tested")
        self.assertIn("corrobore", corro[0].title.lower())


# =================================================================================================
class TestSessionSecrecy(unittest.TestCase):
    """Garde-fou (4) : le matériel d'auth gouverné, attaché aux requêtes IN-SCOPE par `Oracle._http`,
    ne fuite JAMAIS dans l'evidence ni le PoC du finding. On exerce le VRAI chemin `_http` (urlopen
    monkeypatché) : le secret DOIT être attaché à la requête in-scope mais ABSENT du finding."""

    class _Capture:
        def __init__(self):
            self.by_url = {}

        def __call__(self, req, timeout=None, *a, **k):
            self.by_url[req.full_url] = " ".join(str(v) for v in req.headers.values())
            raise urllib.error.URLError("captured (no network in test)")

    def test_session_material_attached_but_not_leaked(self):
        cap = self._Capture()
        scope = Scope({"in_scope": ["app.test"]})
        store = SessionStore(scope, default={"bearer": SECRET})
        with patch("forge.modules.oracle.Oracle._raw_open", cap), sessionmod.using(store):
            f = SstiEval().fire(Action("ssti.eval", "https://app.test/r",
                                       params={"param": "q", "in_scope": ["app.test"]}))
        # le secret a bien été attaché à AU MOINS une requête in-scope (session gouvernée active)
        self.assertTrue(any(SECRET in v for v in cap.by_url.values()),
                        "le matériel de session aurait dû être attaché aux requêtes in-scope")
        # ... mais il ne fuite NULLE PART dans le finding (evidence / poc / title)
        for fd in f:
            blob = f"{fd.title} {fd.evidence} {fd.poc}"
            self.assertNotIn(SECRET, blob, "le secret de session a fuité dans le finding")


if __name__ == "__main__":
    unittest.main(verbosity=2)

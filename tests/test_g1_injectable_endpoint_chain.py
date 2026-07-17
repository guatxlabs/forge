"""G1 — CHAÎNE D'EXPLOITATION AUTONOME : le crawl découvre une SURFACE INJECTABLE (url+param) que le
cerveau branche aux oracles à injection, qui prennent alors leur CHEMIN DE TEST RÉEL au lieu d'émettre
« … non testé — config manquante ».

Le TROU (prouvé live, T31) : dans un run armé, `sqli.probe`/`rce.probe`/`ssti.eval`/… émettaient tous
« config manquante » car ils exigent une surface injectable (une URL + un `param`) qu'un scan autonome
bare-host/host:port ne fournit jamais. Ce module PROUVE de bout en bout que la chaîne est refermée :

  (A) CRAWL -> DÉCOUVERTE D'ENDPOINT : un crawler du catalogue (katana/gospider/gau) émet chaque URL
      crawlée in-scope comme un NŒUD chaînable (marqueur DISCOVERY_ENDPOINT_MARKER, target=URL), les
      URLs porteuses d'un `?param=` (INJECTABLES) priorisées — au lieu d'un simple finding texte.
  (B) GOUVERNANCE de la découverte : une URL crawlée HORS périmètre n'est JAMAIS émise (fail-closed).
  (C) CHAÎNAGE : le cerveau détecte le nœud d'endpoint et propose les oracles à injection AVEC le
      `param`+`value` extraits de l'URL (SQLi/XSS + le panel élargi SSTI/cmdi/nosql/…/rce).
  (D) BOUT EN BOUT : `sqli.probe` tiré sur l'endpoint découvert AVEC le param chaîné prend son CHEMIN
      DE TEST RÉEL (seam `_fetch` mocké -> réponse oracle vulnérable) -> verdict `vulnerable`, PAS
      « config manquante ». Sans param -> « config manquante » (contraste).
  (E) GOUVERNANCE des oracles : un endpoint injectable HORS scope est VETOé (scope-guard, zéro I/O) ;
      un oracle EXPLOIT (`rce.probe`) sans opt-in fort-impact reste gaté par le plancher exploit.

Tous les tests sont HERMÉTIQUES : le subprocess du crawler et le `_fetch` des oracles sont mockés
(zéro réseau/outil réel).
"""
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import modules as mods                              # noqa: E402
from forge import runner                                      # noqa: E402
from forge import session as sessionmod                        # noqa: E402
from forge import techniques                                  # noqa: E402
from forge.brain import HeuristicBrain                         # noqa: E402
from forge.graph import EngagementGraph                        # noqa: E402
from forge.roe import Action, Scope                            # noqa: E402
from forge.schema import Finding                               # noqa: E402
from forge.session import SessionStore                         # noqa: E402
from forge.modules.injection import SqliProbe                  # noqa: E402
from forge.modules.rce import RceProbe                         # noqa: E402

EP_MARK = techniques.DISCOVERY_ENDPOINT_MARKER


class _Patch:
    """Remplace temporairement des attributs du module `runner` (référencé à l'appel par toolspec)."""

    def __init__(self, **attrs):
        self.attrs = attrs
        self.saved = {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(runner, k)
            setattr(runner, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(runner, k, v)


def _patch_fetch(cls, fn):
    """Remplace cls._fetch (seam réseau des oracles) par fn ; renvoie un restaurateur."""
    orig = cls._fetch
    cls._fetch = staticmethod(fn)
    return lambda: setattr(cls, "_fetch", orig)


def _boom(*a, **k):
    raise AssertionError("réseau/outil atteint alors que le scope-guard/plancher aurait dû court-circuiter")


def _disc_endpoint(url):
    """Finding de découverte d'endpoint tel qu'émis par un crawler (target=URL, marqueur partagé)."""
    return Finding(target=url, title=f"{EP_MARK} : {url}", severity="INFO",
                   category="recon", status="tested")


# =================================================================================================
# (A) CRAWL -> DÉCOUVERTE D'ENDPOINT INJECTABLE
# =================================================================================================
class TestCrawlEmitsInjectableEndpoints(unittest.TestCase):
    def test_katana_emits_endpoint_discovery_nodes_with_url(self):
        m = mods.get("recon.katana")
        out = ("http://app.test:8000/static/logo.png\n"       # sans param (non injectable)
               "http://app.test:8000/x?id=1\n")               # injectable (?param=)
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, out, "")):
            f = m.fire(Action("recon.katana", "app.test", params={"in_scope": ["app.test"]}))
        by_target = {x.target: x for x in f}
        # chaque URL crawlée devient un NŒUD porteur du marqueur d'endpoint (target = l'URL elle-même)
        self.assertIn("http://app.test:8000/x?id=1", by_target)
        self.assertIn(EP_MARK, by_target["http://app.test:8000/x?id=1"].title)
        # INJECTABLE D'ABORD : l'URL avec ?param= est priorisée (survit au cap, en tête)
        self.assertEqual(f[0].target, "http://app.test:8000/x?id=1")
        # proof-oriented : jamais vulnerable à la découverte
        for x in f:
            self.assertNotEqual(x.status, "vulnerable")

    def test_gospider_and_gau_also_emit_endpoint_discovery(self):
        for kind in ("recon.gospider", "recon.gau"):
            m = mods.get(kind)
            tgt = "app.test" if kind != "recon.gau" else "app.test"
            out = "http://app.test/search?q=1\n"
            with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, out, "")):
                f = m.fire(Action(kind, tgt, params={"in_scope": ["app.test"]}))
            titles = [x.title for x in f if x.target == "http://app.test/search?q=1"]
            self.assertTrue(titles, f"{kind} n'a pas émis d'endpoint chaînable")
            self.assertIn(EP_MARK, titles[0])

    def test_spec_flag_enabled_on_crawlers(self):
        for kind in ("recon.katana", "recon.gospider", "recon.gau"):
            self.assertTrue(mods.get(kind).spec.emit_endpoint_discovery, kind)


# =================================================================================================
# (B) GOUVERNANCE DE LA DÉCOUVERTE — un endpoint crawlé HORS scope n'est JAMAIS émis
# =================================================================================================
class TestDiscoveryGovernance(unittest.TestCase):
    def test_out_of_scope_crawled_url_dropped_fail_closed(self):
        m = mods.get("recon.katana")
        out = ("http://app.test/ok?id=1\n"
               "http://evil.attacker.com/pwn?id=1\n")          # hors périmètre
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, out, "")):
            f = m.fire(Action("recon.katana", "app.test", params={"in_scope": ["app.test"]}))
        targets = {x.target for x in f}
        self.assertIn("http://app.test/ok?id=1", targets)
        self.assertFalse(any("evil.attacker.com" in t for t in targets))   # fail-closed


# =================================================================================================
# (C) CHAÎNAGE — le cerveau branche les oracles à injection AVEC le param sur l'endpoint découvert
# =================================================================================================
class TestBrainChainsInjectionOracles(unittest.TestCase):
    def test_injectable_endpoint_chains_full_panel_with_param(self):
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        ep = "http://app.test:8000/x?id=5"
        g.add_finding(_disc_endpoint(ep))
        actions = HeuristicBrain().propose(g)
        onep = {a.kind for a in actions if a.target == ep}
        # les 3 historiques + le panel élargi param-drivé
        for k in ("access_control.idor", "sqli.probe", "xss.reflected",
                  "ssti.eval", "cmdi.probe", "nosql.probe", "lucene.probe",
                  "rce.probe", "redirect.open", "prototype_pollution.probe",
                  "ssrf.xspa", "ssrf.cloud_metadata"):
            self.assertIn(k, onep, k)
        # le param+value sont portés aux sondes -> sonde RÉELLE (pas config manquante)
        sqli = next(a for a in actions if a.kind == "sqli.probe" and a.target == ep)
        self.assertEqual(sqli.params.get("param"), "id")
        self.assertEqual(sqli.params.get("value"), "5")
        ssti = next(a for a in actions if a.kind == "ssti.eval" and a.target == ep)
        self.assertEqual(ssti.params.get("param"), "id")
        # rce.probe reste EXPLOIT (dérivé de la table) -> gaté par le ROE en aval
        rce = next(a for a in actions if a.kind == "rce.probe" and a.target == ep)
        self.assertTrue(rce.exploit)

    def test_endpoint_without_param_only_seeds_degrading_trio(self):
        # sans ?param=, le panel élargi n'est PAS chaîné (il dégraderait tout en « config manquante ») ;
        # IDOR/SQLi/XSS restent proposés (ils dégradent proprement en `tested`, jamais de crash).
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        ep = "http://app.test/api/orders"
        g.add_finding(_disc_endpoint(ep))
        onep = {a.kind for a in HeuristicBrain().propose(g) if a.target == ep}
        self.assertEqual(onep, {"access_control.idor", "sqli.probe", "xss.reflected"})

    def test_multi_param_chains_each_param_bounded(self):
        # MULTI-PARAM : chaque paramètre (borné à MAX_PARAMS_PER_ENDPOINT, dédupliqué par nom) chaîne
        # l'oracle une fois -> `?a=&b=&c=&d=&e=` sonde a,b,c (cap), PAS d,e (borne le fan-out).
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        ep = "http://app.test/x?a=1&b=2&c=3&d=4&e=5"
        g.add_finding(_disc_endpoint(ep))
        sqli = [a for a in HeuristicBrain().propose(g) if a.kind == "sqli.probe" and a.target == ep]
        params = [a.params.get("param") for a in sqli]
        self.assertEqual(len(sqli), HeuristicBrain.MAX_PARAMS_PER_ENDPOINT)   # borné
        self.assertEqual(params, ["a", "b", "c"])              # ordre stable, cap au 3e
        # id : le 1er param garde l'id STABLE (kind:target) ; les suivants un id suffixé (#param) ->
        # coexistent sans collision (et le bare gagne la course d'id sur l'auto-pentest).
        ids = {a.id for a in sqli}
        self.assertIn(f"sqli.probe:{ep}", ids)
        self.assertIn(f"sqli.probe:{ep}#b", ids)
        self.assertEqual(len(ids), HeuristicBrain.MAX_PARAMS_PER_ENDPOINT)    # tous distincts

    def test_empty_value_param_is_injectable(self):
        # EMPTY-VALUE : un paramètre à valeur VIDE (`?QUERY=`, fréquent sur les formulaires crawlés)
        # était traité comme SANS param -> « config manquante ». Il porte désormais `param` (pas `value`).
        g = EngagementGraph()
        g.add_host("app.test", kind="url")
        ep = "http://app.test/help/?QUERY="
        g.add_finding(_disc_endpoint(ep))
        acts = HeuristicBrain().propose(g)
        sqli = next(a for a in acts if a.kind == "sqli.probe" and a.target == ep)
        self.assertEqual(sqli.params.get("param"), "QUERY")
        self.assertIsNone(sqli.params.get("value"))            # valeur vide -> pas de `value` porté
        # le panel élargi param-drivé est bien chaîné (pas seulement le trio dégradant)
        onep = {a.kind for a in acts if a.target == ep}
        self.assertIn("cmdi.probe", onep)

    def test_url_decoded_param_value(self):
        # URL-DÉCODAGE : `+`/`%xx` sont décodés (comme un vrai crawl `?TOPIC=Getting+Started`).
        pairs = HeuristicBrain._query_params("http://app.test/help/?TOPIC=Getting+Started&Q=a%20b")
        self.assertEqual(pairs, [("TOPIC", "Getting Started"), ("Q", "a b")])


# =================================================================================================
# (D) BOUT EN BOUT — un oracle TESTE RÉELLEMENT un param crawlé (au lieu de « config manquante »)
# =================================================================================================
class TestOracleActuallyTestsDiscoveredParam(unittest.TestCase):
    EP = "http://app.test:8000/x?id=1"

    def test_sqli_takes_real_path_and_proves_vulnerable(self):
        # le param que le CERVEAU dériverait de l'endpoint découvert
        param, value = HeuristicBrain._first_query_pair(self.EP)
        self.assertEqual((param, value), ("id", "1"))

        # oracle SQLi : VRAI ~= baseline, FAUX diffère -> différentiel booléen fiable
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            if "'1'='2" in dec or "1=2" in dec:
                return (200, "FALSE-BRANCH-empty")
            return (200, "BASELINE-BRANCH-full")

        restore = _patch_fetch(SqliProbe, fake)
        try:
            f = SqliProbe().fire(Action("sqli.probe", self.EP,
                                        params={"param": param, "value": value, "in_scope": ["app.test"]}))
        finally:
            restore()
        # VERDICT RÉEL — pas « config manquante »
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertNotIn("config manquante", f[0].title)
        self.assertIn("différentiel booléen", f[0].title)

    def test_same_endpoint_without_param_is_config_manquante(self):
        # CONTRASTE : sans le param fourni par le chaînage, l'oracle court-circuite en « config manquante ».
        restore = _patch_fetch(SqliProbe, _boom)               # aucune requête ne doit partir
        try:
            f = SqliProbe().fire(Action("sqli.probe", self.EP, params={"in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "tested")
        self.assertIn("config manquante", f[0].title)


# =================================================================================================
# (E) GOUVERNANCE DES ORACLES — VETO hors scope + plancher exploit
# =================================================================================================
class TestOracleGovernance(unittest.TestCase):
    def test_out_of_scope_injectable_endpoint_vetoed_zero_io(self):
        # un endpoint injectable découvert HORS périmètre : scope-guard fail-closed, aucune requête émise.
        restore = _patch_fetch(SqliProbe, _boom)
        try:
            f = SqliProbe().fire(Action("sqli.probe", "http://evil.example/x?id=1",
                                        params={"param": "id", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_exploit_oracle_gated_by_exploit_floor_without_optin(self):
        # rce.probe (exploit) : une session gouvernée est liée SANS opt-in fort-impact -> refusé, zéro I/O,
        # MÊME si le param crawlé est fourni. Le plancher exploit reste OFF par défaut.
        scope = Scope({"in_scope": ["app.test"], "out_scope": [], "allow_exploit": False})
        store = SessionStore(scope)
        restore = _patch_fetch(RceProbe, _boom)
        try:
            with sessionmod.using(store):
                f = RceProbe().fire(Action("rce.probe", "http://app.test/x?id=1",
                                           params={"param": "id", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("plancher exploit", f[0].title.lower())

    def test_exploit_oracle_fires_when_optin_armed(self):
        # opt-in fort-impact armé -> l'oracle prend son chemin réel (seam mocké, pas de preuve ici) et
        # rend un verdict `tested` (pas « config manquante », pas « refusé »).
        scope = Scope({"in_scope": ["app.test"], "out_scope": [], "allow_exploit": True})
        store = SessionStore(scope)

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "benign-static-page-no-marker")

        restore = _patch_fetch(RceProbe, fake)
        try:
            with sessionmod.using(store):
                f = RceProbe().fire(Action("rce.probe", "http://app.test/x?id=1",
                                           params={"param": "id", "in_scope": ["app.test"]}))
        finally:
            restore()
        self.assertEqual(f[0].status, "tested")
        self.assertNotIn("config manquante", f[0].title)
        self.assertNotIn("refusé", f[0].title.lower())


# =================================================================================================
# (F) RÉGRESSION LIVE (G1-residual, T36) — le VRAI chemin d'émission katana/gospider, pas un nœud
#     synthétique. Le TROU : le crawl live remontait des URLs `?TOPIC=x&QUERY=` (multi-param +
#     valeur vide), mais seul le 1er param à valeur NON vide était sondé -> `QUERY` (et tout endpoint
#     `?QUERY=` seul) restait « config manquante ». Le test synthétique précédent (nœud fait main
#     `?id=1`, mono-param à valeur pleine) NE L'AURAIT PAS ATTRAPÉ. Ici on part de la sortie RÉELLE
#     du crawler (parse + émission `endpoint_discovery_findings`) pour reproduire puis prouver le fix.
# =================================================================================================
class _Katana:
    """Exécute le VRAI module recon.katana avec un subprocess mocké (sortie crawl réaliste)."""
    @staticmethod
    def crawl(output, target="127.0.0.1:631", in_scope=("127.0.0.1",)):
        m = mods.get("recon.katana")
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, output, "")):
            return m.fire(Action("recon.katana", target, params={"in_scope": list(in_scope)}))


class TestLiveCrawlDrivesOraclesWithParam(unittest.TestCase):
    # sortie katana réaliste (CUPS :631) — multi-param + `QUERY=` à valeur VIDE (le cas live exact)
    CUPS_OUT = ("http://127.0.0.1:631/help/?TOPIC=Getting+Started&QUERY=\n"
                "http://127.0.0.1:631/help/?QUERY=\n"
                "http://127.0.0.1:631/robots.txt\n")

    def _graph_from_crawl(self):
        """Reproduit ce que fait l'engine : les findings de découverte d'endpoint émis par le VRAI
        module katana sont ajoutés au graphe (target=URL, marqueur partagé), PAS des nœuds à la main."""
        findings = _Katana.crawl(self.CUPS_OUT)
        g = EngagementGraph()
        g.add_host("127.0.0.1:631", kind="url")
        for f in findings:
            self.assertIn(EP_MARK, f.to_dict()["title"])       # le VRAI marqueur d'émission
            g.add_finding(f)
        return g

    def test_real_katana_url_preserves_query_and_chains_each_param(self):
        g = self._graph_from_crawl()
        acts = HeuristicBrain().propose(g)
        ep = "http://127.0.0.1:631/help/?TOPIC=Getting+Started&QUERY="
        params = sorted(a.params.get("param") for a in acts
                        if a.kind == "sqli.probe" and a.target == ep)
        # LES DEUX params crawlés sont sondés (le fix) — avant : seul TOPIC (QUERY jamais nourri).
        self.assertEqual(params, ["QUERY", "TOPIC"])
        # l'endpoint `?QUERY=` SEUL (valeur vide) est désormais injectable, pas « config manquante ».
        ep2 = "http://127.0.0.1:631/help/?QUERY="
        sqli2 = next(a for a in acts if a.kind == "sqli.probe" and a.target == ep2)
        self.assertEqual(sqli2.params.get("param"), "QUERY")

    def test_regression_live_bug_would_be_caught(self):
        # PREUVE que ce test aurait attrapé le bug live : le param `QUERY` (2e param, valeur vide) est
        # nourri à un ORACLE param-drivé du panel élargi (cmdi) -> il ne reste PAS « config manquante ».
        g = self._graph_from_crawl()
        acts = HeuristicBrain().propose(g)
        ep = "http://127.0.0.1:631/help/?TOPIC=Getting+Started&QUERY="
        query_acts = [a for a in acts if a.target == ep and a.params.get("param") == "QUERY"]
        kinds = {a.kind for a in query_acts}
        for k in ("sqli.probe", "xss.reflected", "cmdi.probe", "ssti.eval", "nosql.probe"):
            self.assertIn(k, kinds, f"{k} non chaîné sur le 2e param crawlé QUERY")

    def test_end_to_end_query_param_takes_real_sqli_path_not_config_manquante(self):
        # BOUT EN BOUT sur le param `QUERY` DÉRIVÉ DU VRAI CRAWL : l'oracle SQLi prend son chemin réel
        # (seam `_fetch` mocké -> oracle-positif) -> `vulnerable`, PAS « config manquante ».
        g = self._graph_from_crawl()
        ep = "http://127.0.0.1:631/help/?TOPIC=Getting+Started&QUERY="
        sqli_query = next(a for a in HeuristicBrain().propose(g)
                          if a.kind == "sqli.probe" and a.target == ep
                          and a.params.get("param") == "QUERY")

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            dec = urllib.parse.unquote_plus(url)
            if "'1'='2" in dec or "1=2" in dec:
                return (200, "FALSE-BRANCH-empty")
            return (200, "BASELINE-BRANCH-full")

        params = dict(sqli_query.params); params["in_scope"] = ["127.0.0.1"]
        restore = _patch_fetch(SqliProbe, fake)
        try:
            f = SqliProbe().fire(Action("sqli.probe", ep, params=params))
        finally:
            restore()
        self.assertEqual(f[0].status, "vulnerable")
        self.assertNotIn("config manquante", f[0].title)

    def test_governance_out_of_scope_crawled_endpoint_vetoed(self):
        # GOUVERNANCE : une URL crawlée HORS périmètre n'est jamais émise (fail-closed) -> aucun oracle.
        out = ("http://127.0.0.1:631/ok?id=1\n"
               "http://evil.attacker.com/pwn?q=1\n")
        findings = _Katana.crawl(out)
        self.assertFalse(any("evil.attacker.com" in f.to_dict()["target"] for f in findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)

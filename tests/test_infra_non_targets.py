# SPDX-License-Identifier: AGPL-3.0-or-later
"""NON-CIBLES D'INFRASTRUCTURE D'EDGE — le mur n'est pas la cible.

Régression d'un run RÉEL contre une cible autorisée derrière Cloudflare (ledger `gxrun`) : la
découverte backed-browser a capturé la requête XHR que le navigateur émet VERS LE CDN pour résoudre
SON PROPRE défi — `https://guatx.com/cdn-cgi/challenge-platform/h/b/fo/<token>` — et l'a adoptée
comme un endpoint applicatif. Le cerveau en a fait un nœud du graphe, puis **85 des 1573 tirs
(5,4 %)** ont visé cette URL. Sur les 2 endpoints que la découverte a réellement produits, UN était
le mur : 50 % de la surface « découverte » était l'infra du CDN.

Trois axes :
  (A) RECONNAISSANCE (`forge/infra_urls.py`) — pure, jamais de réseau, jamais levante, et surtout PAS
      sur-filtrante : un hôte contenant la chaîne, une route applicative, un chemin délibérément EXCLU
      (`/.well-known/acme-challenge/`, souvent servi par l'application) restent des cibles.
  (B) ÉMISSION (`PassiveSurface._endpoint_findings`) — la non-cible n'entre PAS dans le graphe, ne
      consomme PAS le budget d'endpoints, et l'écart est DIT (constat unique, `status='skipped'`).
  (C) GATE MOTEUR (`Engine._decide_blocking`) — défense en profondeur pour toutes les autres voies :
      verdict SKIP NOMMÉ, aucun `fire()`, compté dans `coverage()['errors']`, constat dit UNE fois.

CONTRAT COVERAGE-SAFE (l'invariant à ne pas casser) : ce qui est écarté est `skipped` — « je n'ai pas
vérifié » — JAMAIS `tested` — « j'ai vérifié, rien trouvé » —, et jamais en silence.

Hermétique : aucun réseau sortant (le seul module tiré est `demo.fingerprint`, sans I/O).
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import infra_urls                                  # noqa: E402
from forge.engine import Engine, Phase                        # noqa: E402
from forge.roe import Action, Scope                           # noqa: E402
from forge.modules.recon_surface import JsEndpoints           # noqa: E402

# L'URL EXACTE capturée par `evasion.discover` sur le run réel (ledger gxrun, seq 5605) — c'est elle
# qui a mangé 85 tirs et fait planter `origin.find`.
CF_CHALLENGE_URL = (
    "https://guatx.com/cdn-cgi/challenge-platform/h/b/fo/56157302:1786104021:"
    "CSa7tAN08690_xntt1UxTwNjsX0zja0eJpSVtxNsQwI/a2766b4c7995e1c5/"
    "k9HCseD3GpB3VMNZDlvo5_Cy_5MGDV9l7j_0BZFUW4s-1786107153-1.2.1.1-"
    "cGYoPBTKon6lgw0q8jkze6TDlPp51_Frx7xk51.3Qso9UX6LxHFHyj5jvUIc65BA")
# L'autre endpoint que la MÊME découverte a produit : une vraie URL applicative, à préserver.
REAL_ENDPOINT = "https://guatx.com/favicon.ico"


# --- (A) reconnaissance pure ----------------------------------------------------------------------
class TestClassify(unittest.TestCase):
    def test_recognises_the_real_cloudflare_challenge_url(self):
        self.assertEqual(infra_urls.classify(CF_CHALLENGE_URL), "cloudflare/cdn-cgi")

    def test_recognised_families_have_a_reason_and_an_escape_hatch(self):
        for name, _prefixes, _why in infra_urls.EDGE_NAMESPACES:
            self.assertTrue(infra_urls.why(name), f"famille sans justification : {name}")
            reason = infra_urls.skip_reason(name)
            self.assertIn(name, reason)                       # la famille est NOMMÉE
            self.assertIn("non testé", reason)                # dit que ce n'est PAS un « rien trouvé »
            self.assertIn(infra_urls.ALLOW_ENV, reason)       # dit COMMENT le tester quand même

    def test_other_edge_families_recognised(self):
        for url, family in (
                ("https://app.test/__cf_chl_rt_tk=abc", "cloudflare/__cf"),
                ("https://app.test/_Incapsula_Resource?SWJIYLWA=x", "imperva/incapsula"),
                ("https://app.test/_sec/cp_challenge/ak-challenge-3-3.htm", "akamai/bot-manager"),
                ("https://app.test/akam/13/xyz", "akamai/edge")):
            self.assertEqual(infra_urls.classify(url), family, url)

    # --- garde ANTI-SUR-FILTRAGE : ce qui doit RESTER une cible ---
    def test_bare_hosts_and_hostports_are_never_classified(self):
        for t in ("guatx.com", "www.guatx.com", "guatx.com:8443", "cdn-cgi.example.com",
                  "https://cdn-cgi.example.com/", "https://app.test/akamai-report"):
            self.assertEqual(infra_urls.classify(t), "", t)

    def test_application_routes_are_never_classified(self):
        for t in ("https://app.test/api/v1/users?id=1", "https://app.test/",
                  "https://app.test/static/cdn-cgi.js",       # le préfixe doit être en TÊTE de chemin
                  "https://app.test/.well-known/acme-challenge/tok"):   # EXCLU délibérément (servi par l'app)
            self.assertEqual(infra_urls.classify(t), "", t)

    def test_never_raises_on_hostile_input(self):
        for t in (None, 42, "", "   ", "http://[::1", "://", object()):
            self.assertEqual(infra_urls.classify(t), "")

    # --- échappatoires EXPLICITES (un endpoint d'infra PEUT être une vraie cible) ---
    def test_scope_naming_the_namespace_disarms_it(self):
        self.assertEqual(
            infra_urls.classify(CF_CHALLENGE_URL, allow_patterns=["guatx.com/cdn-cgi/*"]), "")

    def test_unrelated_scope_pattern_does_not_disarm(self):
        self.assertEqual(
            infra_urls.classify(CF_CHALLENGE_URL, allow_patterns=["guatx.com", "*.guatx.com"]),
            "cloudflare/cdn-cgi")

    def test_env_override_disarms_everything(self):
        prev = os.environ.get(infra_urls.ALLOW_ENV)
        os.environ[infra_urls.ALLOW_ENV] = "1"
        try:
            self.assertEqual(infra_urls.classify(CF_CHALLENGE_URL), "")
        finally:
            os.environ.pop(infra_urls.ALLOW_ENV, None)
            if prev is not None:
                os.environ[infra_urls.ALLOW_ENV] = prev


# --- (B) émission : la non-cible n'entre pas dans le graphe, et l'écart est DIT --------------------
class TestEndpointEmission(unittest.TestCase):
    PARAMS = {"in_scope": ["guatx.com", "*.guatx.com"]}

    def _emit(self, urls, params=None):
        return JsEndpoints()._endpoint_findings(
            Action("recon.js_endpoints", "guatx.com", params=dict(params or self.PARAMS)),
            urls, "Endpoint in-scope")

    def test_real_discovery_keeps_the_app_endpoint_and_drops_the_wall(self):
        # REJOUE la sortie EXACTE d'evasion.discover sur le run réel : 2 endpoints, dont 1 est le mur.
        out = self._emit([REAL_ENDPOINT, CF_CHALLENGE_URL])
        targets = [f.target for f in out if f.status == "tested"]
        self.assertEqual(targets, [REAL_ENDPOINT],
                         "la vraie URL applicative doit rester une cible, la non-cible partir")
        self.assertNotIn(CF_CHALLENGE_URL, [f.target for f in out])

    def test_the_drop_is_said_once_named_and_counted(self):
        out = self._emit([REAL_ENDPOINT, CF_CHALLENGE_URL])
        constats = [f for f in out if infra_urls.NON_TARGET_MARKER in f.title]
        self.assertEqual(len(constats), 1, "UN constat, pas un par URL")
        c = constats[0]
        self.assertEqual(c.status, "skipped",
                         "écarté = 'je n'ai pas vérifié', JAMAIS 'tested' (contrat coverage-safe)")
        self.assertIn("1 endpoint(s) écarté(s)", c.title)      # COMPTÉ
        self.assertIn("cloudflare/cdn-cgi", c.evidence)        # NOMMÉ
        self.assertIn(CF_CHALLENGE_URL, c.evidence)            # la preuve est là, rien n'est perdu
        self.assertIn(infra_urls.ALLOW_ENV, c.evidence)        # échappatoire rappelée

    def test_nothing_is_dropped_silently_when_there_is_nothing_to_drop(self):
        out = self._emit([REAL_ENDPOINT])
        self.assertEqual([f.title for f in out if infra_urls.NON_TARGET_MARKER in f.title], [],
                         "aucun constat parasite quand aucune non-cible n'a été rencontrée")

    def test_dropped_urls_do_not_consume_the_endpoint_budget(self):
        # 25 non-cibles PUIS 3 vraies URLs : sans l'écart, le cap (25) aurait mangé tout le budget et
        # les vraies URLs n'auraient jamais été émises.
        walls = [f"https://guatx.com/cdn-cgi/challenge-platform/h/b/fo/tok{i}" for i in range(25)]
        real = [f"https://guatx.com/api/v1/item/{i}" for i in range(3)]
        out = self._emit(walls + real)
        kept = [f.target for f in out if f.status == "tested"]
        self.assertEqual(kept, real)

    def test_scope_naming_the_namespace_keeps_it_as_a_target(self):
        out = self._emit([CF_CHALLENGE_URL],
                         params={"in_scope": ["guatx.com", "guatx.com/cdn-cgi/*"]})
        self.assertIn(CF_CHALLENGE_URL, [f.target for f in out if f.status == "tested"])
        self.assertEqual([f for f in out if infra_urls.NON_TARGET_MARKER in f.title], [])


# --- (C) gate moteur : SKIP nommé, aucun tir, constat unique ---------------------------------------
class _Spy:
    """Remplace `fire()` par un enregistreur SANS I/O sur les modules utilisés ici — prouve qu'aucun
    tir n'est parti ET garantit l'HERMÉTICITÉ même sous mutation : si la gate est retirée (preuve par
    mutation), les modules réseau (`recon.dns`, `recon.tech`) ne doivent toujours PAS sortir."""

    CLASSES = ("forge.modules.demo:DemoFingerprint",
               "forge.modules.recon_surface:DnsRecords",
               "forge.modules.recon_surface:TechFingerprint")

    def __init__(self):
        self.fired = []
        self._saved = []

    def install(self):
        import importlib
        for spec in self.CLASSES:
            mod_name, cls_name = spec.split(":")
            cls = getattr(importlib.import_module(mod_name), cls_name)
            self._saved.append((cls, cls.fire))
            cls.fire = lambda _self, action, _rec=self.fired: (_rec.append(action.target) or [])

    def remove(self):
        for cls, orig in self._saved:
            cls.fire = orig


class TestEngineGate(unittest.TestCase):
    def setUp(self):
        self.spy = _Spy()
        self.spy.install()
        self.addCleanup(self.spy.remove)
        self.lines = []

    def _engine(self, in_scope=("guatx.com", "*.guatx.com")):
        eng = Engine(Scope({"mode": "grey", "in_scope": list(in_scope)}),
                     progress=self.lines.append)
        eng.arm()
        return eng

    def _run(self, eng, target, kind="demo.fingerprint"):
        a = Action(kind, target)
        eng.approve(a.id)
        return eng.execute(a)

    def test_action_on_a_non_target_is_skipped_and_never_fires(self):
        eng = self._engine()
        res = self._run(eng, CF_CHALLENGE_URL)
        self.assertEqual(res["verdict"], "SKIP")
        self.assertEqual(self.spy.fired, [], "un tir est parti sur le mur du CDN")
        self.assertEqual(eng.findings, [], "aucun finding fabriqué sur une cible non vérifiée")

    def test_skip_reason_names_the_family_and_the_escape_hatch(self):
        eng = self._engine()
        reason = " ".join(self._run(eng, CF_CHALLENGE_URL)["reasons"])
        self.assertIn(infra_urls.NON_TARGET_MARKER, reason)
        self.assertIn("cloudflare/cdn-cgi", reason)
        self.assertIn(infra_urls.ALLOW_ENV, reason)

    def test_a_real_target_still_fires(self):
        # garde anti-sur-filtrage au niveau moteur : la gate ne doit toucher QUE les non-cibles.
        eng = self._engine()
        res = self._run(eng, REAL_ENDPOINT)
        self.assertEqual(res["verdict"], "FIRE")
        self.assertEqual(self.spy.fired, [REAL_ENDPOINT])

    def test_every_skipped_action_is_counted_and_listed(self):
        eng = self._engine()
        for kind in ("demo.fingerprint", "recon.dns", "recon.tech"):
            self._run(eng, CF_CHALLENGE_URL, kind=kind)
        errors = eng.coverage()["errors"]
        self.assertEqual(len(errors), 3, "chaque action écartée doit rester traçable une par une")
        self.assertTrue(all("cloudflare/cdn-cgi" in " ".join(e["reasons"]) for e in errors))

    def test_the_constat_is_said_exactly_once_per_target(self):
        eng = self._engine()
        for kind in ("demo.fingerprint", "recon.dns", "recon.tech"):
            self._run(eng, CF_CHALLENGE_URL, kind=kind)
        constats = [ln for ln in self.lines if ln.startswith("[NON-CIBLE]")]
        self.assertEqual(len(constats), 1, "le constat doit être DIT une fois, pas redécouvert par action")
        self.assertIn(CF_CHALLENGE_URL, constats[0])
        self.assertEqual(eng.coverage()["non_targets"], {CF_CHALLENGE_URL: "cloudflare/cdn-cgi"})

    def test_scope_naming_the_namespace_lets_the_engine_fire(self):
        eng = self._engine(in_scope=("guatx.com", "guatx.com/cdn-cgi/*"))
        res = self._run(eng, CF_CHALLENGE_URL)
        self.assertEqual(res["verdict"], "FIRE")
        self.assertEqual(self.spy.fired, [CF_CHALLENGE_URL])

    def test_phase_is_named(self):
        self.assertEqual(Phase.INFRA_NON_TARGET.value, "infra_non_target")


if __name__ == "__main__":
    unittest.main(verbosity=2)

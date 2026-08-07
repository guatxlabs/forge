# SPDX-License-Identifier: AGPL-3.0-or-later
"""RECON DERRIÈRE UN DÉFI FRANCHI — l'ordre de précédence des en-têtes dans `PassiveSurface._http_get`.

Le trou MESURÉ : le défaut de politesse `User-Agent: forge-surface` était posé AVANT la fusion du
matériel de session, donc le `setdefault` en aval ne pouvait plus le remplacer. L'UA récolté du
NAVIGATEUR (avec le cookie `cf_clearance`) perdait systématiquement — et un `cf_clearance` est lié à
l'UA EXACT : sous un autre UA il est INOPÉRANT. Même store, même URL, mesuré :

    Oracle._http             -> 200 · 153 o de contenu   (les ~40 oracles passaient)
    PassiveSurface._http_get -> 403 · 0 o                (TOUTE la recon restait dehors)

Conséquence : `recon.js_endpoints` / `.content` / `.tech` / `.urls` / `.subdomains` ne profitaient
PAS du franchissement et émettaient le marqueur « découverte HTTP challengée » sur une cible pourtant
FRANCHIE — d'où une surface découverte quasi vide, et des tirs concentrés sur la seule URL disponible
(le mur du CDN, cf. `test_infra_non_targets.py`).

PROUVÉ PAR LA PORTÉE, PAS PAR L'INSPECTION : un serveur factice se comporte comme Cloudflare (200 +
contenu SEULEMENT si cookie de clearance ET UA exact ; 403 vide sinon), et on compte ce que la recon
OBTIENT. Aucun test ne se contente de regarder un dict d'en-têtes.

Le scope-guard de `headers_for` reste INTACT et est re-testé ici : hors périmètre, AUCUN matériel ne
part (un `cf_clearance` qui fuiterait vers un tiers serait une fuite de session).

Hermétique : `urllib.request.urlopen` et `Oracle._raw_open` sont stubés — zéro réseau.
"""
import io
import sys
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import session as sessionmod                        # noqa: E402
from forge.modules.oracle import Oracle                        # noqa: E402
from forge.modules.recon_surface import PassiveSurface, JsEndpoints   # noqa: E402
from forge.roe import Action, Scope                            # noqa: E402

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Camoufox/135.0"
CLEARANCE = "cf_clearance=Xk9.abcdef_TOKEN"
# Page telle que la sert un site DERRIÈRE Cloudflare : le script applicatif ET le script d'edge
# (`/cdn-cgi/challenge-platform/scripts/…`), qui est in-scope PAR L'HÔTE mais n'est pas une cible.
PAGE = ('<html><head><script src="/static/app.js"></script>'
        '<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script></head><body>'
        '<script>fetch("https://app.test/api/orders");var a="/api/v1/users";</script></body></html>')
JS = 'const p="/api/v2/secret"; const g="https://app.test/graphql";'


class _Resp(io.BytesIO):
    """Réponse urllib minimale (context-manager) — `status` + `headers` + corps."""

    def __init__(self, status, body):
        super().__init__(body.encode())
        self.status = status
        self.headers = {"Content-Type": "text/html"}

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class _Edge:
    """Serveur factice Cloudflare-like : sert le site UNIQUEMENT avec le cookie de clearance ET l'UA
    EXACT du navigateur. Enregistre les en-têtes vus, pour le contrôle de fuite hors-scope."""

    def __init__(self):
        self.seen = []

    def __call__(self, req, timeout=None, **_k):
        hdrs = {k.lower(): v for k, v in req.header_items()}
        self.seen.append((req.full_url, hdrs))
        if CLEARANCE not in (hdrs.get("cookie") or "") or hdrs.get("user-agent") != BROWSER_UA:
            return _Resp(403, "")                       # défi : rien de servi
        return _Resp(200, JS if req.full_url.endswith(".js") else PAGE)


OPERATOR_SECRET = "S3CR3T-operator-header"


def _cleared_store():
    """Store gouverné réaliste : session GLOBALE de l'opérateur (secret) + matériel de franchissement
    du navigateur adopté pour app.test. Le défaut global est indispensable pour que le contrôle de
    fuite hors-scope MORDE : sans lui, un scope-guard retiré n'aurait tout simplement rien à faire
    fuiter, et le test resterait vert sans rien prouver."""
    store = sessionmod.SessionStore(Scope({"in_scope": ["app.test"], "out_scope": ["cdn.evil.test"]}),
                                    default={"headers": {"X-Auth": OPERATOR_SECRET}})
    assert store.adopt_clearance("https://app.test/",
                                 {"cookies": CLEARANCE, "headers": {"User-Agent": BROWSER_UA}})
    return store


class TestReconReachesThroughClearance(unittest.TestCase):
    def setUp(self):
        self.edge = _Edge()
        self.store = _cleared_store()
        p = patch.object(urllib.request, "urlopen", self.edge)
        p.start()
        self.addCleanup(p.stop)

    def test_recon_and_oracles_reach_the_same_content(self):
        """LA mesure : les deux chokepoints doivent voir le MÊME site. C'est l'asymétrie qui était
        le bug — l'oracle passait, la recon restait dehors."""
        with patch.object(Oracle, "_raw_open", staticmethod(self.edge)), sessionmod.using(self.store):
            o_st, o_body, _ = Oracle._http("https://app.test/")
            p_st, p_body, _ = PassiveSurface._http_get("https://app.test/")
        self.assertEqual((o_st, len(o_body)), (200, len(PAGE)))
        self.assertEqual((p_st, len(p_body)), (200, len(PAGE)),
                         "la recon reste derrière le défi que les oracles franchissent déjà")

    def test_recon_discovers_the_surface_instead_of_reporting_a_challenge(self):
        """PORTÉE : combien la recon OBTIENT-elle réellement ? 0 endpoint + marqueur « challengée »
        avant le correctif ; la surface complète après."""
        with sessionmod.using(self.store):
            out = JsEndpoints().fire(Action("recon.js_endpoints", "app.test",
                                            params={"in_scope": ["app.test"]}))
        endpoints = [f.target for f in out if f.title.startswith("Endpoint in-scope :")]
        self.assertGreaterEqual(len(endpoints), 5, f"surface découverte trop pauvre : {endpoints}")
        self.assertIn("https://app.test/api/orders", endpoints)
        self.assertIn("https://app.test/api/v2/secret", endpoints,   # extrait du JS récupéré DERRIÈRE le mur
                      "le JS in-scope n'a pas été récupéré : la clearance n'a pas porté")
        self.assertNotIn("challengée", out[0].title,
                         "un défi est rapporté alors qu'il a été franchi")

    def test_edge_scripts_are_not_fetched_once_the_wall_is_crossed(self):
        """Le corollaire du franchissement : la page derrière le défi référence les SCRIPTS DE L'EDGE.
        In-scope par l'hôte, ils seraient récupérés — effort perdu et requêtes de plus vers le CDN.
        Ils sont écartés comme non-cibles reconnues, et l'écart est DIT (jamais en silence)."""
        with sessionmod.using(self.store):
            out = JsEndpoints().fire(Action("recon.js_endpoints", "app.test",
                                            params={"in_scope": ["app.test"]}))
        fetched = [u for u, _h in self.edge.seen]
        self.assertIn("https://app.test/static/app.js", fetched, "le JS applicatif doit être récupéré")
        self.assertFalse([u for u in fetched if "/cdn-cgi/" in u],
                         "un script d'edge a été récupéré (bruit envoyé au CDN)")
        constats = [f for f in out if "non-cible d'infrastructure" in f.title]
        self.assertEqual(len(constats), 1, "l'écart doit être dit UNE fois, et pas être silencieux")
        self.assertEqual(constats[0].status, "skipped")
        self.assertIn("cloudflare/cdn-cgi", constats[0].evidence)

    def test_caller_headers_still_win_over_the_session(self):
        """La précédence complète : appelant > session > défaut. Un UA explicite de l'appelant reste
        souverain (et, ici, se fait légitimement refuser par l'edge)."""
        with sessionmod.using(self.store):
            st, _body, _h = PassiveSurface._http_get("https://app.test/",
                                                     headers={"User-Agent": "operator-choice"})
        self.assertEqual(st, 403)
        self.assertEqual(self.edge.seen[-1][1].get("user-agent"), "operator-choice")

    # --- scope-guard : INTACT (le matériel ne sort jamais du périmètre) ---
    def test_no_material_leaks_out_of_scope_and_default_ua_still_applies(self):
        with sessionmod.using(self.store):
            PassiveSurface._http_get("https://cdn.evil.test/asset.js")
        _url, hdrs = self.edge.seen[-1]
        blob = " ".join(f"{k}: {v}" for k, v in hdrs.items())
        self.assertNotIn("cookie", hdrs, "le cookie de clearance a fuité hors périmètre")
        self.assertNotIn(OPERATOR_SECRET, blob, "la session globale a fuité hors périmètre")
        self.assertEqual(hdrs.get("user-agent"), "forge-surface",
                         "l'UA du navigateur a fuité hors périmètre (empreinte de session)")

    def test_in_scope_still_carries_the_operator_session_under_the_clearance(self):
        """L'adoption du matériel de franchissement ne doit pas MASQUER la session de l'opérateur."""
        with sessionmod.using(self.store):
            PassiveSurface._http_get("https://app.test/")
        _url, hdrs = self.edge.seen[-1]
        self.assertEqual(hdrs.get("x-auth"), OPERATOR_SECRET)
        self.assertEqual(hdrs.get("user-agent"), BROWSER_UA)

    def test_default_ua_still_applies_without_any_store(self):
        PassiveSurface._http_get("https://app.test/")
        self.assertEqual(self.edge.seen[-1][1].get("user-agent"), "forge-surface")


if __name__ == "__main__":
    unittest.main(verbosity=2)

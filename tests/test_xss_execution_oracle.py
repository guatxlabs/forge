# SPDX-License-Identifier: AGPL-3.0-or-later
"""ORACLE D'EXÉCUTION XSS — `xss.execution` (forge/modules/xssexec.py).

Ce que ce fichier doit prouver, et pourquoi chaque preuve compte :

  (1) EXÉCUTÉ ≠ RÉFLÉCHI — le seul point qui justifie l'existence de cet oracle. Trois fixtures :
        · charge EXÉCUTÉE (le double de navigateur joue le rôle du moteur JS et recolle le témoin)
          -> `vulnerable` ;
        · charge RÉFLÉCHIE ÉCHAPPÉE                                    -> `tested` (contrôle négatif) ;
        · charge RÉFLÉCHIE BRUTE dans un `<script>` — soit EXACTEMENT ce que `xss.reflected` promeut,
          à juste titre, comme reflet exécutable — mais NON exécutée -> `tested`.
      La 3e est le contrôle négatif DUR : sans elle, on ne saurait pas si l'oracle mesure l'exécution
      ou la simple présence du texte. Un test l'exerce sur TOUS les vecteurs, et un autre montre côté
      à côté que `xss.reflected` promeut là où `xss.execution` refuse (les deux oracles ne mesurent
      pas la même chose — c'est le contrat de complémentarité).

  (2) LE VERROU STRUCTUREL — le témoin `forgexec…` n'apparaît JAMAIS EN ENTIER dans la charge : il est
      assemblé à l'exécution. C'est ce qui rend le point (1) impossible à contourner par accident.

  (3) MARQUEUR BÉNIN — aucune charge ne contient `alert(`, `fetch(`, `document.cookie`, … ; le vecteur
      image utilise `src="data:,"` (aucune requête sortante). Le PoC est rejouable sans danger.

  (4) GOUVERNANCE — scope-guard fail-closed (cible / persistance / vue : ZÉRO appel), dégradation
      gracieuse (navigateur absent OU sonde non aboutie -> `skipped`, jamais un verdict négatif),
      flags exploit/destructive/web_allowed déclarés, session jamais fuitée dans un finding.
      Contrôle négatif de la dégradation : une sonde ABOUTIE sans témoin conclut bien (`tested`) —
      sinon un oracle qui refuse TOUJOURS de conclure passerait ce fichier haut la main.

HERMÉTIQUE : le client navigateur (`bc`) est MOCKÉ (swap de `xssexec.bc`) et `_fetch` monkeypatché.
Aucun réseau, aucun service requis.
"""
import html
import io
import json
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                       # noqa: E402
from forge import modules as mods                                  # noqa: E402
from forge import techniques                                       # noqa: E402
from forge import cli                                              # noqa: E402
from forge.modules.oracle import Oracle, ScopeGuardedOracle        # noqa: E402
from forge.modules.clientflow import ClientFlowOracle, XssReflected, _XSS_PROBE   # noqa: E402
from forge.modules import xssexec as xssmod                        # noqa: E402
from forge.modules.xssexec import (                                # noqa: E402
    XssExecution, VECTORS, VECTOR_NAMES, _EXEC_ATTR, _BEACON_PREFIX)

TGT = "https://app.test/search"
BASE = {"param": "q", "in_scope": ["app.test"]}
SESSION_SECRET = "S3SSION-xssexec-7f3a91"      # jeton témoin cherché dans TOUS les findings

# Les trois littéraux que la charge fait concaténer : 'forgexec' + 6 hex + 6 hex (quotes ' ou ").
_ASSEMBLE_RX = re.compile(
    r"""(['"])forgexec\1\s*\+\s*(['"])([0-9a-f]{6})\2\s*\+\s*(['"])([0-9a-f]{6})\4""")


def _simulate_js(payload):
    """Ce que ferait un MOTEUR JS : recoller les trois littéraux -> le témoin. Le double de navigateur
    l'utilise pour ne PAS se voir offrir le témoin par le test : il le DÉRIVE comme le ferait
    l'exécution réelle. Renvoie None si la charge ne contient pas d'assemblage (donc rien à exécuter)."""
    m = _ASSEMBLE_RX.search(payload or "")
    return (_BEACON_PREFIX + m.group(3) + m.group(5)) if m else None


class _FakeBrowser:
    """Double du client `browser_client` (swap de `xssexec.bc`). Enregistre les appels et RENVOIE un
    DOM construit selon le mode de la page simulée :

      mode='execute'  : la charge TOURNE -> l'attribut témoin est posé (témoin dérivé par _simulate_js) ;
      mode='innerhtml': sink DOM `innerHTML` — SEULES les charges à gestionnaire (onerror/javascript:)
                        s'exécutent ; un `<script>` inséré ainsi NE tourne PAS (sémantique réelle) ;
      mode='raw'      : la charge est RÉFLÉCHIE BRUTE dans un <script> — aucune exécution ;
      mode='escaped'  : la charge est RÉFLÉCHIE ÉCHAPPÉE — aucune exécution ;
      mode='inert'    : page sans reflet ni exécution.

    Le double modèle aussi la NAVIGATION MÊME DOCUMENT : deux URL qui ne diffèrent que par le
    fragment ne rechargent pas la page (les scripts ne re-tournent pas), exactement comme un vrai
    navigateur — c'est ce qui rend testable le faux négatif du mode `fragment`.

    `dead_goto`/`dead_read` simulent un service qui ne navigue pas / ne rend rien (sonde non aboutie).
    `raise_all=True` prouve qu'AUCUN appel navigateur ne part (scope-guard / config)."""

    DEFAULT_TAB = "forge"

    def __init__(self, mode="inert", health=True, dead_goto=False, dead_read=False,
                 raise_all=False, dom_extra="", echo_beacon_in_url=False):
        self.calls, self.urls = [], []
        self.mode, self._health = mode, health
        self.dead_goto, self.dead_read = dead_goto, dead_read
        self._raise_all, self.dom_extra = raise_all, dom_extra
        # /content renvoie AUSSI l'URL naviguée : ce drapeau y place le témoin COMPLET (une app qui
        # ré-affiche l'URL de requête produirait la même chose). Le DOM, lui, reste sans exécution.
        self.echo_beacon_in_url = echo_beacon_in_url
        self._beacon_seen = None
        self._dom = ""
        self._doc = None                 # document courant (URL sans fragment) — cf. same-document
        # mode PERSISTÉ : la charge n'est pas dans l'URL de la vue — le serveur l'a stockée puis la
        # re-rend. Le test la dépose ici depuis le `_fetch` de persistance (modèle fidèle du stored).
        self.persisted = None

    # --- plomberie du double ---
    def _rec(self, name):
        if self._raise_all:
            raise AssertionError("appel navigateur INTERDIT (garde-fou violé) : " + name)
        self.calls.append(name)

    def names(self):
        return list(self.calls)

    def probed(self):
        """URL réellement SONDÉES (les `about:blank` de remise à zéro sont de la plomberie)."""
        return [u for u in self.urls if u != "about:blank"]

    def base_url(self):
        return "http://fake-browser:8080"

    def health(self, timeout=2):
        self._rec("health")
        return self._health

    def goto(self, url, tab="forge", wait=5, timeout=45):
        self._rec("goto")
        self.urls.append(url)
        if url == "about:blank":
            self._doc, self._dom = url, "<html><head></head><body></body></html>"
            return (200, {"url": url})
        if self.dead_goto:
            return (0, "connection refused")
        doc = url.split("#", 1)[0]
        if doc == self._doc:
            # NAVIGATION MÊME DOCUMENT (seul le fragment change) : le navigateur NE recharge PAS et
            # les scripts de la page NE re-tournent PAS -> le DOM reste celui du chargement précédent.
            return (200, {"url": url})
        self._doc = doc
        self._dom = self._render(self._payload_of(url))
        return (200, {"url": url})

    def evaluate(self, script, tab="forge", timeout=30):
        self._rec("evaluate")
        if self.dead_read:
            return (0, "connection refused")
        m = re.search(r'getAttribute\(\'([^\']+)\'\)', script or "")
        attr = m.group(1) if m else ""
        got = re.search(r'<html ' + re.escape(attr) + r'="([^"]+)"', self._dom)
        return (200, {"tab": tab, "result": got.group(1) if got else None})

    def content(self, max_length=50000, tab="forge", timeout=30):
        self._rec("content")
        if self.dead_read:
            return (0, "connection refused")
        # la réponse porte AUSSI l'URL naviguée (qui contient la charge) : le module ne doit lire que
        # le champ `content` — sinon il confondrait la charge présente dans l'URL avec une exécution.
        url = self.urls[-1] if self.urls else ""
        if self.echo_beacon_in_url and self._beacon_seen:
            url = url + "&echo=" + self._beacon_seen
        return (200, {"tab": tab, "url": url, "content": self._dom})

    # --- simulation de page ---
    def _payload_of(self, url):
        """La charge rendue par la page : extraite de la query/du fragment de l'URL sondée, ou —
        en mode PERSISTÉ — celle que le serveur a stockée (déposée par le `_fetch` du test)."""
        import urllib.parse
        parts = urllib.parse.urlsplit(url)
        for blob in (parts.query, parts.fragment):
            vals = urllib.parse.parse_qs(blob)
            for key in vals:
                return vals[key][0]
        return self.persisted or ""

    def _render(self, payload):
        body = ""
        attr = ""
        self._beacon_seen = _simulate_js(payload)
        if self.mode == "execute":
            beacon = self._beacon_seen
            if beacon:
                attr = ' {}="{}"'.format(_EXEC_ATTR, beacon)
        elif self.mode == "innerhtml":
            # sémantique RÉELLE du sink innerHTML : un <script> inséré ne s'exécute pas ; un
            # gestionnaire (onerror) ou une URL `javascript:` si.
            runs = ("onerror=" in payload) or ("javascript:" in payload)
            if runs and self._beacon_seen:
                attr = ' {}="{}"'.format(_EXEC_ATTR, self._beacon_seen)
            else:
                body = "<div>" + payload + "</div>"
        elif self.mode == "raw":
            # reflet BRUT dans un <script> : le contexte JS-exécutable que xss.reflected promeut.
            body = "<script>var q=" + payload + ";</script>"
        elif self.mode == "escaped":
            body = "<p>" + html.escape(payload) + "</p>"
        return "<html{}><body>{}{}</body></html>".format(attr, body, self.dom_extra)


class _Args:
    def __init__(self, json=False):
        self.json = json


def _boom_fetch(*a, **k):
    raise AssertionError("réseau émis alors qu'aucun ne devait l'être (scope-guard / config)")


def _patch_fetch(cls, fn):
    """Remplace `_fetch` (staticmethod HÉRITÉ) et restaure l'héritage exact ensuite."""
    orig = cls.__dict__.get("_fetch")
    cls._fetch = staticmethod(fn)

    def restore():
        if orig is None:
            del cls._fetch
        else:
            setattr(cls, "_fetch", orig)
    return restore


class _XssExecBase(unittest.TestCase):
    def _fire(self, fake, params=None, target=TGT, fetch=None):
        """Tire l'oracle avec `xssexec.bc` swappé par le double (et `_fetch` optionnellement patché)."""
        orig = xssmod.bc
        xssmod.bc = fake
        restore = _patch_fetch(XssExecution, fetch or _boom_fetch)
        try:
            p = dict(BASE)
            if params:
                p.update(params)
            return XssExecution().fire(Action("xss.execution", target, params=p))
        finally:
            xssmod.bc = orig
            restore()


# =================================================================================================
# (0) Registre / catalogue / CLI — le module apparaît partout sans câblage par-technique.
# =================================================================================================
class TestRegistrationAndCatalog(_XssExecBase):
    def test_registered_and_inherits_oracle_bases(self):
        self.assertIn("xss.execution", mods.kinds())
        m = mods.get("xss.execution")
        self.assertIsInstance(m, ClientFlowOracle)
        self.assertIsInstance(m, ScopeGuardedOracle)
        self.assertIsInstance(m, Oracle)

    def test_capability_flags_declared(self):
        m = mods.get("xss.execution")
        # exploit=True : l'oracle fait TOURNER du code injecté -> le ROE doit exiger allow_exploit
        # AVANT de tirer (c'est la frontière que xss.reflected/xss.stored ne franchissent pas).
        self.assertTrue(m.exploit, "faire exécuter du code injecté DOIT être déclaré exploit")
        self.assertFalse(m.destructive, "attribut inerte : aucun état muté -> destructive=False")
        self.assertTrue(m.web_allowed)

    def test_engine_reconciles_module_exploit_flag_into_action(self):
        # défense en profondeur : c'est l'engine qui remonte la capacité du module dans l'Action AVANT
        # la gate ROE. Sans ce drapeau, l'oracle tirerait sans allow_exploit.
        self.assertTrue(techniques.action_exploit("xss.execution"),
                        "la table de techniques doit aussi déclarer exploit (anti-dérive brain/planner)")

    def test_mitre_and_cwe_match_table(self):
        m = mods.get("xss.execution")
        self.assertEqual(m.mitre, techniques.mitre_for("xss.execution"))
        self.assertEqual(m.cwe, techniques.cwe_for("xss.execution"))
        self.assertEqual(m.mitre, "T1059")
        self.assertEqual(m.cwe, "CWE-79")

    def test_catalog_entry_wellformed(self):
        t = techniques.technique_for("xss.execution")
        self.assertIsNotNone(t)
        self.assertEqual(t.vuln_class, "XSS")
        self.assertEqual(t.phase, "access")
        self.assertEqual(t.capability, "active")
        self.assertEqual(t.stage, t.phase)
        self.assertTrue(t.proof_required, "une promotion doit EXIGER une preuve")
        self.assertIn("xss.execution", techniques.by_vuln_class()["XSS"])
        self.assertIn("xss.execution", techniques.pipeline_ordered())

    def test_registered_set_still_equals_technique_kinds(self):
        # le garde-fou anti-dérive : aucun module ne reste non classé.
        self.assertEqual(set(mods.kinds()), set(techniques.technique_kinds()))

    def test_listed_in_cli_modules_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_modules(_Args(json=True))
        self.assertEqual(rc, 0)
        rows = {r["kind"]: r for r in json.loads(buf.getvalue())}
        self.assertIn("xss.execution", rows)
        self.assertTrue(rows["xss.execution"]["exploit"])
        self.assertFalse(rows["xss.execution"]["destructive"])
        self.assertTrue(rows["xss.execution"]["web_allowed"])
        self.assertEqual(rows["xss.execution"]["vuln_class"], "XSS")

    def test_dry_emits_nothing(self):
        fake = _FakeBrowser(raise_all=True)
        orig = xssmod.bc
        xssmod.bc = fake
        try:
            s = XssExecution().dry(Action("xss.execution", TGT, params=dict(BASE)))
        finally:
            xssmod.bc = orig
        self.assertIn(_EXEC_ATTR, s)
        self.assertEqual(fake.names(), [], "dry() doit être sans effet de bord")


# =================================================================================================
# (1) LE CŒUR — exécuté ≠ réfléchi.
# =================================================================================================
class TestExecutedVersusReflected(_XssExecBase):
    def test_execution_is_confirmed(self):
        fake = _FakeBrowser(mode="execute")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cwe, "CWE-79")
        self.assertEqual(f[0].mitre, "T1059")
        self.assertIn("EXÉCUTÉ", f[0].title)
        self.assertIn("EXÉCUTION CONFIRMÉE", f[0].evidence)
        # le PoC est rejouable : URL sondée + la lecture exacte du témoin dans la console.
        self.assertIn(_EXEC_ATTR, f[0].poc)
        self.assertIn("https://app.test/search?q=", f[0].poc)

    def test_escaped_reflection_is_not_confirmed(self):
        """CONTRÔLE NÉGATIF #1 : la charge revient ÉCHAPPÉE -> aucune exécution -> pas de verdict positif."""
        f = self._fire(_FakeBrowser(mode="escaped"))
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non confirmé", f[0].title)

    def test_raw_reflection_in_script_is_not_confirmed(self):
        """CONTRÔLE NÉGATIF #2 (le dur) : la charge est réfléchie BRUTE dans un `<script>` — le DOM
        contient donc la charge en entier — mais elle n'a pas TOURNÉ. Sans ce test, on ne saurait pas
        si l'oracle mesure l'exécution ou la simple présence du texte."""
        fake = _FakeBrowser(mode="raw")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)
        self.assertIn("reflet", f[0].evidence.lower())

    def test_raw_reflection_not_confirmed_for_every_vector(self):
        """Le contrôle négatif dur, vecteur par vecteur : aucune charge du catalogue ne peut être
        « prouvée » par son propre reflet."""
        for name in VECTOR_NAMES:
            with self.subTest(vector=name):
                f = self._fire(_FakeBrowser(mode="raw"), params={"vectors": [name]})
                self.assertEqual(f[0].status, "tested", name)
                self.assertIn("non confirmé", f[0].title, name)

    def test_complementarity_reflected_promotes_where_execution_refuses(self):
        """Les deux oracles ne mesurent PAS la même chose — démonstration côte à côte sur la MÊME
        forme de page (reflet BRUT en contexte `<script>`) :
          · `xss.reflected` promeut (c'est correct : le reflet EST exécutable) ;
          · `xss.execution` refuse (rien n'a tourné).
        C'est exactement la frontière que ce module ajoute."""
        marker = XssReflected._marker(TGT, "q", "xss")

        def reflected_fetch(url, headers=None, timeout=15, method="GET", data=None,
                            follow_redirects=True):
            return (200, "<html><script>var t=" + marker + _XSS_PROBE + ";</script></html>", [])

        restore = _patch_fetch(XssReflected, reflected_fetch)
        try:
            got = XssReflected().fire(Action("xss.reflected", TGT, params=dict(BASE)))
        finally:
            restore()
        self.assertEqual(got[0].status, "vulnerable", "xss.reflected doit promouvoir un reflet exécutable")
        self.assertEqual(self._fire(_FakeBrowser(mode="raw"))[0].status, "tested")

    def test_verdict_reads_the_live_dom_not_the_probed_url(self):
        """La réponse /content porte AUSSI l'URL naviguée, qui contient la charge. L'oracle ne doit
        lire que le DOM : sinon la charge présente dans l'URL vaudrait « exécution »."""
        fake = _FakeBrowser(mode="inert")
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("evaluate", fake.names(), "le témoin doit être lu dans le DOM VIVANT")

    def test_beacon_echoed_in_the_url_field_is_not_execution(self):
        """CONTRÔLE NÉGATIF #3 — le SECOND verrou, isolé du premier. Ici le témoin COMPLET est présent
        dans le champ `url` de la réponse /content (ce que ferait une app qui ré-affiche l'URL de
        requête), mais le DOM n'a jamais exécuté quoi que ce soit. Un oracle qui lirait la réponse au
        lieu du DOM VIVANT crierait « exécuté ». Verdict attendu : non confirmé."""
        fake = _FakeBrowser(mode="raw", echo_beacon_in_url=True)
        f = self._fire(fake)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("non confirmé", f[0].title)


# =================================================================================================
# (2) LE VERROU STRUCTUREL — le témoin n'existe jamais en entier dans la charge.
# =================================================================================================
class TestBeaconStructuralLock(_XssExecBase):
    def test_beacon_never_appears_whole_in_any_payload(self):
        """L'invariant qui rend le contrôle négatif infalsifiable : une page qui RÉFLÉCHIT la charge
        (brute ou échappée) ne peut PAS faire apparaître le témoin — il n'y est pas."""
        for name, build in VECTORS:
            with self.subTest(vector=name):
                beacon = XssExecution._beacon(TGT, "q", name)
                payload = build(beacon)
                self.assertNotIn(beacon, payload,
                                 "{} : le témoin complet est présent dans la charge -> un simple "
                                 "reflet suffirait à le « prouver »".format(name))
                # ... mais un moteur JS, lui, le reconstitue (sinon la sonde ne prouverait rien).
                self.assertEqual(_simulate_js(payload), beacon, name)

    def test_beacon_is_deterministic_and_distinct_per_vector(self):
        first = XssExecution._beacon(TGT, "q", VECTOR_NAMES[0])
        self.assertEqual(first, XssExecution._beacon(TGT, "q", VECTOR_NAMES[0]))   # rejouable
        self.assertTrue(first.startswith(_BEACON_PREFIX) and first.isalnum())      # bénin, alphanumérique
        seen = {XssExecution._beacon(TGT, "q", n) for n in VECTOR_NAMES}
        self.assertEqual(len(seen), len(VECTOR_NAMES),
                         "témoins distincts par vecteur : un attribut périmé ne doit pas valoir preuve")
        self.assertNotEqual(XssExecution._beacon(TGT, "other", VECTOR_NAMES[0]), first)

    def test_stale_beacon_from_another_vector_is_not_proof(self):
        """Un témoin laissé par un AUTRE vecteur ne prouve rien pour le vecteur courant."""
        stale = XssExecution._beacon(TGT, "q", "html_script")
        fake = _FakeBrowser(mode="raw", dom_extra='<i data-old="{}"></i>'.format(stale))
        f = self._fire(fake, params={"vectors": ["iframe_jsurl"]})
        self.assertEqual(f[0].status, "tested")


# =================================================================================================
# (3) MARQUEUR BÉNIN — le PoC doit être reproductible SANS être dangereux.
# =================================================================================================
class TestBenignMarker(_XssExecBase):
    FORBIDDEN = ("alert(", "prompt(", "confirm(", "fetch(", "XMLHttpRequest", "document.cookie",
                 "localStorage", "sessionStorage", "navigator.sendBeacon", "import(",
                 "document.write", "location.href=", "http://", "https://")

    def test_payloads_are_benign(self):
        for name, build in VECTORS:
            payload = build(XssExecution._beacon(TGT, "q", name))
            for bad in self.FORBIDDEN:
                self.assertNotIn(bad, payload, "{} contient « {} »".format(name, bad))

    def test_image_vector_emits_no_outbound_request(self):
        # `src="data:,"` échoue LOCALEMENT au décodage -> onerror sans AUCUNE requête sortante
        # (le classique `src=x` émettrait un GET 404 sur la cible).
        for name in ("img_onerror", "attr_breakout"):
            payload = dict(VECTORS)[name](XssExecution._beacon(TGT, "q", name))
            self.assertIn('src="data:,"', payload)
            self.assertNotIn("src=x", payload)

    def test_marker_only_sets_an_inert_attribute(self):
        for name, build in VECTORS:
            payload = build(XssExecution._beacon(TGT, "q", name))
            self.assertEqual(payload.count("setAttribute("), 1, name)
            self.assertIn(_EXEC_ATTR, payload)

    def test_injected_page_is_not_left_loaded(self):
        """Hygiène : après la sonde, la page injectée est déchargée du navigateur gouverné."""
        for mode in ("execute", "raw"):
            with self.subTest(mode=mode):
                fake = _FakeBrowser(mode=mode)
                self._fire(fake)
                self.assertEqual(fake.urls[-1], "about:blank")


# =================================================================================================
# (4) GOUVERNANCE — scope-guard, dégradation, secret de session.
# =================================================================================================
class TestScopeGuardFailClosed(_XssExecBase):
    def test_out_of_scope_target_skipped_zero_io(self):
        fake = _FakeBrowser(raise_all=True)          # tout appel navigateur lèverait
        f = self._fire(fake, target="https://evil.example/x")
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)
        self.assertEqual(fake.names(), [])

    def test_out_of_scope_target_with_in_scope_view_still_skipped(self):
        """Isole la garde sur la CIBLE : ici la vue est in-scope, donc SEULE la garde de cible peut
        refuser. Sans elle, l'oracle irait sonder une cible hors périmètre."""
        fake = _FakeBrowser(raise_all=True)
        f = self._fire(fake, params={"view_url": "https://app.test/ok"},
                       target="https://evil.example/x")
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)
        self.assertEqual(fake.names(), [])

    def test_out_of_scope_store_url_skipped_zero_io(self):
        fake = _FakeBrowser(raise_all=True)
        f = self._fire(fake, params={"store_url": "https://evil.example/save"})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)
        self.assertEqual(fake.names(), [])

    def test_out_of_scope_view_url_skipped_zero_io(self):
        fake = _FakeBrowser(raise_all=True)
        f = self._fire(fake, params={"view_url": "https://evil.example/render"})
        self.assertEqual(f[0].status, "skipped")
        self.assertEqual(fake.names(), [])

    def test_missing_param_is_skip_zero_io(self):
        fake = _FakeBrowser(raise_all=True)
        orig = xssmod.bc
        xssmod.bc = fake
        try:
            f = XssExecution().fire(Action("xss.execution", TGT, params={"in_scope": ["app.test"]}))
        finally:
            xssmod.bc = orig
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)
        self.assertEqual(fake.names(), [])


class TestGracefulDegradation(_XssExecBase):
    def test_browser_service_down_is_skipped_no_navigation(self):
        fake = _FakeBrowser(health=False)
        f = self._fire(fake)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("indisponible", f[0].title)
        for forbidden in ("goto", "evaluate", "content"):
            self.assertNotIn(forbidden, fake.names())

    def test_probe_that_never_navigates_yields_no_verdict(self):
        """Une sonde qui n'a pas abouti NE CONCLUT PAS : `skipped`, jamais « pas de XSS »."""
        f = self._fire(_FakeBrowser(mode="execute", dead_goto=True))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("non aboutie", f[0].title)

    def test_probe_that_cannot_read_dom_yields_no_verdict(self):
        f = self._fire(_FakeBrowser(mode="execute", dead_read=True))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("non aboutie", f[0].title)

    def test_completed_probe_without_beacon_still_concludes(self):
        """CONTRÔLE NÉGATIF de la dégradation : sans lui, un oracle qui refuserait TOUJOURS de
        conclure passerait tous les tests ci-dessus."""
        f = self._fire(_FakeBrowser(mode="inert"))
        self.assertEqual(f[0].status, "tested")
        self.assertNotIn("non aboutie", f[0].title)

    def test_unknown_vector_selection_is_skip(self):
        fake = _FakeBrowser(mode="execute")
        f = self._fire(fake, params={"vectors": ["does_not_exist"]})
        self.assertEqual(f[0].severity, "INFO")
        self.assertIn("non testé", f[0].title)
        for forbidden in ("goto", "evaluate", "content"):
            self.assertNotIn(forbidden, fake.names())


class TestSessionSecrecy(_XssExecBase):
    def test_rendered_dom_never_leaks_into_findings(self):
        """Le DOM rendu porte le matériel de session de la victime/opérateur : il ne doit JAMAIS
        entrer dans un finding (l'évidence ne porte que des URL, un vecteur et le témoin)."""
        secret_dom = '<script>var token="{}";</script>'.format(SESSION_SECRET)
        for mode in ("execute", "raw", "inert"):
            with self.subTest(mode=mode):
                f = self._fire(_FakeBrowser(mode=mode, dom_extra=secret_dom))
                blob = json.dumps([x.to_dict() for x in f], ensure_ascii=False)
                self.assertNotIn(SESSION_SECRET, blob, "le DOM (donc la session) a fuité dans un finding")


# =================================================================================================
# (5) MODES D'INJECTION — query / fragment (XSS DOM pur) / persisté.
# =================================================================================================
class TestInjectionModes(_XssExecBase):
    def test_query_mode_puts_payload_in_query(self):
        fake = _FakeBrowser(mode="inert")
        self._fire(fake)
        self.assertTrue(fake.probed()[0].startswith(TGT + "?q="), fake.probed()[0])

    def test_fragment_mode_keeps_payload_client_side_only(self):
        """Le fragment n'est JAMAIS envoyé au serveur : c'est le XSS DOM qu'aucun oracle HTTP ne peut
        voir — la raison d'être du chemin navigateur."""
        fake = _FakeBrowser(mode="execute")
        f = self._fire(fake, params={"fragment": True})
        url = fake.probed()[0]
        self.assertIn("#q=", url)
        self.assertNotIn("?", url.split("#", 1)[0], "la charge ne doit pas partir côté serveur")
        self.assertEqual(f[0].status, "vulnerable")

    def test_stored_mode_persists_then_renders_view(self):
        seen = {}
        fake = _FakeBrowser(mode="execute")

        def fake_fetch(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            import urllib.parse
            seen["url"], seen["method"], seen["data"] = url, method, data
            # le serveur STOCKE la charge : la vue la re-rendra (modèle fidèle du stored XSS).
            fake.persisted = urllib.parse.parse_qs(data or "")["q"][0]
            return (200, "", [])

        f = self._fire(fake, params={"store_url": "https://app.test/profile",
                                     "view_url": "https://app.test/wall"}, fetch=fake_fetch)
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["url"], "https://app.test/profile")
        self.assertIn("q=", seen["data"])
        self.assertEqual(fake.probed()[0], "https://app.test/wall")  # la VUE est rendue, pas l'URL de store
        # charge persistée + exécution confirmée = elle atteint d'AUTRES utilisateurs -> CRITICAL.
        self.assertEqual(f[0].status, "vulnerable")
        self.assertEqual(f[0].severity, "CRITICAL")
        self.assertIn("PERSISTÉE", f[0].title)

    def test_stored_mode_mute_transport_yields_no_verdict(self):
        """La PRÉMISSE compte : si la persistance n'est jamais partie, le rendu qui suit ne prouve rien."""
        def mute(url, headers=None, timeout=15, method="GET", data=None, follow_redirects=True):
            return (None, "", [])

        f = self._fire(_FakeBrowser(mode="inert"),
                       params={"store_url": "https://app.test/profile"}, fetch=mute)
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("persistance indisponible", f[0].title)

    def test_vector_fanout_is_bounded(self):
        fake = _FakeBrowser(mode="inert")
        self._fire(fake)
        self.assertLessEqual(len(fake.probed()), XssExecution.MAX_VECTORS)
        self.assertEqual(len(fake.probed()), len(VECTORS))

    def test_stops_at_first_confirmed_vector(self):
        fake = _FakeBrowser(mode="execute")
        self._fire(fake)
        self.assertEqual(len(fake.probed()), 1, "doit s'arrêter au 1er vecteur confirmé")

    def test_each_probe_starts_from_a_fresh_document(self):
        """Mécanisme du correctif : chaque sonde est précédée d'un `about:blank`. Sans lui, deux URL
        qui ne diffèrent que par le fragment sont une navigation MÊME DOCUMENT — la page ne se
        recharge pas et les vecteurs suivants ne sont jamais réellement exécutés."""
        fake = _FakeBrowser(mode="inert")
        self._fire(fake)
        for i, url in enumerate(fake.urls):
            if url != "about:blank":
                self.assertEqual(fake.urls[i - 1], "about:blank",
                                 "la sonde {} n'est pas partie d'un document neuf".format(url))

    def test_payload_is_percent_encoded_never_plus_encoded(self):
        """RÉGRESSION (bug trouvé contre un NAVIGATEUR RÉEL) : les charges contiennent des ESPACES.
        Encodées en `+` (form-urlencoded), elles arrivent CORROMPUES chez tout sink client-side qui
        décode avec `decodeURIComponent` — lequel laisse le `+` littéral : `<img+src=…>` n'est pas une
        balise `img` et aucun gestionnaire ne se déclenche -> faux négatif silencieux."""
        for fragment in (False, True):
            with self.subTest(fragment=fragment):
                url = XssExecution._inject_url("https://app.test/s", "q", '<img src="data:," x=1>',
                                               fragment=fragment)
                tail = url.split("#", 1)[1] if fragment else url.split("?", 1)[1]
                self.assertNotIn("+", tail, "espace rendue par '+' : corrompue côté client")
                self.assertIn("%20", tail)
                # round-trip : le décodage d'un consommateur client-side rend la charge INTACTE.
                import urllib.parse as up
                self.assertEqual(up.unquote(tail[len("q="):]), '<img src="data:," x=1>')

    def test_fragment_mode_probes_every_vector_not_just_the_first(self):
        """RÉGRESSION (bug trouvé contre un NAVIGATEUR RÉEL, pas en théorie) : en mode `fragment`,
        toutes les URL sondées partagent le même document et ne diffèrent que par le hash. Sans
        rechargement forcé, seul le PREMIER vecteur s'exécute réellement -> les vecteurs suivants
        rendent un FAUX NÉGATIF silencieux. Ici seul un vecteur à gestionnaire peut aboutir (sink
        innerHTML), donc le premier (`html_script`) NE suffit pas : la confirmation prouve que les
        vecteurs suivants ont bien été exécutés."""
        fake = _FakeBrowser(mode="innerhtml")
        f = self._fire(fake, params={"fragment": True})
        self.assertEqual(f[0].status, "vulnerable")
        self.assertNotIn("html_script", f[0].title, "le 1er vecteur ne peut pas aboutir sur ce sink")


if __name__ == "__main__":
    unittest.main(verbosity=2)

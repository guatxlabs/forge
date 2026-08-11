# SPDX-License-Identifier: AGPL-3.0-or-later
"""D6 — FORME DE LA REQUÊTE D'INJECTION : la valeur du paramètre ciblé est REMPLACÉE, les AUTRES
paramètres de la requête sont PRÉSERVÉS, en GET comme en POST.

Ce que ces tests verrouillent, dans l'ordre de ce qui a coûté des trouvailles :

  (1) GET, PARSEUR PREMIER-GAGNANT. L'ancien code AJOUTAIT un doublon (`?id=1&Submit=Submit&id=<P>`).
      Werkzeug 2.2.3 — la pile de VAmPI, mesurée DANS son conteneur — rend `.get("id") == "1"` : la
      charge n'atteignait JAMAIS le sink et l'oracle rendait quand même « non confirmé ». On rejoue
      ici la sémantique premier-gagnant avec `parse_qs(...)[name][0]`, qui est EXACTEMENT ce que lit
      un `MultiDict(parse_qsl(...))`.

  (2) POST, CORPS REMPLACÉ. Le corps ne portait QUE le paramètre injecté ; DVWA exige le co-paramètre
      `Submit` (`isset($_POST['Submit'])`, mesuré : 0 occurrence sans, 1 avec). Le serveur factice
      `_DvwaExec` reproduit cette conjonction à l'identique, et il est SEUL juge du verdict.

  (3) ANTI-DIVERGENCE. Quatre implémentations indépendantes du même geste avaient déjà divergé. Le
      test `test_all_sites_go_through_the_single_builder` espionne `Oracle.inject_request` et exige
      que CHAQUE site l'appelle : un cinquième site recopié à la main fera échouer ce test.

  (4) AUCUN VRAI POSITIF PERDU. Le serveur `_LastWinsEcho` reproduit la sémantique PHP (dernier
      gagnant) sur laquelle l'ancien code fonctionnait : les oracles doivent y confirmer comme avant.

Tous les tests sont HERMÉTIQUES : les seams `_fetch` sont monkeypatchés, ZÉRO octet ne quitte le
processus. Le scope-guard n'est pas relâché (aucun périmètre injecté -> permissif dev/test, chemin
inchangé) et les capacités déclarées des modules ne sont pas touchées.
"""
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                          # noqa: E402
from forge.modules.oracle import Oracle                              # noqa: E402
from forge.modules.injection import SqliProbe                         # noqa: E402
from forge.modules.injection_probes import CmdiProbe                  # noqa: E402
from forge.modules.clientflow import XssReflected, XssStored          # noqa: E402
from forge.modules.rce import RceProbe                                # noqa: E402
from forge.modules.ssrf import SsrfCallback, SsrfXspa, SsrfCloudMetadata  # noqa: E402


# =================================================================================================
#  Outillage de test : un enregistreur de requêtes + deux serveurs factices aux sémantiques OPPOSÉES
# =================================================================================================
class _Recorder:
    """Seam `_fetch` qui ENREGISTRE (url, method, data) et rend une réponse fixe. Arité tolérante :
    sert aussi bien le `_fetch` (st, body) que le `_fetch` header-aware (st, body, pairs)."""

    def __init__(self, status=200, body="", triple=False):
        self.calls = []
        self.status, self.body, self.triple = status, body, triple

    def __call__(self, url, headers=None, timeout=15, method="GET", data=None, **kw):
        self.calls.append({"url": url, "method": method, "data": data})
        return ((self.status, self.body, []) if self.triple else (self.status, self.body))

    @property
    def first(self):
        return self.calls[0]

    def query_of(self, i=0):
        """Paramètres de la query de la i-ème URL appelée, en PREMIER-GAGNANT (sémantique Werkzeug)."""
        q = urllib.parse.urlsplit(self.calls[i]["url"]).query
        return {k: v[0] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}

    def body_of(self, i=0):
        """Paramètres du corps de la i-ème requête (premier-gagnant), {} si aucun corps."""
        raw = self.calls[i]["data"] or ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}


class _DvwaExec:
    """Serveur factice reproduisant `DVWA /vulnerabilities/exec/` (niveau low) — la conjonction
    EXACTE mesurée sur l'application : la commande n'est exécutée que si le CORPS porte `Submit`,
    et la valeur injectée est lue dans `ip`. Sans `Submit` : la page revient sans sortie."""

    def __init__(self):
        self.hits = 0

    def __call__(self, url, headers=None, timeout=15, method="GET", data=None, **kw):
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(data or "", keep_blank_values=True).items()}
        if "Submit" not in form:                      # isset($_POST['Submit']) == false
            return 200, "<html>Ping a device</html>"
        target = form.get("ip", "")
        if ";" not in target and "|" not in target and "&&" not in target:
            return 200, "<html>PING 127.0.0.1</html>"
        self.hits += 1
        echoed = target.split(";", 1)[-1].strip()     # `sh -c "ping <ip>"` : le shell exécute la suite
        if echoed.startswith("echo "):
            return 200, f"<pre>PING 127.0.0.1\n{echoed[5:].strip()}</pre>"
        return 200, "<pre>PING 127.0.0.1</pre>"


class _FirstWinsEcho:
    """Serveur factice à parseur PREMIER-GAGNANT (Flask/Werkzeug) : il ne réfléchit que la PREMIÈRE
    valeur du paramètre. Un payload AJOUTÉ en queue n'y atteint jamais le sink."""

    def __init__(self, param):
        self.param = param

    def _read(self, url, data):
        pool = urllib.parse.urlsplit(url).query if not data else data
        vals = urllib.parse.parse_qs(pool, keep_blank_values=True).get(self.param, [""])
        return vals[0]

    def __call__(self, url, headers=None, timeout=15, method="GET", data=None, **kw):
        return 200, f"<script>var v = '{self._read(url, data)}';</script>"


class _LastWinsEcho(_FirstWinsEcho):
    """Sémantique PHP (DERNIER gagnant) — celle sur laquelle l'ANCIEN code fonctionnait. Sert de
    contrôle « aucun vrai positif perdu »."""

    def _read(self, url, data):
        pool = urllib.parse.urlsplit(url).query if not data else data
        return urllib.parse.parse_qs(pool, keep_blank_values=True).get(self.param, [""])[-1]


def _set(cls, name, fn):
    """Pose `cls.<name>` (staticmethod) et rend le restaurateur. On restaure le DESCRIPTEUR quand
    l'attribut existait — le retirer effacerait la vraie implémentation pour tout le processus (c'est
    exactement ainsi qu'un test de ce lot a pollué la suite entière avant d'être corrigé)."""
    had = name in cls.__dict__
    orig = cls.__dict__.get(name)
    setattr(cls, name, staticmethod(fn))

    def restore():
        if had:
            setattr(cls, name, orig)
        else:
            delattr(cls, name)
    return restore


def _patch_fetch(cls, fn):
    """Remplace `cls._fetch` — même discipline que `tests/test_injection_oracles.py::_patch`."""
    return _set(cls, "_fetch", fn)


# =================================================================================================
#  1. LA FORME, PURE — `Oracle.inject_request`
# =================================================================================================
class TestInjectRequestForm(unittest.TestCase):
    TGT = "http://app.test/vulnerabilities/sqli/?id=1&Submit=Submit"

    def test_get_replaces_in_place_and_keeps_the_others(self):
        url, data = Oracle.inject_request(self.TGT, "id", "PAYLOAD", "GET")
        self.assertIsNone(data, "une injection GET ne porte pas de corps")
        q = urllib.parse.urlsplit(url).query
        self.assertEqual(q, "id=PAYLOAD&Submit=Submit",
                         "la valeur est remplacée EN PLACE et l'ordre des autres est conservé")
        self.assertEqual(urllib.parse.urlsplit(url).path, "/vulnerabilities/sqli/")

    def test_get_reaches_a_first_wins_parser(self):
        """LE défaut mesuré : sur un parseur premier-gagnant, un doublon AJOUTÉ n'arrive jamais."""
        url, _ = Oracle.inject_request(self.TGT, "id", "PAYLOAD", "GET")
        first_wins = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["id"][0]
        self.assertEqual(first_wins, "PAYLOAD")
        # contre-épreuve : la construction HISTORIQUE, rejouée ici, échoue sur le même parseur.
        legacy = f"{self.TGT}&{urllib.parse.urlencode({'id': 'PAYLOAD'})}"
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(legacy).query)["id"][0], "1")

    def test_get_no_query_is_byte_identical_to_legacy(self):
        for tgt in ("http://app.test/x", "http://app.test", "http://app.test/x/",
                    "https://app.test:8443/a/b"):
            url, data = Oracle.inject_request(tgt, "q", "a b&c=d", "GET")
            self.assertEqual(url, f"{tgt}?{urllib.parse.urlencode({'q': 'a b&c=d'})}", tgt)
            self.assertIsNone(data)

    def test_get_collapses_duplicates_of_the_targeted_param(self):
        """Un doublon RÉSIDUEL ferait lire deux choses différentes à deux parseurs : on n'en laisse pas."""
        url, _ = Oracle.inject_request("http://app.test/x?id=1&id=2&z=9", "id", "P", "GET")
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True)
        self.assertEqual(pairs, [("id", "P"), ("z", "9")])

    def test_get_appends_when_absent(self):
        url, _ = Oracle.inject_request("http://app.test/x?a=1", "b", "P", "GET")
        self.assertEqual(urllib.parse.urlsplit(url).query, "a=1&b=P")

    def test_get_keeps_blank_valued_co_params(self):
        """`?q=` est un point d'injection légitime : la paire vide ne doit pas disparaître."""
        url, _ = Oracle.inject_request("http://app.test/x?q=&id=1", "id", "P", "GET")
        self.assertEqual(urllib.parse.urlsplit(url).query, "q=&id=P")

    def test_post_body_carries_the_co_params(self):
        url, data = Oracle.inject_request("http://app.test/exec/?Submit=Submit", "ip", "1;echo X", "POST")
        self.assertEqual(url, "http://app.test/exec/?Submit=Submit", "l'URL n'est PAS réécrite")
        form = {k: v[0] for k, v in urllib.parse.parse_qs(data, keep_blank_values=True).items()}
        self.assertEqual(form, {"Submit": "Submit", "ip": "1;echo X"})

    def test_post_no_query_is_byte_identical_to_legacy(self):
        url, data = Oracle.inject_request("http://app.test/exec/", "ip", "1;echo X", "POST")
        self.assertEqual(url, "http://app.test/exec/")
        self.assertEqual(data, urllib.parse.urlencode({"ip": "1;echo X"}))

    def test_hostile_target_never_raises(self):
        for tgt in (None, "", "::::", "http://[", "not a url at all"):
            for method in ("GET", "POST"):
                url, data = Oracle.inject_request(tgt, "p", "v", method)
                self.assertIsInstance(url, str)
                self.assertTrue(data is None or isinstance(data, str))

    def test_bracketed_keys_survive(self):
        """`nosql.probe` / `prototype_pollution.probe` injectent dans la CLÉ (`q[$ne]`, `__proto__[k]`)."""
        url, _ = Oracle.inject_request("http://app.test/x?q=1", "q[$ne]", "garbage", "GET")
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True)
        self.assertEqual(pairs, [("q", "1"), ("q[$ne]", "garbage")])


# =================================================================================================
#  2. ANTI-DIVERGENCE — un seul constructeur, et tous les sites y passent
# =================================================================================================
class TestSingleBuilder(unittest.TestCase):
    """Le défaut D6 n'était pas quatre bugs mais UN geste recopié quatre fois. Ce test échoue si un
    site cesse de passer par `Oracle.inject_request` — y compris un CINQUIÈME site ajouté plus tard
    en recopiant le motif `sep = "&" if "?" in ...`."""

    HDR = {"Cookie": "k=v"}

    def _spy(self):
        seen = []
        real = Oracle.inject_request.__func__

        def spy(cls, target, param, payload, method="GET"):
            out = real(cls, target, param, payload, method)
            seen.append({"target": target, "param": param, "method": method, "out": out})
            return out
        Oracle.inject_request = classmethod(spy)
        return seen, lambda: setattr(Oracle, "inject_request", classmethod(real))

    def _fire(self, cls, action, fetch, extra_patches=()):
        undo = [_patch_fetch(cls, fetch)]
        for c, f in extra_patches:
            undo.append(_patch_fetch(c, f))
        try:
            return cls().fire(action)
        finally:
            for u in reversed(undo):
                u()

    def test_all_sites_go_through_the_single_builder(self):
        seen, restore = self._spy()
        try:
            cases = [
                # (label, classe, action, seam)
                ("injection._send (sqli.probe)", SqliProbe,
                 Action("sqli.probe", "http://app.test/x?id=1&Submit=Submit",
                        params={"param": "id", "headers": self.HDR}),
                 _Recorder(200, "ok")),
                ("injection._send hérité (cmdi.probe)", CmdiProbe,
                 Action("cmdi.probe", "http://app.test/exec/?Submit=Submit",
                        params={"param": "ip", "method": "POST"}),
                 _Recorder(200, "ok")),
                ("clientflow._send_h (xss.reflected)", XssReflected,
                 Action("xss.reflected", "http://app.test/x?name=a&lang=fr",
                        params={"param": "name"}),
                 _Recorder(200, "ok", triple=True)),
                ("rce._send", RceProbe,
                 Action("rce.probe", "http://app.test/exec/?Submit=Submit",
                        params={"param": "ip", "method": "POST"}),
                 _Recorder(200, "ok")),
                ("ssrf.callback (inline)", SsrfCallback,
                 Action("ssrf.callback", "http://app.test/f?url=x&t=1",
                        params={"param": "url", "callback_base": "http://cb.test",
                                "callback_check_url": "http://cb.test/check"}),
                 _Recorder(200, "ok")),
                ("ssrf.xspa._inject", SsrfXspa,
                 Action("ssrf.xspa", "http://app.test/f?url=x&t=1",
                        params={"param": "url", "ports": [80],
                                "internal_host": "127.0.0.1"}),
                 _Recorder(200, "ok")),
                ("ssrf.cloud_metadata._inject", SsrfCloudMetadata,
                 Action("ssrf.cloud_metadata", "http://app.test/f?url=x&t=1",
                        params={"param": "url", "providers": ["AWS"]}),
                 _Recorder(200, "ok")),
            ]
            for label, cls, action, fetch in cases:
                with self.subTest(site=label):
                    before = len(seen)
                    self._fire(cls, action, fetch)
                    self.assertGreater(len(seen), before,
                                       f"{label} ne passe PAS par Oracle.inject_request")
        finally:
            restore()

    def test_stored_xss_persist_goes_through_the_single_builder(self):
        seen, restore = self._spy()
        try:
            undo = [_patch_fetch(XssStored, _Recorder(200, "ok", triple=True)),
                    _set(XssStored, "_browser_available", lambda: True),
                    _set(XssStored, "_browser_render", lambda url, tab=None: (200, "<html/>"))]
            try:
                XssStored().fire(Action(
                    "xss.stored", "http://app.test/guestbook.php?form=1",
                    params={"param": "mtxMessage", "store_method": "POST"}))
            finally:
                for u in reversed(undo):
                    u()
            self.assertTrue(seen, "xss.stored._persist ne passe PAS par Oracle.inject_request")
            self.assertEqual(seen[0]["param"], "mtxMessage")
        finally:
            restore()

    def test_no_module_rebuilds_the_query_by_hand(self):
        """Garde LEXICALE sur les fichiers ralliés : le motif exact qui a divergé quatre fois ne doit
        plus y apparaître. C'est la seule borne qui attrape une RE-divergence AVANT qu'elle ne coûte
        une trouvaille (un futur `_send` recopié compilerait et passerait les tests de comportement
        de son propre module)."""
        root = Path(__file__).resolve().parents[1] / "forge" / "modules"
        for name in ("injection.py", "injection_probes.py", "clientflow.py", "rce.py", "ssrf.py"):
            src = (root / name).read_text(encoding="utf-8")
            with self.subTest(module=name):
                self.assertNotIn('sep = "&" if "?" in', src,
                                 f"{name} reconstruit une query à la main (cf. D6)")


# =================================================================================================
#  3. LE FAUX NÉGATIF MESURÉ SUR DVWA — le co-paramètre POST
# =================================================================================================
class TestDvwaPostCoParameter(unittest.TestCase):
    """`_DvwaExec` est SEUL juge : il n'exécute que si le CORPS porte `Submit` (la conjonction exacte
    mesurée sur l'application). L'oracle est donc confirmé par la CIBLE, pas par le test."""

    TGT = "http://app.test/vulnerabilities/exec/?Submit=Submit"

    def _fire(self, cls, params):
        srv = _DvwaExec()
        undo = _patch_fetch(cls, srv)
        try:
            return cls().fire(Action(cls.kind, self.TGT, params=params)), srv
        finally:
            undo()

    def test_cmdi_probe_now_confirms(self):
        findings, srv = self._fire(CmdiProbe, {"param": "ip", "method": "POST"})
        self.assertEqual([f.status for f in findings], ["vulnerable"], findings[0].title)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertGreaterEqual(srv.hits, 1, "aucune commande n'a été exécutée côté cible")

    def test_rce_probe_now_confirms(self):
        findings, srv = self._fire(RceProbe, {"param": "ip", "method": "POST"})
        self.assertEqual([f.status for f in findings], ["vulnerable"], findings[0].title)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertGreaterEqual(srv.hits, 1)

    def test_the_body_actually_carries_both_params(self):
        rec = _Recorder(200, "no output")
        undo = _patch_fetch(CmdiProbe, rec)
        try:
            CmdiProbe().fire(Action("cmdi.probe", self.TGT,
                                    params={"param": "ip", "method": "POST"}))
        finally:
            undo()
        form = rec.body_of(0)
        self.assertEqual(form.get("Submit"), "Submit")
        self.assertIn("echo", form.get("ip", ""))
        self.assertEqual(rec.first["method"], "POST")

    def test_without_the_co_param_the_target_still_refuses(self):
        """CONTRÔLE NÉGATIF — le serveur factice n'est pas complaisant : privé de `Submit`, il
        n'exécute rien et l'oracle s'abstient. Le test positif ci-dessus mesure donc bien le
        co-paramètre, et non une cible qui dirait oui à tout."""
        findings, srv = self._fire(CmdiProbe,
                                   {"param": "ip", "method": "POST"})   # cible AVEC Submit -> vuln
        self.assertEqual(findings[0].status, "vulnerable")
        srv2 = _DvwaExec()
        undo = _patch_fetch(CmdiProbe, srv2)
        try:                                                            # cible SANS Submit -> rien
            f2 = CmdiProbe().fire(Action("cmdi.probe",
                                         "http://app.test/vulnerabilities/exec/",
                                         params={"param": "ip", "method": "POST"}))
        finally:
            undo()
        self.assertEqual(f2[0].status, "tested")
        self.assertEqual(srv2.hits, 0)


# =================================================================================================
#  4. LE FAUX NÉGATIF MESURÉ EN GET — parseur premier-gagnant vs dernier-gagnant
# =================================================================================================
class TestFirstWinsParser(unittest.TestCase):
    TGT = "http://app.test/x?name=seed&lang=fr"

    def _xss(self, server):
        undo = _patch_fetch(XssReflected, server)
        try:
            return XssReflected().fire(Action("xss.reflected", self.TGT,
                                              params={"param": "name"}))
        finally:
            undo()

    def _wrap_triple(self, srv):
        def fn(url, headers=None, timeout=15, method="GET", data=None, **kw):
            st, body = srv(url, headers, timeout, method, data)
            return st, body, []
        return fn

    def test_reaches_the_sink_on_a_first_wins_parser(self):
        findings = self._xss(self._wrap_triple(_FirstWinsEcho("name")))
        self.assertEqual(findings[0].status, "vulnerable", findings[0].title)
        self.assertIn("contexte_exécutable=script", findings[0].evidence)

    def test_no_true_positive_lost_on_a_last_wins_parser(self):
        """Contrôle « rien perdu » : la sémantique PHP, sur laquelle l'ANCIEN code marchait, marche
        toujours. Le correctif ne troque pas un faux négatif contre un autre."""
        findings = self._xss(self._wrap_triple(_LastWinsEcho("name")))
        self.assertEqual(findings[0].status, "vulnerable", findings[0].title)

    def test_co_param_survives_the_injection(self):
        rec = _Recorder(200, "", triple=True)
        undo = _patch_fetch(XssReflected, rec)
        try:
            XssReflected().fire(Action("xss.reflected", self.TGT, params={"param": "name"}))
        finally:
            undo()
        q = rec.query_of(0)
        self.assertEqual(q.get("lang"), "fr", "le co-paramètre a été perdu")
        self.assertNotEqual(q.get("name"), "seed", "la valeur ciblée n'a pas été remplacée")

    def test_ssrf_xspa_preserves_co_params(self):
        rec = _Recorder(200, "x")
        undo = _patch_fetch(SsrfXspa, rec)
        try:
            SsrfXspa().fire(Action("ssrf.xspa", "http://app.test/fetch?url=http://a/&fmt=json",
                                   params={"param": "url", "ports": [80],
                                           "internal_host": "127.0.0.1"}))
        finally:
            undo()
        self.assertTrue(rec.calls)
        for i in range(len(rec.calls)):
            q = rec.query_of(i)
            self.assertEqual(q.get("fmt"), "json")
            self.assertTrue(q.get("url", "").startswith("http://127.0.0.1:"))


if __name__ == "__main__":
    unittest.main()

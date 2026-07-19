# SPDX-License-Identifier: AGPL-3.0-or-later
"""R6 — enrichissement OPTIONNEL de PAYLOADS d'injection par le LLM gouverné (advisory-only).

Le LLM (quand activé + egress autorisé) PROPOSE des chaînes de payload SUPPLÉMENTAIRES pour les
endpoints/params d'injection crawlés ; l'oracle DÉTERMINISTE (forge/modules/injection.py) les TESTE
et les CONFIRME avec sa preuve inchangée. Aucun finding LLM-only.

Garanties prouvées (miroir des principes gouvernés de Forge, cf. enrich_triage / allow_private) :
  (a) OFF PAR DÉFAUT   : LLM désactivé => enrichissement NON appelé, jeu de payloads BYTE-IDENTIQUE ;
  (b) ENRICHI+BORNÉ    : activé + mock 2 payloads => ils entrent dans le jeu testé de l'oracle, dédupé ;
  (c) EGRESS GATÉ      : egress non autorisé (externe sans allow_external) => AUCUN appel, AUCUN egress ;
  (d) FAIL-OPEN        : le mock LLM lève/timeout => run continue, payloads déterministes intacts ;
  (e) BORNE            : mock 500 payloads => plafonné au knob (MAX_ENRICH_PAYLOADS / top-N endpoints) ;
  (f) PAS DE LLM-ONLY  : un payload suggéré NON confirmé par l'oracle => AUCUN finding (tested) ;
  (g) SECRET RÉDIGÉ    : api_key jamais dans le ledger d'egress ; sortie LLM rédigée.
Stdlib only, zéro réseau (urlopen est monkeypatché ; le _fetch de l'oracle est monkeypatché).
"""
import io
import json
import os
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import llm as L                                     # noqa: E402
from forge import resource_profile                             # noqa: E402
from forge.roe import Action, Scope                            # noqa: E402
from forge.ledger import Ledger                                # noqa: E402
from forge.engine import Engine                                # noqa: E402
from forge.modules.injection import SstiEval, InjectionOracle  # noqa: E402


# --- doublures réseau (urlopen mocké) --------------------------------------------------------------
class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


def _ok_response(content):
    payload = {"choices": [{"message": {"role": "assistant", "content": content}}]}
    return _FakeResp(json.dumps(payload).encode("utf-8"))


class _Recorder:
    def __init__(self, content="{{N*M}}\n${N*M}", boom=False):
        self.calls = []
        self.content = content
        self.boom = boom

    def __call__(self, req, timeout=None):
        self.calls.append(req)
        if self.boom:
            raise TimeoutError("LLM injoignable (simulé)")
        return _ok_response(self.content)


def _patch_urlopen(recorder):
    orig = L.urllib.request.urlopen
    L.urllib.request.urlopen = recorder
    return lambda: setattr(L.urllib.request, "urlopen", orig)


def _boom_urlopen(*a, **k):
    raise AssertionError("réseau LLM appelé alors qu'aucun appel ne devait avoir lieu")


def _ledger_entries(path):
    if not Path(path).exists():
        return []
    return [json.loads(ln) for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]


def _cfg(**kw):
    d = {"enabled": True, "base_url": "http://127.0.0.1:11434"}
    d.update(kw)
    return L.LLMConfig.from_dict(d)


# ==================================================================================================
class TestEnrichPayloadsGovernance(unittest.TestCase):
    """(a)(c)(d)(e)(g) — contrat gouverné de `llm.enrich_payloads` (unité, zéro réseau)."""

    def test_off_by_default_no_call_no_payloads(self):
        # LLM désactivé (défaut) => [] immédiat, AUCUN appel réseau (urlopen lève si touché).
        restore = _patch_urlopen(_boom_urlopen)
        try:
            self.assertEqual(L.enrich_payloads("ssti.eval", "https://app.test/x", "q", L.LLMConfig()), [])
            self.assertEqual(L.enrich_payloads("ssti.eval", "https://app.test/x", "q", None), [])
        finally:
            restore()

    def test_non_enrichable_kind_no_call(self):
        # kind hors ENRICHABLE_KINDS => [] sans appel (pas de payload pour une technique non câblée).
        restore = _patch_urlopen(_boom_urlopen)
        try:
            self.assertNotIn("sqli.probe", L.ENRICHABLE_KINDS)
            self.assertEqual(L.enrich_payloads("sqli.probe", "https://app.test/x", "q", _cfg()), [])
        finally:
            restore()

    def test_missing_param_no_call(self):
        restore = _patch_urlopen(_boom_urlopen)
        try:
            self.assertEqual(L.enrich_payloads("ssti.eval", "https://app.test/x", "", _cfg()), [])
            self.assertEqual(L.enrich_payloads("ssti.eval", "https://app.test/x", None, _cfg()), [])
        finally:
            restore()

    def test_external_gated_no_call_no_egress(self):
        # (c) endpoint EXTERNE sans allow_external => aucun appel, aucun egress ledgeré (gate tient).
        import tempfile
        restore = _patch_urlopen(_boom_urlopen)
        try:
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / "ledger.jsonl"
                led = Ledger(path)
                cfg = L.LLMConfig.from_dict({"enabled": True, "base_url": "https://api.openai.com",
                                             "allow_external": False})
                self.assertFalse(cfg.egress_authorized())
                self.assertEqual(L.enrich_payloads("ssti.eval", "https://app.test/x", "q", cfg, ledger=led), [])
                self.assertNotIn("llm.egress",
                                 [e["kind"] for e in _ledger_entries(path)])
        finally:
            restore()

    def test_fail_open_on_exception(self):
        # (d) le mock LLM lève => [] SANS propager d'exception (le run continuera avec le déterministe).
        rec = _Recorder(boom=True)
        restore = _patch_urlopen(rec)
        try:
            self.assertEqual(L.enrich_payloads("ssti.eval", "https://app.test/x", "q", _cfg()), [])
            self.assertEqual(len(rec.calls), 1)                # l'appel a été TENTÉ (fail-open, pas skip)
        finally:
            restore()

    def test_bounded_and_deduped(self):
        # (e) mock renvoie 500 payloads DISTINCTS => plafonné à MAX_ENRICH_PAYLOADS.
        distinct = "\n".join(f"{{{{N*M}}}}#{i}" for i in range(500))
        restore = _patch_urlopen(_Recorder(content=distinct))
        try:
            out = L.enrich_payloads("ssti.eval", "https://app.test/x", "q", _cfg())
            self.assertLessEqual(len(out), L.MAX_ENRICH_PAYLOADS)
            self.assertEqual(len(out), len(set(out)))          # dédupliqué
        finally:
            restore()
        # payloads IDENTIQUES répétés => dédupliqués à 1.
        restore = _patch_urlopen(_Recorder(content="\n".join(["${N*M}"] * 50)))
        try:
            out = L.enrich_payloads("ssti.eval", "https://app.test/x", "q", _cfg())
            self.assertEqual(out, ["${N*M}"])
        finally:
            restore()

    def test_overlong_and_nonstring_dropped(self):
        # défense en profondeur : chaîne trop longue rejetée, vide rejetée.
        content = "${N*M}\n" + ("A" * (L._MAX_PAYLOAD_LEN + 5)) + "\n   \n{{N*M}}"
        restore = _patch_urlopen(_Recorder(content=content))
        try:
            out = L.enrich_payloads("ssti.eval", "https://app.test/x", "q", _cfg())
            self.assertIn("${N*M}", out)
            self.assertIn("{{N*M}}", out)
            self.assertTrue(all(len(p) <= L._MAX_PAYLOAD_LEN and p.strip() for p in out))
        finally:
            restore()

    def test_parse_json_array_and_object(self):
        self.assertEqual(L._parse_payloads('["{{N*M}}", "${N*M}"]'), ["{{N*M}}", "${N*M}"])
        self.assertEqual(L._parse_payloads('{"payloads": ["#{N*M}"]}'), ["#{N*M}"])
        # repli ligne-par-ligne avec puces/numérotation retirées + clôtures de code.
        self.assertEqual(L._parse_payloads("- {{N*M}}\n2) ${N*M}\n`#{N*M}`"),
                         ["{{N*M}}", "${N*M}", "#{N*M}"])
        self.assertEqual(L._parse_payloads(""), [])
        self.assertEqual(L._parse_payloads(None), [])

    def test_egress_ledgered_before_call_no_secret(self):
        # (d ledgeré) + (g) : activé loopback => `llm.egress` (technique+param, PAS d'api_key/payload).
        import tempfile
        restore = _patch_urlopen(_Recorder(content="{{N*M}}"))
        try:
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / "ledger.jsonl"
                led = Ledger(path)
                cfg = _cfg(api_key="sk-SECRET-should-never-appear")
                out = L.enrich_payloads("ssti.eval", "https://app.test/render", "q", cfg, ledger=led)
                self.assertTrue(out)
                entries = _ledger_entries(path)
                egress = [e for e in entries if e["kind"] == "llm.egress"]
                self.assertEqual(len(egress), 1)
                det = egress[0]["detail"]
                self.assertEqual(det["data_class"], "injection_context")
                self.assertEqual(det["kind"], "ssti.eval")
                self.assertEqual(det["param"], "q")
                self.assertEqual(det["target_host"], "app.test")     # HÔTE seul (pas l'URL complète)
                # (g) SECRET : l'api_key n'apparaît NULLE PART dans le ledger.
                self.assertNotIn("sk-SECRET-should-never-appear", Path(path).read_text(encoding="utf-8"))
                self.assertNotIn("api_key", json.dumps(det))
        finally:
            restore()


# ==================================================================================================
class TestSstiConsumesLlmPayloads(unittest.TestCase):
    """(b)(f) — l'oracle DÉTERMINISTE teste les payloads suggérés ; jamais de finding LLM-only."""

    TGT = "https://app.test/render"
    BASE = {"param": "name", "in_scope": ["app.test"]}

    def _patch_fetch(self, fn):
        orig = SstiEval._fetch
        SstiEval._fetch = staticmethod(fn)
        return lambda: setattr(SstiEval, "_fetch", orig)

    def _substituted(self, tmpl):
        n, m, _ = SstiEval._marker(self.TGT, "name")
        return tmpl.replace("N", str(n)).replace("M", str(m))

    def test_llm_payloads_appear_in_tested_set(self):
        # (b) les payloads suggérés (attachés via params.llm_payloads) sont RÉELLEMENT injectés/testés.
        sent = []

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            sent.append(urllib.parse.unquote_plus(url))
            return (200, "aucune évaluation ici")            # ne confirme JAMAIS -> tous les payloads tirés
        restore = self._patch_fetch(fake)
        try:
            params = dict(self.BASE, llm_payloads=["[[N*M]]", "~{N*M}"])
            f = SstiEval().fire(Action("ssti.eval", self.TGT, params=params))
        finally:
            restore()
        joined = " ".join(sent)
        # les 2 wrappers SUGGÉRÉS ont été substitués (N/M -> facteurs) puis injectés.
        self.assertIn(self._substituted("[[N*M]]"), joined)
        self.assertIn(self._substituted("~{N*M}"), joined)
        # ET les wrappers DÉTERMINISTES aussi (le déterministe reste primaire) — ex `{{N*M}}`.
        self.assertIn(self._substituted("{{N*M}}"), joined)
        # aucun confirmé => tested (pas de faux positif).
        self.assertEqual(f[0].status, "tested")

    def test_llm_payload_confirmed_still_requires_deterministic_proof(self):
        # un wrapper SUGGÉRÉ ne devient un finding QUE si l'oracle observe le PRODUIT (preuve déterministe).
        n, m, product = SstiEval._marker(self.TGT, "name")

        def fake(url, headers=None, timeout=15, method="GET", data=None):
            u = urllib.parse.unquote_plus(url)
            # le serveur "évalue" UNIQUEMENT le wrapper suggéré `[[...]]` -> renvoie le produit.
            if "[[" in u and str(product) not in u:
                return (200, f"<x>{product}</x>")
            return (200, "reflected verbatim: " + u)
        restore = self._patch_fetch(fake)
        try:
            params = dict(self.BASE, llm_payloads=["[[N*M]]"])
            f = SstiEval().fire(Action("ssti.eval", self.TGT, params=params))
        finally:
            restore()
        self.assertEqual(f[0].status, "vulnerable")           # confirmé PAR LA PREUVE déterministe
        self.assertIn(str(product), f[0].evidence)
        self.assertIn("[[", f[0].evidence)                    # la syntaxe qui a matché est le wrapper suggéré

    def test_no_finding_when_llm_payload_unconfirmed(self):
        # (f) PAS DE LLM-ONLY : payloads suggérés présents mais AUCUN produit évalué => tested, 0 vulnérable.
        def fake(url, headers=None, timeout=15, method="GET", data=None):
            return (200, "reflected verbatim, never evaluated")
        restore = self._patch_fetch(fake)
        try:
            params = dict(self.BASE, llm_payloads=["[[N*M]]", "{%N*M%}"])
            f = SstiEval().fire(Action("ssti.eval", self.TGT, params=params))
        finally:
            restore()
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].severity, "INFO")
        self.assertNotEqual(f[0].status, "vulnerable")

    def test_no_llm_payloads_is_byte_identical(self):
        # (a) SANS params.llm_payloads => jeu injecté IDENTIQUE à aujourd'hui (byte-identique).
        def run(params):
            sent = []

            def fake(url, headers=None, timeout=15, method="GET", data=None):
                sent.append(urllib.parse.unquote_plus(url))
                return (200, "no eval")
            restore = self._patch_fetch(fake)
            try:
                SstiEval().fire(Action("ssti.eval", self.TGT, params=dict(self.BASE, **params)))
            finally:
                restore()
            return sent

        baseline = run({})
        empty = run({"llm_payloads": []})
        garbage = run({"llm_payloads": "not-a-list"})
        self.assertEqual(baseline, empty)
        self.assertEqual(baseline, garbage)

    def test_oracle_re_bounds_and_validates(self):
        # défense en profondeur : l'oracle re-borne/valide llm_payloads (non-string, trop long, cap).
        many = [f"{{{{N*M}}}}#{i}" for i in range(50)] + [None, 123, "A" * 999, "   "]
        out = InjectionOracle()._llm_extra_payloads(
            Action("ssti.eval", self.TGT, params={"llm_payloads": many}))
        self.assertLessEqual(len(out), InjectionOracle._LLM_MAX_PAYLOADS)
        self.assertTrue(all(isinstance(p, str) and p.strip()
                            and len(p) <= InjectionOracle._LLM_MAX_PAYLOAD_LEN for p in out))


# ==================================================================================================
class TestEngineEnrichmentWiring(unittest.TestCase):
    """Le câblage moteur (_llm_enrich_injections) : OFF no-op, egress gate, top-N borné, in-scope."""

    def _actions(self, n=4):
        # n actions ssti param-portées in-scope + 1 non-injection + 1 hors-scope (ne doivent PAS être enrichies).
        out = [Action("ssti.eval", f"https://app.test/p{i}?q={i}",
                      params={"param": "q", "in_scope": ["app.test"]}) for i in range(n)]
        out.append(Action("recon.httpx", "https://app.test/x", params={"in_scope": ["app.test"]}))
        out.append(Action("ssti.eval", "https://evil.example/z?q=1",
                          params={"param": "q", "in_scope": ["app.test"]}))
        return out

    def _engine(self, llm_cfg, ledger=None):
        data = {"in_scope": ["app.test"], "mode": "grey"}
        if llm_cfg is not None:
            data["llm"] = llm_cfg
        return Engine(Scope(data), ledger=ledger)

    def test_off_by_default_noop(self):
        # (a) LLM absent => AUCUN appel, AUCUN params.llm_payloads attaché (byte-identique).
        restore = _patch_urlopen(_boom_urlopen)
        try:
            acts = self._actions()
            self._engine(None)._llm_enrich_injections(acts)
            for a in acts:
                self.assertNotIn("llm_payloads", a.params)
        finally:
            restore()

    def test_egress_gate_external_noop(self):
        # (c) enabled mais externe sans allow_external => AUCUN appel, rien d'attaché.
        restore = _patch_urlopen(_boom_urlopen)
        try:
            acts = self._actions()
            eng = self._engine({"enabled": True, "base_url": "https://api.openai.com"})
            eng._llm_enrich_injections(acts)
            for a in acts:
                self.assertNotIn("llm_payloads", a.params)
        finally:
            restore()

    def test_knob_zero_disables(self):
        # (e) knob llm_enrich_max_endpoints=0 (profil low) => AUCUN appel malgré LLM activé loopback.
        prev = os.environ.get(resource_profile.ENV_VAR)
        os.environ[resource_profile.ENV_VAR] = "low"
        restore = _patch_urlopen(_boom_urlopen)
        try:
            self.assertEqual(resource_profile.resolve("llm_enrich_max_endpoints", default=0), 0)
            acts = self._actions()
            self._engine({"enabled": True})._llm_enrich_injections(acts)
            for a in acts:
                self.assertNotIn("llm_payloads", a.params)
        finally:
            restore()
            if prev is None:
                os.environ.pop(resource_profile.ENV_VAR, None)
            else:
                os.environ[resource_profile.ENV_VAR] = prev

    def test_enabled_attaches_bounded_topN_in_scope_only(self):
        # (b)(e) enabled loopback + knob balanced(3) => TOP-3 actions ssti in-scope enrichies, bornées.
        import tempfile
        prev = os.environ.get(resource_profile.ENV_VAR)
        os.environ.pop(resource_profile.ENV_VAR, None)        # profil balanced (défaut) => knob=3
        rec = _Recorder(content="{{N*M}}\n${N*M}")
        restore = _patch_urlopen(rec)
        try:
            self.assertEqual(resource_profile.resolve("llm_enrich_max_endpoints", default=0), 3)
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / "ledger.jsonl"
                led = Ledger(path)
                acts = self._actions(n=5)                     # 5 ssti in-scope + httpx + 1 hors-scope
                self._engine({"enabled": True}, ledger=led)._llm_enrich_injections(acts)

                enriched = [a for a in acts if "llm_payloads" in a.params]
                # TOP-3 seulement (borne top-N) — jamais plus que le knob.
                self.assertEqual(len(enriched), 3)
                for a in enriched:
                    self.assertEqual(a.kind, "ssti.eval")
                    self.assertTrue(a.target.startswith("https://app.test/"))   # in-scope only
                    self.assertEqual(a.params["llm_payloads"], ["{{N*M}}", "${N*M}"])
                # l'action non-injection et l'action hors-scope ne sont JAMAIS enrichies.
                httpx = [a for a in acts if a.kind == "recon.httpx"][0]
                evil = [a for a in acts if "evil.example" in a.target][0]
                self.assertNotIn("llm_payloads", httpx.params)
                self.assertNotIn("llm_payloads", evil.params)
                # egress ledgeré 1×/action enrichie (borné), jamais plus.
                egress = [e for e in _ledger_entries(path) if e["kind"] == "llm.egress"]
                self.assertEqual(len(egress), 3)
                self.assertEqual(len(rec.calls), 3)
        finally:
            restore()
            if prev is not None:
                os.environ[resource_profile.ENV_VAR] = prev

    def test_fail_open_engine_never_raises(self):
        # (d) le LLM lève => _llm_enrich_injections ne propage RIEN ; actions intactes (pas de payloads).
        restore = _patch_urlopen(_Recorder(boom=True))
        try:
            acts = self._actions()
            self._engine({"enabled": True})._llm_enrich_injections(acts)   # ne doit pas lever
            for a in acts:
                self.assertNotIn("llm_payloads", a.params)
        finally:
            restore()


if __name__ == "__main__":
    unittest.main()

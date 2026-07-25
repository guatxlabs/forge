# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests IA-2 — assist LLM OPT-IN, compatible OpenAI, gouverné (forge/llm.py + report wiring).

Garanties prouvées (miroir des principes gouvernés de Forge, cf. allow_private / triage IA-1) :
  (a) OFF PAR DÉFAUT  : aucun appel réseau, rapport BYTE-IDENTIQUE au rapport sans-LLM ;
  (b) FAIL-OPEN       : endpoint qui lève/timeout => triage/rapport quand même produits, IA-1 intacte ;
  (c) ADVISORY-ONLY   : la réponse LLM (mockée) est un bloc ÉTIQUETÉ ; findings/ordre/ledger inchangés ;
  (d) EGRESS LEDGERÉ  : activé + appelé => événement `llm.egress` (endpoint + comptes) ;
  (e) EXTERNE GATÉ    : base_url non-loopback sans autorisation => aucun egress, aucun appel ;
  (f) SECRET RÉDIGÉ   : l'api_key n'apparaît JAMAIS dans le GET config / logs / ledger ;
  (g) FORME OpenAI    : POST <base_url>/v1/chat/completions, body {model,messages,...}, Bearer.
Stdlib only, zéro réseau (urlopen est monkeypatché).
"""
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import llm as L                               # noqa: E402
from forge.schema import Finding                         # noqa: E402
from forge.roe import Scope                               # noqa: E402
from forge.engine import Engine                           # noqa: E402
from forge.ledger import Ledger                           # noqa: E402
from forge.report import build_report                     # noqa: E402


# --- jeu de findings représentatif (quelques MEDIUM actionnables + du bruit INFO répété) ----------
def _findings():
    f = []
    for i in range(8):
        u = f"http://a.example.com/archive/p{i}?id={i}"
        f.append(Finding(target=u, title=f"Endpoint in-scope : {u}", severity="INFO",
                         category="Recon", status="tested", tool="recon.gau",
                         evidence="Endpoint in-scope découvert par gau."))
    f.append(Finding(target="b.example.com/orders/42", title="IDOR sur /orders/{id}", severity="MEDIUM",
                     category="CWE-639", status="tested", tool="oracle",
                     evidence="GET /orders/42 (compte A) renvoie la commande du compte B (189€)."))
    f.append(Finding(target="api.example.com/me", title="CORS credentials wildcard", severity="MEDIUM",
                     category="CWE-942", status="tested", tool="oracle",
                     evidence="ACAO reflète Origin arbitraire avec ACAC:true."))
    return f


def _engine(findings, llm_cfg=None, ledger=None):
    data = {"in_scope": ["*.example.com"], "mode": "grey"}
    if llm_cfg is not None:
        data["llm"] = llm_cfg
    eng = Engine(Scope(data), ledger=ledger)
    eng.findings = list(findings)
    return eng


class _FakeResp(io.BytesIO):
    """Réponse HTTP factice compatible `with urlopen(...) as r: json.load(r)`."""
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


def _ok_response(content="Regarde d'abord l'IDOR /orders (CWE-639) puis le CORS wildcard."):
    payload = {"choices": [{"message": {"role": "assistant", "content": content}}]}
    return _FakeResp(json.dumps(payload).encode("utf-8"))


class _Recorder:
    """urlopen espion : capture la requête, renvoie une réponse OK (ou lève si `boom`)."""
    def __init__(self, boom=False, response_factory=_ok_response):
        self.calls = []
        self.boom = boom
        self.response_factory = response_factory

    def __call__(self, req, timeout=None):
        self.calls.append({"req": req, "timeout": timeout})
        if self.boom:
            raise TimeoutError("endpoint injoignable (simulé)")
        return self.response_factory()


def _patch_urlopen(recorder):
    """Remplace forge.llm.urllib.request.urlopen ; renvoie l'original pour restauration."""
    orig = L.urllib.request.urlopen
    L.urllib.request.urlopen = recorder
    return orig


def _ledger_kinds(path):
    if not Path(path).exists():
        return []
    kinds = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            kinds.append(json.loads(line).get("kind"))
    return kinds


def _ledger_text(path):
    return Path(path).read_text(encoding="utf-8")


# ==================================================================================================
class TestOffByDefault(unittest.TestCase):
    """(a) OFF par défaut : aucun réseau, rapport BYTE-IDENTIQUE au rapport sans-LLM."""

    def test_off_by_default_no_call_and_byte_identical(self):
        findings = _findings()

        # urlopen doit lever si jamais appelé -> prouve qu'AUCUN appel réseau n'a lieu.
        def _boom(*a, **k):
            raise AssertionError("réseau appelé alors que le LLM est OFF par défaut")
        orig = _patch_urlopen(_boom)
        try:
            baseline = build_report(_engine(findings))               # scope SANS clé `llm`
            explicit_off = build_report(_engine(findings, {"enabled": False}))
        finally:
            L.urllib.request.urlopen = orig

        # aucun bloc assist, et les deux rapports sont IDENTIQUES (byte-identique).
        self.assertNotIn("Assist LLM", baseline)
        self.assertEqual(baseline, explicit_off)
        # les MEDIUM actionnables sont bien présents (le rapport a tourné normalement).
        self.assertIn("IDOR sur /orders", baseline)

    def test_config_default_is_disabled(self):
        self.assertFalse(L.LLMConfig().enabled)
        self.assertFalse(L.LLMConfig.from_dict(None).enabled)
        self.assertFalse(L.LLMConfig.from_dict("garbage").enabled)
        # enrich_triage renvoie None immédiatement quand désactivé (aucun appel).
        self.assertIsNone(L.enrich_triage(object(), L.LLMConfig()))


class TestFailOpen(unittest.TestCase):
    """(b) FAIL-OPEN : endpoint qui lève/timeout => rapport quand même produit, IA-1 intacte."""

    def test_endpoint_down_never_breaks_run(self):
        findings = _findings()
        rec = _Recorder(boom=True)                                    # urlopen lève TimeoutError
        orig = _patch_urlopen(rec)
        try:
            # rapport SANS assist (baseline déterministe IA-1)
            off = build_report(_engine(findings))
            # rapport AVEC assist activé (loopback) mais endpoint DOWN
            rep = build_report(_engine(findings, {"enabled": True,
                                                  "base_url": "http://127.0.0.1:11434"}))
        finally:
            L.urllib.request.urlopen = orig

        # l'appel a bien été TENTÉ (fail-open, pas skip silencieux)…
        self.assertEqual(len(rec.calls), 1)
        # …mais AUCUN crash : le rapport est produit et signale l'indisponibilité.
        self.assertIn("Assist indisponible", rep)
        # IA-1 INTACTE : tous les findings rendus, MEDIUM actionnables présents, même ordre que off.
        self.assertEqual(rep.count("### ["), len(findings))
        self.assertIn("IDOR sur /orders", rep)
        # le corps triage/findings (IA-1) est identique : le fail-open n'a touché QUE le bloc assist.
        self.assertIn("## Triage des findings", off)
        self.assertIn("## Triage des findings", rep)

    def test_chat_returns_none_on_any_error(self):
        rec = _Recorder(boom=True)
        orig = _patch_urlopen(rec)
        try:
            self.assertIsNone(L.LLMClient(L.LLMConfig(enabled=True)).chat([{"role": "user", "content": "x"}]))
        finally:
            L.urllib.request.urlopen = orig


class TestAdvisoryOnly(unittest.TestCase):
    """(c) ADVISORY-ONLY : la réponse LLM est un bloc étiqueté ; findings/ordre/ledger inchangés."""

    def test_llm_block_attached_but_findings_and_order_unchanged(self):
        findings = _findings()
        marker = "PRIORISER-IDOR-CWE-639-PUIS-CORS"
        rec = _Recorder(response_factory=lambda: _ok_response(marker))
        orig = _patch_urlopen(rec)
        try:
            # rapport IA-1 seul (référence) — urlopen ne sera pas touché (OFF)
            off = build_report(_engine(findings))
            rep = build_report(_engine(findings, {"enabled": True}))
        finally:
            L.urllib.request.urlopen = orig

        # le bloc advisory est présent, ÉTIQUETÉ, et contient la narrative mockée.
        self.assertIn("## Assist LLM (advisory", rep)
        self.assertIn("CONSULTATIF", rep)
        self.assertIn(marker, rep)

        # ADVISORY-ONLY : le set de findings et leur ORDRE de rendu sont INCHANGÉS vs IA-1 seul.
        def _finding_blocks(text):
            return [ln for ln in text.splitlines() if ln.startswith("### [")]
        self.assertEqual(_finding_blocks(off), _finding_blocks(rep))
        # tout ce qui précède les Findings est IDENTIQUE (le LLM n'a rien réécrit en amont) : le bloc
        # assist est inséré ENTRE la section triage et les Findings, donc l'en-tête+synthèse+triage matche.
        head_off = off.split("## Findings")[0]
        head_rep = rep.split("## Assist LLM")[0]
        self.assertEqual(head_off, head_rep)

    def test_llm_does_not_add_or_change_finding_ledger_entries(self):
        findings = _findings()
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ledger.jsonl"
            led = Ledger(path)
            # on pré-remplit le ledger avec les findings (comme le ferait le moteur).
            for f in findings:
                led.append("finding", f.to_dict())
            before = _ledger_kinds(path)
            n_finding_before = before.count("finding")

            rec = _Recorder()
            orig = _patch_urlopen(rec)
            try:
                build_report(_engine(findings, {"enabled": True}, ledger=led))
            finally:
                L.urllib.request.urlopen = orig

            after = _ledger_kinds(path)
            # AUCUN événement `finding` ajouté / modifié par le LLM (advisory-only).
            self.assertEqual(after.count("finding"), n_finding_before)
            # la SEULE nouvelle entrée est l'audit d'egress (gouvernance), rien d'autre.
            self.assertEqual(after, before + ["llm.egress"])
            # intégrité du ledger toujours OK (aucune réécriture).
            self.assertTrue(led.verify()["ok"])


class TestEgressLedgered(unittest.TestCase):
    """(d) EGRESS LEDGERÉ : activé + appelé => `llm.egress` (endpoint + comptes)."""

    def test_egress_event_recorded_with_endpoint_and_counts(self):
        findings = _findings()
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ledger.jsonl"
            led = Ledger(path)
            rec = _Recorder()
            orig = _patch_urlopen(rec)
            try:
                build_report(_engine(findings, {"enabled": True,
                                                "base_url": "http://127.0.0.1:11434"}, ledger=led))
            finally:
                L.urllib.request.urlopen = orig

            entries = [json.loads(ln) for ln in _ledger_text(path).splitlines() if ln.strip()]
            egress = [e for e in entries if e["kind"] == "llm.egress"]
            self.assertEqual(len(egress), 1)
            det = egress[0]["detail"]
            self.assertEqual(det["endpoint"], "127.0.0.1")
            self.assertTrue(det["loopback"])
            self.assertFalse(det["external"])
            self.assertEqual(det["data_class"], "triage_summary")
            # comptes présents (transparence), et cohérents avec le nombre de findings envoyés.
            self.assertEqual(det["counts"]["total"], len(findings))
            self.assertGreaterEqual(det["counts"]["actionable"], 2)   # les 2 MEDIUM


class TestExternalGated(unittest.TestCase):
    """(e) EXTERNE GATÉ : base_url non-loopback sans autorisation => aucun egress, aucun appel."""

    def test_external_endpoint_blocked_without_authorization(self):
        findings = _findings()
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ledger.jsonl"
            led = Ledger(path)
            rec = _Recorder()                                        # ne DOIT pas être appelé
            orig = _patch_urlopen(rec)
            try:
                rep = build_report(_engine(findings, {"enabled": True,
                                                      "base_url": "https://api.openai.com"}, ledger=led))
            finally:
                L.urllib.request.urlopen = orig

            # AUCUN appel réseau, AUCUN egress ledgeré (fail-closed sur l'externe non autorisé).
            self.assertEqual(len(rec.calls), 0)
            self.assertNotIn("llm.egress", _ledger_kinds(path))
            # le rapport SIGNALE le gate (transparence).
            self.assertIn("Egress REFUSÉ", rep)
            self.assertIn("api.openai.com", rep)

    def test_external_endpoint_allowed_with_operator_gate(self):
        findings = _findings()
        rec = _Recorder()                                              # urlopen NON épinglé : ne doit pas être touché
        orig = _patch_urlopen(rec)
        # La sous-gate anti-SSRF résout l'hôte externe : on mocke le résolveur (public IP) pour rester
        # OFFLINE + déterministe (public => non bloqué par la sous-gate privé/link-local). La connexion
        # externe passe par le seam ÉPINGLÉ et reçoit l'IP VETTÉE (anti-rebinding, pas de 2e résolution).
        orig_resolve = L._resolve_ips
        orig_pinned = L._pinned_urlopen
        pinned_ips = []
        L._resolve_ips = lambda host, timeout=None: ["93.184.216.34"]   # public (documentation IP)
        L._pinned_urlopen = lambda req, ip, timeout=None: (pinned_ips.append(ip) or _ok_response())
        try:
            rep = build_report(_engine(findings, {"enabled": True, "base_url": "https://api.openai.com",
                                                  "allow_external": True}))
        finally:
            L.urllib.request.urlopen = orig
            L._resolve_ips = orig_resolve
            L._pinned_urlopen = orig_pinned
        # autorisation opérateur explicite => l'appel a lieu SUR l'IP vettée (pin), le bloc advisory rendu.
        self.assertEqual(len(rec.calls), 0)                            # jamais l'urlopen non épinglé
        self.assertEqual(pinned_ips, ["93.184.216.34"])               # connecté sur l'IP vettée (pas re-résolu)
        self.assertIn("## Assist LLM (advisory", rep)
        self.assertIn("endpoint EXTERNE", rep)

    def test_is_loopback_classification(self):
        for url in ("http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:8080",
                    "http://127.5.5.5", "http://foo.localhost"):
            self.assertTrue(L.is_loopback(url), url)
        for url in ("https://api.openai.com", "http://10.0.0.5:11434", "http://example.com",
                    "", None, "not a url"):
            self.assertFalse(L.is_loopback(url), url)


class TestSecretRedaction(unittest.TestCase):
    """(f) SECRET : l'api_key n'apparaît JAMAIS dans le GET config / logs / ledger."""

    SECRET = "sk-supersecretkey0123456789abcdef"

    def test_api_key_absent_from_config_dict(self):
        cfg = L.LLMConfig(enabled=True, api_key=self.SECRET)
        d = cfg.to_dict()
        # la clé n'est pas exposée ; seul un booléen atteste sa présence.
        self.assertNotIn("api_key", d)
        self.assertNotIn(self.SECRET, json.dumps(d))
        self.assertTrue(d["api_key_set"])
        # config sans clé => api_key_set False.
        self.assertFalse(L.LLMConfig().to_dict()["api_key_set"])

    def test_api_key_absent_from_ledger_egress(self):
        findings = _findings()
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ledger.jsonl"
            led = Ledger(path)
            rec = _Recorder()
            orig = _patch_urlopen(rec)
            try:
                build_report(_engine(findings, {"enabled": True, "api_key": self.SECRET}, ledger=led))
            finally:
                L.urllib.request.urlopen = orig
            # le secret n'apparaît NULLE PART dans le ledger sur disque.
            self.assertNotIn(self.SECRET, _ledger_text(path))
            self.assertIn("llm.egress", _ledger_kinds(path))

    def test_leaked_secret_in_llm_output_is_redacted(self):
        # si le LLM RECRACHE un secret dans sa narrative, il est rédigé avant rendu.
        findings = _findings()
        leak = f"attention le token est {self.SECRET} — à révoquer"
        rec = _Recorder(response_factory=lambda: _ok_response(leak))
        orig = _patch_urlopen(rec)
        try:
            rep = build_report(_engine(findings, {"enabled": True}))
        finally:
            L.urllib.request.urlopen = orig
        self.assertIn("## Assist LLM", rep)
        self.assertNotIn(self.SECRET, rep)
        self.assertIn("[REDACTED]", rep)


class TestOpenAICompatShape(unittest.TestCase):
    """(g) FORME OpenAI : POST <base_url>/v1/chat/completions, body {model,messages,...}, Bearer."""

    def test_request_shape(self):
        cfg = L.LLMConfig(enabled=True, base_url="http://127.0.0.1:11434", model="llama3.2:1b",
                          api_key="sk-abc0123456789abcdef", max_tokens=256, temperature=0.1)
        rec = _Recorder()
        orig = _patch_urlopen(rec)
        try:
            L.LLMClient(cfg).chat([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}])
        finally:
            L.urllib.request.urlopen = orig

        self.assertEqual(len(rec.calls), 1)
        req = rec.calls[0]["req"]
        # URL = <base_url>/v1/chat/completions, méthode POST.
        self.assertEqual(req.full_url, "http://127.0.0.1:11434/v1/chat/completions")
        self.assertEqual(req.get_method(), "POST")
        # en-têtes : Content-Type JSON + Authorization Bearer.
        headers = {k.lower(): v for k, v in req.header_items()}
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["authorization"], "Bearer sk-abc0123456789abcdef")
        # body OpenAI-compat : model, messages (liste role/content), max_tokens, temperature, stream.
        body = json.loads(req.data)
        self.assertEqual(body["model"], "llama3.2:1b")
        self.assertEqual([m["role"] for m in body["messages"]], ["system", "user"])
        self.assertEqual(body["max_tokens"], 256)
        self.assertEqual(body["temperature"], 0.1)
        self.assertFalse(body["stream"])
        # keep_alive (extension Ollama) présent car endpoint LOOPBACK.
        self.assertEqual(body.get("keep_alive"), "0")
        # timeout borné transmis à urlopen.
        self.assertEqual(rec.calls[0]["timeout"], cfg.timeout)

    def test_keep_alive_omitted_for_external_openai_endpoint(self):
        # compat OpenAI STRICTE : pas de paramètre inconnu `keep_alive` vers un endpoint externe.
        cfg = L.LLMConfig(enabled=True, base_url="https://api.openai.com", allow_external=True)
        rec = _Recorder()
        orig = _patch_urlopen(rec)
        try:
            L.LLMClient(cfg).chat([{"role": "user", "content": "u"}])
        finally:
            L.urllib.request.urlopen = orig
        body = json.loads(rec.calls[0]["req"].data)
        self.assertNotIn("keep_alive", body)
        self.assertEqual(rec.calls[0]["req"].full_url, "https://api.openai.com/v1/chat/completions")

    def test_no_authorization_header_without_key(self):
        cfg = L.LLMConfig(enabled=True)                              # pas d'api_key
        rec = _Recorder()
        orig = _patch_urlopen(rec)
        try:
            L.LLMClient(cfg).chat([{"role": "user", "content": "u"}])
        finally:
            L.urllib.request.urlopen = orig
        headers = {k.lower(): v for k, v in rec.calls[0]["req"].header_items()}
        self.assertNotIn("authorization", headers)


if __name__ == "__main__":
    unittest.main()

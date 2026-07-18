# SPDX-License-Identifier: AGPL-3.0-only
"""Sous-gate défense-en-profondeur (anti-SSRF) sur la DESTINATION d'egress LLM (forge/llm.py).

`allow_external` autorisait TOUT hôte non-loopback — y compris RFC1918 (10/8, 172.16/12, 192.168/16),
link-local 169.254.169.254 (metadata cloud/IMDS) et ULA/link-local v6. Config OPÉRATEUR (pas
attaquant-atteignable), mais un `base_url` mal réglé sur un réseau d'entreprise toucherait un service
interne / l'IMDS. La sous-gate RÉSOUT l'hôte de `base_url` et REFUSE l'egress si l'adresse RÉSOLUE est
privée/link-local, SAUF opt-in explicite `allow_private`. Loopback (Ollama local) reste TOUJOURS exempt.

Garanties prouvées :
  (a) LOOPBACK NO-OP     : 127.0.0.1:11434 => autorisé, AUCUNE résolution (chemin Ollama par défaut) ;
  (b) PUBLIC OK          : hôte public + allow_external => autorisé (résolution => IP publique) ;
  (c) PRIVÉ BLOQUÉ       : RFC1918 / 169.254 + allow_external SANS allow_private => BLOQUÉ (0 appel,
                           0 egress ledgeré, status gated_private ; advisory fail-open continue) ;
  (d) OVERRIDE OPÉRATEUR : même hôte privé + allow_private explicite => autorisé ;
  (e) RÉSOLUTION VÉRIFIÉE: hostname qui RÉSOUT vers 169.254.169.254 => BLOQUÉ (pas juste le littéral) ;
  (f) FAIL-CLOSED        : timeout / NXDOMAIN / erreur de résolution => BLOQUÉ (advisory sauté).
Réutilise le prédicat AUTORITAIRE roe._ip_is_private (aucune logique CIDR dupliquée). Zéro réseau
(urlopen + résolveur monkeypatchés) ; offline/déterministe.
"""
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import llm as L                                    # noqa: E402
from forge.schema import Finding                              # noqa: E402
from forge.roe import Scope                                   # noqa: E402
from forge.engine import Engine                               # noqa: E402
from forge.ledger import Ledger                               # noqa: E402
from forge.report import build_report                         # noqa: E402


# --- doublures réseau / ledger --------------------------------------------------------------------
class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


def _ok_response(content="ordre d'investigation consultatif"):
    payload = {"choices": [{"message": {"role": "assistant", "content": content}}]}
    return _FakeResp(json.dumps(payload).encode("utf-8"))


class _Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, req, timeout=None):
        self.calls.append({"req": req, "timeout": timeout})
        return _ok_response()


class _FakeLedger:
    def __init__(self):
        self.entries = []

    def append(self, kind, detail):
        self.entries.append((kind, detail))

    def kinds(self):
        return [k for k, _ in self.entries]


class _Triage:
    """Objet triage minimal : enrich_triage lit seulement `.summary`."""
    def __init__(self, summary=None):
        self.summary = summary or {"total": 3, "actionable": 2, "noise": 1, "num_clusters": 0,
                                   "top_findings": [{"severity": "MEDIUM", "title": "IDOR", "target": "x"}]}


def _patch(urlopen=None, resolve=None, pinned=None):
    """Patch urlopen, _resolve_ips et/ou _pinned_urlopen (connexion épinglée externe) ; renvoie une
    fonction de restauration."""
    o_u, o_r, o_p = L.urllib.request.urlopen, L._resolve_ips, L._pinned_urlopen
    if urlopen is not None:
        L.urllib.request.urlopen = urlopen
    if resolve is not None:
        L._resolve_ips = resolve
    if pinned is not None:
        L._pinned_urlopen = pinned

    def restore():
        L.urllib.request.urlopen = o_u
        L._resolve_ips = o_r
        L._pinned_urlopen = o_p
    return restore


class _PinnedRecorder:
    """Espion pour le seam de connexion ÉPINGLÉE : capture l'IP VETTÉE reçue (prouve le pin + l'absence
    de 2e résolution) et renvoie une réponse OK."""
    def __init__(self):
        self.ips = []

    def __call__(self, req, ip, timeout=None):
        self.ips.append(ip)
        return _ok_response()


def _boom_urlopen(*a, **k):
    raise AssertionError("réseau LLM appelé alors que l'egress devait être BLOQUÉ / no-op")


def _boom_resolve(*a, **k):
    raise AssertionError("résolveur appelé sur le chemin LOOPBACK (aucune I/O attendue)")


def _cfg(**kw):
    d = {"enabled": True, "base_url": "http://127.0.0.1:11434"}
    d.update(kw)
    return L.LLMConfig.from_dict(d)


# ==================================================================================================
class TestEgressAuthorizedSubGate(unittest.TestCase):
    """Le prédicat unifié `egress_authorized()` (consommé par enrich_payloads ET engine)."""

    def test_a_loopback_allowed_no_resolution(self):
        # (a) loopback => autorisé SANS résoudre (résolveur lève s'il est touché -> prouve le no-op).
        restore = _patch(resolve=_boom_resolve)
        try:
            self.assertTrue(_cfg().egress_authorized())
            self.assertTrue(_cfg(base_url="http://localhost:11434").egress_authorized())
            self.assertFalse(L._egress_blocked_private(_cfg()))
        finally:
            restore()

    def test_b_public_host_allow_external_allowed(self):
        # (b) hôte public + allow_external => autorisé (résolution mockée vers une IP publique).
        restore = _patch(resolve=lambda host, timeout=None: ["93.184.216.34"])
        try:
            cfg = _cfg(base_url="https://api.openai.com", allow_external=True)
            self.assertTrue(cfg.egress_authorized())
            self.assertFalse(L._egress_blocked_private(cfg))
        finally:
            restore()

    def test_c_rfc1918_literal_blocked_even_with_allow_external(self):
        # (c) 10.0.0.5 littéral + allow_external SANS allow_private => BLOQUÉ. Offline : _resolve_ips
        # court-circuite le littéral IP (aucune I/O), donc pas besoin de mock.
        for url in ("http://10.0.0.5", "http://172.16.9.9:11434", "http://192.168.1.10",
                    "http://169.254.169.254"):
            cfg = _cfg(base_url=url, allow_external=True)
            self.assertFalse(cfg.egress_authorized(), url)
            self.assertTrue(L._egress_blocked_private(cfg), url)

    def test_d_private_allowed_with_explicit_allow_private(self):
        # (d) même hôte privé + allow_private explicite => override opérateur => autorisé (aucune I/O).
        restore = _patch(resolve=_boom_resolve)   # override => pas de résolution nécessaire
        try:
            cfg = _cfg(base_url="http://10.0.0.5", allow_external=True, allow_private=True)
            self.assertTrue(cfg.egress_authorized())
            self.assertFalse(L._egress_blocked_private(cfg))
        finally:
            restore()

    def test_e_hostname_resolving_to_metadata_blocked(self):
        # (e) hostname qui RÉSOUT vers 169.254.169.254 => BLOQUÉ (vérif de l'adresse RÉSOLUE, pas du littéral).
        restore = _patch(resolve=lambda host, timeout=None: ["169.254.169.254"])
        try:
            cfg = _cfg(base_url="https://metadata.internal.example", allow_external=True)
            self.assertFalse(cfg.egress_authorized())
            self.assertTrue(L._egress_blocked_private(cfg))
        finally:
            restore()
        # un hostname public + un membre privé dans la résolution => BLOQUÉ (une IP privée suffit).
        restore = _patch(resolve=lambda host, timeout=None: ["93.184.216.34", "10.1.2.3"])
        try:
            cfg = _cfg(base_url="https://split-horizon.example", allow_external=True)
            self.assertTrue(L._egress_blocked_private(cfg))
        finally:
            restore()

    def test_f_resolution_failure_fails_closed(self):
        # (f) NXDOMAIN ([]) ET timeout/erreur (raise) => fail-closed => BLOQUÉ (advisory sauté).
        restore = _patch(resolve=lambda host, timeout=None: [])            # NXDOMAIN / hôte inconnu
        try:
            cfg = _cfg(base_url="https://nx.example", allow_external=True)
            self.assertFalse(cfg.egress_authorized())
            self.assertTrue(L._egress_blocked_private(cfg))
        finally:
            restore()

        def _raise(host, timeout=None):
            raise TimeoutError("résolution expirée (simulée)")
        restore = _patch(resolve=_raise)
        try:
            cfg = _cfg(base_url="https://slow.example", allow_external=True)
            self.assertFalse(cfg.egress_authorized())
            self.assertTrue(L._egress_blocked_private(cfg))
        finally:
            restore()

    def test_to_dict_exposes_allow_private_default_false(self):
        d = L.LLMConfig().to_dict()
        self.assertIn("allow_private", d)
        self.assertFalse(d["allow_private"])
        self.assertTrue(L.LLMConfig.from_dict({"allow_private": True}).to_dict()["allow_private"])


# ==================================================================================================
class TestEnrichTriageSubGate(unittest.TestCase):
    """`enrich_triage` : le sous-gate renvoie `gated_private`, sans appel ni egress ledgeré."""

    def test_private_destination_gated_no_call_no_egress(self):
        # (c) RFC1918 + allow_external sans allow_private => gated_private, 0 appel réseau, 0 egress ledgeré.
        led = _FakeLedger()
        restore = _patch(urlopen=_boom_urlopen)               # urlopen lève s'il est touché
        try:
            cfg = _cfg(base_url="http://10.0.0.5", allow_external=True)
            block = L.enrich_triage(_Triage(), cfg, ledger=led)
        finally:
            restore()
        self.assertEqual(block["status"], "gated_private")
        self.assertEqual(block["narrative"], "")
        self.assertNotIn("llm.egress", led.kinds())           # AUCUN egress ledgeré (aucune donnée sortie)

    def test_metadata_hostname_gated(self):
        # (e) hostname -> 169.254.169.254 => gated_private (adresse résolue, pas littéral).
        led = _FakeLedger()
        restore = _patch(urlopen=_boom_urlopen, resolve=lambda host, timeout=None: ["169.254.169.254"])
        try:
            cfg = _cfg(base_url="https://imds.corp.example", allow_external=True)
            block = L.enrich_triage(_Triage(), cfg, ledger=led)
        finally:
            restore()
        self.assertEqual(block["status"], "gated_private")
        self.assertNotIn("llm.egress", led.kinds())

    def test_loopback_still_calls_and_ledgers(self):
        # (a) loopback INCHANGÉ : appel effectué, egress ledgeré, status ok, résolveur JAMAIS touché.
        led = _FakeLedger()
        rec = _Recorder()
        restore = _patch(urlopen=rec, resolve=_boom_resolve)
        try:
            block = L.enrich_triage(_Triage(), _cfg(), ledger=led)
        finally:
            restore()
        self.assertEqual(block["status"], "ok")
        self.assertEqual(len(rec.calls), 1)
        self.assertIn("llm.egress", led.kinds())

    def test_public_host_allowed_calls_and_ledgers(self):
        # (b) public + allow_external => appel + egress ledgeré (résolveur mocké vers IP publique). La
        # connexion externe passe par le seam ÉPINGLÉ et reçoit l'IP VETTÉE (anti-rebinding, pas de 2e
        # résolution) ; l'urlopen NON épinglé lève s'il est touché.
        led = _FakeLedger()
        pinrec = _PinnedRecorder()
        restore = _patch(urlopen=_boom_urlopen, pinned=pinrec,
                         resolve=lambda host, timeout=None: ["93.184.216.34"])
        try:
            cfg = _cfg(base_url="https://api.openai.com", allow_external=True)
            block = L.enrich_triage(_Triage(), cfg, ledger=led)
        finally:
            restore()
        self.assertEqual(block["status"], "ok")
        self.assertEqual(pinrec.ips, ["93.184.216.34"])       # connecté SUR l'IP vettée (pin, pas re-résolu)
        self.assertIn("llm.egress", led.kinds())

    def test_private_with_allow_private_override_calls(self):
        # (d) hôte privé + allow_private => appel effectué (override opérateur).
        led = _FakeLedger()
        rec = _Recorder()
        restore = _patch(urlopen=rec, resolve=_boom_resolve)   # override => pas de résolution
        try:
            cfg = _cfg(base_url="http://10.0.0.5", allow_external=True, allow_private=True)
            block = L.enrich_triage(_Triage(), cfg, ledger=led)
        finally:
            restore()
        self.assertEqual(block["status"], "ok")
        self.assertEqual(len(rec.calls), 1)


# ==================================================================================================
class TestEnrichPayloadsSubGate(unittest.TestCase):
    """`enrich_payloads` hérite du sous-gate via `egress_authorized()`."""

    def test_private_destination_no_payloads_no_call(self):
        # (c) RFC1918 + allow_external sans allow_private => [] (aucun payload), aucun appel, aucun egress.
        led = _FakeLedger()
        restore = _patch(urlopen=_boom_urlopen)
        try:
            cfg = _cfg(base_url="http://169.254.169.254", allow_external=True)
            out = L.enrich_payloads("ssti.eval", "https://app.test/x", "q", cfg, ledger=led)
        finally:
            restore()
        self.assertEqual(out, [])
        self.assertNotIn("llm.egress", led.kinds())


# ==================================================================================================
class TestReportFailOpenAdvisoryContinues(unittest.TestCase):
    """Le rapport (advisory) CONTINUE quand l'egress est gaté : IA-1 intacte, aucun crash."""

    def _findings(self):
        f = [Finding(target="b.example.com/orders/42", title="IDOR sur /orders/{id}", severity="MEDIUM",
                     category="CWE-639", status="tested", tool="oracle",
                     evidence="GET /orders/42 (compte A) renvoie la commande du compte B.")]
        return f

    def _engine(self, llm_cfg, ledger=None):
        data = {"in_scope": ["*.example.com"], "mode": "grey", "llm": llm_cfg}
        eng = Engine(Scope(data), ledger=ledger)
        eng.findings = self._findings()
        return eng

    def test_gated_private_report_still_produced(self):
        # (c) destination privée => aucun appel, aucun egress, MAIS le rapport IA-1 est produit intact.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ledger.jsonl"
            led = Ledger(path)
            restore = _patch(urlopen=_boom_urlopen,
                             resolve=lambda host, timeout=None: ["169.254.169.254"])
            try:
                rep = build_report(self._engine(
                    {"enabled": True, "base_url": "https://imds.corp.example", "allow_external": True},
                    ledger=led))
            finally:
                restore()
            # IA-1 intacte : le finding actionnable est rendu ; aucun egress ledgeré (gate anti-SSRF).
            self.assertIn("IDOR sur /orders", rep)
            # ledger non écrit du tout (gate => aucune entrée) ou, s'il existe, sans `llm.egress`.
            kinds = ([json.loads(ln)["kind"]
                      for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
                     if path.exists() else [])
            self.assertNotIn("llm.egress", kinds)


# ==================================================================================================
class TestEgressPinnedAntiRebinding(unittest.TestCase):
    """FIX : la connexion externe DIALE l'IP VETTÉE résolue par le gate (UNE fois) au lieu de re-résoudre
    — ferme le check-vs-use (DNS-rebinding : public au gate, 169.254.169.254 au connect)."""

    def test_rebinding_domain_pinned_to_first_resolution_no_second_resolve(self):
        # Résolveur REBINDING : public au 1er appel (gate), privé (metadata) au 2e. Le gate résout UNE
        # SEULE FOIS et ÉPINGLE l'IP publique ; la connexion DIALE cette IP vettée (aucune 2e résolution)
        # -> le 169.254.169.254 rebindé n'est JAMAIS atteint.
        led = _FakeLedger()
        calls = {"n": 0}

        def _rebind(host, timeout=None):
            calls["n"] += 1
            return ["93.184.216.34"] if calls["n"] == 1 else ["169.254.169.254"]

        pinrec = _PinnedRecorder()
        restore = _patch(urlopen=_boom_urlopen, pinned=pinrec, resolve=_rebind)
        try:
            cfg = _cfg(base_url="https://rebind.example", allow_external=True)
            block = L.enrich_triage(_Triage(), cfg, ledger=led)
        finally:
            restore()
        self.assertEqual(block["status"], "ok")
        self.assertEqual(calls["n"], 1, "résolu UNE seule fois (verdict+pin), jamais re-résolu au connect")
        self.assertEqual(pinrec.ips, ["93.184.216.34"], "connecté SUR l'IP vettée, pas le rebind 169.254")
        self.assertIn("llm.egress", led.kinds())

    def test_metadata_first_resolution_private_blocked_no_connection(self):
        # si la résolution (unique) rend une IP privée/metadata -> gated_private, AUCUNE connexion
        # (ni urlopen NON épinglé ni seam épinglé), aucun egress ledgeré.
        led = _FakeLedger()
        pinrec = _PinnedRecorder()
        restore = _patch(urlopen=_boom_urlopen, pinned=pinrec,
                         resolve=lambda host, timeout=None: ["169.254.169.254"])
        try:
            cfg = _cfg(base_url="https://imds.example", allow_external=True)
            block = L.enrich_triage(_Triage(), cfg, ledger=led)
        finally:
            restore()
        self.assertEqual(block["status"], "gated_private")
        self.assertEqual(pinrec.ips, [])                      # aucune connexion épinglée
        self.assertNotIn("llm.egress", led.kinds())

    def test_loopback_never_pinned_uses_urlopen(self):
        # (a) loopback (Ollama local) : chemin par défaut BYTE-IDENTIQUE — urlopen NORMAL, JAMAIS le seam
        # épinglé, AUCUNE résolution.
        led = _FakeLedger()
        rec = _Recorder()

        def _boom_pinned(*a, **k):
            raise AssertionError("le seam épinglé ne doit PAS être utilisé pour loopback")

        restore = _patch(urlopen=rec, pinned=_boom_pinned, resolve=_boom_resolve)
        try:
            block = L.enrich_triage(_Triage(), _cfg(), ledger=led)
        finally:
            restore()
        self.assertEqual(block["status"], "ok")
        self.assertEqual(len(rec.calls), 1)                   # urlopen normal (non épinglé)

    def test_payloads_external_public_pinned(self):
        # enrich_payloads partage le MÊME gate/pin : externe public => connexion épinglée sur l'IP vettée.
        led = _FakeLedger()
        captured = {}

        def _pinned(req, ip, timeout=None):
            captured["ip"] = ip
            payload = {"choices": [{"message": {"content": "${N*M}"}}]}
            return _FakeResp(json.dumps(payload).encode("utf-8"))

        restore = _patch(urlopen=_boom_urlopen, pinned=_pinned,
                         resolve=lambda host, timeout=None: ["93.184.216.34"])
        try:
            cfg = _cfg(base_url="https://api.openai.com", allow_external=True)
            out = L.enrich_payloads("ssti.eval", "https://app.test/x", "q", cfg, ledger=led)
        finally:
            restore()
        self.assertEqual(captured.get("ip"), "93.184.216.34")
        self.assertTrue(out)                                  # payload suggéré revenu (pin transparent)
        self.assertIn("llm.egress", led.kinds())


if __name__ == "__main__":
    unittest.main()

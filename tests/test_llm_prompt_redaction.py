# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rédaction du prompt SORTANT vers le LLM — la donnée qui QUITTE Forge, pas seulement celle qui revient.

Trou trouvé à l'audit du hook LLM : la sortie du modèle était rédigée AU RETOUR (`enrich_triage` /
`enrich_payloads` passent la réponse par `forge.redact`), mais l'ALLER ne l'était PAS. Or les deux
prompts portent de la donnée ATTAQUANT-INFLUENCÉE, non rédigée :

  - `_payload_messages` y met l'URL COMPLÈTE de la cible crawlée (`action.target`). Une URL découverte
    par le crawl porte régulièrement `?session_token=…`, `?api_key=…`, ou un `scheme://user:pass@`.
  - `_assist_messages` y met `title` / `target` des top-findings, lus par `triage.py` en ATTRIBUTS
    BRUTS (`getattr(f, "target")`) — donc SANS passer par `Finding.to_dict()`, qui, lui, rédige.

Asymétrie révélatrice : le ledger d'egress, lui, était scrupuleux (`_payload_egress_detail` ne
journalise que `target_host`, jamais l'URL). Le prompt SORTAIT donc avec PLUS de secret que sa propre
trace d'audit n'en avouait.

Garde prouvée ici : `LLMClient._redact_messages`, appliquée dans `_build_request` — le point où les
messages deviennent des OCTETS, donc la DERNIÈRE barrière avant l'egress, qu'aucun futur chemin de
prompt ne peut contourner. Zéro réseau (urlopen monkeypatché) ; on inspecte le CORPS RÉELLEMENT ÉMIS.
"""
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import llm as L                      # noqa: E402
from forge.redact import REDACTED               # noqa: E402

# Secrets PLANTÉS dans les entrées : ils ne doivent JAMAIS apparaître dans les octets émis.
SESSION_TOKEN = "s3cr3tsessionvalue123456"
API_KEY = "AIzaSyA1234567890abcdefghijklmnop"
URL_PASSWORD = "p4ssw0rdInUrl"


class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


class _BodyRecorder:
    """Capture le CORPS RÉELLEMENT SÉRIALISÉ de chaque requête (pas les messages en amont) : c'est
    l'octet qui sort sur le socket qui fait foi, pas l'intention du code appelant."""

    def __init__(self):
        self.bodies = []

    def __call__(self, req, timeout=None):
        self.bodies.append(req.data.decode("utf-8"))
        return _FakeResp(json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": "{{N*M}}"}}]}).encode("utf-8"))

    @property
    def last(self):
        return self.bodies[-1]

    def last_messages(self):
        return json.loads(self.last)["messages"]


class _PromptRedactionCase(unittest.TestCase):
    def setUp(self):
        self.rec = _BodyRecorder()
        self._orig = L.urllib.request.urlopen
        L.urllib.request.urlopen = self.rec
        self.addCleanup(lambda: setattr(L.urllib.request, "urlopen", self._orig))

    def cfg(self, **kw):
        d = {"enabled": True, "base_url": "http://127.0.0.1:11434"}   # loopback => egress autorisé
        d.update(kw)
        return L.LLMConfig.from_dict(d)

    def assertNoSecret(self, blob):
        for secret in (SESSION_TOKEN, API_KEY, URL_PASSWORD):
            self.assertNotIn(secret, blob, f"secret « {secret} » SORTI dans le prompt LLM")


class TestPayloadPromptRedaction(_PromptRedactionCase):
    """Chaîne d'injection : l'URL crawlée complète part dans le prompt."""

    TARGET = (f"https://app.example.com/render"
              f"?session_token={SESSION_TOKEN}&api_key={API_KEY}&tpl=x")

    def test_target_url_secrets_never_leave_in_payload_prompt(self):
        out = L.enrich_payloads("ssti.eval", self.TARGET, "tpl", self.cfg())
        self.assertEqual(out, ["{{N*M}}"])                 # le chemin nominal marche toujours
        self.assertEqual(len(self.rec.bodies), 1)          # UN seul appel (borne inchangée)
        self.assertNoSecret(self.rec.last)
        self.assertIn(REDACTED, self.rec.last)             # les secrets ont bien été MASQUÉS, pas droppés
        # ce qui reste est le CONTEXTE utile : la technique, l'hôte, le nom du paramètre.
        user = self.rec.last_messages()[1]["content"]
        self.assertIn("ssti.eval", user)
        self.assertIn("app.example.com", user)
        self.assertIn("tpl", user)

    def test_url_embedded_credentials_redacted(self):
        # forme `scheme://user:pass@host` — l'autre façon dont un crawl ramène un identifiant.
        L.enrich_payloads("ssti.eval", f"https://admin:{URL_PASSWORD}@app.example.com/x", "q", self.cfg())
        self.assertNoSecret(self.rec.last)

    def test_prompt_leaks_no_more_than_its_own_audit_trail(self):
        """Propriété de cohérence : le ledger d'egress ne consigne que `target_host`. Le prompt ne doit
        pas SORTIR plus de secret que ce que la trace d'audit avoue — sinon l'audit ment par omission."""
        detail = L._payload_egress_detail(self.cfg(), "ssti.eval", self.TARGET, "tpl")
        self.assertNoSecret(json.dumps(detail))            # l'audit était déjà propre…
        L.enrich_payloads("ssti.eval", self.TARGET, "tpl", self.cfg())
        self.assertNoSecret(self.rec.last)                 # …le prompt l'est désormais aussi


class TestAssistPromptRedaction(_PromptRedactionCase):
    """Chaîne de triage : `title`/`target` des findings partent en attributs BRUTS (non rédigés)."""

    class _Triage:
        def __init__(self, summary):
            self.summary = summary

    def _triage(self):
        return self._Triage({
            "total": 2, "actionable": 2, "noise": 0, "duplicates": 0, "num_clusters": 0,
            "top_findings": [
                {"severity": "HIGH", "title": "Jeton de session exposé",
                 "target": f"https://api.example.com/v1?session_token={SESSION_TOKEN}"},
                {"severity": "MEDIUM", "title": "Identifiants en clair dans l'URL",
                 "target": f"https://admin:{URL_PASSWORD}@api.example.com/v1"},
            ],
            "clusters": [],
        })

    def test_finding_targets_redacted_before_egress(self):
        res = L.enrich_triage(self._triage(), self.cfg())
        self.assertEqual(res["status"], "ok")              # chemin nominal préservé
        self.assertNoSecret(self.rec.last)
        self.assertIn(REDACTED, self.rec.last)
        self.assertIn("api.example.com", self.rec.last)    # le contexte utile survit

    def test_secret_bearing_title_redacted(self):
        t = self._Triage({"total": 1, "actionable": 1, "top_findings": [
            {"severity": "HIGH", "title": f"Clé trouvée : {API_KEY}", "target": "api.example.com"}],
            "clusters": []})
        L.enrich_triage(t, self.cfg())
        self.assertNoSecret(self.rec.last)


class TestRedactionIsNotCollateralDamage(_PromptRedactionCase):
    """La garde ne doit pas abîmer les prompts bénins : sinon on troque une fuite contre une régression
    silencieuse de la qualité des suggestions."""

    def test_system_prompts_byte_identical(self):
        for name, prompt in (("ASSIST_SYSTEM", L.ASSIST_SYSTEM), ("_PAYLOAD_SYSTEM", L._PAYLOAD_SYSTEM)):
            with self.subTest(prompt=name):
                red = L.LLMClient._redact_messages([{"role": "system", "content": prompt}])
                self.assertEqual(red[0]["content"], prompt)

    def test_benign_payload_prompt_byte_identical(self):
        target = "https://shop.example.com/search?q=chaise&page=2"
        before = L._payload_messages("ssti.eval", target, "q")
        L.enrich_payloads("ssti.eval", target, "q", self.cfg())
        sent = self.rec.last_messages()
        self.assertEqual([m["content"] for m in sent], [m["content"] for m in before])
        self.assertNotIn(REDACTED, self.rec.last)          # aucun masquage parasite

    def test_roles_and_structure_preserved(self):
        L.enrich_payloads("ssti.eval", "https://app.example.com/x", "q", self.cfg())
        sent = self.rec.last_messages()
        self.assertEqual([m["role"] for m in sent], ["system", "user"])

    def test_tolerant_of_malformed_messages(self):
        """Le rédacteur est sur le chemin d'egress : il ne doit JAMAIS être ce qui casse un run
        (fail-open). Message non-dict, contenu non-str, liste vide/None => passent tels quels."""
        weird = [{"role": "user", "content": 42}, "pas-un-dict", {"role": "user"}, None]
        self.assertEqual(L.LLMClient._redact_messages(weird), weird)
        self.assertEqual(L.LLMClient._redact_messages([]), [])
        self.assertEqual(L.LLMClient._redact_messages(None), [])

    def test_redaction_is_idempotent_on_already_redacted_prompt(self):
        once = L.LLMClient._redact_messages([{"role": "user", "content": f"api_key={API_KEY}"}])
        twice = L.LLMClient._redact_messages(once)
        self.assertEqual(once, twice)


class TestGuardIsLoadBearing(_PromptRedactionCase):
    """Contrôle POSITIF : sans la garde, le secret sort bel et bien. Un test qui passe des deux côtés
    ne prouverait rien — celui-ci montre que la garde est ce qui fait la différence."""

    def test_unguarded_serialization_would_leak(self):
        target = f"https://app.example.com/x?session_token={SESSION_TOKEN}"
        raw = json.dumps({"messages": L._payload_messages("ssti.eval", target, "q")})
        self.assertIn(SESSION_TOKEN, raw)                  # messages BRUTS : le secret est là…
        L.enrich_payloads("ssti.eval", target, "q", self.cfg())
        self.assertNotIn(SESSION_TOKEN, self.rec.last)     # …corps ÉMIS : il n'y est plus


if __name__ == "__main__":
    unittest.main(verbosity=2)

# SPDX-License-Identifier: AGPL-3.0-only
"""Tests de la SURFACE UNIQUE de rédaction des secrets (`forge/redact.py`).

Contexte : trois rédacteurs avaient divergé (report_engagement = superset ; importers/_base = tokens
cloud manquants ; modules/exposure = pire + regex PEM cassée sur un type à chiffre) → de vrais secrets
FUYAIENT par deux des trois chemins. Ces tests prouvent que :
  1. le rédacteur canonique masque un représentant de CHAQUE famille de token ;
  2. le MÊME secret est masqué par les TROIS anciens points d'entrée divergents (fuite refermée) ;
  3. régression : une clé privée PEM dont le TYPE contient un chiffre (`EC2 PRIVATE KEY`) est masquée
     (l'ancien exposure._redact la ratait via `[A-Z ]*`).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.redact import redact_secrets, REDACTED          # noqa: E402
from forge import report_engagement as R                   # noqa: E402
from forge.importers import _base                           # noqa: E402
from forge.modules import exposure                          # noqa: E402

# --- un représentant par famille : (nom, texte porteur, sous-chaîne SECRÈTE qui doit disparaître) ----
GH_PAT = "ghp_0123456789abcdefABCDEF0123456789ab"
GHO_TOK = "gho_0123456789abcdefABCDEF0123456789ab"
SLACK = "xoxb-1234567890-0987654321-abcdefGHIJklmno"
GOOGLE = "AIzaSyA1234567890abcdefGHIJKLmnopqrstuv"
OPENAI = "sk-abcdefghijklmnopqrstuvwxyz0123456789AB"
GITLAB = "glpat-abcdef1234567890ABCDxyz"
AWS_KEYID = "AKIAABCDEFGHIJKLMNOP"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKLmnopQRStuv"
BEARER_TOK = "abcDEF1234567890ghIJ"
URL_PW = "sup3rP@sswd"
PEM_EC2 = ("-----BEGIN EC2 PRIVATE KEY-----\n"
           "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\n"
           "uKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQ==\n"
           "-----END EC2 PRIVATE KEY-----")
GENERIC_PW = "Sup3rSecretValue123"

# (label, carrier_text, secret_substring_that_must_vanish)
FAMILIES = [
    ("github-ghp", f"gh token {GH_PAT} end", GH_PAT),
    ("github-gho", f"oauth {GHO_TOK} end", GHO_TOK),
    ("slack", f"slack={SLACK}", SLACK),
    ("google", f"gkey {GOOGLE} x", GOOGLE),
    ("openai", f"OPENAI_API_KEY={OPENAI}", OPENAI),
    ("gitlab", f"pat {GITLAB} x", GITLAB),
    ("aws-akia", f"key {AWS_KEYID} here", AWS_KEYID),
    ("bearer", f"Authorization: Bearer {BEARER_TOK}", BEARER_TOK),
    ("url-cred", f"conn https://user:{URL_PW}@host.example.com/p", URL_PW),
    ("jwt", f"jwt {JWT} end", JWT),
    ("pem-ec2", PEM_EC2, "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q"),
    ("generic-kv", f"password={GENERIC_PW} rest", GENERIC_PW),
    ("generic-kv-json", f'{{"db.password":"{GENERIC_PW}"}}', GENERIC_PW),
]

# points d'entrée qui, historiquement, divergeaient : tous DOIVENT désormais masquer identiquement.
ENTRY_POINTS = [
    ("forge.redact.redact_secrets", redact_secrets),
    ("report_engagement.redact_secrets", R.redact_secrets),
    ("importers._base.redact", _base.redact),
    ("modules.exposure._redact", exposure._redact),
]


class TestCanonicalCoversEveryFamily(unittest.TestCase):
    def test_each_family_masked_by_canonical(self):
        for label, carrier, secret in FAMILIES:
            out = redact_secrets(carrier)
            self.assertNotIn(secret, out, f"[{label}] secret non masqué par le canonique: {out!r}")
            self.assertIn(REDACTED, out, f"[{label}] marqueur absent: {out!r}")


class TestLeakClosedThroughAllThreeEntryPoints(unittest.TestCase):
    """Le cœur de la correction : le MÊME secret disparaît par les TROIS anciens chemins divergents."""

    def test_every_family_masked_by_every_entry_point(self):
        for name, fn in ENTRY_POINTS:
            for label, carrier, secret in FAMILIES:
                out = fn(carrier)
                self.assertNotIn(
                    secret, out,
                    f"FUITE: {name} n'a pas masqué [{label}] -> {out!r}")

    def test_cloud_tokens_previously_leaking_now_masked_everywhere(self):
        # ghp_/sk-/xoxb-/AIza/gho_/gitlab : masqués par report mais FUYAIENT par importer & exposure.
        for token in (GH_PAT, GHO_TOK, SLACK, GOOGLE, OPENAI, GITLAB):
            carrier = f"leak {token} tail"
            self.assertNotIn(token, _base.redact(carrier), "fuite via importer._base.redact")
            self.assertNotIn(token, exposure._redact(carrier), "fuite via exposure._redact")

    def test_jwt_previously_leaking_via_exposure_now_masked(self):
        carrier = f"token {JWT} tail"
        self.assertNotIn(JWT, exposure._redact(carrier))
        self.assertNotIn(JWT, _base.redact(carrier))


class TestPemDigitInTypeRegression(unittest.TestCase):
    """Régression EXACTE de l'ancien bug exposure : `[A-Z ]*` ratait un type PEM contenant un chiffre."""

    def test_ec2_private_key_masked_by_canonical(self):
        out = redact_secrets(PEM_EC2)
        self.assertNotIn("MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q", out)
        self.assertNotIn("uKUpRKfFLfRYC9AIKjbJTWit", out)

    def test_ec2_private_key_masked_through_exposure(self):
        # c'est CE chemin qui laissait fuir le corps de la clé auparavant.
        out = exposure._redact(PEM_EC2)
        self.assertNotIn("MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q", out)

    def test_ec2_private_key_masked_through_importer(self):
        out = _base.redact(PEM_EC2)
        self.assertNotIn("uKUpRKfFLfRYC9AIKjbJTWit", out)


class TestSuperfluousOverRedactionGuards(unittest.TestCase):
    """Anti-régression : on ne sur-masque pas du texte de rapport normal."""

    def test_word_containing_sk_dash_untouched(self):
        # "task-force" contient "sk-" mais n'est PAS un token OpenAI (pas 20+ alnum ni frontière).
        self.assertEqual(redact_secrets("the task-force met"), "the task-force met")

    def test_plain_prose_untouched(self):
        prose = "IDOR sur /orders — accès à la ressource d'un autre utilisateur (CWE-639)."
        self.assertEqual(redact_secrets(prose), prose)


class TestContractsPreserved(unittest.TestCase):
    def test_canonical_non_string_passthrough(self):
        self.assertIsNone(redact_secrets(None))
        self.assertEqual(redact_secrets(42), 42)
        self.assertEqual(redact_secrets(""), "")

    def test_report_wrapper_passthrough(self):
        self.assertIsNone(R.redact_secrets(None))
        self.assertEqual(R.redact_secrets(42), 42)

    def test_importer_wrapper_coerces_never_none(self):
        self.assertEqual(_base.redact(None), "")
        self.assertEqual(_base.redact(""), "")

    def test_exposure_wrapper_empty_on_falsy(self):
        self.assertEqual(exposure._redact(None), "")
        self.assertEqual(exposure._redact(""), "")

    def test_idempotent(self):
        for _label, carrier, _secret in FAMILIES:
            once = redact_secrets(carrier)
            self.assertEqual(redact_secrets(once), once, f"non idempotent: {carrier!r}")


if __name__ == "__main__":
    unittest.main()

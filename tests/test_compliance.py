"""ENTERPRISE (E3 COMPLIANCE) — pluggable checkpoint signer + WORM decision. `python -m unittest -v`.

Proves: (a) sign→verify with the PUBLIC KEY ONLY (non-repudiation); (b) any tamper (payload/sig/pub) fails;
(c) the signer is PLUGGABLE (a KMS/HSM-style callable signer verifies through the SAME path); (d) verify is
BYTE-IDENTICAL to signing.verify_with_pubkey; (e) the WORM gate is fail-closed and LEGAL-HOLD ALWAYS WINS
(a mutation removing the hold check flips a test RED). The module is INERT unless called — importing it never
touches the community engine.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import compliance_signer as cs  # noqa: E402
from forge import ledger as L  # noqa: E402
from forge import signing  # noqa: E402
from forge.ledger import Ledger  # noqa: E402


def _payload():
    return {
        "actor": "root",
        "scope": "engagement",
        "engagement_id": 7,
        "purged_count": 3,
        "purged_head": "ab" * 32,
        "segment_sha256": "cd" * 32,
        "now": 1_700_000_000,
    }


class TestCheckpointSigner(unittest.TestCase):
    def test_default_signer_is_ed25519(self):
        signer = cs.default_signer()  # ephemeral in-memory key
        self.assertEqual(signer.alg, "ed25519")
        self.assertEqual(len(signer.pubkey_hex), 64)

    def test_sign_then_verify_with_public_key_only(self):
        signer = cs.default_signer()
        p = _payload()
        rec = cs.sign_checkpoint(p, signer)
        self.assertEqual(rec["alg"], "ed25519")
        # a third party verifies with the embedded public key only — no secret needed.
        self.assertTrue(cs.verify_checkpoint(p, rec))
        # and with an explicitly PINNED auditor key (same key) — still OK.
        self.assertTrue(cs.verify_checkpoint(p, rec, pubkey_hex=signer.pubkey_hex))

    def test_tampered_payload_fails(self):
        signer = cs.default_signer()
        p = _payload()
        rec = cs.sign_checkpoint(p, signer)
        tampered = dict(p)
        tampered["purged_count"] = 2  # hide one purged record
        self.assertFalse(cs.verify_checkpoint(tampered, rec))

    def test_tampered_signature_fails(self):
        signer = cs.default_signer()
        p = _payload()
        rec = cs.sign_checkpoint(p, signer)
        bad = dict(rec)
        # flip the last hex nibble of the signature
        last = "0" if rec["sig"][-1] != "0" else "1"
        bad["sig"] = rec["sig"][:-1] + last
        self.assertFalse(cs.verify_checkpoint(p, bad))

    def test_wrong_pubkey_fails(self):
        signer = cs.default_signer()
        p = _payload()
        rec = cs.sign_checkpoint(p, signer)
        self.assertFalse(cs.verify_checkpoint(p, rec, pubkey_hex="00" * 32))

    def test_missing_payload_hash_fails(self):
        signer = cs.default_signer()
        p = _payload()
        rec = cs.sign_checkpoint(p, signer)
        del rec["payload_sha256"]
        self.assertFalse(cs.verify_checkpoint(p, rec))

    def test_verify_is_byte_identical_to_signing_verify_with_pubkey(self):
        # The whole point: verify_checkpoint MUST delegate to signing.verify_with_pubkey over the SAME
        # canonical pre-image — a KMS signature and a local one verify through one identical code path.
        signer = cs.default_signer()
        p = _payload()
        rec = cs.sign_checkpoint(p, signer)
        data = cs.canonical_payload(p)
        self.assertTrue(signing.verify_with_pubkey(rec["pub"], data, rec["sig"]))
        # Both agree on truth AND on falsehood (tampered sig).
        bad_sig = rec["sig"][:-1] + ("0" if rec["sig"][-1] != "0" else "1")
        self.assertEqual(
            cs.verify_checkpoint(p, {**rec, "sig": bad_sig}),
            signing.verify_with_pubkey(rec["pub"], data, bad_sig),
        )

    def test_pluggable_callable_signer_kms_seam(self):
        # A KMS/HSM-style signer: an external key produces the signature; Forge only sees sign_fn + pubkey.
        # It MUST verify through the same path as the local signer.
        ephemeral = signing.ephemeral_signer()  # stands in for the KMS-held private key
        self.assertEqual(ephemeral.alg, "ed25519")
        kms = cs.CallableComplianceSigner(sign_fn=ephemeral.sign, pubkey_hex=ephemeral.pubkey_hex)
        p = _payload()
        rec = cs.sign_checkpoint(p, kms)
        self.assertEqual(rec["pub"], ephemeral.pubkey_hex)
        self.assertTrue(cs.verify_checkpoint(p, rec))
        # tamper still caught for the pluggable signer.
        self.assertFalse(cs.verify_checkpoint({**p, "actor": "mallory"}, rec))

    def test_callable_signer_rejects_bad_pubkey(self):
        with self.assertRaises(RuntimeError):
            cs.CallableComplianceSigner(sign_fn=lambda b: "00", pubkey_hex="short")


class TestReanchoredLedgerCrossLanguage(unittest.TestCase):
    """Prove the re-anchored ledger FORMAT the Rust governed purge emits is verifiable by the SHARED Python
    verifier (Ledger.verify) — a genesis-rooted `console.compliance.purge` checkpoint + re-linked
    sha256-console survivors — and that tamper-evidence is preserved after the re-anchor."""

    def _line(self, prev, seq, ts, kind, detail):
        h = L._entry_hash(prev, seq, ts, kind, detail)
        rec = {"seq": seq, "ts": ts, "kind": kind, "detail": detail,
               "prev": prev, "hash": h, "alg": "sha256-console", "sig": ""}
        return L._canon(rec), h

    def test_reanchored_console_ledger_verifies_and_detects_tamper(self):
        d = Path(tempfile.mkdtemp(prefix="forge-comp-"))
        p = d / "l.jsonl"
        # checkpoint R @ genesis (seq 0), then two re-linked survivors (their original seq 4,5 preserved).
        cp = {"reanchor": True, "purged_ledger_entries": 3, "segment_sha256": "ab" * 32}
        l0, h0 = self._line(L.GENESIS, 0, "@1700000000", "console.compliance.purge", cp)
        l1, h1 = self._line(h0, 4, "@1700000100", "console.run.end", {"i": 0})
        l2, _ = self._line(h1, 5, "@1700000200", "console.run.end", {"i": 1})
        p.write_text("\n".join([l0, l1, l2]) + "\n")

        led = Ledger(p)  # default ed25519 signer — unused for these sha256-console entries
        self.assertTrue(led.verify()["ok"], "re-anchored console ledger must verify under Python Ledger.verify")

        # tamper a survivor's detail => the shared verifier must flag it (tamper-evidence intact post re-anchor).
        lines = p.read_text().splitlines()
        bad = json.loads(lines[2])
        bad["detail"]["i"] = 99
        lines[2] = json.dumps(bad, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        p.write_text("\n".join(lines) + "\n")
        self.assertFalse(led.verify()["ok"], "tampered survivor must break the re-anchored chain")


class TestWormDecision(unittest.TestCase):
    """WORM gate: fail-closed, LEGAL-HOLD ALWAYS WINS."""

    RET = 100  # retention window (seconds)

    def test_expired_no_hold_is_purgeable(self):
        self.assertTrue(cs.worm_purge_allowed(self.RET, record_age_secs=500, legal_hold=False))

    def test_under_retention_not_purgeable(self):
        self.assertFalse(cs.worm_purge_allowed(self.RET, record_age_secs=50, legal_hold=False))

    def test_retention_unset_never_purges(self):
        self.assertFalse(cs.worm_purge_allowed(None, record_age_secs=10 ** 9, legal_hold=False))
        self.assertFalse(cs.worm_purge_allowed(0, record_age_secs=10 ** 9, legal_hold=False))

    def test_legal_hold_beats_expired_retention(self):
        # MUTATION SENTINEL: this is the fail-closed core. If the `if legal_hold: return False` line is
        # removed from worm_purge_allowed, this expired-but-held record becomes purgeable and this flips RED.
        self.assertFalse(cs.worm_purge_allowed(self.RET, record_age_secs=10 ** 9, legal_hold=True))


if __name__ == "__main__":
    unittest.main()

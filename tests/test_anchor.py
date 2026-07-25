"""Ancrage hors-host — témoin co-signataire + reconcile détecte une réécriture re-signée localement."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.ledger import Ledger, _entry_hash, GENESIS  # noqa: E402
from forge.anchor import Witness, WitnessAnchor, verify_witness_receipt, reconcile  # noqa: E402


def _resign_all(ledger):
    """Simule un host COMPROMIS (root) : recalcule TOUTE la chaîne, la re-signe avec la clé locale, ET
    réécrit le sidecar HWM pour qu'il colle à la nouvelle queue. C'est précisément le résiduel documenté :
    un attaquant root réécrit AUSSI le HWM (même host) -> verify() local (chaîne+signature+HWM) passe,
    et SEUL le témoin hors-host (reconcile) détecte la réécriture. Sans réécrire le HWM ici, le garde
    anti-troncature local attraperait déjà cette falsification — mais on modélise un root complet."""
    lines = ledger.path.read_text().splitlines()
    recs = [json.loads(l) for l in lines if l.strip()]
    prev = GENESIS
    for rec in recs:
        h = _entry_hash(prev, rec["seq"], rec["ts"], rec["kind"], rec["detail"])
        rec["prev"], rec["hash"] = prev, h
        rec["sig"] = ledger.signer.sign(h.encode())
        prev = h
    ledger.path.write_text("\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in recs) + "\n")
    hwm = Path(str(ledger.path) + ".hwm")                       # root couvre ses traces : HWM recollé sur la queue
    if hwm.exists() and recs:
        hwm.write_text(json.dumps({"seq": recs[-1]["seq"], "hash": prev, "count": recs[-1]["seq"]}))


class TestAnchor(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp(prefix="forge-anchor-")) / "l.jsonl"

    def test_witness_receipt_verifies(self):
        w = Witness()
        a = WitnessAnchor(witness=w)
        cp = {"seq": 1, "head": "ab" * 32, "ts": "2026-06-25T00:00:00"}
        r = a.anchor(cp)
        self.assertTrue(r["anchored"])
        self.assertTrue(verify_witness_receipt(cp, r))          # contre-signature valide
        r["witness_sig"] = "00" * 64
        self.assertFalse(verify_witness_receipt(cp, r))         # signature trafiquée -> invalide

    def test_checkpoint_is_anchored(self):
        w = Witness()
        led = Ledger(self.path, anchor=WitnessAnchor(witness=w))
        led.append("finding", {"t": "a"})
        rec = led.checkpoint("cp1")
        self.assertTrue(rec["detail"]["anchor"]["anchored"])
        self.assertEqual(len(w.log), 1)                         # le témoin a un record indépendant

    def test_reconcile_catches_locally_resigned_tamper(self):
        # le SCÉNARIO clé : verify() local passe, mais le témoin détecte la réécriture.
        w = Witness()
        led = Ledger(self.path, anchor=WitnessAnchor(witness=w))
        led.append("finding", {"t": "a"})
        led.append("finding", {"t": "b"})
        led.append("finding", {"t": "c"})
        led.checkpoint("cp")                                    # témoin contre-signe le head au seq=3

        # attaquant (host compromis) : réécrit l'entrée 2 et re-signe TOUTE la chaîne avec la clé locale
        lines = led.path.read_text().splitlines()
        recs = [json.loads(l) for l in lines]
        recs[1]["detail"] = {"t": "FORGED"}
        led.path.write_text("\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in recs) + "\n")
        _resign_all(led)

        self.assertTrue(Ledger(self.path, signer=led.signer).verify()["ok"])   # verify LOCAL passe (re-signé)
        rec = reconcile(w.log, led)
        self.assertFalse(rec["ok"])                                            # le TÉMOIN détecte la divergence
        self.assertEqual(rec["diverge_seq"], 3)

    def test_reconcile_ok_when_intact(self):
        w = Witness()
        led = Ledger(self.path, anchor=WitnessAnchor(witness=w))
        led.append("finding", {"t": "a"}); led.checkpoint("cp")
        self.assertTrue(reconcile(w.log, led)["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

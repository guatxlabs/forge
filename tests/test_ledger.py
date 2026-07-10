"""Preuves de tamper-evidence du ledger. `python -m unittest -v`."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.ledger import Ledger  # noqa: E402
from forge import signing  # noqa: E402


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="forge-test-"))
        self.path = self.dir / "l.jsonl"

    def _seed(self):
        led = Ledger(self.path, key=b"k" * 32)
        led.append("roe.arm", {"reason": "test"})
        led.append("roe.decision", {"verdict": "FIRE", "target": "app.test"})
        led.append("finding", {"title": "x", "severity": "HIGH"})
        return led

    def test_clean_chain_verifies(self):
        self._seed()
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertTrue(v["ok"]); self.assertEqual(v["entries"], 3)

    def test_tampered_detail_breaks(self):
        self._seed()
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[1]); rec["detail"] = {"verdict": "VETO"}    # réécrit le verdict
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertFalse(v["ok"]); self.assertEqual(v["broken"], 2)

    def test_deleted_entry_breaks_chain(self):
        self._seed()
        lines = self.path.read_text().splitlines()
        del lines[1]                                                       # supprime une entrée
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertFalse(v["ok"])

    def test_wrong_key_breaks_signature(self):
        self._seed()
        v = Ledger(self.path, key=b"WRONG" * 7).verify()                  # mauvaise clé -> signature invalide
        self.assertFalse(v["ok"]); self.assertIn("signature", v["why"])

    def test_forged_hash_breaks(self):
        self._seed()
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[2]); rec["hash"] = "f" * 64
        lines[2] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertFalse(v["ok"])

    def test_malformed_jsonl_line_returns_not_ok_without_raising(self):
        # une ligne JSONL non parsable ne doit PAS lever : verify() retourne ok=False, gracieux
        self._seed()
        lines = self.path.read_text().splitlines()
        lines[1] = "{ ceci n'est pas du JSON valide"            # corruption brute
        self.path.write_text("\n".join(lines) + "\n")
        try:
            v = Ledger(self.path, key=b"k" * 32).verify()
        except Exception as e:                                  # noqa: BLE001
            self.fail(f"verify() a levé sur une ligne malformée: {e!r}")
        self.assertFalse(v["ok"])
        self.assertIn("malformée", v["why"])

    def test_missing_required_field_returns_not_ok(self):
        # une ligne JSON valide mais sans champ requis -> ok=False, pas d'exception
        self._seed()
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[1]); del rec["hash"]             # champ requis absent
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertFalse(v["ok"])


@unittest.skipUnless(signing._HAVE_ED, "cryptography/Ed25519 indisponible")
class TestEd25519(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp(prefix="forge-ed-")) / "l.jsonl"

    def test_default_is_ed25519_and_verifies(self):
        led = Ledger(self.path)                                            # pas de key -> Ed25519 par défaut
        led.append("roe.arm", {"r": "x"}); led.append("finding", {"t": "y"})
        v = led.verify()
        self.assertTrue(v["ok"]); self.assertEqual(v["alg"], "ed25519")
        self.assertTrue(v["pub"].startswith("ed25519:"))

    def test_external_verify_with_pubkey_only(self):
        led = Ledger(self.path)
        led.append("finding", {"t": "y"})
        pub = led.public_id().split(":", 1)[1]                            # hex de la clé publique
        self.assertTrue(led.verify_external(pub)["ok"])                   # tiers : vérifie sans secret
        self.assertFalse(led.verify_external("00" * 32)["ok"])           # mauvaise clé publique -> échec

    def test_external_verify_detects_tamper(self):
        led = Ledger(self.path)
        led.append("finding", {"t": "y"}); led.append("finding", {"t": "z"})
        pub = led.public_id().split(":", 1)[1]
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[0]); rec["detail"] = {"t": "FORGED"}
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        self.assertFalse(led.verify_external(pub)["ok"])                  # altération détectée par la clé publique

    def test_external_verify_malformed_line_returns_not_ok_without_raising(self):
        # comme verify(), verify_external() ne doit PAS lever sur une ligne JSONL non parsable
        led = Ledger(self.path)
        led.append("finding", {"t": "y"}); led.append("finding", {"t": "z"})
        pub = led.public_id().split(":", 1)[1]
        lines = self.path.read_text().splitlines()
        lines[1] = "{ ceci n'est pas du JSON valide"            # corruption brute
        self.path.write_text("\n".join(lines) + "\n")
        try:
            v = led.verify_external(pub)
        except Exception as e:                                  # noqa: BLE001
            self.fail(f"verify_external() a levé sur une ligne malformée: {e!r}")
        self.assertFalse(v["ok"])
        self.assertIn("malformée", v["why"])


class TestMixedAlgs(unittest.TestCase):
    """Régression : un ledger peut mélanger des entrées signées par DEUX composants avec des algos
    DIFFÉRENTS — le moteur Python (ed25519/hmac) et la console Rust (`sha256-console`, chaîne non
    signée). verify() doit valider de bout en bout (chaîne + signature SELON `alg` de chaque entrée),
    et toujours détecter une altération. Reproduit le bug « CASSÉ ❌ » dès l'entrée sha256-console."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="forge-mixed-"))
        self.path = self.dir / "l.jsonl"

    def _append_console_entry(self, led, kind, detail):
        """Reproduit fidèlement console/src/main.rs::append_console_ledger : MÊME pré-image que
        Python (prev|seq|ts|kind|canon(detail)), alg='sha256-console', sig='' (pas de signature)."""
        from forge.ledger import _entry_hash, _canon  # noqa: E402
        prev, seq, ts = led.head, led._seq + 1, "@1234567890"
        h = _entry_hash(prev, seq, ts, kind, detail)
        rec = {"seq": seq, "ts": ts, "kind": kind, "detail": detail,
               "prev": prev, "hash": h, "alg": "sha256-console", "sig": ""}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(_canon(rec) + "\n")
        # avance la tête en mémoire pour pouvoir continuer à chaîner depuis ce Ledger
        led._head, led._seq = h, seq
        return rec

    def _seed_mixed(self, **kw):
        """ed25519 (ou hmac en repli) pour le moteur + sha256-console pour la console, dans le MÊME fichier."""
        led = Ledger(self.path, **kw)
        led.append("roe.decision", {"verdict": "FIRE", "target": "guatx.com"})   # signée par le moteur
        self._append_console_entry(led, "console.run.start", {"run_id": "r1", "campaign": "c"})  # console
        led.append("finding", {"title": "x", "severity": "HIGH"})                # signée par le moteur
        self._append_console_entry(led, "console.run.end", {"run_id": "r1", "status": "done"})   # console
        return led

    def test_mixed_algs_verify_ok_hmac(self):
        # moteur en HMAC (repli, toujours dispo) + console sha256-console -> verify ok de bout en bout
        self._seed_mixed(key=b"k" * 32)
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["entries"], 4)

    def test_mixed_algs_tampered_console_entry_detected(self):
        # altérer le detail de l'entrée console (seq 2) -> hash recalculé != stocké -> cassé à seq 2
        self._seed_mixed(key=b"k" * 32)
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[1]); rec["detail"] = {"run_id": "FORGED", "campaign": "evil"}
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertFalse(v["ok"]); self.assertEqual(v["broken"], 2)

    def test_mixed_algs_tampered_engine_entry_detected(self):
        # altérer une entrée signée par le moteur (seq 3) -> détecté
        self._seed_mixed(key=b"k" * 32)
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[2]); rec["detail"] = {"title": "x", "severity": "LOW"}
        lines[2] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertFalse(v["ok"]); self.assertEqual(v["broken"], 3)

    def test_console_entry_with_unexpected_sig_rejected(self):
        # une entrée sha256-console DOIT avoir sig vide ; une sig non vide est suspecte -> rejet (sans affaiblir)
        self._seed_mixed(key=b"k" * 32)
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[1]); rec["sig"] = "deadbeef"      # sig injectée sur un algo non signé
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertFalse(v["ok"]); self.assertEqual(v["broken"], 2)
        self.assertIn("signature", v["why"])

    @unittest.skipUnless(signing._HAVE_ED, "cryptography/Ed25519 indisponible")
    def test_mixed_algs_verify_ok_ed25519(self):
        # cas canonique du bug : keyfile .ed25519 présent -> moteur ed25519, + entrées console sha256-console.
        # Avant le fix : verify() rapportait « CASSÉ ❌ » dès l'entrée sha256-console. Après : ok.
        led = self._seed_mixed()                                 # pas de key -> ed25519 par défaut
        self.assertEqual(led.alg, "ed25519")
        v = Ledger(self.path).verify()
        self.assertTrue(v["ok"], v); self.assertEqual(v["entries"], 4)

    @unittest.skipUnless(signing._HAVE_ED, "cryptography/Ed25519 indisponible")
    def test_mixed_algs_external_verify_ok_and_detects_tamper(self):
        # verify_external (tiers, clé publique seule) accepte aussi le mélange ed25519 + sha256-console
        led = self._seed_mixed()
        pub = led.public_id().split(":", 1)[1]
        self.assertTrue(led.verify_external(pub)["ok"])
        # altération d'une entrée console -> détectée même en externe
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[1]); rec["detail"] = {"run_id": "FORGED"}
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        self.assertFalse(led.verify_external(pub)["ok"])

    @unittest.skipUnless(signing._HAVE_ED, "cryptography/Ed25519 indisponible")
    def test_mixed_algs_forged_ed25519_sig_still_detected(self):
        # NE PAS affaiblir : une signature ed25519 invalide reste détectée dans un ledger mixte
        led = self._seed_mixed()
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[0]); rec["sig"] = "00" * 64       # signature ed25519 bidon
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path).verify()
        self.assertFalse(v["ok"]); self.assertEqual(v["broken"], 1)
        self.assertIn("signature", v["why"])


class TestDowngradeAttack(unittest.TestCase):
    """RÉGRESSION sûreté HIGH — downgrade vers `sha256-console`.

    PoC : un attaquant write-access réécrit une entrée signée par le moteur (ex: roe.decision
    VETO->FIRE), pose alg='sha256-console'/sig='' et RECOMPUTE le hash. Sans garde, verify_console('')
    renvoie True + la chaîne SHA-256 recolle -> verify() rapportait ok=True (faux). Le kind-guard
    lie l'algo NON signé au kind 'console.*' : un downgrade sur un kind moteur est REFUSÉ. Le relabel
    du kind moteur en 'console.*' tout en gardant la signature ed25519/hmac est lui aussi refusé."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="forge-downgrade-"))
        self.path = self.dir / "l.jsonl"

    def _seed(self):
        led = Ledger(self.path, key=b"k" * 32)
        led.append("roe.arm", {"reason": "test"})
        led.append("roe.decision", {"verdict": "VETO", "target": "app.test"})
        led.append("finding", {"title": "x", "severity": "HIGH"})
        return led

    def _rechain_from(self, lines, start_idx):
        """Recolle la chaîne SHA-256 à partir de start_idx (comme le ferait l'attaquant)."""
        from forge.ledger import _entry_hash, _canon
        prev = json.loads(lines[start_idx - 1])["hash"] if start_idx > 0 else "0" * 64
        for i in range(start_idx, len(lines)):
            rec = json.loads(lines[i])
            rec["prev"] = prev
            rec["hash"] = _entry_hash(prev, rec["seq"], rec["ts"], rec["kind"], rec["detail"])
            lines[i] = _canon(rec)
            prev = rec["hash"]
        return lines

    def test_downgrade_engine_entry_to_console_alg_is_rejected(self):
        # cœur du PoC : VETO->FIRE + alg='sha256-console'/sig='' + recompute hash -> DOIT casser
        self._seed()
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[1])
        rec["detail"] = {"verdict": "FIRE", "target": "app.test"}   # réécriture du verdict
        rec["alg"] = "sha256-console"                                # downgrade vers chaîne non signée
        rec["sig"] = ""                                              # verify_console('') == True
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        lines = self._rechain_from(lines, 1)                         # recolle la chaîne (attaquant)
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertFalse(v["ok"], "downgrade accepté -> ledger forgeable (régression HIGH)")
        self.assertEqual(v["broken"], 2)
        self.assertIn("downgrade", v["why"])

    def test_relabel_engine_kind_to_console_with_signature_is_rejected(self):
        # relabel : on renomme un kind moteur en 'console.*' MAIS on garde l'algo signé hmac -> refus
        # (le moteur n'écrit jamais 'console.*' ; un kind console signé est forcément forgé/relabelé).
        self._seed()
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[1])
        rec["detail"] = {"verdict": "FIRE", "target": "app.test"}
        rec["kind"] = "console.run.start"                            # relabel vers un kind console
        # alg/sig RESTENT hmac-sha256 (signature moteur conservée) — mais hash recomputé pour le nouveau kind
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        # re-signer correctement le hash avec la bonne clé pour isoler le SEUL effet du kind-guard
        from forge.ledger import _entry_hash, _canon
        from forge import signing
        signer = signing.HmacSigner(b"k" * 32)
        prev = json.loads(lines[0])["hash"]
        for i in range(1, len(lines)):
            r = json.loads(lines[i])
            r["prev"] = prev
            r["hash"] = _entry_hash(prev, r["seq"], r["ts"], r["kind"], r["detail"])
            if r.get("alg") == "hmac-sha256":
                r["sig"] = signer.sign(r["hash"].encode("utf-8"))     # signature VALIDE
            lines[i] = _canon(r)
            prev = r["hash"]
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertFalse(v["ok"], "kind console avec signature moteur accepté -> relabel exploitable")
        self.assertEqual(v["broken"], 2)
        self.assertIn("interdit", v["why"])

    @unittest.skipUnless(signing._HAVE_ED, "cryptography/Ed25519 indisponible")
    def test_downgrade_rejected_in_external_verify(self):
        # même garde côté vérif EXTERNE (tiers, clé publique seule)
        led = Ledger(self.path)                                      # ed25519
        led.append("roe.decision", {"verdict": "VETO", "target": "app.test"})
        led.append("finding", {"title": "x"})
        pub = led.public_id().split(":", 1)[1]
        lines = self.path.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["detail"] = {"verdict": "FIRE", "target": "app.test"}
        rec["alg"] = "sha256-console"; rec["sig"] = ""
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        lines = self._rechain_from(lines, 0)
        self.path.write_text("\n".join(lines) + "\n")
        v = Ledger(self.path).verify_external(pub)
        self.assertFalse(v["ok"], "downgrade accepté en vérif externe")
        self.assertIn("downgrade", v["why"])

    def test_legit_console_entry_still_ok(self):
        # NE PAS affaiblir : une VRAIE entrée console (kind 'console.*', sha256-console, sig='') reste valide
        from forge.ledger import _entry_hash, _canon
        led = Ledger(self.path, key=b"k" * 32)
        led.append("roe.arm", {"reason": "test"})
        prev, seq, ts = led.head, led._seq + 1, "@1"
        detail = {"run_id": "r1"}
        h = _entry_hash(prev, seq, ts, "console.run.start", detail)
        rec = {"seq": seq, "ts": ts, "kind": "console.run.start", "detail": detail,
               "prev": prev, "hash": h, "alg": "sha256-console", "sig": ""}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(_canon(rec) + "\n")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["entries"], 2)

    def test_append_rereads_tail_chains_onto_external_writer(self):
        # Deux instances Ledger sur le MÊME fichier (simule console Rust + moteur Python, même clé HMAC).
        # `b` a un _head PÉRIMÉ (il n'a pas vu l'entrée de `a`) : son append DOIT relire la queue disque
        # SOUS le verrou et chaîner sur l'entrée de `a`, au lieu de l'écraser (prev==GENESIS aurait forké).
        a = Ledger(self.path, key=b"k" * 32)
        b = Ledger(self.path, key=b"k" * 32)
        a.append("roe.arm", {"n": 1})            # seq 1
        rec = b.append("roe.decision", {"n": 2})
        self.assertEqual(rec["seq"], 2, "seq contigu malgré un _head mémoire périmé")
        self.assertEqual(rec["prev"], a.head, "chaîné sur l'entrée du writer concurrent (re-read tail)")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["entries"], 2)

    def test_append_after_truncated_last_line_chains_onto_last_valid(self):
        # Un crash en plein write laisse une dernière ligne TRONQUÉE (sans '\n'). L'append suivant DOIT :
        # relire la queue en ignorant la ligne corrompue, chaîner sur la dernière entrée VALIDE, et écrire
        # sur une NOUVELLE ligne (pas collée à la corrompue -> sinon la nouvelle serait perdue).
        led = Ledger(self.path, key=b"k" * 32)
        r1 = led.append("roe.arm", {"n": 1})                       # seq 1, valide
        with self.path.open("a", encoding="utf-8") as f:
            f.write('{"seq": 2, "ts": "@x", "kin')                 # JSON tronqué, PAS de newline
        led2 = Ledger(self.path, key=b"k" * 32)                    # comme un autre processus
        r_new = led2.append("roe.decision", {"n": 3})
        self.assertEqual(r_new["prev"], r1["hash"], "chaîné sur la dernière entrée VALIDE (r1)")
        self.assertEqual(r_new["seq"], 2, "seq = dernier seq valide + 1 (ligne tronquée ignorée)")
        lines = [ln for ln in self.path.read_text().splitlines() if ln.strip()]
        last = json.loads(lines[-1])                               # ne doit PAS lever (ligne propre)
        self.assertEqual(last["hash"], r_new["hash"], "la nouvelle entrée est sur sa propre ligne")

    def test_concurrent_threaded_appends_keep_chain_verifiable(self):
        # Deux threads, chacun sa propre instance Ledger, appendent en parallèle sur le MÊME chemin.
        # Le flock+re-read-tail garantit une chaîne CONTIGUË et VÉRIFIABLE (sans le verrou, les deux
        # partiraient de leur _head mémoire et forkeraient la chaîne : seq dupliqués, verify() cassé).
        import threading
        n_each = 25
        errors = []

        def worker():
            try:
                led = Ledger(self.path, key=b"k" * 32)
                for i in range(n_each):
                    led.append("roe.decision", {"i": i})
            except Exception as e:  # noqa: BLE001 — remonter l'échec du thread au test
                errors.append(e)

        t1, t2 = threading.Thread(target=worker), threading.Thread(target=worker)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(errors, [], f"un thread a échoué (deadlock/exception ?) : {errors}")
        v = Ledger(self.path, key=b"k" * 32).verify()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["entries"], 2 * n_each, "aucune entrée perdue ni écrasée")
        seqs = [json.loads(l)["seq"] for l in self.path.read_text().splitlines() if l.strip()]
        self.assertEqual(seqs, list(range(1, 2 * n_each + 1)), "seq strictement contigus 1..N")


if __name__ == "__main__":
    unittest.main(verbosity=2)

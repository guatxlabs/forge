"""Tests des sous-commandes CLI ajoutées : `doctor --purple` (préflight boucle purple) et
`ledger pubkey` / `ledger keygen`.

Zéro réseau réel : le préflight vise un port loopback fermé (127.0.0.1:1) ; il DOIT dégrader
gracieusement (lignes FAIL/N/A, aucune exception) et sortir non-zéro. Les tests ledger vérifient
que `pubkey` imprime bien 64 hex et que la clé imprimée valide le ledger en vérif externe.
"""
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import cli               # noqa: E402
from forge import signing           # noqa: E402
from forge.ledger import Ledger     # noqa: E402

# Cible garantie injoignable : rien n'écoute sur le port loopback 1 -> connexion refusée immédiate.
UNREACHABLE = "http://127.0.0.1:1"
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class _Args:
    """Stand-in argparse.Namespace : on n'expose que les attributs lus par la commande visée."""
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _capture(fn, args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = fn(args)
    return rc, buf.getvalue()


class TestDoctorPurple(unittest.TestCase):
    def _run(self, env, **argkw):
        args = _Args(purple=True, json=argkw.pop("json", False), timeout=2.0, **argkw)
        with mock.patch.dict(os.environ, env, clear=False):
            # les clés absentes de `env` mais présentes dans l'environnement réel sont neutralisées
            for k in ("FORGE_CONSOLE_URL", "PLUME_URL", "PLUME_TOKEN"):
                if k not in env:
                    os.environ.pop(k, None)
            return _capture(cli.cmd_doctor, args)

    def test_unreachable_deps_fail_without_crashing(self):
        # console ET plume injoignables -> aucune exception, lignes FAIL, sortie non-zéro.
        try:
            rc, out = self._run({"FORGE_CONSOLE_URL": UNREACHABLE,
                                 "PLUME_URL": UNREACHABLE, "PLUME_TOKEN": ""})
        except Exception as e:  # noqa: BLE001
            self.fail(f"doctor --purple a levé sur une cible injoignable: {e!r}")
        self.assertEqual(rc, 1)
        self.assertIn("FAIL", out)
        self.assertIn("console-reachable", out)
        self.assertIn("plume-reachable", out)
        # les contrôles dépendants de Plume dégradent en N/A (jamais fabriqués vert).
        self.assertIn("N/A", out)
        self.assertIn("auth-ok", out)

    def test_plume_url_unset_reports_not_configured(self):
        rc, out = self._run({"FORGE_CONSOLE_URL": UNREACHABLE})   # PLUME_URL absent
        self.assertEqual(rc, 1)
        self.assertIn("PLUME_URL non configuré", out)
        # console injoignable -> FAIL également (critique).
        self.assertIn("console-reachable", out)

    def test_json_output_shape(self):
        rc, out = self._run({"FORGE_CONSOLE_URL": UNREACHABLE, "PLUME_URL": UNREACHABLE,
                             "PLUME_TOKEN": ""}, json=True)
        self.assertEqual(rc, 1)
        import json as _json
        payload = _json.loads(out)
        self.assertFalse(payload["ok"])
        labels = {c["check"] for c in payload["checks"]}
        for expected in ("console-reachable", "plume-reachable", "auth-ok",
                         "detections-returned", "mitre-tagged"):
            self.assertIn(expected, labels)

    def test_detections_parsing_helpers(self):
        # forme nominale {"detections":[...]} + tableau nu, et comptage des tags MITRE.
        self.assertEqual(len(cli._parse_detections('{"detections":[{"mitre":"T1190"}]}')), 1)
        self.assertEqual(len(cli._parse_detections('[{"technique":"T1046"}]')), 1)
        self.assertIsNone(cli._parse_detections("pas du json"))
        dets = [{"mitre": "T1190"}, {"technique": "T1059.001"}, {"mitre": "sans-tag"}, {}]
        self.assertEqual(cli._count_mitre_tagged(dets), 2)


@unittest.skipUnless(signing._HAVE_ED, "Ed25519 requis (cryptography absent -> repli HMAC)")
class TestLedgerPubkey(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="forge-pubkey-"))
        self.path = self.dir / "l.jsonl"

    def _sign_ledger(self):
        led = Ledger(self.path)                       # signeur Ed25519 par défaut (make_signer)
        led.append("roe.arm", {"reason": "test"})
        led.append("finding", {"title": "x", "severity": "HIGH"})
        return led

    def test_pubkey_prints_64_hex_and_alg(self):
        self._sign_ledger()
        rc, out = _capture(cli.cmd_ledger_pubkey, _Args(ledger=str(self.path)))
        self.assertEqual(rc, 0)
        lines = out.strip().splitlines()
        self.assertTrue(HEX64.match(lines[0].strip()), f"1re ligne pas 64-hex: {lines[0]!r}")
        self.assertTrue(any(l.startswith("# alg=ed25519") for l in lines), out)

    def test_printed_pubkey_verifies_ledger_externally(self):
        # la clé imprimée DOIT valider le ledger en vérif externe (non-répudiation, sans secret).
        self._sign_ledger()
        _, out = _capture(cli.cmd_ledger_pubkey, _Args(ledger=str(self.path)))
        hexkey = out.strip().splitlines()[0].strip()
        v = Ledger(self.path).verify_external(hexkey)
        self.assertTrue(v["ok"], v)

    def test_pubkey_stable_across_calls(self):
        self._sign_ledger()
        _, a = _capture(cli.cmd_ledger_pubkey, _Args(ledger=str(self.path)))
        _, b = _capture(cli.cmd_ledger_pubkey, _Args(ledger=str(self.path)))
        self.assertEqual(a.strip().splitlines()[0], b.strip().splitlines()[0])

    def test_pubkey_hmac_fallback_returns_nonzero(self):
        # sans Ed25519 (repli HMAC) : pas de clé publique asymétrique -> sortie non-zéro + note.
        with mock.patch.object(signing, "_HAVE_ED", False):
            rc, out = _capture(cli.cmd_ledger_pubkey, _Args(ledger=str(self.path)))
        self.assertEqual(rc, 1)
        self.assertIn("pas de clé publique Ed25519", out)


@unittest.skipUnless(signing._HAVE_ED, "Ed25519 requis (cryptography absent -> repli HMAC)")
class TestLedgerKeygen(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="forge-keygen-"))
        self.path = self.dir / "l.jsonl"
        self.kp = Path(str(self.path) + ".ed25519")

    def test_keygen_creates_key_and_prints_pubkey(self):
        rc, out = _capture(cli.cmd_ledger_keygen, _Args(ledger=str(self.path), force=False))
        self.assertEqual(rc, 0)
        self.assertTrue(HEX64.match(out.strip().splitlines()[0].strip()))
        self.assertTrue(self.kp.exists())

    def test_keygen_refuses_overwrite_without_force(self):
        _capture(cli.cmd_ledger_keygen, _Args(ledger=str(self.path), force=False))
        before = self.kp.read_bytes()
        rc, out = _capture(cli.cmd_ledger_keygen, _Args(ledger=str(self.path), force=False))
        self.assertEqual(rc, 1)
        self.assertIn("--force", out)
        self.assertEqual(before, self.kp.read_bytes())   # clé INCHANGÉE (pas de rotation silencieuse)

    def test_keygen_force_rotates_key(self):
        _, out1 = _capture(cli.cmd_ledger_keygen, _Args(ledger=str(self.path), force=False))
        _, out2 = _capture(cli.cmd_ledger_keygen, _Args(ledger=str(self.path), force=True))
        self.assertNotEqual(out1.strip().splitlines()[0], out2.strip().splitlines()[0])

    def test_keygen_key_is_used_by_pubkey_and_verify(self):
        # keygen puis signature : la clé générée signe bien le ledger et pubkey la retrouve.
        _, kg = _capture(cli.cmd_ledger_keygen, _Args(ledger=str(self.path), force=False))
        gen = kg.strip().splitlines()[0].strip()
        led = Ledger(self.path); led.append("finding", {"title": "y"})
        _, pk = _capture(cli.cmd_ledger_pubkey, _Args(ledger=str(self.path)))
        self.assertEqual(gen, pk.strip().splitlines()[0].strip())
        self.assertTrue(Ledger(self.path).verify()["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

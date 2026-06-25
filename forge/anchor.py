"""Ancrage hors-host du ledger — interface `Anchor` + témoin (witness) co-signataire.

POURQUOI : la clé privée du ledger vit sur le host Forge. Un attaquant qui root ce host obtient
la clé → il peut réécrire l'histoire ET la re-signer ; `verify()` local passerait. L'ancrage fait
constater l'état du ledger par quelque chose que le host ne peut pas réécrire après coup.

L'INTERFACE : `Anchor.anchor(checkpoint)` prend un checkpoint `{seq, head, ts}` et le fait ancrer.
  - `NullAnchor`     : no-op (défaut).
  - `WitnessAnchor`  : envoie le checkpoint à un TÉMOIN (clé distincte, autre host) qui CONTRE-SIGNE
                       `(seq|head|ts)` et tient son propre journal append-only. Forger l'histoire =>
                       compromettre Forge ET le témoin. Niveau recommandé pour solo/petite équipe.

Le témoin distant serait joint en HTTP ; `Witness` fournit la logique serveur (in-process pour les
tests, ou derrière HTTP plus tard). `reconcile()` est la clé : il recalcule les heads du ledger
depuis la genèse et les compare à ceux contre-signés par le témoin → détecte une réécriture du passé
même re-signée localement. Ed25519 via signing.py.
"""
from . import signing


class Anchor:
    def anchor(self, checkpoint: dict) -> dict:
        raise NotImplementedError


class NullAnchor(Anchor):
    def anchor(self, checkpoint):
        return {"anchored": False}


class Witness:
    """Côté témoin : clé Ed25519 distincte + journal append-only des heads contre-signés."""

    def __init__(self, signer=None):
        self.signer = signer or signing.ephemeral_signer()
        self.log = []        # [{seq, head, ts, sig}] — record indépendant des heads vus

    @staticmethod
    def _msg(seq, head, ts):
        return f"{seq}|{head}|{ts}".encode("utf-8")

    def cosign(self, seq, head, ts):
        sig = self.signer.sign(self._msg(seq, head, ts))
        self.log.append({"seq": seq, "head": head, "ts": ts, "sig": sig})
        return {"witness_pub": self.signer.public_id(), "witness_sig": sig, "witness_ts": ts}

    def pub(self):
        return self.signer.public_id()


class WitnessAnchor(Anchor):
    """Côté Forge : envoie le checkpoint au témoin (objet in-process OU URL HTTP) et stocke le reçu."""

    def __init__(self, witness=None, url=None):
        self.witness = witness   # objet Witness (in-process)
        self.url = url           # ou endpoint HTTP d'un témoin distant

    def anchor(self, checkpoint):
        seq, head, ts = checkpoint["seq"], checkpoint["head"], checkpoint["ts"]
        if self.witness is not None:
            receipt = self.witness.cosign(seq, head, ts)
        elif self.url:
            receipt = self._http(seq, head, ts)
        else:
            return {"anchored": False}
        receipt["anchored"] = True
        return receipt

    def _http(self, seq, head, ts):
        import json
        import urllib.request
        data = json.dumps({"seq": seq, "head": head, "ts": ts}).encode("utf-8")
        req = urllib.request.Request(self.url.rstrip("/") + "/cosign", data=data,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8"))


def verify_witness_receipt(checkpoint, receipt):
    """Vérifie la contre-signature du témoin sur (seq|head|ts) avec sa clé publique (Ed25519)."""
    pub = receipt.get("witness_pub", "")
    if not pub.startswith("ed25519:"):
        return False
    msg = Witness._msg(checkpoint["seq"], checkpoint["head"], checkpoint["ts"])
    return signing.verify_with_pubkey(pub.split(":", 1)[1], msg, receipt.get("witness_sig", ""))


def reconcile(witness_log, ledger):
    """Recalcule les heads du ledger depuis la genèse et les compare aux heads contre-signés.

    Détecte une réécriture du passé MÊME re-signée localement (host compromis) : le head recalculé
    à un seq donné diffère de celui que le témoin a contre-signé à l'époque.
    """
    import json
    from .ledger import _entry_hash, GENESIS

    heads, prev = {}, GENESIS
    for raw in ledger.path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        rec = json.loads(raw)
        h = _entry_hash(prev, rec["seq"], rec["ts"], rec["kind"], rec["detail"])
        heads[rec["seq"]] = h        # head après cette entrée = son hash recalculé
        prev = h                      # chaîne sur le hash RECALCULÉ (pas le stocké)

    for w in witness_log:
        if heads.get(w["seq"]) != w["head"]:
            return {"ok": False, "diverge_seq": w["seq"],
                    "why": "head recalculé != head contre-signé par le témoin (réécriture détectée)"}
    return {"ok": True, "checked": len(witness_log)}

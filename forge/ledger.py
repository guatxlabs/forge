"""Ledger d'engagement append-time, tamper-evident — la preuve ROE de Forge.

Chaque acte (décision ROE, armement, approbation, finding, run-record) est chaîné :

    hash_n = SHA256( hash_{n-1} || seq || ts || kind || canonical_json(detail) )

et SIGNÉ à l'append : `sig_n = sign(hash_n)`. Par défaut signature **Ed25519** (asymétrique →
non-répudiation : un vérificateur externe valide avec la seule clé publique, sans pouvoir forger) ;
repli **HMAC** si `cryptography` est absent (voir signing.py). Les deux corrigent les deux
faiblesses du ledger de Plume relevées à l'analyse :
  - COUVERTURE : ici TOUTES les entrées sont chaînées (Plume ne chaînait que ~8 types admin).
  - ENTRE-CHECKPOINTS : la signature est PAR-ENTRÉE (Plume ne signait qu'au checkpoint).

`verify()` recalcule la chaîne + vérifie chaque hash + chaque signature, et rapporte la PREMIÈRE
entrée cassée. `verify_external(pubkey_hex)` permet à un tiers de vérifier sans aucun secret (Ed25519).

MULTI-ALGOS : un MÊME ledger peut mélanger des entrées d'algos différents — le moteur Python signe
en `ed25519` (ou `hmac-sha256` en repli), tandis que la console Rust écrit ses entrées
`console.run.start`/`.end` en `sha256-console` (chaîne SHA-256 NON signée, `sig: ""`). `verify()` est
donc ALG-AWARE : chaque entrée est vérifiée SELON SON PROPRE `alg` (cf. signing.verify_entry) — la
chaîne de hachage est toujours recalculée pour TOUTES, et `sha256-console` est traité comme « chaîne
vérifiée, signature non-applicable » (intégrité garantie par le hash-chaining, pas de secret). Une
altération de contenu/hash ou une signature ed25519 invalide reste TOUJOURS détectée.

Format disque : JSONL (1 entrée/ligne, champs incl. `sig` + `alg`). Core stdlib (signing.py gère la dep).
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import signing

GENESIS = "0" * 64
# Les entrées de la console Rust (chaîne SHA-256 NON signée, alg=sha256-console) portent toujours un
# kind 'console.*' (cf. console/src/main.rs::append_console_ledger -> console.run.start/.end). Le moteur
# Python n'émet JAMAIS de kind 'console.*'. Cet invariant structurel borne où l'algo non signé est légitime.
CONSOLE_KIND_PREFIX = "console."


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _alg_kind_allowed(alg, kind):
    """Garde structurel anti-downgrade : l'algo NON signé `sha256-console` n'est légitime QUE sur une
    entrée console (kind 'console.*'). Tout autre algo (ed25519/hmac) est interdit sur un kind console
    (le moteur n'écrit jamais ces kinds -> une entrée console signée est forcément forgée/relabelée).
    Cette liaison alg<->kind ferme à la fois le downgrade (entrée moteur -> sha256-console) ET le
    relabel (entrée moteur signée dont on change le kind en 'console.*' pour la faire passer non signée)."""
    is_console_kind = isinstance(kind, str) and kind.startswith(CONSOLE_KIND_PREFIX)
    if alg == signing.CONSOLE_ALG:
        return is_console_kind            # sha256-console interdit hors kind console
    return not is_console_kind            # algos signés interdits sur un kind console


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _entry_hash(prev, seq, ts, kind, detail):
    h = hashlib.sha256()
    h.update(f"{prev}|{seq}|{ts}|{kind}|{_canon(detail)}".encode("utf-8"))
    return h.hexdigest()


class Ledger:
    def __init__(self, path, key=None, signer=None, prefer_ed25519=True, anchor=None):
        self.path = Path(path)
        if signer is not None:
            self.signer = signer
        elif key is not None:                       # rétro-compat : clé fournie => HMAC
            self.signer = signing.HmacSigner(key)
        else:
            self.signer = signing.make_signer(self.path, prefer_ed25519=prefer_ed25519)
        self.alg = self.signer.alg
        self.anchor = anchor                        # anchor.Anchor | None — ancrage hors-host
        self._head = GENESIS
        self._seq = 0
        if self.path.exists():
            self._restore_head()

    def _restore_head(self):
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                head, seq = rec["hash"], rec["seq"]
            except (ValueError, KeyError, TypeError):
                continue                            # ligne corrompue : on garde le dernier head valide
            self._head, self._seq = head, seq

    # --- append (le seul moyen d'écrire) ---
    def append(self, kind, detail):
        seq = self._seq + 1
        ts = _now()
        h = _entry_hash(self._head, seq, ts, kind, detail)
        sig = self.signer.sign(h.encode("utf-8"))
        rec = {"seq": seq, "ts": ts, "kind": kind, "detail": detail,
               "prev": self._head, "hash": h, "alg": self.signer.alg, "sig": sig}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(_canon(rec) + "\n")
        self._head, self._seq = h, seq
        return rec

    def checkpoint(self, note=""):
        cp = {"seq": self._seq, "head": self._head, "ts": _now()}
        receipt = self.anchor.anchor(cp) if self.anchor is not None else {"anchored": False}
        return self.append("ledger.checkpoint",
                           {"note": note, "head": self._head, "seq": self._seq,
                            "pub": self.signer.public_id(), "anchor": receipt})

    # --- verify : recalcul intégral depuis la genèse (avec le signeur local) ---
    def verify(self):
        if not self.path.exists():
            return {"ok": True, "entries": 0, "broken": None, "alg": self.alg}
        prev = GENESIS
        n = 0
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            n += 1
            try:
                rec = json.loads(raw)
                seq, ts, kind, detail = rec["seq"], rec["ts"], rec["kind"], rec["detail"]
            except (ValueError, KeyError, TypeError) as e:
                return {"ok": False, "entries": n, "broken": None, "why": f"entrée malformée: {e}", "alg": self.alg}
            if rec.get("prev") != prev:
                return {"ok": False, "entries": n, "broken": seq, "why": "chaînage rompu (prev)", "alg": self.alg}
            h = _entry_hash(prev, seq, ts, kind, detail)
            if h != rec.get("hash"):
                return {"ok": False, "entries": n, "broken": seq, "why": "hash recalculé != hash stocké (entrée altérée)", "alg": self.alg}
            # vérif signature ALG-AWARE : chaque entrée est validée selon SON PROPRE `alg`
            # (ed25519/hmac via le signeur local ; sha256-console = chaîne déjà vérifiée, sig non-applicable).
            # Un ledger multi-algos (console Rust sha256-console + moteur ed25519) est ainsi validé de bout en bout.
            entry_alg = rec.get("alg")
            # KIND-GUARD anti-downgrade (sûreté HIGH) : `sha256-console` = chaîne NON signée, n'est
            # légitime QUE pour les entrées écrites par la console (kind 'console.*'). Sans ce garde, un
            # attaquant write-access réécrit une entrée moteur (ex: roe.decision VETO->FIRE), pose
            # alg='sha256-console'/sig='' et recompute le hash : verify_console('')=True -> verify() ok.
            # On REFUSE donc `sha256-console` sur tout kind non-console AVANT verify_entry (fail-closed).
            if not _alg_kind_allowed(entry_alg, kind):
                return {"ok": False, "entries": n, "broken": seq,
                        "why": f"algo '{entry_alg}' interdit pour kind '{kind}' (downgrade refusé)", "alg": self.alg}
            if not signing.verify_entry(entry_alg, self.signer, h.encode("utf-8"), rec.get("sig", "")):
                return {"ok": False, "entries": n, "broken": seq, "why": f"signature invalide ({entry_alg or '?'})", "alg": self.alg}
            prev = rec["hash"]
        return {"ok": True, "entries": n, "broken": None, "head": prev, "alg": self.alg, "pub": self.signer.public_id()}

    # --- verify EXTERNE : un tiers vérifie avec la seule clé publique Ed25519 (non-répudiation) ---
    def verify_external(self, pubkey_hex):
        if not self.path.exists():
            return {"ok": True, "entries": 0}
        prev = GENESIS
        n = 0
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            n += 1
            try:
                rec = json.loads(raw)
                seq, ts, kind, detail = rec["seq"], rec["ts"], rec["kind"], rec["detail"]
            except (ValueError, KeyError, TypeError) as e:
                return {"ok": False, "entries": n, "broken": None, "why": f"entrée malformée: {e}"}
            entry_alg = rec.get("alg")
            # multi-algos : ed25519 -> vérif par la clé publique (non-répudiation) ;
            # sha256-console -> chaîne non signée écrite par la console, intégrité = chaîne de hachage
            # (vérifiée juste après) -> signature non-applicable. Tout autre algo (ex: hmac) n'est PAS
            # vérifiable par un tiers sans secret -> refus explicite.
            if entry_alg not in ("ed25519", signing.CONSOLE_ALG):
                return {"ok": False, "entries": n, "broken": seq, "why": f"algo non vérifiable en externe ({entry_alg or '?'})"}
            # KIND-GUARD anti-downgrade (même protection qu'en interne) : `sha256-console` (chaîne non
            # signée) n'est légitime que pour les entrées console (kind 'console.*'). Sinon un attaquant
            # downgrade une entrée ed25519 vers sha256-console/sig='' et la sortirait sans signature.
            if not _alg_kind_allowed(entry_alg, kind):
                return {"ok": False, "entries": n, "broken": seq,
                        "why": f"algo '{entry_alg}' interdit pour kind '{kind}' (downgrade refusé)"}
            if rec.get("prev") != prev:
                return {"ok": False, "entries": n, "broken": seq, "why": "chaînage rompu"}
            h = _entry_hash(prev, seq, ts, kind, detail)
            if h != rec.get("hash"):
                return {"ok": False, "entries": n, "broken": seq, "why": "hash ou signature invalide"}
            if entry_alg == "ed25519" and not signing.verify_with_pubkey(pubkey_hex, h.encode("utf-8"), rec.get("sig", "")):
                return {"ok": False, "entries": n, "broken": seq, "why": "hash ou signature invalide"}
            if entry_alg == signing.CONSOLE_ALG and not signing.verify_console(rec.get("sig", "")):
                return {"ok": False, "entries": n, "broken": seq, "why": "hash ou signature invalide"}
            prev = rec["hash"]
        return {"ok": True, "entries": n, "broken": None}

    @property
    def head(self):
        return self._head

    def public_id(self):
        return self.signer.public_id()

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

ANTI-TRONCATURE (défense-en-profondeur, F4) : chaîner genesis->queue ne détecte PAS un DROP de la
queue (une chaîne plus courte reste « valide » ; `_disk_tail` tolère même une dernière ligne
corrompue). On persiste donc un HIGH-WATER-MARK (HWM) dans un sidecar `<ledger>.hwm` = {seq, hash,
count} de la dernière entrée, écrit + fsync SOUS LE MÊME verrou flock que l'append (il ne peut donc
pas retarder). `verify()`/`verify_external()` recoupent la queue disque contre le HWM : queue seq <
HWM seq (ou hash HWM absent de la chaîne) => TRONCATURE. HONNÊTETÉ du modèle de menace : le HWM relève
la barre contre une troncature ACCIDENTELLE et un falsificateur NON-root/naïf, mais un attaquant ROOT
réécrit AUSSI le HWM — la protection complète reste l'ANCRAGE HORS-HOST (signer distant +
WitnessAnchor/reconcile, cf. anchor.py), opt-in.

MULTI-ALGOS : un MÊME ledger peut mélanger des entrées d'algos différents — le moteur Python signe
en `ed25519` (ou `hmac-sha256` en repli), tandis que la console Rust écrit ses entrées
`console.run.start`/`.end` en `sha256-console` (chaîne SHA-256 NON signée, `sig: ""`). `verify()` est
donc ALG-AWARE : chaque entrée est vérifiée SELON SON PROPRE `alg` (cf. signing.verify_entry) — la
chaîne de hachage est toujours recalculée pour TOUTES, et `sha256-console` est traité comme « chaîne
vérifiée, signature non-applicable » (intégrité garantie par le hash-chaining, pas de secret). Une
altération de contenu/hash ou une signature ed25519 invalide reste TOUJOURS détectée.

Format disque : JSONL (1 entrée/ligne, champs incl. `sig` + `alg`). Core stdlib (signing.py gère la dep).

CONCURRENCE : le même fichier étant écrit par la console Rust ET le moteur Python, `append()` est
SÉRIALISÉ ENTRE PROCESSUS par un verrou consultatif exclusif `fcntl.flock(LOCK_EX)` (POSIX) et rendu
DURABLE par `flush()+os.fsync()` avant relâche du verrou. Sous le verrou, la queue réelle du disque est
RELUE pour chaîner sur une écriture concurrente (jamais l'écraser). Sur non-POSIX (Windows) `fcntl` est
absent -> repli sans verrou (sûr uniquement en écrivain unique, cf. import défensif plus bas).
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import signing

if TYPE_CHECKING:                                         # imports paresseux (type-checking uniquement)
    from .anchor import Anchor

# POSIX advisory file locking. On Windows `fcntl` is unavailable — we import it DEFENSIVELY and fall
# back to the historical (no-lock) behavior. CAVEAT (non-POSIX only): without flock, two processes
# appending to the SAME ledger concurrently can still fork the hash-chain — cross-process serialization
# requires POSIX flock. On Linux (the deployment target) the lock+fsync path below always runs.
try:
    import fcntl
except ImportError:  # pragma: no cover — non-POSIX (Windows) fallback
    fcntl = None  # type: ignore[assignment]  # idiome import-optionnel : sentinelle testée par `is not None`

GENESIS = "0" * 64
# Les entrées de la console Rust (chaîne SHA-256 NON signée, alg=sha256-console) portent toujours un
# kind 'console.*' (cf. console/src/main.rs::append_console_ledger -> console.run.start/.end). Le moteur
# Python n'émet JAMAIS de kind 'console.*'. Cet invariant structurel borne où l'algo non signé est légitime.
CONSOLE_KIND_PREFIX = "console."


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _alg_kind_allowed(alg: Any, kind: Any) -> bool:
    """Garde structurel anti-downgrade : l'algo NON signé `sha256-console` n'est légitime QUE sur une
    entrée console (kind 'console.*'). Tout autre algo (ed25519/hmac) est interdit sur un kind console
    (le moteur n'écrit jamais ces kinds -> une entrée console signée est forcément forgée/relabelée).
    Cette liaison alg<->kind ferme à la fois le downgrade (entrée moteur -> sha256-console) ET le
    relabel (entrée moteur signée dont on change le kind en 'console.*' pour la faire passer non signée)."""
    is_console_kind = isinstance(kind, str) and kind.startswith(CONSOLE_KIND_PREFIX)
    if alg == signing.CONSOLE_ALG:
        return is_console_kind            # sha256-console interdit hors kind console
    return not is_console_kind            # algos signés interdits sur un kind console


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _entry_hash(prev: str, seq: int, ts: str, kind: str, detail: Any) -> str:
    h = hashlib.sha256()
    h.update(f"{prev}|{seq}|{ts}|{kind}|{_canon(detail)}".encode("utf-8"))
    return h.hexdigest()


class Ledger:
    def __init__(self, path: str | Path, key: bytes | None = None,
                 signer: "signing.Signer | None" = None, prefer_ed25519: bool = True,
                 anchor: "Anchor | None" = None,
                 signer_config: dict[str, Any] | None = None) -> None:
        self.path = Path(path)
        if signer is not None:
            self.signer = signer
        elif key is not None:                       # rétro-compat : clé fournie => HMAC
            self.signer = signing.HmacSigner(key)
        else:
            # PLUGGABLE signer seam (E3): default = LocalFileSigner (community, byte-identical) ; an operator
            # may select a remote KMS/HSM/exec signer via `signer_config` or env (flag-gated). With no config
            # and no env the returned signer is exactly today's local Ed25519/HMAC — nothing changes.
            self.signer = signing.make_ledger_signer(
                self.path, prefer_ed25519=prefer_ed25519, config=signer_config)
        self.alg = self.signer.alg
        self.anchor = anchor                        # anchor.Anchor | None — ancrage hors-host
        self._head = GENESIS
        self._seq = 0
        if self.path.exists():
            self._restore_head()

    def _restore_head(self) -> None:
        self._head, self._seq = self._disk_tail()

    def _disk_tail(self) -> tuple[str, int]:
        """Renvoie (hash, seq) de la DERNIÈRE entrée VALIDE sur disque, ou (GENESIS, 0) si le ledger est
        vide/absent. Une dernière ligne CORROMPUE ou TRONQUÉE (crash en plein write) est ignorée — on
        chaîne alors sur la dernière entrée valide. Doit être appelé sous le verrou fichier (append
        re-lit la queue ici pour chaîner sur une écriture concurrente au lieu de l'écraser)."""
        head, seq = GENESIS, 0
        try:
            data = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return head, seq
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                head, seq = rec["hash"], rec["seq"]
            except (ValueError, KeyError, TypeError):
                continue                            # ligne corrompue/tronquée : dernier head valide gardé
        return head, seq

    # --- HIGH-WATER-MARK (HWM) : défense-en-profondeur anti-TRONCATURE -------------------------------
    # GAP fermé ici (audit F4) : sans repère externe, `verify()` chaîne genesis->queue SANS longueur
    # attendue, et `_disk_tail` TOLÈRE une dernière ligne corrompue -> un DROP de la queue produit une
    # chaîne plus courte mais toujours « valide ». Le HWM sidecar `<ledger>.hwm` persiste {seq, hash,
    # count} de la dernière entrée ; il est écrit + fsync SOUS LE MÊME verrou flock que l'append (donc
    # il ne peut pas retarder la queue). MODÈLE DE MENACE (sans sur-promesse) : relève la barre contre
    # une troncature ACCIDENTELLE (crash/copie partielle) et un falsificateur NON-root/naïf (write au
    # seul ledger, HWM oublié) ; NE protège PAS d'un ROOT du host (il réécrit aussi le HWM). Protection
    # complète = ancrage hors-host (RemoteSigner + WitnessAnchor/reconcile, cf. anchor.py), opt-in.
    @property
    def _hwm_path(self) -> Path:
        return Path(str(self.path) + ".hwm")

    def _write_hwm(self, seq: int, h: str) -> None:
        """Persiste le repère de queue {seq, hash, count} de façon ATOMIQUE (rename) + DURABLE (fsync).
        Appelé SOUS le verrou flock, APRÈS le fsync du ledger, pour que le HWM ne retarde pas la queue :
        en régime normal queue == HWM ; queue AU-DELÀ du HWM seulement sur crash ENTRE les deux fsync
        (traité comme PLANCHER en vérif, pas égalité). Best-effort : une I/O HWM qui échoue ne DOIT PAS
        faire échouer un append déjà durable — le prochain append recrée le HWM ; un HWM manquant/périmé
        = check de troncature simplement sauté/planché (jamais un faux positif)."""
        tmp = Path(str(self._hwm_path) + ".tmp")
        payload = _canon({"seq": seq, "hash": h, "count": seq})   # count == seq (seqs contigus 1..N)
        try:
            with tmp.open("w", encoding="utf-8") as hf:
                hf.write(payload)
                hf.flush()
                os.fsync(hf.fileno())
            os.replace(tmp, self._hwm_path)                       # rename atomique (POSIX)
        except OSError:                                           # HWM best-effort : ne casse pas l'append
            try:
                tmp.unlink(missing_ok=True)                       # py>=3.8
            except OSError:
                pass

    def _read_hwm(self) -> "dict[str, Any] | None":
        """Lit le sidecar HWM. Absent (1er run / ledger LEGACY) ou corrompu -> None : le check de
        troncature est alors SAUTÉ (on ne casse JAMAIS un ledger existant dépourvu de HWM)."""
        try:
            raw = self._hwm_path.read_text(encoding="utf-8")
        except OSError:                                           # FileNotFoundError inclus
            return None
        try:
            rec = json.loads(raw)
        except ValueError:
            return None
        return rec if isinstance(rec, dict) else None

    def _hwm_truncation_reason(self, hwm: "dict[str, Any]", tail_seq: int,
                               seen_hashes: "set[str]") -> "str | None":
        """Raison de TRONCATURE si la queue disque est EN-DEÇÀ du HWM, sinon None. Le HWM est un
        PLANCHER : une queue AU-DELÀ (crash entre les deux fsync) est TOLÉRÉE tant que le hash du HWM
        est présent dans la chaîne recalculée. HWM malformé -> None (skip, rétro-compat)."""
        hwm_seq, hwm_hash = hwm.get("seq"), hwm.get("hash")
        if not isinstance(hwm_seq, int) or not isinstance(hwm_hash, str):
            return None
        if tail_seq < hwm_seq:
            return "ledger tronqué (seq < high-water-mark)"
        if hwm_hash not in seen_hashes:                          # queue >= HWM seq mais head HWM absent
            return "ledger tronqué (hash high-water-mark absent de la chaîne)"
        return None

    def _read_locked(self) -> str:
        """Lit tout le fichier ledger SOUS UN VERROU PARTAGÉ (`fcntl.flock LOCK_SH`, M2). Un append
        concurrent prend `LOCK_EX` : le verrou partagé l'exclut LE TEMPS DE LA LECTURE, si bien que
        `verify()`/`verify_external()` ne lisent JAMAIS une queue à moitié écrite (faux positif transitoire
        « entrée altérée » sur un ledger honnête écrit par un AUTRE processus — le cas multi-process visé
        par le module). Plusieurs lecteurs partagent le LOCK_SH (pas de sérialisation entre vérifs). Repli
        sans verrou sur non-POSIX (`fcntl` absent), parité avec `append`. Appelé APRÈS le check d'existence."""
        with self.path.open("r", encoding="utf-8") as f:
            if fcntl is not None:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                return f.read()
            finally:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _nonempty_lines(text: str) -> "list[str]":
        """Lignes non vides (strippées) du JSONL. Sert à identifier la DERNIÈRE ligne : une dernière ligne
        non parsable = crash en plein append (tolérée, cf. `_disk_tail`) ; une ligne INTÉRIEURE non
        parsable = falsification (rejetée). C'est la distinction au cœur du fix M2."""
        return [s for s in (ln.strip() for ln in text.splitlines()) if s]

    # --- append (le seul moyen d'écrire) — flock+fsync-sérialisé ENTRE PROCESSUS ---
    # Le MÊME ledger est écrit par la console Rust (kinds `console.*`) ET le moteur Python. Un append
    # est donc rendu ATOMIQUE vis-à-vis des autres processus par un verrou consultatif EXCLUSIF
    # (`fcntl.flock LOCK_EX`, POSIX) et DURABLE par `flush()+os.fsync()` avant relâche du verrou. Comme
    # `_head` est mis en cache en mémoire, on RE-LIT la vraie queue sur disque SOUS le verrou : l'entrée
    # d'un writer concurrent est ainsi CHAÎNÉE dessus (pas écrasée). Sans ce verrou, deux appends quasi
    # simultanés liraient le même `_head` et écriraient tous deux prev=H -> verify() verrait la chaîne
    # rompue sur un ledger honnête ; un crash en plein write pourrait tronquer la dernière ligne.
    def append(self, kind: str, detail: Any) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()               # fail-closed : ne pas laisser un ledger VIDE si sign() lève
        try:
            with self.path.open("a+", encoding="utf-8") as f:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    # SOUS LE VERROU : re-lire la queue disque (le `_head` mémoire peut être périmé si un autre
                    # processus — ou la console Rust — a appendé depuis). Empty/absent -> GENESIS/0.
                    head, last_seq = self._disk_tail()
                    seq = last_seq + 1
                    ts = _now()
                    h = _entry_hash(head, seq, ts, kind, detail)
                    sig = self.signer.sign(h.encode("utf-8"))   # PEUT LEVER (ex: KMS injoignable) -> fail-closed
                    rec = {"seq": seq, "ts": ts, "kind": kind, "detail": detail,
                           "prev": head, "hash": h, "alg": self.signer.alg, "sig": sig}
                    # Si la dernière ligne existante est TRONQUÉE (crash sans '\n' final), l'isoler d'abord :
                    # sans ça, l'append (à EOF) collerait la nouvelle entrée sur la ligne corrompue, la rendant
                    # elle aussi illisible. `os.pread` lit à un offset SANS bouger la position du flux (POSIX).
                    if fcntl is not None:
                        end = os.fstat(f.fileno()).st_size
                        if end and os.pread(f.fileno(), 1, end - 1) != b"\n":
                            f.write("\n")
                    f.write(_canon(rec) + "\n")
                    f.flush()
                    os.fsync(f.fileno())           # durable AVANT de relâcher le verrou
                    # HWM sous LE MÊME verrou, APRÈS le fsync du ledger : le repère de queue ne peut donc
                    # pas retarder la queue durable (anti-troncature, cf. _write_hwm). Best-effort.
                    self._write_hwm(seq, h)
                finally:
                    if fcntl is not None:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except BaseException:
            # sign() (ou une I/O) a échoué APRÈS l'open : si on vient de CRÉER le fichier et qu'il est resté
            # VIDE (aucune entrée écrite), le supprimer — ne pas laisser de ledger vide (fail-closed, parité
            # avec l'ancien comportement qui signait AVANT d'ouvrir le fichier). Le garde `st_size == 0` ne
            # supprime JAMAIS un fichier contenant des données.
            if not existed:
                try:
                    if self.path.exists() and self.path.stat().st_size == 0:
                        self.path.unlink()
                except OSError:
                    pass
            raise
        self._head, self._seq = h, seq
        return rec

    def checkpoint(self, note: str = "") -> dict[str, Any]:
        cp = {"seq": self._seq, "head": self._head, "ts": _now()}
        receipt = self.anchor.anchor(cp) if self.anchor is not None else {"anchored": False}
        return self.append("ledger.checkpoint",
                           {"note": note, "head": self._head, "seq": self._seq,
                            "pub": self.signer.public_id(), "anchor": receipt})

    # --- verify : recalcul intégral depuis la genèse (avec le signeur local) ---
    def verify(self) -> dict[str, Any]:
        hwm = self._read_hwm()
        if not self.path.exists():
            # ledger absent : troncature TOTALE si un HWM (seq>=1) atteste d'entrées passées.
            r = self._hwm_truncation_reason(hwm, 0, set()) if hwm is not None else None
            if r is not None:
                return {"ok": False, "entries": 0, "broken": None, "why": r, "alg": self.alg}
            return {"ok": True, "entries": 0, "broken": None, "alg": self.alg}
        prev = GENESIS
        n = 0
        tail_seq = 0
        seen: set[str] = set()
        # M2 : lecture SOUS LOCK_SH (pas de queue à moitié écrite lue) + tolérance de la DERNIÈRE ligne
        # tronquée (crash mid-append), alignée sur `append`/`_disk_tail`. Une ligne non parsable n'est une
        # falsification (tamper) que si elle est INTÉRIEURE ; la dernière est ignorée (chaîne sur la dernière
        # entrée valide, exactement comme `_disk_tail`). Le HWM couvre la vraie troncature (drop de queue).
        lines = self._nonempty_lines(self._read_locked())
        last_idx = len(lines) - 1
        for i, raw in enumerate(lines):
            try:
                rec = json.loads(raw)
                seq, ts, kind, detail = rec["seq"], rec["ts"], rec["kind"], rec["detail"]
            except (ValueError, KeyError, TypeError) as e:
                if i == last_idx:
                    break  # dernière ligne tronquée : tolérée (crash en plein write), pas une falsification
                return {"ok": False, "entries": n + 1, "broken": None, "why": f"entrée malformée (intérieure): {e}", "alg": self.alg}
            n += 1
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
            tail_seq = seq
            seen.add(rec["hash"])
        # ANTI-TRONCATURE : la chaîne genesis->queue est intègre, mais est-elle COMPLÈTE ? Recouper la
        # queue contre le HWM fsync'd (cf. _write_hwm). Un HWM absent (ledger legacy) -> check sauté.
        if hwm is not None:
            r = self._hwm_truncation_reason(hwm, tail_seq, seen)
            if r is not None:
                return {"ok": False, "entries": n, "broken": tail_seq or None, "why": r, "alg": self.alg}
        return {"ok": True, "entries": n, "broken": None, "head": prev, "alg": self.alg, "pub": self.signer.public_id()}

    # --- verify EXTERNE : un tiers vérifie avec la seule clé publique Ed25519 (non-répudiation) ---
    def verify_external(self, pubkey_hex: str) -> dict[str, Any]:
        # Le HWM est un sidecar LOCAL : un tiers qui a copié le `.hwm` à côté du ledger bénéficie aussi
        # de l'anti-troncature ; s'il n'a que le ledger -> _read_hwm() None -> check simplement sauté.
        hwm = self._read_hwm()
        if not self.path.exists():
            r = self._hwm_truncation_reason(hwm, 0, set()) if hwm is not None else None
            if r is not None:
                return {"ok": False, "entries": 0, "broken": None, "why": r}
            return {"ok": True, "entries": 0}
        prev = GENESIS
        n = 0
        tail_seq = 0
        seen: set[str] = set()
        # M2 (parité avec verify()) : LOCK_SH + tolérance de la dernière ligne tronquée ; une ligne non
        # parsable INTÉRIEURE reste une falsification. Un tiers (`forge ledger verify --pubkey`) ne doit pas
        # non plus voir un ledger honnête à dernière ligne tronquée comme « CASSÉ ».
        lines = self._nonempty_lines(self._read_locked())
        last_idx = len(lines) - 1
        for i, raw in enumerate(lines):
            try:
                rec = json.loads(raw)
                seq, ts, kind, detail = rec["seq"], rec["ts"], rec["kind"], rec["detail"]
            except (ValueError, KeyError, TypeError) as e:
                if i == last_idx:
                    break  # dernière ligne tronquée : tolérée (crash en plein write)
                return {"ok": False, "entries": n + 1, "broken": None, "why": f"entrée malformée (intérieure): {e}"}
            n += 1
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
            tail_seq = seq
            seen.add(rec["hash"])
        if hwm is not None:                                       # anti-troncature (cf. verify())
            r = self._hwm_truncation_reason(hwm, tail_seq, seen)
            if r is not None:
                return {"ok": False, "entries": n, "broken": tail_seq or None, "why": r}
        return {"ok": True, "entries": n, "broken": None}

    @property
    def head(self) -> str:
        return self._head

    def public_id(self) -> str:
        return self.signer.public_id()

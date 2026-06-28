"""Connecteur Metasploit (`msf.module`) — PILOTE msfrpcd, ne génère AUCUN payload.

Forge ne développe pas de capacité offensive ici : il PARLE à msfrpcd (le démon RPC de
Metasploit, un framework de pentest STANDARD que l'opérateur exécute déjà lui-même), lance le
module MSF que l'opérateur a explicitement choisi dans `action.params.msf_module`, et MAPPE le
résultat de l'outil en Finding(s). Toute la génération de shellcode/payload reste CÔTÉ MSF.

Transport : MessagePack-RPC sur HTTP POST `/api/` (le protocole natif de msfrpcd). Codec msgpack
auto-contenu (sous-ensemble : nil/bool/int/str/bin/array/map) pour rester PUR-STDLIB — zéro
dépendance dure, comme le reste du cœur Forge. `available` sonde le service À FIRE-TIME (TTL
court), JAMAIS au catalogue : lister les modules ne doit pas marteler le réseau.

Oracle À PREUVE (anti-faux-positif structurel) : `module.execute` est FIRE-AND-FORGET — il rend un
`job_id`/`uuid` dès que le job DÉMARRE, AVANT de savoir si l'exploit a réussi. Promouvoir en
`vulnerable` sur ce seul signal = faux positif systématique (« job lancé » ≠ « cible compromise »).
Donc, pour un module de type 'exploit', on PRÉLÈVE les sessions AVANT le tir (`session.list`), puis
on POLLE `session.list` après `module.execute` (budget BORNÉ : max_polls × poll_interval) à la
recherche d'une session NOUVELLE — corrélée par `exploit_uuid == uuid` du job quand disponible,
sinon toute session apparue qui n'existait pas dans le snapshot pré-tir. La PREUVE = une session
réellement ouverte ; on n'émet `vulnerable` QU'À CETTE CONDITION et on expose le SESSION-ID dans
l'evidence du Finding. Sans session dans le budget -> `reported_by_tool` (l'outil a tiré, aucune
preuve de shell). auxiliary/scanner/post n'ouvrent pas de session -> jamais de poll, jamais de
`vulnerable` (au mieux `reported_by_tool`).

Gouvernance (héritée automatiquement de l'engine/ROE autour de fire(), NON contournée ici) :
  - Un module MSF de type 'exploit' -> ce connecteur déclare `exploit=True` POUR CETTE ACTION
    (via _exploit_for) => l'engine exige allow_exploit (opt-in fort-impact) avant de tirer.
  - auxiliary / scanner / post -> exploit=False.
  - destructive=False par défaut (le lancement reste un geste opérateur opt-in).
  - web_allowed=False : ce connecteur n'est PAS une surface de scan web public/recon — il se
    lance via opérateur/opt-in derrière la gouvernance, donc il ne compte pas dans le plancher web.

Config via env (miroir scope) : MSF_RPC_HOST/PORT/USER/PASS/SSL, ou MSF_RPC_TOKEN (token
permanent). action.params peut surcharger (host/port/user/pass/ssl/token).
"""
import os
import socket
import struct
import time
import urllib.error
import urllib.request

from .registry import register, Module


# --------------------------------------------------------------------------------------------
# Codec MessagePack minimal (pur stdlib) — sous-ensemble suffisant pour l'API msfrpcd.
# On encode : None, bool, int (signé), str (utf-8), bytes, list, dict. On décode tout ce que
# msfrpcd renvoie (str/bin, ints, float, array, map, bool, nil). Zéro dépendance dure.
# --------------------------------------------------------------------------------------------
def mp_pack(obj):
    if obj is None:
        return b"\xc0"
    if obj is True:
        return b"\xc3"
    if obj is False:
        return b"\xc2"
    if isinstance(obj, int) and not isinstance(obj, bool):
        if 0 <= obj <= 0x7F:
            return struct.pack("B", obj)
        if -32 <= obj < 0:
            return struct.pack("b", obj)
        if 0 <= obj <= 0xFF:
            return b"\xcc" + struct.pack("B", obj)
        if 0 <= obj <= 0xFFFF:
            return b"\xcd" + struct.pack(">H", obj)
        if 0 <= obj <= 0xFFFFFFFF:
            return b"\xce" + struct.pack(">I", obj)
        if 0 <= obj <= 0xFFFFFFFFFFFFFFFF:
            return b"\xcf" + struct.pack(">Q", obj)
        if -0x80 <= obj < 0:
            return b"\xd0" + struct.pack(">b", obj)
        if -0x8000 <= obj < 0:
            return b"\xd1" + struct.pack(">h", obj)
        if -0x80000000 <= obj < 0:
            return b"\xd2" + struct.pack(">i", obj)
        return b"\xd3" + struct.pack(">q", obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _pack_str(raw)
    if isinstance(obj, (bytes, bytearray)):
        raw = bytes(obj)
        n = len(raw)
        if n <= 0xFF:
            return b"\xc4" + struct.pack("B", n) + raw
        if n <= 0xFFFF:
            return b"\xc5" + struct.pack(">H", n) + raw
        return b"\xc6" + struct.pack(">I", n) + raw
    if isinstance(obj, (list, tuple)):
        n = len(obj)
        if n <= 0x0F:
            head = struct.pack("B", 0x90 | n)
        elif n <= 0xFFFF:
            head = b"\xdc" + struct.pack(">H", n)
        else:
            head = b"\xdd" + struct.pack(">I", n)
        return head + b"".join(mp_pack(x) for x in obj)
    if isinstance(obj, dict):
        n = len(obj)
        if n <= 0x0F:
            head = struct.pack("B", 0x80 | n)
        elif n <= 0xFFFF:
            head = b"\xde" + struct.pack(">H", n)
        else:
            head = b"\xdf" + struct.pack(">I", n)
        return head + b"".join(mp_pack(k) + mp_pack(v) for k, v in obj.items())
    raise TypeError(f"msgpack: type non supporté {type(obj)!r}")


def _pack_str(raw):
    n = len(raw)
    if n <= 0x1F:
        return struct.pack("B", 0xA0 | n) + raw
    if n <= 0xFF:
        return b"\xd9" + struct.pack("B", n) + raw
    if n <= 0xFFFF:
        return b"\xda" + struct.pack(">H", n) + raw
    return b"\xdb" + struct.pack(">I", n) + raw


def mp_unpack(data):
    """Décode UN objet msgpack ; renvoie l'objet (les bin/str -> str utf-8 best-effort)."""
    obj, _ = _unpack_at(data, 0)
    return obj


def _read_str(data, i, n):
    return data[i:i + n].decode("utf-8", "replace"), i + n


def _unpack_at(data, i):  # noqa: C901  (un dispatch msgpack est intrinsèquement long mais plat)
    b = data[i]
    i += 1
    if b == 0xC0:
        return None, i
    if b == 0xC2:
        return False, i
    if b == 0xC3:
        return True, i
    if b <= 0x7F:                                 # positive fixint
        return b, i
    if b >= 0xE0:                                 # negative fixint
        return b - 0x100, i
    if 0x80 <= b <= 0x8F:                         # fixmap
        return _unpack_map(data, i, b & 0x0F)
    if 0x90 <= b <= 0x9F:                         # fixarray
        return _unpack_array(data, i, b & 0x0F)
    if 0xA0 <= b <= 0xBF:                         # fixstr
        return _read_str(data, i, b & 0x1F)
    if b == 0xCC:
        return data[i], i + 1
    if b == 0xCD:
        return struct.unpack(">H", data[i:i + 2])[0], i + 2
    if b == 0xCE:
        return struct.unpack(">I", data[i:i + 4])[0], i + 4
    if b == 0xCF:
        return struct.unpack(">Q", data[i:i + 8])[0], i + 8
    if b == 0xD0:
        return struct.unpack(">b", data[i:i + 1])[0], i + 1
    if b == 0xD1:
        return struct.unpack(">h", data[i:i + 2])[0], i + 2
    if b == 0xD2:
        return struct.unpack(">i", data[i:i + 4])[0], i + 4
    if b == 0xD3:
        return struct.unpack(">q", data[i:i + 8])[0], i + 8
    if b == 0xCA:
        return struct.unpack(">f", data[i:i + 4])[0], i + 4
    if b == 0xCB:
        return struct.unpack(">d", data[i:i + 8])[0], i + 8
    if b in (0xD9, 0xC4):                         # str8 / bin8
        n = data[i]
        return _read_str(data, i + 1, n)
    if b in (0xDA, 0xC5):                         # str16 / bin16
        n = struct.unpack(">H", data[i:i + 2])[0]
        return _read_str(data, i + 2, n)
    if b in (0xDB, 0xC6):                         # str32 / bin32
        n = struct.unpack(">I", data[i:i + 4])[0]
        return _read_str(data, i + 4, n)
    if b == 0xDC:                                 # array16
        n = struct.unpack(">H", data[i:i + 2])[0]
        return _unpack_array(data, i + 2, n)
    if b == 0xDD:                                 # array32
        n = struct.unpack(">I", data[i:i + 4])[0]
        return _unpack_array(data, i + 4, n)
    if b == 0xDE:                                 # map16
        n = struct.unpack(">H", data[i:i + 2])[0]
        return _unpack_map(data, i + 2, n)
    if b == 0xDF:                                 # map32
        n = struct.unpack(">I", data[i:i + 4])[0]
        return _unpack_map(data, i + 4, n)
    raise ValueError(f"msgpack: octet de tête inattendu 0x{b:02x}")


def _unpack_array(data, i, n):
    out = []
    for _ in range(n):
        v, i = _unpack_at(data, i)
        out.append(v)
    return out, i


def _unpack_map(data, i, n):
    out = {}
    for _ in range(n):
        k, i = _unpack_at(data, i)
        v, i = _unpack_at(data, i)
        out[k] = v
    return out, i


# --------------------------------------------------------------------------------------------

_EXPLOIT_KINDS = ("exploit",)                     # seul ce type MSF élève à exploit=True
_SEV_BY_TYPE = {"exploit": "HIGH", "post": "MEDIUM", "auxiliary": "LOW",
                "scanner": "LOW", "encoder": "INFO", "nop": "INFO", "payload": "INFO"}


def _cfg(action):
    """Config msfrpcd depuis env (miroir scope), surchargée par action.params."""
    p = action.params or {}
    return {
        "host": p.get("host") or os.environ.get("MSF_RPC_HOST", "127.0.0.1"),
        "port": int(p.get("port") or os.environ.get("MSF_RPC_PORT", "55553")),
        "user": p.get("user") or os.environ.get("MSF_RPC_USER", "msf"),
        "pass": p.get("pass") or os.environ.get("MSF_RPC_PASS", ""),
        "ssl": _as_bool(p.get("ssl"), os.environ.get("MSF_RPC_SSL", "true")),
        "token": p.get("token") or os.environ.get("MSF_RPC_TOKEN") or None,
    }


def _as_bool(override, env_default):
    if override is not None:
        return bool(override) if isinstance(override, bool) else str(override).lower() in ("1", "true", "yes")
    return str(env_default).lower() in ("1", "true", "yes")


def _rpc_url(cfg):
    scheme = "https" if cfg["ssl"] else "http"
    return f"{scheme}://{cfg['host']}:{cfg['port']}/api/"


def _rpc_call(cfg, method, *args, timeout=30):
    """Un appel msgpack-RPC à msfrpcd. Renvoie l'objet décodé, ou lève sur erreur réseau."""
    payload = mp_pack([method, *args])
    req = urllib.request.Request(_rpc_url(cfg), data=payload, method="POST",
                                 headers={"Content-Type": "binary/message-pack"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return mp_unpack(r.read())


def _probe(cfg, timeout=2):
    """available() à fire-time : le service msfrpcd est-il joignable ? (TCP connect, jamais lève)."""
    try:
        with socket.create_connection((cfg["host"], cfg["port"]), timeout=timeout):
            return True
    except OSError:
        return False


@register("msf.module")
class MsfModule(Module):
    kind = "msf.module"
    # `exploit` STATIQUE conservateur : un module MSF arbitraire PEUT être un exploit, donc on
    # déclare exploit=True au niveau classe (fail-safe : l'engine exigera allow_exploit). Le verdict
    # FIN par action est affiné par _exploit_for (auxiliary/scanner/post -> n'a pas besoin d'opt-in,
    # mais on ne RABAISSE jamais la garde au niveau classe — on ne fait que la documenter).
    exploit = True
    destructive = False
    web_allowed = False                               # lancé via opérateur/opt-in, PAS surface web recon
    mitre = "T1210"                                   # Exploitation of Remote Services
    description = ("Pilote msfrpcd (RPC msgpack) : lance le module Metasploit choisi par "
                  "l'opérateur, POLLE session.list (budget borné) et ne promeut en vulnerable "
                  "QU'avec une session réellement obtenue (PREUVE) — sinon reported_by_tool.")

    # Budget de poll BORNÉ après un exploit : max_polls × poll_interval (surchargés par params).
    # Défauts modestes (un module à 1 session ouvre vite ; on ne martèle pas msfrpcd).
    _POLL_INTERVAL = 1.0
    _MAX_POLLS = 15                                    # ~15s par défaut

    @property
    def available(self):
        # SONDE À FIRE-TIME, jamais figée au catalogue. cmd_modules lit `.available` -> on garde
        # la sonde rapide (TCP connect 2s) ; pas d'auth/exec ici (lister != lancer).
        return _probe(_cfg(_FakeAction()))

    @staticmethod
    def _exploit_for(module_type):
        """exploit=True UNIQUEMENT pour un module MSF de type 'exploit' (fort-impact)."""
        return str(module_type or "").lower() in _EXPLOIT_KINDS

    def _login(self, cfg):
        """auth.login -> token, sauf si un token permanent est fourni. Lève sur échec."""
        if cfg.get("token"):
            return cfg["token"]
        res = _rpc_call(cfg, "auth.login", cfg["user"], cfg["pass"])
        if isinstance(res, dict) and res.get("result") == "success" and res.get("token"):
            return res["token"]
        raise RuntimeError(f"auth.login refusé: {res!r}")

    def dry(self, action):
        p = action.params or {}
        mtype = p.get("msf_type", "exploit")
        name = p.get("msf_module", "?")
        opts = p.get("msf_options", {})
        cfg = _cfg(action)
        return (f"# msgpack-RPC -> {_rpc_url(cfg)} : auth.login(user) -> token ; "
                f"module.execute('{mtype}', '{name}', {opts})   "
                f"# PILOTE msfrpcd (opérateur), aucun payload généré par Forge")

    def fire(self, action):
        p = action.params or {}
        name = p.get("msf_module")
        mtype = (p.get("msf_type") or "exploit").lower()
        opts = p.get("msf_options", {}) or {}
        cfg = _cfg(action)

        if not name:
            return [self.finding(
                target=action.target, title="MSF non lancé — module manquant", severity="INFO",
                category="msf", status="tested", tool="msfrpcd",
                evidence="Requiert params.msf_module (ex: 'auxiliary/scanner/http/title') et params.msf_type.",
                poc=self.dry(action))]

        # exploit=True pour CETTE action si le type MSF est 'exploit' -> l'engine a déjà exigé
        # allow_exploit en amont (la classe déclare exploit=True ; on documente le motif ici).
        is_exploit = self._exploit_for(mtype)

        try:
            token = self._login(cfg)
            # Snapshot des sessions AVANT le tir (seulement pour un exploit : on corrèle une
            # session NOUVELLE après coup). session.list ne lève pas le test hors-exploit.
            pre_sessions = self._session_ids(cfg, token) if is_exploit else set()
            res = _rpc_call(cfg, "module.execute", token, mtype, name, opts)
        except (urllib.error.URLError, OSError, RuntimeError, ValueError) as e:
            return [self.finding(
                target=action.target, title=f"MSF — échec RPC ({type(e).__name__})", severity="INFO",
                category="msf", status="tested", tool="msfrpcd",
                evidence=str(e)[:500], poc=self.dry(action))]

        return self._map_result(action, cfg, token, name, mtype, is_exploit, opts, res, pre_sessions)

    @staticmethod
    def _session_ids(cfg, token):
        """Ensemble des session-ids ACTUELS (session.list -> map {id: info}). Vide si erreur/aucune."""
        try:
            res = _rpc_call(cfg, "session.list", token, timeout=10)
        except (urllib.error.URLError, OSError, ValueError):
            return set()
        if isinstance(res, dict) and not res.get("error"):
            return {str(k) for k in res.keys()}
        return set()

    def _session_table(self, cfg, token):
        """La map complète des sessions (session.list). {} si erreur/aucune session."""
        try:
            res = _rpc_call(cfg, "session.list", token, timeout=10)
        except (urllib.error.URLError, OSError, ValueError):
            return {}
        return res if (isinstance(res, dict) and not res.get("error")) else {}

    def _poll_for_session(self, action, cfg, token, uuid, pre_sessions):
        """Poll BORNÉ de session.list : renvoie (session_id, info) d'une session NOUVELLE, ou
        (None, None) si rien dans le budget. Corrélation : exploit_uuid == uuid du job si présent,
        sinon premier id absent du snapshot pré-tir."""
        p = action.params or {}
        max_polls = max(1, int(p.get("max_polls") or self._MAX_POLLS))
        interval = float(p.get("poll_interval") or self._POLL_INTERVAL)
        for i in range(max_polls):
            table = self._session_table(cfg, token)
            # 1) corrélation forte par exploit_uuid (la session porte l'uuid du job qui l'a ouverte).
            if uuid:
                for sid, info in table.items():
                    if isinstance(info, dict) and str(info.get("exploit_uuid") or "") == str(uuid):
                        return str(sid), info
            # 2) à défaut, toute session apparue qui n'existait pas avant le tir.
            for sid in table:
                if str(sid) not in pre_sessions:
                    return str(sid), table[sid]
            # budget BORNÉ : on ne dort PAS après la dernière sonde (sinon on gaspille `interval`
            # secondes pour rien) — le poll reste réactif et son temps total est ≤ (max_polls-1)*interval.
            if i < max_polls - 1:
                time.sleep(interval)
        return None, None

    def _map_result(self, action, cfg, token, name, mtype, is_exploit, opts, res, pre_sessions):
        """Mappe module.execute (job_id/uuid/error) en Finding(s).

        Pour un exploit lancé : on POLLE session.list ; `vulnerable` UNIQUEMENT si une session
        réelle est obtenue (PREUVE, session-id dans l'evidence). Sinon `reported_by_tool`.
        auxiliary/scanner/post lancé : `reported_by_tool` (l'outil a tourné), jamais `vulnerable`."""
        sev = _SEV_BY_TYPE.get(mtype, "INFO")
        if isinstance(res, dict) and res.get("error"):
            return [self.finding(
                target=action.target, title=f"MSF {name} — refusé par le framework",
                severity="INFO", category="msf", mitre=self.mitre, status="not_vulnerable",
                tool=f"msfrpcd:{name}",
                evidence=f"error={res.get('error_message') or res.get('error_string') or res.get('error')}"[:500],
                poc=self.dry(action))]

        job_id = res.get("job_id") if isinstance(res, dict) else None
        uuid = res.get("uuid") if isinstance(res, dict) else None
        launched = isinstance(res, dict) and (res.get("result") == "success" or job_id is not None or uuid)

        if not launched:
            return [self.finding(
                target=action.target, title=f"MSF {name} — réponse inattendue",
                severity="INFO", category="msf", mitre=self.mitre, status="tested",
                tool=f"msfrpcd:{name}",
                evidence=f"type={mtype} exploit={is_exploit} job_id={job_id} uuid={uuid} options={opts} raw={str(res)[:400]}",
                poc=self.dry(action))]

        # Exploit lancé -> POLL pour une session : la PREUVE de compromission.
        if is_exploit:
            sid, sinfo = self._poll_for_session(action, cfg, token, uuid, pre_sessions)
            if sid is not None:
                stype = (sinfo.get("type") if isinstance(sinfo, dict) else None) or "?"
                shost = (sinfo.get("session_host") or sinfo.get("target_host")
                         if isinstance(sinfo, dict) else None) or action.target
                return [self.finding(
                    target=action.target, title=f"MSF exploit RÉUSSI: {name} (session {sid})",
                    severity=sev, category="msf", mitre=self.mitre, status="vulnerable",
                    tool=f"msfrpcd:{name}",
                    evidence=(f"PREUVE: session {sid} ouverte (type={stype} host={shost} "
                              f"exploit_uuid={uuid}) via job_id={job_id} options={opts}"),
                    poc=self.dry(action))]
            # Lancé mais AUCUNE session dans le budget -> pas de preuve -> reported_by_tool.
            return [self.finding(
                target=action.target, title=f"MSF exploit lancé (sans session): {name} (job {job_id})",
                severity=sev, category="msf", mitre=self.mitre, status="reported_by_tool",
                tool=f"msfrpcd:{name}",
                evidence=(f"job lancé sans session obtenue dans le budget de poll "
                          f"(job_id={job_id} uuid={uuid} options={opts}) — PAS de preuve de shell"),
                poc=self.dry(action))]

        # auxiliary/scanner/post lancé -> l'outil a tourné, pas de session attendue.
        return [self.finding(
            target=action.target, title=f"MSF {mtype} lancé: {name}",
            severity=sev, category="msf", mitre=self.mitre, status="reported_by_tool",
            tool=f"msfrpcd:{name}",
            evidence=f"type={mtype} exploit={is_exploit} job_id={job_id} uuid={uuid} options={opts} raw={str(res)[:400]}",
            poc=self.dry(action))]


class _FakeAction:
    """Action minimale pour lire la config env depuis la property `available` (pas de params)."""
    params = {}

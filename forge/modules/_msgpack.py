"""Codec MessagePack minimal auto-contenu (pur stdlib) — encode/décode le sous-ensemble msgpack
suffisant pour l'API msfrpcd (nil/bool/int signé/str utf-8/bin/array/map). Zéro dépendance dure.
Extrait de `msf.py` : aucun couplage à Metasploit, réutilisable tel quel.
"""
import struct


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

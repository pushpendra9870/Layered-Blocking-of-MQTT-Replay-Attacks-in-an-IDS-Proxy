"""MQTT 3.1.1 wire helpers for the proxy. Reuses remaining-length and
PUBLISH/PUBACK builders from the original external_eval/mqtt_io.py."""
import struct

from . import _legacy  # noqa: F401
from mqtt_io import encode_remaining_length, build_publish, build_puback  # noqa: F401

CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP = 1, 2, 3, 4, 5, 6, 7
SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT = 8, 9, 10, 11, 12, 13, 14
NAMES = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
         6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE",
         11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"}


class ProtocolError(Exception):
    pass


class StreamFramer:
    """Incremental TCP-stream -> whole MQTT packets (handles split/coalesced reads)."""

    def __init__(self, max_packet=1 << 20):
        self.buf = bytearray()
        self.max_packet = max_packet

    def feed(self, data):
        self.buf += data
        out = []
        while True:
            if len(self.buf) < 2:
                break
            rem, mult, i = 0, 1, 1
            complete = False
            while i < len(self.buf) and i <= 4:
                b = self.buf[i]
                rem += (b & 0x7F) * mult
                i += 1
                if not b & 0x80:
                    complete = True
                    break
                mult *= 128
            if not complete:
                if i > 4:
                    raise ProtocolError("malformed remaining length")
                break
            if rem > self.max_packet:
                raise ProtocolError(f"packet too large ({rem})")
            end = i + rem
            if len(self.buf) < end:
                break
            out.append(bytes(self.buf[:end]))
            del self.buf[:end]
        return out


def _rl(pkt):
    rem, mult, i = 0, 1, 1
    while True:
        if i >= len(pkt):
            raise ProtocolError("truncated")
        b = pkt[i]; i += 1
        rem += (b & 0x7F) * mult
        if not b & 0x80:
            return rem, i
        mult *= 128


def _str(pkt, off):
    if off + 2 > len(pkt):
        raise ProtocolError("truncated string")
    n = struct.unpack(">H", pkt[off:off + 2])[0]
    if off + 2 + n > len(pkt):
        raise ProtocolError("truncated string")
    return pkt[off + 2:off + 2 + n], off + 2 + n


def parse(pkt):
    """Parse one packet (MQTT 3.1/3.1.1 layout) into a dict."""
    ptype, flags = pkt[0] >> 4, pkt[0] & 0x0F
    rem, vh = _rl(pkt)
    d = {"type": ptype, "name": NAMES.get(ptype, str(ptype)), "flags": flags, "raw": pkt}
    if ptype == CONNECT:
        proto, off = _str(pkt, vh)
        if off + 4 > len(pkt):
            raise ProtocolError("short CONNECT")
        level, cflags = pkt[off], pkt[off + 1]
        keep = struct.unpack(">H", pkt[off + 2:off + 4])[0]
        d.update(proto=proto.decode("utf-8", "replace"), level=level,
                 clean_session=bool(cflags & 0x02), keep_alive=keep,
                 has_username=bool(cflags & 0x80), has_password=bool(cflags & 0x40))
        if level in (3, 4):
            cid, _ = _str(pkt, off + 4)
            d["client_id"] = cid.decode("utf-8", "replace")
        else:
            d["client_id"] = None
    elif ptype == PUBLISH:
        qos = (flags >> 1) & 3
        if qos == 3:
            raise ProtocolError("PUBLISH with QoS 3")
        topic, off = _str(pkt, vh)
        pid = 0
        if qos > 0:
            if off + 2 > len(pkt):
                raise ProtocolError("truncated packet id")
            pid = struct.unpack(">H", pkt[off:off + 2])[0]
            off += 2
        d.update(dup=bool(flags & 8), qos=qos, retain=bool(flags & 1),
                 topic=topic.decode("utf-8", "replace"), packet_id=pid,
                 payload=bytes(pkt[off:]), payload_offset=off)
    elif ptype in (PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK):
        if vh + 2 > len(pkt):
            raise ProtocolError("truncated ack")
        d["packet_id"] = struct.unpack(">H", pkt[vh:vh + 2])[0]
    return d


def rewrite_publish_payload(pkt, new_payload):
    """Same PUBLISH (flags, topic, packet id) with a different payload."""
    p = parse(pkt)
    head = pkt[0:1] + encode_remaining_length(p["payload_offset"] - _rl(pkt)[1] + len(new_payload))
    return head + pkt[_rl(pkt)[1]:p["payload_offset"]] + new_payload


def build_ack(ptype, pid):
    first = {PUBACK: 0x40, PUBREC: 0x50, PUBREL: 0x62, PUBCOMP: 0x70, UNSUBACK: 0xB0}[ptype]
    return bytes([first]) + encode_remaining_length(2) + struct.pack(">H", pid)


def _s(text):
    b = text.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def build_connect(client_id, keep_alive=60, clean=True, level=4):
    name = b"MQIsdp" if level == 3 else b"MQTT"
    vh = struct.pack(">H", len(name)) + name + bytes([level, 0x02 if clean else 0x00]) \
        + struct.pack(">H", keep_alive)
    body = vh + _s(client_id)
    return b"\x10" + encode_remaining_length(len(body)) + body


def build_connack(session_present=False, rc=0):
    return bytes([0x20, 2, 1 if session_present else 0, rc])


def build_subscribe(pid, filters):
    body = struct.pack(">H", pid) + b"".join(_s(f) + bytes([q]) for f, q in filters)
    return b"\x82" + encode_remaining_length(len(body)) + body


def build_suback(pid, codes):
    body = struct.pack(">H", pid) + bytes(codes)
    return b"\x90" + encode_remaining_length(len(body)) + body


def parse_subscribe(pkt):
    rem, vh = _rl(pkt)
    pid = struct.unpack(">H", pkt[vh:vh + 2])[0]
    off, out = vh + 2, []
    while off < len(pkt):
        f, off = _str(pkt, off)
        out.append((f.decode("utf-8", "replace"), pkt[off] & 3))
        off += 1
    return pid, out


def parse_unsubscribe(pkt):
    rem, vh = _rl(pkt)
    pid = struct.unpack(">H", pkt[vh:vh + 2])[0]
    off, out = vh + 2, []
    while off < len(pkt):
        f, off = _str(pkt, off)
        out.append(f.decode("utf-8", "replace"))
    return pid, out


PINGREQ_PKT = b"\xC0\x00"
PINGRESP_PKT = b"\xD0\x00"
DISCONNECT_PKT = b"\xE0\x00"

import struct

TYPE_NAME = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
             6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
             12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"}
PUBLISH, PUBACK, PUBCOMP = 3, 4, 7


def decode_remaining_length(raw, i):
    multiplier = 1
    value = 0
    for _ in range(4):
        if i >= len(raw):
            return None, None
        b = raw[i]
        value += (b & 0x7F) * multiplier
        i += 1
        if (b & 0x80) == 0:
            return value, i
        multiplier *= 128
    return None, None


def encode_remaining_length(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 0x80
        out.append(b)
        if n == 0:
            break
    return bytes(out)


def split_stream(raw):
    packets = []
    i = 0
    n = len(raw)
    while i < n:
        if i + 1 >= n:
            break
        rem, after = decode_remaining_length(raw, i + 1)
        if rem is None:
            break
        end = after + rem
        if end > n:
            break
        packets.append(raw[i:end])
        i = end
    return packets


def read_fields(pkt):
    if len(pkt) < 2:
        return None
    ptype = (pkt[0] >> 4) & 0x0F
    flags = pkt[0] & 0x0F
    rem, vh = decode_remaining_length(pkt, 1)
    if rem is None:
        return None
    if ptype == PUBLISH:
        dup = bool((flags >> 3) & 0x01)
        qos = (flags >> 1) & 0x03
        retain = bool(flags & 0x01)
        if vh + 2 > len(pkt):
            return None
        tlen = struct.unpack(">H", pkt[vh:vh + 2])[0]
        tstart = vh + 2
        topic = pkt[tstart:tstart + tlen].decode("utf-8", "replace")
        off = tstart + tlen
        packet_id = 0
        if qos > 0:
            if off + 2 > len(pkt):
                return None
            packet_id = struct.unpack(">H", pkt[off:off + 2])[0]
            off += 2
        return {"type": PUBLISH, "type_name": "PUBLISH", "dup": dup, "qos": qos,
                "retain": retain, "topic": topic, "packet_id": packet_id,
                "payload": pkt[off:]}
    if ptype in (PUBACK, PUBCOMP):
        if vh + 2 > len(pkt):
            return None
        return {"type": ptype, "type_name": TYPE_NAME.get(ptype, str(ptype)),
                "packet_id": struct.unpack(">H", pkt[vh:vh + 2])[0]}
    return None


def build_publish(topic, packet_id, payload, qos=1, dup=False, retain=False):
    flags = (qos << 1) | (0x08 if dup else 0) | (0x01 if retain else 0)
    b0 = 0x30 | flags
    vh = struct.pack(">H", len(topic)) + topic.encode("utf-8")
    if qos > 0:
        vh += struct.pack(">H", packet_id)
    body = vh + payload
    return bytes([b0]) + encode_remaining_length(len(body)) + body


def build_puback(packet_id):
    return bytes([0x40]) + encode_remaining_length(2) + struct.pack(">H", packet_id)

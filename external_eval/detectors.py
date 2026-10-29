import datetime
import json
from dataclasses import dataclass, field

from signing import verify


@dataclass
class MQTTPacketInfo:
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    packet_type_name: str = ""
    client_id: str = ""
    topic: str = ""
    payload: bytes = field(default_factory=bytes)
    qos: int = 0
    retain: bool = False
    dup: bool = False
    packet_id: int = 0
    timestamp: str = ""


@dataclass
class Alert:
    rule_name: str
    detail: str
    evidence: dict = field(default_factory=dict)


class PacketIdReuseRule:
    name = "Packet-ID / DUP reuse"
    ACKED_ID_RETENTION_SECONDS = 3600
    MAX_TRACKED_CONNECTIONS = 500
    MAX_IDS_PER_CONNECTION = 20000
    BROKER_PORT = 1883

    def __init__(self, broker_port=1883):
        self.BROKER_PORT = broker_port
        self.acked_ids = {}
        self.pending_ids = {}

    def _client_key(self, packet):
        if packet.dst_port == self.BROKER_PORT:
            return (packet.src_ip, packet.src_port)
        if packet.src_port == self.BROKER_PORT:
            return (packet.dst_ip, packet.dst_port)
        return (packet.src_ip, packet.src_port)

    def analyze(self, packet):
        conn_key = self._client_key(packet)
        if packet.packet_type_name == "PUBLISH" and packet.qos > 0:
            return self._check_publish(packet, conn_key)
        if packet.packet_type_name in ("PUBACK", "PUBCOMP"):
            self._mark_acked(packet, conn_key)
        return None

    def _check_publish(self, packet, conn_key):
        pid = packet.packet_id
        now = datetime.datetime.now()
        acked = self.acked_ids.get(conn_key, {})
        pending = self.pending_ids.setdefault(conn_key, {})
        if pid in acked and not packet.dup:
            age = (now - acked[pid]).total_seconds()
            return Alert(self.name,
                         f"Packet Identifier {pid} on {packet.src_ip}:{packet.src_port} "
                         f"was already ACKed {age:.1f}s ago and is reused with DUP=0.",
                         {"packet_id": pid, "dup": packet.dup, "qos": packet.qos,
                          "topic": packet.topic})
        if pid not in pending:
            pending[pid] = now
            self._bound(pending, self.MAX_IDS_PER_CONNECTION)
        self._bound_connections()
        return None

    def _mark_acked(self, packet, conn_key):
        pid = packet.packet_id
        now = datetime.datetime.now()
        self.pending_ids.get(conn_key, {}).pop(pid, None)
        acked = self.acked_ids.setdefault(conn_key, {})
        acked[pid] = now
        self._prune_old(acked, now)
        self._bound(acked, self.MAX_IDS_PER_CONNECTION)
        self._bound_connections()

    def _prune_old(self, acked, now):
        for pid in [p for p, t in acked.items()
                    if (now - t).total_seconds() > self.ACKED_ID_RETENTION_SECONDS]:
            del acked[pid]

    @staticmethod
    def _bound(d, max_len):
        while len(d) > max_len:
            del d[min(d, key=lambda k: d[k])]

    def _bound_connections(self):
        if len(self.acked_ids) + len(self.pending_ids) > self.MAX_TRACKED_CONNECTIONS:
            keys = set(self.acked_ids) | set(self.pending_ids)
            if keys:
                def last(k):
                    ts = list(self.acked_ids.get(k, {}).values()) + \
                         list(self.pending_ids.get(k, {}).values())
                    return max(ts) if ts else datetime.datetime.min
                drop = min(keys, key=last)
                self.acked_ids.pop(drop, None)
                self.pending_ids.pop(drop, None)


class HmacFreshnessRule:
    name = "HMAC + freshness"
    BROKER_PORT = 1883

    def __init__(self, broker_port=1883):
        self.BROKER_PORT = broker_port
        self.last_seq = {}

    def _client_key(self, packet):
        if packet.dst_port == self.BROKER_PORT:
            return (packet.src_ip, packet.src_port)
        if packet.src_port == self.BROKER_PORT:
            return (packet.dst_ip, packet.dst_port)
        return (packet.src_ip, packet.src_port)

    def analyze(self, packet):
        if packet.packet_type_name != "PUBLISH":
            return None
        conn_key = self._client_key(packet)
        try:
            obj = json.loads(packet.payload.decode("utf-8"))
            data = obj["data"]
            seq = int(obj["seq"])
            ts = obj["ts"]
            sig = obj["sig"]
        except Exception:
            return Alert(self.name, "PUBLISH carried no valid signed payload.",
                         {"topic": packet.topic})
        if not verify(packet.topic, data, seq, ts, sig):
            return Alert(self.name,
                         f"Signature check failed on '{packet.topic}' (seq={seq}).",
                         {"topic": packet.topic, "seq": seq, "reason": "signature_mismatch"})
        highest = self.last_seq.get(conn_key)
        if highest is not None and seq <= highest:
            return Alert(self.name,
                         f"Freshness check failed on '{packet.topic}': seq={seq} "
                         f"did not advance past {highest}.",
                         {"topic": packet.topic, "seq": seq,
                          "last_accepted_seq": highest, "reason": "stale_sequence"})
        self.last_seq[conn_key] = seq
        return None

"""Layered MQTT Replay detection engine (shared by Output 2 and Output 3).

Stage A  PacketIdTransactionRule : MQTT packet-id / DUP / ack-transaction state
         (successor of external_eval/detectors.PacketIdReuseRule).
Stage B  HmacFreshnessStage      : HMAC verification + sequence freshness
         (successor of external_eval/detectors.HmacFreshnessRule; reuses signing.verify).
Correlator                       : combines both signals into ONE verdict.

Neither stage alone is trusted:
  * packet-id state alone cannot tell legitimate reuse of an ID after completion
    from a replay, and misses DUP-evasion replays;
  * HMAC alone proves authenticity, not freshness, and strict seq monotonicity
    rejects legitimate retransmissions.
"""
import json
import time
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional

from . import _legacy  # noqa: F401
import signing
from .config import Config

# classifications / actions
LEGIT, REPLAY, INVALID, UNCERTAIN = "legit", "replay", "invalid", "uncertain"
FORWARD, DROP = "forward", "drop"


@dataclass
class Decision:
    action: str
    classification: str
    reason: str
    detector: str
    detail: str = ""
    signals: dict = field(default_factory=dict)
    client_id: str = ""
    conn_id: Any = None
    qos: int = 0
    pid: int = 0
    dup: bool = False
    topic: str = ""
    seq: Optional[int] = None
    data: Any = None            # verified application data (for minimization)
    has_data: bool = False

    def to_log(self):
        return {"event": "decision", "client_id": self.client_id, "conn_id": str(self.conn_id),
                "packet": "PUBLISH", "qos": self.qos, "packet_id": self.pid, "dup": self.dup,
                "topic": self.topic, "seq": self.seq, "detector": self.detector,
                "classification": self.classification, "reason": self.reason,
                "action": self.action, "detail": self.detail, "signals": self.signals}


@dataclass
class Txn:
    pid: int
    qos: int
    state: str            # in_flight | await_pubrel | await_pubcomp | completed
    seq: Optional[int]
    digest: str
    conn_id: Any
    t_start: float
    t_done: float = 0.0


class ClientState:
    def __init__(self, client_id):
        self.client_id = client_id
        self.highest = None
        self.seen = {}                       # accepted seq -> content digest
        self.txns = OrderedDict()            # pid -> Txn
        self.conn_id = None
        self.conn_started = 0.0
        self.session_resumed = False
        self.nodup_publish_on_conn = False


# ---------------------------------------------------------------- Stage A
class PacketIdTransactionRule:
    name = "packet_id"

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def inspect(self, cs, qos, pid, dup, digest, conn_id, now):
        if qos == 0:
            return {"state": "n/a"}
        t = cs.txns.get(pid)
        if t is None:
            return {"state": "unused", "legacy_flag": False}
        if t.state == "completed" and now - t.t_done > self.cfg.completed_retention_s:
            del cs.txns[pid]
            return {"state": "unused", "legacy_flag": False}
        done = t.state == "completed"
        return {"state": "completed" if done else "in_flight", "txn_state": t.state,
                "same_content": t.digest == digest, "same_conn": t.conn_id == conn_id,
                "age_s": round(now - (t.t_done if done else t.t_start), 3),
                # what the ORIGINAL PacketIdReuseRule would have concluded
                "legacy_flag": bool(done and not dup)}

    def open(self, cs, qos, pid, seq, digest, conn_id, now):
        if qos == 0:
            return
        cs.txns.pop(pid, None)
        cs.txns[pid] = Txn(pid, qos, "in_flight", seq, digest, conn_id, now)
        while len(cs.txns) > self.cfg.max_txns_per_client:
            cs.txns.popitem(last=False)

    def ack(self, cs, ptype_name, pid, now):
        t = cs.txns.get(pid)
        if t is None or t.state == "completed":
            return                            # orphan / duplicate ack: no state change
        if ptype_name == "PUBACK" and t.qos == 1:
            t.state, t.t_done = "completed", now
        elif ptype_name == "PUBREC" and t.qos == 2 and t.state == "in_flight":
            t.state = "await_pubrel"
        elif ptype_name == "PUBCOMP" and t.qos == 2:
            t.state, t.t_done = "completed", now

    def pubrel(self, cs, pid, now):
        t = cs.txns.get(pid)
        if t and t.qos == 2 and t.state in ("in_flight", "await_pubrel"):
            t.state = "await_pubcomp"


# ---------------------------------------------------------------- Stage B
class HmacFreshnessStage:
    name = "hmac_freshness"

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.key = cfg.hmac_secret.encode() if cfg.hmac_secret else signing.DEFAULT_SECRET

    def inspect(self, cs, topic, payload, now):
        """-> (signal dict, parsed envelope or None)"""
        try:
            obj = json.loads(payload.decode("utf-8"))
            data, seq, ts, sig = obj["data"], obj["seq"], obj["ts"], obj["sig"]
            if isinstance(seq, bool) or not isinstance(seq, int) or not isinstance(sig, str):
                raise ValueError("bad field types")
        except Exception as e:
            return {"status": "missing_signature", "error": type(e).__name__}, None
        try:
            ok = signing.verify(topic, data, seq, ts, sig, self.key)
        except Exception:
            ok = False
        if not ok:
            return {"status": "invalid_hmac", "seq": seq}, None
        digest = signing.sign(topic, data, seq, ts, self.key)   # == verified sig
        env = {"data": data, "seq": seq, "ts": ts, "digest": digest}
        sig_out = {"seq": seq, "highest": cs.highest, "window": self.cfg.seq_window}
        if self.cfg.ts_max_age_s:
            try:
                if abs(now - float(ts)) > self.cfg.ts_max_age_s:
                    sig_out["status"] = "stale_timestamp"
                    return sig_out, env
            except (TypeError, ValueError):
                sig_out["status"] = "stale_timestamp"
                return sig_out, env
        if seq in cs.seen:
            sig_out.update(status="seen", same_content=cs.seen[seq] == digest)
        elif cs.highest is None or seq > cs.highest:
            sig_out["status"] = "fresh"
        elif seq > cs.highest - self.cfg.seq_window:
            sig_out["status"] = "late_unseen"
        else:
            sig_out["status"] = "stale"
        return sig_out, env

    def commit(self, cs, seq, digest):
        cs.seen[seq] = digest
        if cs.highest is None or seq > cs.highest:
            cs.highest = seq
        floor = cs.highest - self.cfg.seq_window
        if len(cs.seen) > self.cfg.seq_window * 2:
            for s in [s for s in cs.seen if s <= floor]:
                del cs.seen[s]


# ---------------------------------------------------------------- Pipeline
class LayeredReplayEngine:
    def __init__(self, cfg: Config, log=None):
        self.cfg = cfg
        self.rule_a = PacketIdTransactionRule(cfg)
        self.rule_b = HmacFreshnessStage(cfg)
        self.clients = OrderedDict()
        self.conns = {}
        self.log = log
        self.stats = Counter()

    # ---- session / connection events
    def _state(self, client_id):
        cs = self.clients.get(client_id)
        if cs is None:
            cs = self.clients[client_id] = ClientState(client_id)
            while len(self.clients) > self.cfg.max_clients:
                self.clients.popitem(last=False)
        else:
            self.clients.move_to_end(client_id)
        return cs

    def on_connect(self, conn_id, client_id, clean_session, keep_alive=0, now=None):
        now = time.time() if now is None else now
        cs = self._state(client_id)
        existed = bool(cs.txns or cs.seen)
        if clean_session:
            cs.txns.clear()          # MQTT: clean session discards packet-id state.
        # NOTE: seq/HMAC state is application-layer and is deliberately KEPT.
        cs.conn_id, cs.conn_started = conn_id, now
        cs.session_resumed = (not clean_session) and existed
        cs.nodup_publish_on_conn = False
        self.conns[conn_id] = client_id
        self._event("connect", client_id=client_id, conn_id=str(conn_id),
                    clean_session=clean_session, keep_alive=keep_alive,
                    session_resumed=cs.session_resumed)

    def on_disconnect(self, conn_id):
        client_id = self.conns.pop(conn_id, None)
        if client_id is not None:
            cs = self.clients.get(client_id)
            if cs and cs.conn_id == conn_id:
                cs.conn_id = None
            self._event("disconnect", client_id=client_id, conn_id=str(conn_id))

    def on_broker_ack(self, conn_id, ptype_name, pid, now=None):
        """Call when a broker->client PUBACK/PUBREC/PUBCOMP is about to be relayed."""
        cs = self._cs(conn_id)
        if cs:
            self.rule_a.ack(cs, ptype_name, pid, time.time() if now is None else now)

    def on_client_pubrel(self, conn_id, pid, now=None):
        cs = self._cs(conn_id)
        if cs:
            self.rule_a.pubrel(cs, pid, time.time() if now is None else now)

    def _cs(self, conn_id):
        cid = self.conns.get(conn_id)
        return self.clients.get(cid) if cid is not None else None

    def _event(self, name, **kw):
        if self.log:
            self.log.write({"event": name, **kw})

    # ---- the pipeline
    def on_client_publish(self, conn_id, topic, payload, qos, dup, pid, now=None):
        now = time.time() if now is None else now
        client_id = self.conns.get(conn_id)
        if client_id is None:                       # PUBLISH before CONNECT
            client_id = f"unknown-{conn_id}"
            self.on_connect(conn_id, client_id, True, 0, now)
        cs = self.clients[client_id]
        sig_b, env = self.rule_b.inspect(cs, topic, payload, now)
        digest = env["digest"] if env else ""
        sig_a = self.rule_a.inspect(cs, qos, pid, dup, digest, conn_id, now) if env \
            else {"state": "not_evaluated"}
        d = self._correlate(cs, conn_id, dup, sig_a, sig_b, env, now)
        d.client_id, d.conn_id, d.qos, d.pid, d.dup, d.topic = client_id, conn_id, qos, pid, dup, topic
        d.signals = {"packet_id": sig_a, "hmac_freshness": sig_b}
        if env:
            d.seq = env["seq"]
        if d.action == FORWARD:
            if env:                                 # commit state only for forwarded packets
                self.rule_b.commit(cs, env["seq"], digest)
                self.rule_a.open(cs, qos, pid, env["seq"], digest, conn_id, now)
                d.data, d.has_data = env["data"], True
            if not dup:
                cs.nodup_publish_on_conn = True
        self.stats[(d.classification, d.reason, d.action)] += 1
        if self.log:
            self.log.write(d.to_log())
        return d

    def _correlate(self, cs, conn_id, dup, A, B, env, now):
        cfg = self.cfg
        st = B["status"]

        def mk(cls, reason, det, detail, action=None):
            if action is None:
                action = {LEGIT: FORWARD, REPLAY: DROP,
                          UNCERTAIN: cfg.uncertain_action}[cls]
            return Decision(action, cls, reason, det, detail)

        # ---- authenticity first (HMAC alone is NOT replay prevention, but forged
        #      or unsigned traffic cannot be freshness-checked at all)
        if st == "missing_signature":
            return Decision(DROP if cfg.on_missing_signature == "drop" else FORWARD, INVALID,
                            "missing_signature", self.rule_b.name,
                            "PUBLISH carries no valid signed envelope; freshness cannot be verified")
        if st == "invalid_hmac":
            return Decision(DROP if cfg.on_invalid_hmac == "drop" else FORWARD, INVALID,
                            "invalid_hmac", self.rule_b.name, "HMAC verification failed")
        if st == "stale_timestamp":
            return mk(REPLAY, "replay_stale_timestamp", self.rule_b.name,
                      "signed timestamp outside allowed age")

        pstate = A["state"]
        both = f"{self.rule_a.name}+{self.rule_b.name}"

        if st == "stale":
            return mk(REPLAY, "replay_stale_sequence", self.rule_b.name,
                      f"seq {B['seq']} is older than window floor (highest={B['highest']}, "
                      f"window={cfg.seq_window})")

        if st == "seen":
            if not B["same_content"]:
                return mk(REPLAY, "replay_seq_content_mismatch", self.rule_b.name,
                          "accepted sequence number re-used with different content")
            if pstate == "in_flight":
                if dup:
                    return mk(LEGIT, "retransmit_inflight", both,
                              "DUP=1 resend of a still-unacknowledged transaction with identical content")
                return mk(REPLAY, "replay_duplicate_inflight_nodup", both,
                          "already-accepted message resent with DUP=0 while original is in flight")
            if pstate == "completed":
                if (not A["same_conn"] and dup and A["same_content"] and cs.session_resumed
                        and not cs.nodup_publish_on_conn
                        and (now - cs.conn_started) <= cfg.resend_window_s):
                    return mk(UNCERTAIN, "possible_lost_ack_retransmit", both,
                              "DUP=1 resend of an ACKed transaction right after session resume: "
                              "ACK may have been lost with the old connection")
                return mk(REPLAY, "replay_completed_transaction", both,
                          f"transaction already completed {A['age_s']}s ago; seq {B['seq']} already accepted")
            return mk(REPLAY, "replay_seq_already_accepted", self.rule_b.name,
                      "sequence already accepted and no open transaction explains a retransmit")

        # st in (fresh, late_unseen): sequence never accepted before
        if st == "late_unseen" and not dup:
            return mk(REPLAY, "replay_late_sequence_nodup", self.rule_b.name,
                      f"seq {B['seq']} < highest {B['highest']} with DUP=0 (a live sender is monotonic)")
        if pstate == "in_flight":
            return mk(UNCERTAIN, "pid_in_flight_reuse", self.rule_a.name,
                      "fresh signed message re-uses a packet id that is still in flight")
        if pstate == "completed":
            return mk(LEGIT, "pid_reuse_after_completion_fresh_seq", both,
                      "packet id reused after transaction completed; fresh signed sequence => legitimate "
                      "(legacy Packet-ID rule would flag this)")
        if dup:
            return mk(LEGIT, "retransmit_original_unobserved", both,
                      "DUP=1 resend whose first transmission was not observed; valid HMAC, "
                      "sequence unseen and inside window")
        return mk(LEGIT, "fresh_sequence", both, "valid HMAC, fresh sequence")

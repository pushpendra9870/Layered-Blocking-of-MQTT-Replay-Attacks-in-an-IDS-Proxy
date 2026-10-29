"""Configuration (JSON). Three entry points differ only by config."""
import json
from dataclasses import dataclass, field, fields
from pathlib import Path


@dataclass
class Config:
    name: str = "output2_layered_ids"
    ids_enabled: bool = True
    minimize: bool = False                 # Output 3
    listen_host: str = "127.0.0.1"
    listen_port: int = 18840
    broker_host: str = "127.0.0.1"
    broker_port: int = 18830
    # --- policies (see README "Decision table") ---
    on_missing_signature: str = "drop"     # drop | forward
    on_invalid_hmac: str = "drop"          # drop | forward
    uncertain_action: str = "forward"      # forward | drop
    drop_response: str = "ack"             # ack | silent | disconnect
    mqtt5: str = "reject"                  # reject | passthrough (UNINSPECTED)
    # --- freshness / state ---
    seq_window: int = 256                  # tolerated lag of a DUP retransmit behind highest seq
    resend_window_s: float = 10.0          # reconnect window in which DUP resends are expected
    completed_retention_s: float = 3600.0
    ts_max_age_s: float = 0.0              # 0 = timestamp age not checked
    max_clients: int = 10000
    max_txns_per_client: int = 20000
    max_packet_bytes: int = 1 << 20
    # --- outputs ---
    decision_log: str = ""
    app_feed: str = ""                     # Output 3 JSONL (client_id/message/keep_alive)
    hmac_secret: str = ""                  # empty => MQTT_HMAC_SECRET / signing.py default
    console: bool = True
    stats_path: str = ""                   # benchmark: proxy writes timing/byte counters here

    @classmethod
    def load(cls, path):
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        flat = {}
        for k, v in raw.items():
            if isinstance(v, dict):
                flat.update(v)
            else:
                flat[k] = v
        names = {f.name for f in fields(cls)}
        unknown = set(flat) - names
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        return cls(**flat)

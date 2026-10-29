import hmac
import hashlib
import json
import os

DEFAULT_SECRET = os.environ.get("MQTT_HMAC_SECRET",
                                "lab-shared-secret-key-do-not-use-in-production").encode()


def canonical_signing_string(topic, data, seq, ts):
    data_text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return f"{topic}|{data_text}|{seq}|{ts}"


def sign(topic, data, seq, ts, key=DEFAULT_SECRET):
    msg = canonical_signing_string(topic, data, seq, ts).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify(topic, data, seq, ts, sig, key=DEFAULT_SECRET):
    return hmac.compare_digest(sign(topic, data, seq, ts, key), sig)


def build_signed_payload(topic, data, seq, ts, key=DEFAULT_SECRET):
    obj = {"data": data, "seq": seq, "ts": ts,
           "sig": sign(topic, data, seq, ts, key)}
    return json.dumps(obj).encode("utf-8")

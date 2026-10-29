"""Output 3: application-facing minimization (after verification)."""
import json

# the ONLY keys allowed in the application-facing PUBLISH payload
APP_PAYLOAD_KEYS = ("client_id", "message")
VERIFICATION_ONLY_KEYS = ("sig", "hmac", "seq", "ts", "signature", "digest")


def minimized_payload(client_id, message):
    return json.dumps({"client_id": client_id, "message": message},
                      separators=(",", ":"), sort_keys=True).encode("utf-8")


class AppFeed:
    """JSONL feed of application-facing records. Keep Alive is CONNECTION metadata:
    it is emitted once per connection as a 'session' record, never in the PUBLISH."""
    def __init__(self, path):
        self.fh = open(path, "w", encoding="utf-8") if path else None

    def session(self, client_id, keep_alive, clean_session):
        self._w({"type": "session", "client_id": client_id, "keep_alive": keep_alive,
                 "clean_session": clean_session})

    def message(self, client_id, topic, message, keep_alive):
        self._w({"type": "message", "client_id": client_id, "topic": topic,
                 "message": message, "keep_alive": keep_alive})

    def _w(self, rec):
        if self.fh:
            self.fh.write(json.dumps(rec, separators=(",", ":")) + "\n"); self.fh.flush()

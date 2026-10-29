import datetime, json, sys


class DecisionLog:
    """JSONL log of every detector decision + session events; optional console echo."""
    def __init__(self, path="", console=True, keep=False, output=""):
        self.fh = open(path, "w", encoding="utf-8") if path else None
        self.console, self.keep, self.output = console, keep, output
        self.records = [] if keep else None

    def write(self, rec):
        rec = {"ts": datetime.datetime.now().isoformat(timespec="milliseconds"),
               "output": self.output, **rec}
        if self.fh:
            self.fh.write(json.dumps(rec, default=str) + "\n"); self.fh.flush()
        if self.records is not None:
            self.records.append(rec)
        if self.console and rec.get("event") == "decision" and (
                rec["action"] == "drop" or rec["classification"] in ("uncertain", "invalid")):
            print(f"[IDS] {rec['action'].upper():7s} {rec['classification']:9s} "
                  f"{rec['detector']:32s} client={rec['client_id']} pid={rec['packet_id']} "
                  f"dup={int(rec['dup'])} seq={rec['seq']} reason={rec['reason']}", flush=True)

    def close(self):
        if self.fh:
            self.fh.close()

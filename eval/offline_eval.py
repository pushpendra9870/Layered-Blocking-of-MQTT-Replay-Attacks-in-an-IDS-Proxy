"""Offline (no sockets) evaluation on the EXISTING fixed_dataset.json.
Reuses score.py's score()/metrics() unchanged, so legacy detectors and the
layered pipeline are scored by exactly the same code.
Writes to results/offline/ ; never touches external_eval/results/ (originals)."""
import argparse, csv, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from replay_ids import _legacy  # noqa
from replay_ids.config import Config
from replay_ids.engine import LayeredReplayEngine, DROP
from detectors import PacketIdReuseRule, HmacFreshnessRule, Alert
import score as legacy_score


class LayeredAdapter:
    """Presents the layered engine through the legacy rule.analyze() interface."""
    def __init__(self, cfg, name="Layered IDS (packet-id + HMAC/freshness)"):
        self.name = name
        self.engine = LayeredReplayEngine(cfg)
        self.decisions = []
        self._seen = set()

    def analyze(self, p):
        conn = (p.src_ip, p.src_port) if p.dst_port == 1883 else (p.dst_ip, p.dst_port)
        cid = f"{conn[0]}:{conn[1]}"
        try:
            now = float(p.timestamp)
        except ValueError:
            now = 0.0
        if conn not in self._seen:
            self._seen.add(conn)
            self.engine.on_connect(conn, cid, True, 0, now)
        if p.packet_type_name in ("PUBACK", "PUBREC", "PUBCOMP"):
            self.engine.on_broker_ack(conn, p.packet_type_name, p.packet_id, now)
            return None
        d = self.engine.on_client_publish(conn, p.topic, p.payload, p.qos, p.dup, p.packet_id, now)
        self.decisions.append(d)
        return Alert(self.name, d.reason) if d.action == DROP else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(ROOT / "external_eval" / "fixed_dataset.json"))
    ap.add_argument("--out", default=str(ROOT / "results" / "offline"))
    ap.add_argument("--sensitivity", action="store_true", help="also sweep seq_window")
    a = ap.parse_args()
    records = json.loads(Path(a.dataset).read_text())
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    cfg = Config(console=False)
    dets = [PacketIdReuseRule(1883), HmacFreshnessRule(1883), LayeredAdapter(cfg)]
    rows, js = [], {}
    for det in dets:
        m, pk = legacy_score.score(det, records)
        mt = legacy_score.metrics(m)
        legacy_score.print_matrix(det.name, m, mt, pk)
        rows.append([det.name, m["TP"], m["FP"], m["TN"], m["FN"],
                     *(f"{mt[k]:.4f}" for k in ("precision", "recall", "f1", "accuracy"))])
        js[det.name] = {"matrix": m, "metrics": mt, "by_kind": pk}
        if isinstance(det, LayeredAdapter):
            from collections import Counter
            js["layered_reason_breakdown"] = {f"{c}|{r}|{ac}": n for (c, r, ac), n in
                                              det.engine.stats.items()}
            print("\n    layered reason breakdown:")
            for (c, r, ac), n in sorted(det.engine.stats.items(), key=lambda x: -x[1]):
                print(f"      {n:>5}  {ac:7s} {c:9s} {r}")
    with (out / "metrics.csv").open("w", newline="") as f:
        w = csv.writer(f); w.writerow(["detector","TP","FP","TN","FN","precision","recall","f1","accuracy"]); w.writerows(rows)
    (out / "offline_results.json").write_text(json.dumps(js, indent=2))
    if a.sensitivity:
        sweep = []
        print("\n    seq_window sensitivity (layered):")
        for w in (16, 64, 128, 178, 179, 256, 1024, 100000):
            m, _ = legacy_score.score(LayeredAdapter(Config(console=False, seq_window=w)), records)
            mt = legacy_score.metrics(m)
            sweep.append({"seq_window": w, **m, **{k: round(v, 4) for k, v in mt.items()}})
            print(f"      window={w:>6}  TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']}  "
                  f"precision={mt['precision']:.3f} recall={mt['recall']:.3f}")
        (out / "seq_window_sensitivity.json").write_text(json.dumps(sweep, indent=1))
    print(f"\nsaved -> {out}")

if __name__ == "__main__":
    main()

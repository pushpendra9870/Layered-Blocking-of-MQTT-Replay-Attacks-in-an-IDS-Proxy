"""Offline scoring of the EXISTING detectors + the layered engine on the prepared external-CSV dataset.

The CSV has no ACK exchange, so a SYNTHETIC PUBACK record is inserted right after every legitimate PUBLISH
(same packet id, reversed endpoints). This mirrors what the broker returns in the live runs, which use REAL
Mosquitto ACKs. Scoring code is the project's own score.py (unchanged). Output: results/csv_external/offline/"""
import argparse, copy, csv, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "eval"))
from replay_ids.config import Config
from offline_eval import LayeredAdapter, legacy_score
from detectors import PacketIdReuseRule, HmacFreshnessRule


def add_synthetic_acks(records, template):
    out = []
    for r in records:
        out.append(r)
        if r["truth"] == "legit":
            p = r["packet"]; a = copy.deepcopy(template)
            a["packet"].update(src_ip=p["dst_ip"], dst_ip=p["src_ip"], src_port=p["dst_port"], dst_port=p["src_port"],
                               packet_id=p["packet_id"], timestamp=p["timestamp"])
            a["note"] = "SYNTHETIC PUBACK (CSV has no ACKs)"
            out.append(a)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(ROOT / "external_data" / "csv_replay_test_ready.json"))
    ap.add_argument("--out", default=str(ROOT / "results" / "csv_external" / "offline"))
    a = ap.parse_args()
    recs = json.loads(Path(a.dataset).read_text())
    tmpl = next(r for r in json.loads((ROOT / "external_eval" / "fixed_dataset.json").read_text())
                if r["packet"]["packet_type_name"] == "PUBACK")
    recs = add_synthetic_acks(recs, tmpl)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    dets = [PacketIdReuseRule(1883), HmacFreshnessRule(1883), LayeredAdapter(Config(console=False))]
    rows, js = [], {}
    for det in dets:
        m, pk = legacy_score.score(det, recs); mt = legacy_score.metrics(m)
        legacy_score.print_matrix(det.name, m, mt, pk)
        rows.append([det.name, *[m[k] for k in ("TP", "FP", "TN", "FN")], *(f"{mt[k]:.4f}" for k in ("precision", "recall", "f1", "accuracy"))])
        js[det.name] = {"matrix": m, "metrics": mt, "by_kind": pk}
    with (out / "metrics.csv").open("w", newline="") as f:
        w = csv.writer(f); w.writerow(["detector", "TP", "FP", "TN", "FN", "precision", "recall", "f1", "accuracy"]); w.writerows(rows)
    (out / "offline_results.json").write_text(json.dumps(js, indent=2))
    print("saved ->", out)


if __name__ == "__main__":
    main()

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from detectors import MQTTPacketInfo, PacketIdReuseRule, HmacFreshnessRule

HERE = Path(__file__).parent


def to_packet(p):
    return MQTTPacketInfo(
        src_ip=p["src_ip"], dst_ip=p["dst_ip"],
        src_port=p["src_port"], dst_port=p["dst_port"],
        packet_type_name=p["packet_type_name"], client_id=p.get("client_id", ""),
        topic=p.get("topic", ""), payload=bytes.fromhex(p.get("payload_hex", "")),
        qos=p.get("qos", 0), retain=p.get("retain", False),
        dup=p.get("dup", False), packet_id=p.get("packet_id", 0),
        timestamp=p.get("timestamp", ""))


def metrics(m):
    tp, fp, tn, fn = m["TP"], m["FP"], m["TN"], m["FN"]
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    return {"precision": p, "recall": r, "f1": f1, "accuracy": acc}


def score(rule, records):
    m = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    pk = defaultdict(lambda: {"total": 0, "flagged": 0, "truth": None})
    for rec in records:
        alert = rule.analyze(to_packet(rec["packet"]))
        if not rec["scored"]:
            continue
        flagged = alert is not None
        is_replay = rec["truth"] == "replay"
        d = pk[rec["kind"]]; d["total"] += 1; d["truth"] = rec["truth"]
        if flagged:
            d["flagged"] += 1
        if is_replay and flagged: m["TP"] += 1
        elif is_replay: m["FN"] += 1
        elif flagged: m["FP"] += 1
        else: m["TN"] += 1
    return m, dict(pk)


def print_matrix(name, m, mt, pk):
    print(f"\n{'-'*62}\n  {name}\n{'-'*62}")
    print("                     predicted REPLAY   predicted LEGIT")
    print(f"    actual REPLAY          TP={m['TP']:<5}          FN={m['FN']:<5}")
    print(f"    actual LEGIT           FP={m['FP']:<5}          TN={m['TN']:<5}")
    print(f"\n    precision={mt['precision']:.3f}  recall={mt['recall']:.3f}  "
          f"F1={mt['f1']:.3f}  accuracy={mt['accuracy']:.3f}")
    print("    by packet type:")
    for kind, d in pk.items():
        print(f"      {kind:22s} {str(d['truth']):7s} {d['flagged']:>4}/{d['total']:<5}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(HERE / "fixed_dataset.json"))
    ap.add_argument("--broker-port", type=int, default=1883)
    ap.add_argument("--results", default=str(HERE / "results"))
    args = ap.parse_args()

    records = json.loads(Path(args.dataset).read_text())
    scored = [r for r in records if r["scored"]]
    pos = sum(1 for r in scored if r["truth"] == "replay")
    neg = len(scored) - pos

    comp = defaultdict(int)
    for r in scored:
        comp[r["kind"]] += 1
    print("=" * 62)
    print("  PACKETS USED")
    print("=" * 62)
    print(f"  scored PUBLISH : {len(scored)}   replay={pos}  legit={neg}")
    for k in sorted(comp):
        print(f"    {k:22s} {comp[k]}")

    detectors = [PacketIdReuseRule(args.broker_port), HmacFreshnessRule(args.broker_port)]
    outdir = Path(args.results); outdir.mkdir(parents=True, exist_ok=True)
    all_m, all_mt = {}, {}
    for det in detectors:
        m, pk = score(det, records)
        mt = metrics(m)
        all_m[det.name], all_mt[det.name] = m, mt
        print_matrix(det.name, m, mt, pk)

    (outdir / "confusion_matrices.json").write_text(
        json.dumps({"matrices": all_m, "metrics": all_mt}, indent=2))
    with (outdir / "metrics.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["detector", "TP", "FP", "TN", "FN",
                    "precision", "recall", "f1", "accuracy"])
        for name in all_m:
            m, mt = all_m[name], all_mt[name]
            w.writerow([name, m["TP"], m["FP"], m["TN"], m["FN"],
                        f"{mt['precision']:.4f}", f"{mt['recall']:.4f}",
                        f"{mt['f1']:.4f}", f"{mt['accuracy']:.4f}"])
    print(f"\nsaved: {outdir/'metrics.csv'}")
    print(f"       {outdir/'confusion_matrices.json'}")


if __name__ == "__main__":
    main()

"""Detector-only micro-benchmark (no sockets): per-PUBLISH decision time of
  legacy PacketIdReuseRule, legacy HmacFreshnessRule, the layered engine (no log),
  the layered engine + JSONL decision log (as deployed), and the Output-3 payload rewrite.
Same 4,080 scored PUBLISH + 15,000 PUBACK context records of fixed_dataset.json, in order."""
import argparse, gc, json, statistics, sys, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))
from replay_ids import _legacy  # noqa
from replay_ids import codec
from replay_ids.config import Config
from replay_ids.decisionlog import DecisionLog
from replay_ids.engine import LayeredReplayEngine
from replay_ids.minimizer import minimized_payload
from detectors import PacketIdReuseRule, HmacFreshnessRule
import score as sc

ns = time.perf_counter_ns


def pct(xs, f):
    s = sorted(xs); return s[min(len(s) - 1, int(f * len(s)))]


def run_legacy(rule, recs):
    t = []
    for r in recs:
        p = sc.to_packet(r["packet"]) if "_pk" not in r else r["_pk"]
        t0 = ns(); rule.analyze(p); dt = ns() - t0
        if r["scored"]:
            t.append(dt)
    return t


def run_layered(recs, log):
    cfg = Config(console=False)
    eng = LayeredReplayEngine(cfg, log)
    seen, t = set(), []
    for r in recs:
        p = r["packet"]
        conn = (p["src_ip"], p["src_port"]) if p["dst_port"] == 1883 else (p["dst_ip"], p["dst_port"])
        if conn not in seen:
            seen.add(conn); eng.on_connect(conn, f"{conn[0]}:{conn[1]}", True, 0, float(p["timestamp"]))
        if p["packet_type_name"] == "PUBACK":
            eng.on_broker_ack(conn, "PUBACK", p["packet_id"], float(p["timestamp"])); continue
        payload = r["_payload"]
        t0 = ns()
        eng.on_client_publish(conn, p["topic"], payload, p["qos"], p["dup"], p["packet_id"], float(p["timestamp"]))
        t.append(ns() - t0)
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=7)
    ap.add_argument("--out", default=str(ROOT / "results" / "bench" / "engine_microbench.json"))
    a = ap.parse_args()
    recs = json.loads((ROOT / "external_eval" / "fixed_dataset.json").read_text())
    for r in recs:                                   # pre-decode so decoding is not timed
        r["_pk"] = sc.to_packet(r["packet"]); r["_payload"] = bytes.fromhex(r["packet"].get("payload_hex", ""))
    npub = sum(1 for r in recs if r["scored"])
    # minimization cost: rewrite one representative forwarded PUBLISH per scored record
    pubs = [(r["packet"]["topic"], r["_payload"], r["packet"]["packet_id"]) for r in recs if r["scored"]]
    res = {}
    gc.collect()
    series = {"legacy_packet_id": [], "legacy_hmac_freshness": [], "layered_engine_no_log": [],
              "layered_engine_with_jsonl_log": [], "output3_minimize_rewrite": []}
    for rep in range(a.reps):
        series["legacy_packet_id"].append(run_legacy(PacketIdReuseRule(1883), recs))
        series["legacy_hmac_freshness"].append(run_legacy(HmacFreshnessRule(1883), recs))
        series["layered_engine_no_log"].append(run_layered(recs, None))
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False); tmp.close()
        lg = DecisionLog(tmp.name, console=False)
        series["layered_engine_with_jsonl_log"].append(run_layered(recs, lg)); lg.close()
        tm = []
        for topic, payload, pid in pubs:
            raw = codec.build_publish(topic, pid, payload, 1)
            obj = json.loads(payload)
            t0 = ns()
            codec.rewrite_publish_payload(raw, minimized_payload("dev-00000", obj["data"]))
            tm.append(ns() - t0)
        series["output3_minimize_rewrite"].append(tm)
    for k, reps in series.items():
        flat = [x for r in reps for x in r]
        means = [statistics.fmean(r) / 1e3 for r in reps]            # us, per repetition
        res[k] = {"n_calls_per_rep": len(reps[0]), "reps": a.reps,
                  "mean_us": statistics.fmean(flat) / 1e3, "p50_us": pct(flat, .5) / 1e3,
                  "p95_us": pct(flat, .95) / 1e3, "p99_us": pct(flat, .99) / 1e3,
                  "rep_means_us": means, "rep_sd_us": statistics.stdev(means) if len(means) > 1 else 0.0,
                  "decisions_per_s": 1e6 / statistics.fmean(means)}
    Path(a.out).write_text(json.dumps({"n_scored_publishes": npub, "results": res}, indent=1))
    for k, v in res.items():
        print(f"{k:32s} mean={v['mean_us']:8.2f}us p50={v['p50_us']:8.2f} p95={v['p95_us']:8.2f} p99={v['p99_us']:8.2f} rate={v['decisions_per_s']:9.0f}/s")


if __name__ == "__main__":
    main()

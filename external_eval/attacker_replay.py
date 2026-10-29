import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent


def clone(pkt, dup, ts_offset, index):
    p = dict(pkt)
    p["dup"] = dup
    try:
        p["timestamp"] = f"{float(p.get('timestamp', '0') or 0) + ts_offset:.6f}"
    except Exception:
        p["timestamp"] = f"{ts_offset:.6f}"
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=str(HERE / "legit_base.json"))
    ap.add_argument("--type1", type=int, default=40)
    ap.add_argument("--type2", type=int, default=40)
    ap.add_argument("--out", default=str(HERE / "fixed_dataset.json"))
    args = ap.parse_args()

    base = json.loads(Path(args.base).read_text())
    records = base["records"]
    acked = {k: set(v) for k, v in base["acked_ids"].items()}

    def is_acked(pkt):
        key = f"{pkt['src_ip']}:{pkt['src_port']}"
        return pkt["packet_id"] in acked.get(key, set())

    sources = [r["packet"] for r in records
               if r["kind"] == "legit_fresh" and is_acked(r["packet"])]

    need = args.type1 + args.type2
    if len(sources) < need:
        print(f"warning: only {len(sources)} replayable packets available, "
              f"need {need}; reducing counts to fit.")
        args.type1 = min(args.type1, len(sources) // 2)
        args.type2 = min(args.type2, len(sources) - args.type1)

    out = [dict(r, index=i, note="real legit traffic")
           for i, r in enumerate(records)]

    pick = 0
    print("attacker: replaying real captured packets\n")
    for _ in range(args.type1):
        src = sources[pick]; pick += 1
        p = clone(src, dup=False, ts_offset=1000.0 + pick, index=0)
        out.append({"index": len(out), "kind": "replay_exact", "truth": "replay",
                    "scored": True, "note": "type1 exact replay", "packet": p})
        print(f"  [type1 exact ] resent id={p['packet_id']} topic={p['topic'][:40]}")
    for _ in range(args.type2):
        src = sources[pick]; pick += 1
        p = clone(src, dup=True, ts_offset=2000.0 + pick, index=0)
        out.append({"index": len(out), "kind": "replay_dupevasion", "truth": "replay",
                    "scored": True, "note": "type2 dup-evasion replay", "packet": p})
        print(f"  [type2 dupev ] resent id={p['packet_id']} DUP=1 topic={p['topic'][:40]}")

    Path(args.out).write_text(json.dumps(out))

    scored = [r for r in out if r["scored"]]
    legit = [r for r in scored if r["truth"] == "legit"]
    replay = [r for r in scored if r["truth"] == "replay"]
    fresh = sum(1 for r in legit if r["kind"] == "legit_fresh")
    retx = sum(1 for r in legit if r["kind"] == "legit_retransmit")
    t1 = sum(1 for r in replay if r["kind"] == "replay_exact")
    t2 = sum(1 for r in replay if r["kind"] == "replay_dupevasion")

    print("\n" + "=" * 60)
    print("  DATASET COMPOSITION (packets we are using)")
    print("=" * 60)
    print(f"  total scored PUBLISH packets : {len(scored)}")
    print(f"    legit                      : {len(legit)}")
    print(f"       legit fresh             : {fresh}")
    print(f"       legit retransmission    : {retx}")
    print(f"    replay attacks             : {len(replay)}")
    print(f"       type1 exact replay      : {t1}")
    print(f"       type2 dup-evasion replay: {t2}")
    print(f"  context PUBACK packets       : {sum(1 for r in out if not r['scored'])}")
    print("=" * 60)
    print(f"wrote dataset -> {args.out}")


if __name__ == "__main__":
    main()

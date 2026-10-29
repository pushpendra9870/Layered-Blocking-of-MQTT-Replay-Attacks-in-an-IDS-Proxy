import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mqtt_io import split_stream, read_fields, PUBLISH, PUBACK
from signing import build_signed_payload

HERE = Path(__file__).parent


def pub_record(src, dst, sp, dp, topic, pid, dup, signed, ts, kind):
    return {"kind": kind, "truth": "legit", "scored": True,
            "packet": {"src_ip": src, "dst_ip": dst, "src_port": sp, "dst_port": dp,
                       "packet_type_id": PUBLISH, "packet_type_name": "PUBLISH",
                       "client_id": "", "topic": topic, "payload_hex": signed.hex(),
                       "qos": 1, "retain": False, "dup": dup, "packet_id": pid,
                       "timestamp": f"{ts:.6f}"}}


def ack_record(src, dst, sp, dp, pid, ts):
    return {"kind": "puback", "truth": None, "scored": False,
            "packet": {"src_ip": src, "dst_ip": dst, "src_port": sp, "dst_port": dp,
                       "packet_type_id": PUBACK, "packet_type_name": "PUBACK",
                       "client_id": "", "topic": "", "payload_hex": "",
                       "qos": 0, "retain": False, "dup": False, "packet_id": pid,
                       "timestamp": f"{ts:.6f}"}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--count", type=int, default=4000)
    ap.add_argument("--skip", type=int, default=0)
    ap.add_argument("--broker-port", type=int, default=1883)
    ap.add_argument("--grace", type=int, default=4000)
    ap.add_argument("--out", default=str(HERE / "legit_base.json"))
    args = ap.parse_args()

    from scapy.all import PcapReader, TCP, Raw, IP

    records = []
    counter = {}
    seq_map = {}
    acked = {}
    pub_index = 0
    recorded = 0
    grace_left = args.grace
    stopping = False

    for pkt in PcapReader(args.pcap):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        sp, dp = int(pkt[TCP].sport), int(pkt[TCP].dport)
        if args.broker_port not in (sp, dp):
            continue
        src = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "0.0.0.0"
        ts = float(pkt.time)

        for mb in split_stream(bytes(pkt[Raw].load)):
            f = read_fields(mb)
            if not f:
                continue

            if f["type"] == PUBACK and sp == args.broker_port:
                acked.setdefault((dst, dp), set()).add(f["packet_id"])
                if args.skip <= pub_index and not stopping:
                    records.append(ack_record(src, dst, sp, dp, f["packet_id"], ts))
                elif stopping:
                    records.append(ack_record(src, dst, sp, dp, f["packet_id"], ts))
                continue

            if f["type"] == PUBLISH and dp == args.broker_port and f["qos"] == 1:
                if stopping:
                    continue
                conn = (src, sp)
                key = (conn, f["topic"])
                if key in seq_map:
                    seq = seq_map[key]
                    kind = "legit_retransmit"
                else:
                    counter[conn] = counter.get(conn, 0) + 1
                    seq = counter[conn]
                    seq_map[key] = seq
                    kind = "legit_fresh"
                pub_index += 1
                if pub_index <= args.skip:
                    continue
                data = {"raw": f["payload"].hex()}
                signed = build_signed_payload(f["topic"], data, seq, f"{ts:.3f}")
                records.append(pub_record(src, dst, sp, dp, f["topic"], f["packet_id"],
                                          f["dup"], signed, ts, kind))
                recorded += 1
                if recorded >= args.count:
                    stopping = True

        if stopping:
            grace_left -= 1
            if grace_left <= 0:
                break

    out = {"broker_port": args.broker_port,
           "acked_ids": {f"{ip}:{port}": sorted(ids) for (ip, port), ids in acked.items()},
           "records": records}
    Path(args.out).write_text(json.dumps(out))

    npub = sum(1 for r in records if r["scored"])
    nfresh = sum(1 for r in records if r["kind"] == "legit_fresh")
    nretx = sum(1 for r in records if r["kind"] == "legit_retransmit")
    nack = sum(1 for r in records if r["kind"] == "puback")
    print(f"read real capture: {args.pcap}")
    print(f"window: skipped {args.skip} publishes, then took {npub}")
    print(f"  legit fresh          : {nfresh}")
    print(f"  legit retransmission : {nretx}")
    print(f"  PUBACK context       : {nack}")
    print(f"  acked ids available  : {sum(len(v) for v in acked.values())}")
    print(f"wrote -> {args.out}")


if __name__ == "__main__":
    main()
